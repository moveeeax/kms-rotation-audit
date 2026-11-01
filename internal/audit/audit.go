// Package audit inspects AWS KMS customer-managed keys and reports the ones
// whose automatic rotation is disabled (or slower than a chosen threshold).
package audit

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
)

// KMSAPI is the slice of the KMS client the auditor needs. The concrete
// *kms.Client satisfies it, and tests supply a fake.
type KMSAPI interface {
	ListKeys(context.Context, *kms.ListKeysInput, ...func(*kms.Options)) (*kms.ListKeysOutput, error)
	DescribeKey(context.Context, *kms.DescribeKeyInput, ...func(*kms.Options)) (*kms.DescribeKeyOutput, error)
	GetKeyRotationStatus(context.Context, *kms.GetKeyRotationStatusInput, ...func(*kms.Options)) (*kms.GetKeyRotationStatusOutput, error)
	EnableKeyRotation(context.Context, *kms.EnableKeyRotationInput, ...func(*kms.Options)) (*kms.EnableKeyRotationOutput, error)
}

// Options tunes an audit run.
type Options struct {
	// MaxDays flags an enabled key whose rotation period exceeds this many
	// days. Zero disables the check.
	MaxDays int
}

// Finding is one key that violates the policy.
type Finding struct {
	KeyID  string `json:"keyId"`
	ARN    string `json:"arn"`
	Reason string `json:"reason"`
}

// Audit lists every customer-managed symmetric encryption key and returns a
// Finding for each one whose rotation is disabled or slower than opts.MaxDays.
// AWS-managed keys and keys that are not enabled are skipped.
func Audit(ctx context.Context, c KMSAPI, opts Options) ([]Finding, error) {
	var findings []Finding
	var marker *string

	for {
		out, err := c.ListKeys(ctx, &kms.ListKeysInput{Marker: marker})
		if err != nil {
			return nil, fmt.Errorf("list keys: %w", err)
		}

		for _, k := range out.Keys {
			id := aws.ToString(k.KeyId)
			f, skip, err := inspect(ctx, c, id, opts)
			if err != nil {
				return nil, err
			}
			if skip {
				continue
			}
			if f != nil {
				findings = append(findings, *f)
			}
		}

		if !out.Truncated {
			break
		}
		marker = out.NextMarker
	}

	return findings, nil
}

// inspect examines a single key. skip is true when the key is out of scope
// (AWS-managed, not enabled, or not a symmetric encryption key).
func inspect(ctx context.Context, c KMSAPI, id string, opts Options) (f *Finding, skip bool, err error) {
	dk, err := c.DescribeKey(ctx, &kms.DescribeKeyInput{KeyId: &id})
	if err != nil {
		return nil, false, fmt.Errorf("describe key %s: %w", id, err)
	}
	md := dk.KeyMetadata
	if md == nil {
		return nil, true, nil
	}
	if md.KeyManager != types.KeyManagerTypeCustomer {
		return nil, true, nil // AWS-managed key
	}
	if md.KeyState != types.KeyStateEnabled {
		return nil, true, nil // disabled / pending deletion
	}
	if md.KeyUsage != types.KeyUsageTypeEncryptDecrypt || md.KeySpec != types.KeySpecSymmetricDefault {
		return nil, true, nil // rotation only applies to symmetric encryption keys
	}

	arn := aws.ToString(md.Arn)
	rs, err := c.GetKeyRotationStatus(ctx, &kms.GetKeyRotationStatusInput{KeyId: &id})
	if err != nil {
		return nil, false, fmt.Errorf("rotation status %s: %w", id, err)
	}

	if !rs.KeyRotationEnabled {
		return &Finding{KeyID: id, ARN: arn, Reason: "automatic rotation disabled"}, false, nil
	}
	if opts.MaxDays > 0 && rs.RotationPeriodInDays != nil && int(*rs.RotationPeriodInDays) > opts.MaxDays {
		return &Finding{
			KeyID:  id,
			ARN:    arn,
			Reason: fmt.Sprintf("rotation period %dd exceeds max %dd", *rs.RotationPeriodInDays, opts.MaxDays),
		}, false, nil
	}
	return nil, false, nil
}

// Bounds of RotationPeriodInDays accepted by EnableKeyRotation. When the
// parameter is omitted, KMS uses a 365-day period.
// https://docs.aws.amazon.com/kms/latest/APIReference/API_EnableKeyRotation.html
const (
	MinRotationPeriodDays = 90
	MaxRotationPeriodDays = 2560
)

// ValidateFixMaxDays reports whether Fix can bring keys within maxDays.
// KMS rejects rotation periods shorter than MinRotationPeriodDays, so a
// tighter policy can be audited but never remediated.
func ValidateFixMaxDays(maxDays int) error {
	if maxDays > 0 && maxDays < MinRotationPeriodDays {
		return fmt.Errorf("--max-days %d is below the KMS minimum rotation period of %d days; fix cannot satisfy it", maxDays, MinRotationPeriodDays)
	}
	return nil
}

// Fix enables rotation on each flagged key and returns the ids it changed.
// When opts.MaxDays is set, it also sets the rotation period to opts.MaxDays,
// so keys flagged for a slow period (or enabled with the 365-day default)
// end up within the policy. EnableKeyRotation updates the period of a key
// whose rotation is already on.
func Fix(ctx context.Context, c KMSAPI, findings []Finding, opts Options) ([]string, error) {
	if err := ValidateFixMaxDays(opts.MaxDays); err != nil {
		return nil, err
	}
	var period *int32
	if opts.MaxDays >= MinRotationPeriodDays && opts.MaxDays <= MaxRotationPeriodDays {
		period = aws.Int32(int32(opts.MaxDays))
	}
	// A MaxDays above MaxRotationPeriodDays is satisfied by the 365-day
	// default, so the period is left unset in that case.

	var fixed []string
	for _, f := range findings {
		id := f.KeyID
		in := &kms.EnableKeyRotationInput{KeyId: &id, RotationPeriodInDays: period}
		if _, err := c.EnableKeyRotation(ctx, in); err != nil {
			return fixed, fmt.Errorf("enable rotation %s: %w", id, err)
		}
		fixed = append(fixed, id)
	}
	return fixed, nil
}
