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

	// IncludeUnrotatable reports keys that cannot have automatic rotation
	// (imported key material, custom key store) as findings instead of
	// listing them as skipped.
	IncludeUnrotatable bool

	// Region is the region the client talks to. It is copied into every
	// Finding.
	Region string

	// ScannedRegions holds every region of the run. A multi-Region replica
	// whose primary is in one of them is skipped, so the key set is
	// reported once, on the primary. A replica whose primary is outside
	// the run is audited in its own region.
	ScannedRegions map[string]bool
}

// Finding is one key that violates the policy, or one key the audit skipped.
type Finding struct {
	KeyID  string `json:"keyId"`
	ARN    string `json:"arn"`
	Region string `json:"region"`
	Reason string `json:"reason"`

	// Unfixable says why EnableKeyRotation cannot be called on this key.
	// Fix leaves such findings alone. Empty for keys fix can change.
	Unfixable string `json:"unfixable,omitempty"`
}

// Report is the result of an audit.
type Report struct {
	Findings []Finding `json:"findings"`
	// Skipped lists in-scope keys the audit did not judge: keys where
	// automatic rotation does not apply, and multi-Region replicas reported
	// on their primary.
	Skipped []Finding `json:"skipped"`
	// Errors lists regions whose scan failed. Empty for a complete run.
	Errors []RegionError `json:"errors"`
}

// RegionError is a region the audit could not scan.
type RegionError struct {
	Region string `json:"region"`
	Error  string `json:"error"`
}

// Reasons for keys where automatic rotation does not apply.
// https://docs.aws.amazon.com/kms/latest/APIReference/API_EnableKeyRotation.html
const (
	ReasonImported       = "rotation not supported: imported key material"
	ReasonCustomKeyStore = "rotation not supported: custom key store"
)

// Audit lists every customer-managed symmetric encryption key and returns a
// Finding for each one whose rotation is disabled or slower than opts.MaxDays.
// AWS-managed keys, keys that are not enabled, and keys that are not
// symmetric encryption keys are ignored. Keys with imported key material or
// in a custom key store go to Report.Skipped unless opts.IncludeUnrotatable
// is set. Audit never fills Report.Errors; it returns the error instead.
func Audit(ctx context.Context, c KMSAPI, opts Options) (Report, error) {
	var rep Report
	var marker *string

	for {
		out, err := c.ListKeys(ctx, &kms.ListKeysInput{Marker: marker})
		if err != nil {
			return Report{}, fmt.Errorf("list keys: %w", err)
		}

		for _, k := range out.Keys {
			id := aws.ToString(k.KeyId)
			f, skipped, err := inspect(ctx, c, id, opts)
			if err != nil {
				return Report{}, err
			}
			if skipped != nil {
				rep.Skipped = append(rep.Skipped, *skipped)
			}
			if f != nil {
				rep.Findings = append(rep.Findings, *f)
			}
		}

		if !out.Truncated {
			break
		}
		marker = out.NextMarker
	}

	return rep, nil
}

// inspect examines a single key. It returns a finding, a skipped entry, or
// neither when the key is out of scope (AWS-managed, not enabled, not a
// symmetric encryption key) or complies.
func inspect(ctx context.Context, c KMSAPI, id string, opts Options) (f, skipped *Finding, err error) {
	dk, err := c.DescribeKey(ctx, &kms.DescribeKeyInput{KeyId: &id})
	if err != nil {
		return nil, nil, fmt.Errorf("describe key %s: %w", id, err)
	}
	md := dk.KeyMetadata
	if md == nil {
		return nil, nil, nil
	}
	if md.KeyManager != types.KeyManagerTypeCustomer {
		return nil, nil, nil // AWS-managed key
	}
	if md.KeyState != types.KeyStateEnabled {
		return nil, nil, nil // disabled / pending deletion
	}
	if md.KeyUsage != types.KeyUsageTypeEncryptDecrypt || md.KeySpec != types.KeySpecSymmetricDefault {
		return nil, nil, nil // rotation only applies to symmetric encryption keys
	}

	key := Finding{KeyID: id, ARN: aws.ToString(md.Arn), Region: opts.Region}

	// Rotation of a multi-Region key set is a shared property set on the
	// primary. Report the set once, on the primary, when the run covers it.
	primaryRegion, primaryARN, replica := replicaOf(md)
	if replica {
		if opts.ScannedRegions[primaryRegion] {
			key.Reason = fmt.Sprintf("multi-Region replica, reported on primary %s", primaryARN)
			return nil, &key, nil
		}
		key.Unfixable = fmt.Sprintf("multi-Region replica: rotation is set on primary %s", primaryARN)
	}

	if reason := unrotatable(md); reason != "" {
		key.Reason = reason
		if !opts.IncludeUnrotatable {
			return nil, &key, nil
		}
		key.Unfixable = reason
		return &key, nil, nil
	}

	rs, err := c.GetKeyRotationStatus(ctx, &kms.GetKeyRotationStatusInput{KeyId: &id})
	if err != nil {
		return nil, nil, fmt.Errorf("rotation status %s: %w", id, err)
	}

	if !rs.KeyRotationEnabled {
		key.Reason = "automatic rotation disabled"
		return &key, nil, nil
	}
	if opts.MaxDays > 0 && rs.RotationPeriodInDays != nil && int(*rs.RotationPeriodInDays) > opts.MaxDays {
		key.Reason = fmt.Sprintf("rotation period %dd exceeds max %dd", *rs.RotationPeriodInDays, opts.MaxDays)
		return &key, nil, nil
	}
	return nil, nil, nil
}

// unrotatable returns why automatic rotation cannot be enabled on a
// symmetric encryption key, or "" when it can. KMS rejects EnableKeyRotation
// for keys with imported key material and for keys in a custom key store
// (CloudHSM or external).
func unrotatable(md *types.KeyMetadata) string {
	switch {
	case md.CustomKeyStoreId != nil:
		return ReasonCustomKeyStore + " " + *md.CustomKeyStoreId
	case md.Origin == types.OriginTypeAwsCloudhsm || md.Origin == types.OriginTypeExternalKeyStore:
		return ReasonCustomKeyStore
	case md.Origin == types.OriginTypeExternal:
		return ReasonImported
	}
	return ""
}

// replicaOf reports whether md is a multi-Region replica key, and if so the
// region and ARN of its primary.
func replicaOf(md *types.KeyMetadata) (region, arn string, ok bool) {
	mrc := md.MultiRegionConfiguration
	if !aws.ToBool(md.MultiRegion) || mrc == nil || mrc.MultiRegionKeyType != types.MultiRegionKeyTypeReplica || mrc.PrimaryKey == nil {
		return "", "", false
	}
	return aws.ToString(mrc.PrimaryKey.Region), aws.ToString(mrc.PrimaryKey.Arn), true
}

// Bounds of RotationPeriodInDays accepted by EnableKeyRotation, and the
// period KMS uses when the parameter is omitted.
// https://docs.aws.amazon.com/kms/latest/APIReference/API_EnableKeyRotation.html
const (
	MinRotationPeriodDays     = 90
	MaxRotationPeriodDays     = 2560
	DefaultRotationPeriodDays = 365
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
// Findings with Unfixable set are left alone and not returned.
// When opts.MaxDays is set, it also sets the rotation period to
// min(opts.MaxDays, DefaultRotationPeriodDays). A tighter policy brings
// slow keys within it; a looser one never stretches a key past the KMS
// default, so `fix --max-days 2000` does not enable rotation with a
// 2000-day period. The period is sent explicitly rather than omitted
// because EnableKeyRotation also modifies the period of a key whose
// rotation is already on.
func Fix(ctx context.Context, c KMSAPI, findings []Finding, opts Options) ([]string, error) {
	if err := ValidateFixMaxDays(opts.MaxDays); err != nil {
		return nil, err
	}
	var period *int32
	if opts.MaxDays > 0 {
		period = aws.Int32(int32(min(opts.MaxDays, DefaultRotationPeriodDays)))
	}

	var fixed []string
	for _, f := range findings {
		if f.Unfixable != "" {
			continue
		}
		id := f.KeyID
		in := &kms.EnableKeyRotationInput{KeyId: &id, RotationPeriodInDays: period}
		if _, err := c.EnableKeyRotation(ctx, in); err != nil {
			return fixed, fmt.Errorf("enable rotation %s: %w", id, err)
		}
		fixed = append(fixed, id)
	}
	return fixed, nil
}
