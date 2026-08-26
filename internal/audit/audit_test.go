package audit

import (
	"context"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
)

// fakeKMS is a table-programmed KMS client for tests.
type fakeKMS struct {
	pages    [][]string // ListKeys pages of key ids
	meta     map[string]types.KeyMetadata
	rotation map[string]*kms.GetKeyRotationStatusOutput
	enabled  []string // ids passed to EnableKeyRotation
}

func (f *fakeKMS) ListKeys(_ context.Context, in *kms.ListKeysInput, _ ...func(*kms.Options)) (*kms.ListKeysOutput, error) {
	idx := 0
	if in.Marker != nil {
		idx = int((*in.Marker)[0] - '0')
	}
	page := f.pages[idx]
	out := &kms.ListKeysOutput{}
	for _, id := range page {
		id := id
		out.Keys = append(out.Keys, types.KeyListEntry{KeyId: &id})
	}
	if idx+1 < len(f.pages) {
		out.Truncated = true
		next := string(rune('0' + idx + 1))
		out.NextMarker = &next
	}
	return out, nil
}

func (f *fakeKMS) DescribeKey(_ context.Context, in *kms.DescribeKeyInput, _ ...func(*kms.Options)) (*kms.DescribeKeyOutput, error) {
	md := f.meta[*in.KeyId]
	md.Arn = aws.String("arn:aws:kms:us-east-1:111:key/" + *in.KeyId)
	md.KeyId = in.KeyId
	return &kms.DescribeKeyOutput{KeyMetadata: &md}, nil
}

func (f *fakeKMS) GetKeyRotationStatus(_ context.Context, in *kms.GetKeyRotationStatusInput, _ ...func(*kms.Options)) (*kms.GetKeyRotationStatusOutput, error) {
	return f.rotation[*in.KeyId], nil
}

func (f *fakeKMS) EnableKeyRotation(_ context.Context, in *kms.EnableKeyRotationInput, _ ...func(*kms.Options)) (*kms.EnableKeyRotationOutput, error) {
	f.enabled = append(f.enabled, *in.KeyId)
	return &kms.EnableKeyRotationOutput{}, nil
}

// customerKey is a standard in-scope symmetric encryption key metadata.
func customerKey() types.KeyMetadata {
	return types.KeyMetadata{
		KeyManager: types.KeyManagerTypeCustomer,
		KeyState:   types.KeyStateEnabled,
		KeyUsage:   types.KeyUsageTypeEncryptDecrypt,
		KeySpec:    types.KeySpecSymmetricDefault,
	}
}

func rotated(enabled bool, period int32) *kms.GetKeyRotationStatusOutput {
	out := &kms.GetKeyRotationStatusOutput{KeyRotationEnabled: enabled}
	if period > 0 {
		out.RotationPeriodInDays = &period
	}
	return out
}

func TestAuditFlagsDisabledRotation(t *testing.T) {
	f := &fakeKMS{
		pages: [][]string{{"good", "bad"}},
		meta:  map[string]types.KeyMetadata{"good": customerKey(), "bad": customerKey()},
		rotation: map[string]*kms.GetKeyRotationStatusOutput{
			"good": rotated(true, 365),
			"bad":  rotated(false, 0),
		},
	}
	got, err := Audit(context.Background(), f, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].KeyID != "bad" {
		t.Fatalf("want 1 finding for bad, got %+v", got)
	}
	if got[0].ARN == "" {
		t.Error("finding should carry the key ARN")
	}
}

func TestAuditSkipsOutOfScopeKeys(t *testing.T) {
	awsManaged := customerKey()
	awsManaged.KeyManager = types.KeyManagerTypeAws
	disabled := customerKey()
	disabled.KeyState = types.KeyStateDisabled
	asym := customerKey()
	asym.KeySpec = types.KeySpecRsa2048
	asym.KeyUsage = types.KeyUsageTypeSignVerify

	f := &fakeKMS{
		pages: [][]string{{"aws", "disabled", "asym"}},
		meta: map[string]types.KeyMetadata{
			"aws": awsManaged, "disabled": disabled, "asym": asym,
		},
		rotation: map[string]*kms.GetKeyRotationStatusOutput{
			"aws": rotated(false, 0), "disabled": rotated(false, 0), "asym": rotated(false, 0),
		},
	}
	got, err := Audit(context.Background(), f, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Fatalf("out-of-scope keys must be skipped, got %+v", got)
	}
}

func TestAuditMaxDays(t *testing.T) {
	f := &fakeKMS{
		pages: [][]string{{"slow", "fast"}},
		meta:  map[string]types.KeyMetadata{"slow": customerKey(), "fast": customerKey()},
		rotation: map[string]*kms.GetKeyRotationStatusOutput{
			"slow": rotated(true, 365),
			"fast": rotated(true, 90),
		},
	}
	got, err := Audit(context.Background(), f, Options{MaxDays: 180})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].KeyID != "slow" {
		t.Fatalf("want slow flagged for exceeding max days, got %+v", got)
	}
}

func TestAuditPaginates(t *testing.T) {
	f := &fakeKMS{
		pages: [][]string{{"a"}, {"b"}},
		meta:  map[string]types.KeyMetadata{"a": customerKey(), "b": customerKey()},
		rotation: map[string]*kms.GetKeyRotationStatusOutput{
			"a": rotated(false, 0),
			"b": rotated(false, 0),
		},
	}
	got, err := Audit(context.Background(), f, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("want both pages audited, got %d findings", len(got))
	}
}

func TestFixEnablesRotation(t *testing.T) {
	f := &fakeKMS{}
	fixed, err := Fix(context.Background(), f, []Finding{{KeyID: "k1"}, {KeyID: "k2"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(fixed) != 2 || len(f.enabled) != 2 || f.enabled[0] != "k1" {
		t.Fatalf("fix should enable rotation on both keys, enabled=%v", f.enabled)
	}
}
