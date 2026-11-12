package audit

import (
	"context"
	"fmt"
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
	periods  []*int32 // RotationPeriodInDays passed to EnableKeyRotation
	statused []string // ids passed to GetKeyRotationStatus
	listErr  error    // returned by ListKeys when set
}

func (f *fakeKMS) ListKeys(_ context.Context, in *kms.ListKeysInput, _ ...func(*kms.Options)) (*kms.ListKeysOutput, error) {
	if f.listErr != nil {
		return nil, f.listErr
	}
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
	f.statused = append(f.statused, *in.KeyId)
	out, ok := f.rotation[*in.KeyId]
	if !ok {
		return nil, fmt.Errorf("unexpected GetKeyRotationStatus for %s", *in.KeyId)
	}
	return out, nil
}

func (f *fakeKMS) EnableKeyRotation(_ context.Context, in *kms.EnableKeyRotationInput, _ ...func(*kms.Options)) (*kms.EnableKeyRotationOutput, error) {
	f.enabled = append(f.enabled, *in.KeyId)
	f.periods = append(f.periods, in.RotationPeriodInDays)
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
	rep, err := Audit(context.Background(), f, Options{})
	if err != nil {
		t.Fatal(err)
	}
	got := rep.Findings
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
	rep, err := Audit(context.Background(), f, Options{})
	if err != nil {
		t.Fatal(err)
	}
	got := rep.Findings
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
	rep, err := Audit(context.Background(), f, Options{MaxDays: 180})
	if err != nil {
		t.Fatal(err)
	}
	got := rep.Findings
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
	rep, err := Audit(context.Background(), f, Options{})
	if err != nil {
		t.Fatal(err)
	}
	got := rep.Findings
	if len(got) != 2 {
		t.Fatalf("want both pages audited, got %d findings", len(got))
	}
}

func TestFixEnablesRotation(t *testing.T) {
	f := &fakeKMS{}
	fixed, err := Fix(context.Background(), f, []Finding{{KeyID: "k1"}, {KeyID: "k2"}}, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if len(fixed) != 2 || len(f.enabled) != 2 || f.enabled[0] != "k1" {
		t.Fatalf("fix should enable rotation on both keys, enabled=%v", f.enabled)
	}
}

func TestFixDefaultPeriodWithoutMaxDays(t *testing.T) {
	f := &fakeKMS{}
	if _, err := Fix(context.Background(), f, []Finding{{KeyID: "k1"}}, Options{}); err != nil {
		t.Fatal(err)
	}
	if f.periods[0] != nil {
		t.Fatalf("without --max-days the period must be left to KMS, got %d", *f.periods[0])
	}
}

func TestFixSetsPeriodToMaxDays(t *testing.T) {
	f := &fakeKMS{}
	findings := []Finding{
		{KeyID: "slow", Reason: "rotation period 365d exceeds max 180d"},
		{KeyID: "off", Reason: "automatic rotation disabled"},
	}
	if _, err := Fix(context.Background(), f, findings, Options{MaxDays: 180}); err != nil {
		t.Fatal(err)
	}
	for i, p := range f.periods {
		if p == nil || *p != 180 {
			t.Fatalf("key %s: want RotationPeriodInDays=180, got %v", f.enabled[i], p)
		}
	}
}

func TestFixLooseMaxDaysCapsAtDefault(t *testing.T) {
	for _, maxDays := range []int{365, 1000, 2560, 3000} {
		f := &fakeKMS{}
		findings := []Finding{
			{KeyID: "off", Reason: "automatic rotation disabled"},
			{KeyID: "slow", Reason: fmt.Sprintf("rotation period 2560d exceeds max %dd", maxDays)},
		}
		if _, err := Fix(context.Background(), f, findings, Options{MaxDays: maxDays}); err != nil {
			t.Fatal(err)
		}
		for i, p := range f.periods {
			if p == nil || *p != DefaultRotationPeriodDays {
				t.Fatalf("max-days %d, key %s: want RotationPeriodInDays=%d, got %v", maxDays, f.enabled[i], DefaultRotationPeriodDays, p)
			}
		}
	}
}

func TestFixRejectsMaxDaysBelowKMSMinimum(t *testing.T) {
	f := &fakeKMS{}
	_, err := Fix(context.Background(), f, []Finding{{KeyID: "k1"}}, Options{MaxDays: 30})
	if err == nil {
		t.Fatal("want an error for max-days below the KMS minimum")
	}
	if len(f.enabled) != 0 {
		t.Fatalf("no key should be touched, enabled=%v", f.enabled)
	}
}

func TestAuditSkipsUnrotatableKeys(t *testing.T) {
	imported := customerKey()
	imported.Origin = types.OriginTypeExternal
	cloudHSM := customerKey()
	cloudHSM.Origin = types.OriginTypeAwsCloudhsm
	cloudHSM.CustomKeyStoreId = aws.String("cks-1234")
	xks := customerKey()
	xks.Origin = types.OriginTypeExternalKeyStore
	native := customerKey()
	native.Origin = types.OriginTypeAwsKms

	f := &fakeKMS{
		pages: [][]string{{"imported", "hsm", "xks", "native"}},
		meta: map[string]types.KeyMetadata{
			"imported": imported, "hsm": cloudHSM, "xks": xks, "native": native,
		},
		rotation: map[string]*kms.GetKeyRotationStatusOutput{"native": rotated(false, 0)},
	}
	rep, err := Audit(context.Background(), f, Options{Region: "us-east-1"})
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Findings) != 1 || rep.Findings[0].KeyID != "native" {
		t.Fatalf("only the AWS_KMS key should be a finding, got %+v", rep.Findings)
	}
	want := map[string]string{
		"imported": ReasonImported,
		"hsm":      ReasonCustomKeyStore + " cks-1234",
		"xks":      ReasonCustomKeyStore,
	}
	if len(rep.Skipped) != len(want) {
		t.Fatalf("want %d skipped keys, got %+v", len(want), rep.Skipped)
	}
	for _, s := range rep.Skipped {
		if s.Reason != want[s.KeyID] {
			t.Errorf("skipped %s: reason %q, want %q", s.KeyID, s.Reason, want[s.KeyID])
		}
		if s.Region != "us-east-1" || s.ARN == "" {
			t.Errorf("skipped %s should carry region and ARN, got %+v", s.KeyID, s)
		}
	}
	if len(f.statused) != 1 || f.statused[0] != "native" {
		t.Fatalf("rotation status should only be read for rotatable keys, got %v", f.statused)
	}
}

func TestAuditIncludeUnrotatable(t *testing.T) {
	imported := customerKey()
	imported.Origin = types.OriginTypeExternal
	f := &fakeKMS{
		pages: [][]string{{"imported"}},
		meta:  map[string]types.KeyMetadata{"imported": imported},
	}
	rep, err := Audit(context.Background(), f, Options{IncludeUnrotatable: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Skipped) != 0 || len(rep.Findings) != 1 {
		t.Fatalf("want the imported key as a finding, got %+v", rep)
	}
	got := rep.Findings[0]
	if got.Reason != ReasonImported || got.Unfixable == "" {
		t.Fatalf("want reason %q and Unfixable set, got %+v", ReasonImported, got)
	}
}

func TestFixSkipsUnfixableFindings(t *testing.T) {
	f := &fakeKMS{}
	findings := []Finding{
		{KeyID: "imported", Reason: ReasonImported, Unfixable: ReasonImported},
		{KeyID: "off", Reason: "automatic rotation disabled"},
	}
	fixed, err := Fix(context.Background(), f, findings, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if len(f.enabled) != 1 || f.enabled[0] != "off" || len(fixed) != 1 {
		t.Fatalf("fix must not call EnableKeyRotation on unfixable keys, enabled=%v", f.enabled)
	}
}

// replicaKey is a multi-Region replica of a primary in primaryRegion.
func replicaKey(primaryRegion string) types.KeyMetadata {
	md := customerKey()
	md.MultiRegion = aws.Bool(true)
	md.MultiRegionConfiguration = &types.MultiRegionConfiguration{
		MultiRegionKeyType: types.MultiRegionKeyTypeReplica,
		PrimaryKey: &types.MultiRegionKey{
			Arn:    aws.String("arn:aws:kms:" + primaryRegion + ":111:key/mrk-1"),
			Region: aws.String(primaryRegion),
		},
	}
	return md
}

func TestAuditReplicaReportedOnPrimary(t *testing.T) {
	primary := customerKey()
	primary.MultiRegion = aws.Bool(true)
	primary.MultiRegionConfiguration = &types.MultiRegionConfiguration{
		MultiRegionKeyType: types.MultiRegionKeyTypePrimary,
		PrimaryKey: &types.MultiRegionKey{
			Arn:    aws.String("arn:aws:kms:us-east-1:111:key/mrk-1"),
			Region: aws.String("us-east-1"),
		},
	}
	clients := map[string]*fakeKMS{
		"us-east-1": {
			pages:    [][]string{{"mrk-1"}},
			meta:     map[string]types.KeyMetadata{"mrk-1": primary},
			rotation: map[string]*kms.GetKeyRotationStatusOutput{"mrk-1": rotated(false, 0)},
		},
		"eu-west-1": {
			pages: [][]string{{"mrk-1"}},
			meta:  map[string]types.KeyMetadata{"mrk-1": replicaKey("us-east-1")},
		},
	}
	rep := AuditRegions(context.Background(), []string{"us-east-1", "eu-west-1"},
		func(r string) KMSAPI { return clients[r] }, Options{})
	if len(rep.Errors) != 0 {
		t.Fatalf("unexpected errors %+v", rep.Errors)
	}
	if len(rep.Findings) != 1 || rep.Findings[0].Region != "us-east-1" || rep.Findings[0].Unfixable != "" {
		t.Fatalf("want one fixable finding on the primary, got %+v", rep.Findings)
	}
	if len(rep.Skipped) != 1 || rep.Skipped[0].Region != "eu-west-1" {
		t.Fatalf("want the replica skipped, got %+v", rep.Skipped)
	}
	if len(clients["eu-west-1"].statused) != 0 {
		t.Fatal("rotation status of a replica covered by its primary should not be read")
	}
}

func TestAuditReplicaWithPrimaryOutsideRun(t *testing.T) {
	f := &fakeKMS{
		pages:    [][]string{{"mrk-1"}},
		meta:     map[string]types.KeyMetadata{"mrk-1": replicaKey("us-east-1")},
		rotation: map[string]*kms.GetKeyRotationStatusOutput{"mrk-1": rotated(false, 0)},
	}
	rep, err := Audit(context.Background(), f, Options{
		Region:         "eu-west-1",
		ScannedRegions: map[string]bool{"eu-west-1": true},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Findings) != 1 {
		t.Fatalf("a replica whose primary is not scanned must still be audited, got %+v", rep)
	}
	if rep.Findings[0].Unfixable == "" {
		t.Fatal("fix cannot enable rotation on a replica; Unfixable should say so")
	}
}
