package audit

import (
	"context"
	"errors"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
)

type fakeEC2 struct {
	in      *ec2.DescribeRegionsInput
	regions []ec2types.Region
}

func (f *fakeEC2) DescribeRegions(_ context.Context, in *ec2.DescribeRegionsInput, _ ...func(*ec2.Options)) (*ec2.DescribeRegionsOutput, error) {
	f.in = in
	return &ec2.DescribeRegionsOutput{Regions: f.regions}, nil
}

func TestEnabledRegions(t *testing.T) {
	f := &fakeEC2{regions: []ec2types.Region{
		{RegionName: aws.String("us-west-2"), OptInStatus: aws.String("opt-in-not-required")},
		{RegionName: aws.String("af-south-1"), OptInStatus: aws.String("opted-in")},
		{RegionName: aws.String("me-south-1"), OptInStatus: aws.String("not-opted-in")},
	}}
	got, err := EnabledRegions(context.Background(), f)
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"af-south-1", "us-west-2"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	if aws.ToBool(f.in.AllRegions) {
		t.Fatal("DescribeRegions must not ask for disabled regions")
	}
}

func TestParseRegions(t *testing.T) {
	got, err := ParseRegions(" us-east-1, eu-west-1,,us-east-1 ")
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"us-east-1", "eu-west-1"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	if _, err := ParseRegions(" , "); err == nil {
		t.Fatal("an empty list should be rejected")
	}
}

func TestAuditRegionsTagsRegionAndKeepsOrder(t *testing.T) {
	regions := []string{"us-east-1", "eu-west-1", "ap-south-1"}
	clients := map[string]*fakeKMS{}
	for _, r := range regions {
		clients[r] = &fakeKMS{
			pages:    [][]string{{"k-" + r}},
			meta:     map[string]types.KeyMetadata{"k-" + r: customerKey()},
			rotation: map[string]*kms.GetKeyRotationStatusOutput{"k-" + r: rotated(false, 0)},
		}
	}
	rep := AuditRegions(context.Background(), regions, func(r string) KMSAPI { return clients[r] }, Options{})
	if len(rep.Findings) != len(regions) {
		t.Fatalf("want one finding per region, got %+v", rep.Findings)
	}
	for i, f := range rep.Findings {
		if f.Region != regions[i] || f.KeyID != "k-"+regions[i] {
			t.Errorf("finding %d: got %+v, want key k-%s in %s", i, f, regions[i], regions[i])
		}
	}
}

func TestAuditRegionsRecordsFailedRegion(t *testing.T) {
	denied := errors.New("AccessDeniedException: not authorized to perform kms:ListKeys")
	clients := map[string]*fakeKMS{
		"us-east-1": {
			pages:    [][]string{{"bad"}},
			meta:     map[string]types.KeyMetadata{"bad": customerKey()},
			rotation: map[string]*kms.GetKeyRotationStatusOutput{"bad": rotated(false, 0)},
		},
		"eu-west-1": {listErr: denied},
	}
	rep := AuditRegions(context.Background(), []string{"us-east-1", "eu-west-1"},
		func(r string) KMSAPI { return clients[r] }, Options{})
	if len(rep.Errors) != 1 || rep.Errors[0].Region != "eu-west-1" {
		t.Fatalf("want the denied region in Errors, got %+v", rep.Errors)
	}
	if len(rep.Findings) != 1 || rep.Findings[0].Region != "us-east-1" {
		t.Fatalf("the other region should still be audited, got %+v", rep.Findings)
	}
}

// slowKMS counts concurrent ListKeys calls.
type slowKMS struct {
	fakeKMS
	inFlight, peak *int32
	mu             *sync.Mutex
}

func (s *slowKMS) ListKeys(ctx context.Context, in *kms.ListKeysInput, o ...func(*kms.Options)) (*kms.ListKeysOutput, error) {
	n := atomic.AddInt32(s.inFlight, 1)
	s.mu.Lock()
	if n > *s.peak {
		*s.peak = n
	}
	s.mu.Unlock()
	time.Sleep(20 * time.Millisecond)
	atomic.AddInt32(s.inFlight, -1)
	return &kms.ListKeysOutput{}, nil
}

func TestAuditRegionsBoundsWorkers(t *testing.T) {
	var inFlight, peak int32
	var mu sync.Mutex
	regions := []string{"r1", "r2", "r3", "r4", "r5", "r6", "r7", "r8", "r9", "r10"}
	rep := AuditRegions(context.Background(), regions, func(string) KMSAPI {
		return &slowKMS{inFlight: &inFlight, peak: &peak, mu: &mu}
	}, Options{})
	if len(rep.Errors) != 0 {
		t.Fatalf("unexpected errors %+v", rep.Errors)
	}
	if peak > RegionWorkers {
		t.Fatalf("at most %d regions may run at once, saw %d", RegionWorkers, peak)
	}
	if peak < 2 {
		t.Fatalf("regions should be scanned concurrently, peak was %d", peak)
	}
}
