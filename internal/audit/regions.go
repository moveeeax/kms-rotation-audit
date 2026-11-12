package audit

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
)

// RegionWorkers bounds how many regions AuditRegions scans at once.
const RegionWorkers = 4

// EC2API is the slice of the EC2 client used to list regions.
type EC2API interface {
	DescribeRegions(context.Context, *ec2.DescribeRegionsInput, ...func(*ec2.Options)) (*ec2.DescribeRegionsOutput, error)
}

// EnabledRegions returns the sorted names of the regions enabled for the
// account. DescribeRegions without AllRegions already omits regions the
// account has not opted in to; the not-opted-in filter is a second guard.
func EnabledRegions(ctx context.Context, c EC2API) ([]string, error) {
	out, err := c.DescribeRegions(ctx, &ec2.DescribeRegionsInput{AllRegions: aws.Bool(false)})
	if err != nil {
		return nil, fmt.Errorf("describe regions: %w", err)
	}
	var regions []string
	for _, r := range out.Regions {
		if aws.ToString(r.OptInStatus) == "not-opted-in" {
			continue
		}
		if name := aws.ToString(r.RegionName); name != "" {
			regions = append(regions, name)
		}
	}
	sort.Strings(regions)
	return regions, nil
}

// ParseRegions splits a comma-separated region list, trimming blanks and
// dropping duplicates while keeping the given order.
func ParseRegions(s string) ([]string, error) {
	var regions []string
	seen := map[string]bool{}
	for _, r := range strings.Split(s, ",") {
		r = strings.TrimSpace(r)
		if r == "" || seen[r] {
			continue
		}
		seen[r] = true
		regions = append(regions, r)
	}
	if len(regions) == 0 {
		return nil, fmt.Errorf("--regions %q names no region", s)
	}
	return regions, nil
}

// AuditRegions runs Audit in every region, at most RegionWorkers at a time,
// with the client clientFor returns for that region. A region whose scan
// fails is recorded in Report.Errors and the other regions still run.
// Findings and skipped keys come back grouped by region in the order of
// regions. opts.Region and opts.ScannedRegions are set per call.
func AuditRegions(ctx context.Context, regions []string, clientFor func(region string) KMSAPI, opts Options) Report {
	scanned := make(map[string]bool, len(regions))
	for _, r := range regions {
		scanned[r] = true
	}

	results := make([]Report, len(regions))
	errs := make([]error, len(regions))
	sem := make(chan struct{}, RegionWorkers)
	var wg sync.WaitGroup
	for i, region := range regions {
		wg.Add(1)
		go func() {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			o := opts
			o.Region = region
			o.ScannedRegions = scanned
			results[i], errs[i] = Audit(ctx, clientFor(region), o)
		}()
	}
	wg.Wait()

	var rep Report
	for i, region := range regions {
		if errs[i] != nil {
			rep.Errors = append(rep.Errors, RegionError{Region: region, Error: errs[i].Error()})
			continue
		}
		rep.Findings = append(rep.Findings, results[i].Findings...)
		rep.Skipped = append(rep.Skipped, results[i].Skipped...)
	}
	return rep
}
