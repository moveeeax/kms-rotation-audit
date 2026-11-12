// Command kms-rotation-audit reports AWS KMS customer-managed keys whose
// automatic rotation is disabled, and can turn rotation on with `fix`.
//
// It exits non-zero when it finds a violation, so it works as a CI gate.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"text/tabwriter"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/kms"

	"github.com/moveeeax/kms-rotation-audit/internal/audit"
)

const usage = `kms-rotation-audit — flag KMS keys with rotation disabled

Usage:
  kms-rotation-audit audit [--json] [--max-days N] [--include-unrotatable]
                           [--region R | --regions R1,R2 | --all-regions] [--profile P]
  kms-rotation-audit fix   [same flags]

Commands:
  audit   Report keys with rotation disabled. Exit 1 if any are found.
  fix     Same scan, then call EnableKeyRotation on every flagged key.
          With --max-days N (N >= 90) the rotation period is set to
          min(N, 365), so a loose N never lengthens it past the KMS default.

Exit codes: 0 clean, 1 audit found violations, 2 error (including any
region that could not be scanned).

Flags:
  --json                 Emit a JSON object (findings, skipped, errors).
  --max-days N           Also flag enabled keys whose rotation period exceeds N days.
  --include-unrotatable  Report keys with imported key material or in a custom
                         key store as findings instead of skipping them.
  --region R             AWS region (defaults to the SDK's resolved region).
  --regions R1,R2        Scan these regions.
  --all-regions          Scan every region enabled for the account
                         (needs ec2:DescribeRegions).
  --profile P            Shared-config profile to use.
`

// regionLister is the region used for the DescribeRegions call when the SDK
// resolves none. Any enabled region returns the account's full list.
const regionLister = "us-east-1"

// exitError carries a process exit code out of run.
type exitError int

func (e exitError) Error() string { return fmt.Sprintf("exit %d", int(e)) }

func main() {
	if err := run(os.Args[1:]); err != nil {
		if code, ok := err.(exitError); ok {
			os.Exit(int(code))
		}
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(2)
	}
}

func run(args []string) error {
	if len(args) == 0 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	cmd := args[0]
	if cmd == "-h" || cmd == "--help" || cmd == "help" {
		fmt.Print(usage)
		return nil
	}
	if cmd != "audit" && cmd != "fix" {
		return fmt.Errorf("unknown command %q (want audit or fix)", cmd)
	}

	fs := flag.NewFlagSet(cmd, flag.ContinueOnError)
	fs.Usage = func() { fmt.Fprint(os.Stderr, usage) }
	var (
		asJSON      = fs.Bool("json", false, "emit JSON")
		maxDays     = fs.Int("max-days", 0, "flag rotation period over N days")
		unrotatable = fs.Bool("include-unrotatable", false, "report keys where rotation does not apply")
		region      = fs.String("region", "", "AWS region")
		regionList  = fs.String("regions", "", "comma-separated AWS regions")
		allRegions  = fs.Bool("all-regions", false, "scan every enabled region")
		profile     = fs.String("profile", "", "shared config profile")
	)
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	if n := countSet(*region != "", *regionList != "", *allRegions); n > 1 {
		return fmt.Errorf("use only one of --region, --regions, --all-regions")
	}

	if cmd == "fix" {
		if err := audit.ValidateFixMaxDays(*maxDays); err != nil {
			return err
		}
	}

	ctx := context.Background()
	var opts []func(*config.LoadOptions) error
	if *region != "" {
		opts = append(opts, config.WithRegion(*region))
	}
	if *profile != "" {
		opts = append(opts, config.WithSharedConfigProfile(*profile))
	}
	cfg, err := config.LoadDefaultConfig(ctx, opts...)
	if err != nil {
		return fmt.Errorf("load aws config: %w", err)
	}

	var regions []string
	switch {
	case *regionList != "":
		if regions, err = audit.ParseRegions(*regionList); err != nil {
			return err
		}
	case *allRegions:
		ec2Client := ec2.NewFromConfig(cfg, func(o *ec2.Options) {
			if o.Region == "" {
				o.Region = regionLister
			}
		})
		if regions, err = audit.EnabledRegions(ctx, ec2Client); err != nil {
			return err
		}
	default:
		if cfg.Region == "" {
			return fmt.Errorf("no AWS region: pass --region, --regions or --all-regions, or set AWS_REGION")
		}
		regions = []string{cfg.Region}
	}

	clients := make(map[string]*kms.Client, len(regions))
	for _, r := range regions {
		clients[r] = kms.NewFromConfig(cfg, func(o *kms.Options) { o.Region = r })
	}
	clientFor := func(r string) audit.KMSAPI { return clients[r] }

	auditOpts := audit.Options{MaxDays: *maxDays, IncludeUnrotatable: *unrotatable}
	rep := audit.AuditRegions(ctx, regions, clientFor, auditOpts)
	for _, e := range rep.Errors {
		fmt.Fprintf(os.Stderr, "error: region %s: %s\n", e.Region, e.Error)
	}

	if cmd == "fix" && len(rep.Findings) > 0 {
		var fixedCount, unfixable int
		var fixErr error
		for _, r := range regions {
			var inRegion []audit.Finding
			for _, f := range rep.Findings {
				if f.Region != r {
					continue
				}
				if f.Unfixable != "" {
					unfixable++
				}
				inRegion = append(inRegion, f)
			}
			if len(inRegion) == 0 {
				continue
			}
			fixed, err := audit.Fix(ctx, clientFor(r), inRegion, auditOpts)
			fixedCount += len(fixed)
			if err != nil {
				fixErr = fmt.Errorf("region %s: %w", r, err)
				break
			}
		}
		fmt.Fprintf(os.Stderr, "enabled rotation on %d key(s)\n", fixedCount)
		if unfixable > 0 {
			fmt.Fprintf(os.Stderr, "left %d key(s) unchanged: rotation cannot be enabled on them\n", unfixable)
		}
		if fixErr != nil {
			return fixErr
		}
	}

	if err := report(os.Stdout, rep, *asJSON); err != nil {
		return err
	}
	if len(rep.Errors) > 0 {
		return exitError(2)
	}
	if len(rep.Findings) > 0 && cmd == "audit" {
		return exitError(1)
	}
	return nil
}

func countSet(flags ...bool) int {
	n := 0
	for _, f := range flags {
		if f {
			n++
		}
	}
	return n
}

func report(w io.Writer, rep audit.Report, asJSON bool) error {
	if asJSON {
		if rep.Findings == nil {
			rep.Findings = []audit.Finding{}
		}
		if rep.Skipped == nil {
			rep.Skipped = []audit.Finding{}
		}
		if rep.Errors == nil {
			rep.Errors = []audit.RegionError{}
		}
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(rep)
	}
	if len(rep.Findings) == 0 {
		if len(rep.Errors) == 0 {
			fmt.Fprintln(w, "OK: every customer-managed key has rotation enabled.")
		} else {
			fmt.Fprintf(w, "No violations in the scanned regions; %d region(s) failed.\n", len(rep.Errors))
		}
	} else {
		tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
		fmt.Fprintln(tw, "REGION\tKEY ID\tREASON")
		for _, f := range rep.Findings {
			fmt.Fprintf(tw, "%s\t%s\t%s\n", f.Region, f.KeyID, f.Reason)
		}
		if err := tw.Flush(); err != nil {
			return err
		}
		fmt.Fprintf(w, "\n%d key(s) violate the rotation policy.\n", len(rep.Findings))
	}
	if n := countUnrotatable(rep.Skipped); n > 0 {
		fmt.Fprintf(w, "%d key(s) skipped: automatic rotation does not apply (imported key material or custom key store); --include-unrotatable reports them.\n", n)
	}
	return nil
}

// countUnrotatable counts skipped keys that cannot rotate, leaving out
// multi-Region replicas that were reported on their primary.
func countUnrotatable(skipped []audit.Finding) int {
	n := 0
	for _, s := range skipped {
		if strings.HasPrefix(s.Reason, audit.ReasonImported) || strings.HasPrefix(s.Reason, audit.ReasonCustomKeyStore) {
			n++
		}
	}
	return n
}
