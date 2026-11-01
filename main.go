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
	"os"
	"text/tabwriter"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/kms"

	"github.com/moveeeax/kms-rotation-audit/internal/audit"
)

const usage = `kms-rotation-audit — flag KMS keys with rotation disabled

Usage:
  kms-rotation-audit audit [--json] [--max-days N] [--region R] [--profile P]
  kms-rotation-audit fix   [--json] [--max-days N] [--region R] [--profile P]

Commands:
  audit   Report keys with rotation disabled. Exit 1 if any are found.
  fix     Same scan, then call EnableKeyRotation on every flagged key.
          With --max-days N (90..2560) the rotation period is set to N.

Flags:
  --json        Emit findings as JSON instead of a table.
  --max-days N  Also flag enabled keys whose rotation period exceeds N days.
  --region R    AWS region (defaults to the SDK's resolved region).
  --profile P   Shared-config profile to use.
`

func main() {
	if err := run(os.Args[1:]); err != nil {
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
		asJSON  = fs.Bool("json", false, "emit JSON")
		maxDays = fs.Int("max-days", 0, "flag rotation period over N days")
		region  = fs.String("region", "", "AWS region")
		profile = fs.String("profile", "", "shared config profile")
	)
	if err := fs.Parse(args[1:]); err != nil {
		return err
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
	client := kms.NewFromConfig(cfg)

	auditOpts := audit.Options{MaxDays: *maxDays}
	findings, err := audit.Audit(ctx, client, auditOpts)
	if err != nil {
		return err
	}

	if cmd == "fix" && len(findings) > 0 {
		fixed, err := audit.Fix(ctx, client, findings, auditOpts)
		if err != nil {
			return err
		}
		fmt.Fprintf(os.Stderr, "enabled rotation on %d key(s)\n", len(fixed))
	}

	if err := report(os.Stdout, findings, *asJSON); err != nil {
		return err
	}
	if len(findings) > 0 && cmd == "audit" {
		os.Exit(1)
	}
	return nil
}

func report(w *os.File, findings []audit.Finding, asJSON bool) error {
	if asJSON {
		if findings == nil {
			findings = []audit.Finding{}
		}
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(findings)
	}
	if len(findings) == 0 {
		fmt.Fprintln(w, "OK: every customer-managed key has rotation enabled.")
		return nil
	}
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "KEY ID\tREASON")
	for _, f := range findings {
		fmt.Fprintf(tw, "%s\t%s\n", f.KeyID, f.Reason)
	}
	if err := tw.Flush(); err != nil {
		return err
	}
	fmt.Fprintf(w, "\n%d key(s) violate the rotation policy.\n", len(findings))
	return nil
}
