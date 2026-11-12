package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/moveeeax/kms-rotation-audit/internal/audit"
)

func TestReportJSONShape(t *testing.T) {
	var buf bytes.Buffer
	if err := report(&buf, audit.Report{}, true); err != nil {
		t.Fatal(err)
	}
	var got map[string][]any
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatalf("not a JSON object: %v\n%s", err, buf.String())
	}
	for _, k := range []string{"findings", "skipped", "errors"} {
		if v, ok := got[k]; !ok || v == nil {
			t.Errorf("key %q should be an empty array, got %s", k, buf.String())
		}
	}
}

func TestReportTable(t *testing.T) {
	rep := audit.Report{
		Findings: []audit.Finding{{KeyID: "k1", Region: "eu-west-1", Reason: "automatic rotation disabled"}},
		Skipped: []audit.Finding{
			{KeyID: "k2", Region: "eu-west-1", Reason: audit.ReasonImported},
			{KeyID: "mrk-1", Region: "eu-west-1", Reason: "multi-Region replica, reported on primary arn"},
		},
	}
	var buf bytes.Buffer
	if err := report(&buf, rep, false); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	for _, want := range []string{"REGION", "eu-west-1", "k1", "1 key(s) violate", "1 key(s) skipped"} {
		if !strings.Contains(out, want) {
			t.Errorf("table output lacks %q:\n%s", want, out)
		}
	}
}

func TestRunRejectsConflictingRegionFlags(t *testing.T) {
	err := run([]string{"audit", "--region", "us-east-1", "--all-regions"})
	if err == nil || !strings.Contains(err.Error(), "only one of") {
		t.Fatalf("want a conflict error, got %v", err)
	}
}
