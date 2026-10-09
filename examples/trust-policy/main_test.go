package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRunRejectsMissingArgumentsAndInvalidTrust(t *testing.T) {
	if err := run(nil); err == nil || !strings.Contains(err.Error(), "usage:") {
		t.Fatalf("missing arguments: %v", err)
	}
	path := filepath.Join(t.TempDir(), "profile.json")
	if err := os.WriteFile(path, []byte("{}"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{"agent.example", path, "acme.example", "invalid"}); err == nil {
		t.Fatal("invalid trust profile was accepted")
	}
	// A valid profile reaches pin validation without querying DNS.
	if err := os.WriteFile(path, []byte(`{
  "version": 1,
  "scope": "public",
  "log_prefix": "https://log.example",
  "tlog_policy": "log log.example+3db4ee08+AcqTrBcFGHBx1nuDx/8O/oEI6OxFMFdddyaHkzPb2r58\nwitness primary witness.example+da76602f+BG56HN0psLeP0Tr0xVmP7/TvKpcWbjym8uT7/M2AUFvx\nquorum primary\n",
  "bundle_verifier_keys": [
    "dnsid-stream-bundle+dfa43feb+AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
  ]
}`), 0600); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{"agent.example", path, "acme.example", "invalid"}); err == nil || !strings.Contains(strings.ToLower(err.Error()), "thumbprint") {
		t.Fatalf("invalid pin: %v", err)
	}
}
