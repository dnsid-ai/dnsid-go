package config

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	dnsid "github.com/dnsid-ai/dnsid-go"
)

func TestLoadDeploymentFile_FoundryExpectations(t *testing.T) {
	path := filepath.Join(t.TempDir(), "deployment.json")
	if err := os.WriteFile(path, []byte(`{"foundry":{"organizationId":"org-exact","governanceId":"Governance.Example."}}`), 0600); err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadDeploymentFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Foundry != (FoundryConfig{OrganizationID: "org-exact", GovernanceID: "Governance.Example."}) || loaded.Dnsid.Identity != nil {
		t.Fatalf("loaded=%+v", loaded)
	}
	manager, err := Construct(context.Background(), loaded, Dependencies{})
	if err != nil || manager.Domain() != "" {
		t.Fatalf("foundry inferred core identity: %v", err)
	}
	merged := Merge(loaded, Loaded{Foundry: FoundryConfig{GovernanceID: "other.example"}})
	if merged.Foundry.OrganizationID != "org-exact" || merged.Foundry.GovernanceID != "other.example" {
		t.Fatalf("merge=%+v", merged.Foundry)
	}
	if Merge(merged, Loaded{}).Foundry != merged.Foundry {
		t.Fatal("absent overlay cleared expectations")
	}
	if loaded.Foundry.GovernanceID != "Governance.Example." {
		t.Fatal("merge mutated base")
	}
}

func TestLoadDeploymentFile_FoundryRejectsInvalidValues(t *testing.T) {
	for _, input := range []string{`{"foundry":{"domain":"agent.example"}}`, `{"foundry":{"organizationId":4}}`, `{"foundry":{"governanceId":null}}`, `{"foundry":{"organizationId":"a","organizationId":"b"}}`, `{"foundry":[]}`} {
		path := filepath.Join(t.TempDir(), "deployment.json")
		if err := os.WriteFile(path, []byte(input), 0600); err != nil {
			t.Fatal(err)
		}
		_, err := LoadDeploymentFile(path)
		var argument *dnsid.ArgumentError
		if !errors.As(err, &argument) {
			t.Fatalf("accepted %s: %v", input, err)
		}
	}
}

func TestLoadDeploymentFile_FoundryAbsentAndWhitespace(t *testing.T) {
	for _, input := range []string{`{}`, `{"foundry":{}}`, `{"foundry":{"organizationId":" ","governanceId":"\t"}}`} {
		path := filepath.Join(t.TempDir(), "deployment.json")
		if err := os.WriteFile(path, []byte(input), 0600); err != nil {
			t.Fatal(err)
		}
		loaded, err := LoadDeploymentFile(path)
		if err != nil || loaded.Foundry != (FoundryConfig{}) {
			t.Fatalf("input=%s loaded=%+v err=%v", input, loaded, err)
		}
	}
	loaded, err := LoadEnvironment(func(name string) string {
		if name == "DNSID_GOVERNANCE_ID" {
			return "core-governance.example"
		}
		return ""
	})
	if err != nil || loaded.Foundry != (FoundryConfig{}) {
		t.Fatal("environment inferred Foundry expectations")
	}
	if loaded.Dnsid.Identity == nil || loaded.Dnsid.Identity.GovernanceID != "core-governance.example" {
		t.Fatal("environment governance ID did not remain a core identity setting")
	}
}
