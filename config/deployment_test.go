package config

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	dnsid "github.com/dnsid-ai/dnsid-go"
)

func TestLoadDeploymentFile_ManagedSetupAndMerge(t *testing.T) {
	path := filepath.Join(t.TempDir(), "deployment.json")
	if err := os.WriteFile(path, []byte(`{"dnsid":{"verification":{"dnssecMode":"required","trustedEntities":[]},"transport":{"dnsServer":"1.1.1.1:53"}},"logTrust":{"managed":true},"registry":{"registryUrl":"https://registry.example"},"registration":{"governanceId":"account.example","entityKeyUrl":"https://account.example/entity.json"}}`), 0600); err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadDeploymentFile(path)
	if err != nil {
		t.Fatal(err)
	}
	expected := Loaded{Dnsid: dnsid.Config{Verification: dnsid.VerificationConfig{DNSSECMode: dnsid.DNSSECModeRequired, TrustedEntities: []dnsid.TrustedEntity{}}, Transport: dnsid.TransportConfig{DNSServer: "1.1.1.1:53"}}, LogTrust: LogTrust{Managed: true}, Registry: Registry{RegistryURL: "https://registry.example"}, Registration: ManagedRegistrationConfig{GovernanceID: "account.example", EntityKeyURL: "https://account.example/entity.json"}}
	if !reflect.DeepEqual(loaded, expected) {
		t.Fatalf("loaded = %#v", loaded)
	}
	merged := Merge(loaded, Loaded{Registration: ManagedRegistrationConfig{GovernanceID: "other.example"}})
	if merged.Registration.GovernanceID != "other.example" || merged.Registration.EntityKeyURL != loaded.Registration.EntityKeyURL {
		t.Fatal("registration merge is not field-wise")
	}
	// Ordinary construction neither infers an identity nor validates setup-only fields.
	loaded.LogTrust = LogTrust{}
	loaded.Registration.EntityKeyURL = "invalid setup endpoint"
	manager, err := Construct(context.Background(), loaded, Dependencies{})
	if err != nil {
		t.Fatal(err)
	}
	if manager.Domain() != "" {
		t.Fatal("setup configuration inferred local identity")
	}
}

func TestLoadDeploymentFile_IdentityPresence(t *testing.T) {
	for _, test := range []struct {
		document string
		present  bool
	}{
		{`{}`, false},
		{`{"dnsid":{"identity":{}}}`, false},
		{`{"dnsid":{"identity":{"domain":""}}}`, true},
		{`{"dnsid":{"identity":{"policyFlags":[]}}}`, true},
	} {
		t.Run(test.document, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "deployment.json")
			if err := os.WriteFile(path, []byte(test.document), 0600); err != nil {
				t.Fatal(err)
			}
			loaded, err := LoadDeploymentFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if (loaded.Dnsid.Identity != nil) != test.present {
				t.Fatalf("identity presence = %v, want %v", loaded.Dnsid.Identity != nil, test.present)
			}
			manager, err := Construct(context.Background(), loaded, Dependencies{})
			if test.present {
				wantArgumentError(t, err)
			} else if err != nil || manager.Domain() != "" {
				t.Fatalf("verification-only construction: %v", err)
			}
		})
	}
}

func TestLoadDeploymentFile_RejectsInvalidDocuments(t *testing.T) {
	for _, document := range []string{
		`{"registry":{"apiKey":"secret"}}`,
		`{"keySource":{"privateKey":"secret"}}`,
		`{"keySource":{"settings":{"region":42}}}`,
		`{"keySource":{"generation":{"algorithm":"ES256","secret":"x"}}}`,
		`{"registration":{"governanceId":1}}`,
		`{"registration":{"entityKeyUrl":null}}`,
		`{"registration":{"governanceId":"one.example","governanceId":"two.example"}}`,
		`{"logTrust":{}}`,
		`{"logTrust":{"managed":false}}`,
		`{} {}`,
		`[]`,
	} {
		t.Run(document, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "deployment.json")
			if err := os.WriteFile(path, []byte(document), 0600); err != nil {
				t.Fatal(err)
			}
			_, err := LoadDeploymentFile(path)
			wantArgumentError(t, err)
		})
	}
}
