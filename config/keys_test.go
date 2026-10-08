package config

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	dnsid "github.com/dnsid-ai/dnsid-go"
)

func TestKeySource_LoadMergeAndFactorySelection(t *testing.T) {
	provider := dnsid.GenerateEd25519KeyProvider()
	calls := 0
	RegisterKeyProviderFactory("google-kms", KeyProviderFactory{
		Validate: func(src KeySource) error {
			if src.KeyRef != "stable-key" {
				return dnsid.NewArgumentError("wrong reference", nil)
			}
			return nil
		},
		Open: func(context.Context, KeySource, string) (dnsid.KeyProvider, error) { calls++; return provider, nil },
	})
	defer func() { keyFactories.Lock(); delete(keyFactories.values, "google-kms"); keyFactories.Unlock() }()
	path := filepath.Join(t.TempDir(), "deployment.json")
	if err := os.WriteFile(path, []byte(`{"registration":{"organizationId":"org"},"keySource":{"provider":"google-kms","keyRef":"stable-key","settings":{"project":"test"}}}`), 0600); err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadDeploymentFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Registration.OrganizationID != "org" || loaded.KeySource.Settings["project"] != "test" {
		t.Fatal("file lost bindings")
	}
	merged := Merge(loaded, Loaded{Registration: ManagedRegistrationConfig{OrganizationID: "other"}, KeySource: KeySource{Settings: map[string]string{"project": "next"}}})
	if merged.Registration.OrganizationID != "other" || merged.KeySource.Provider != "google-kms" || merged.KeySource.KeyRef != "stable-key" || merged.KeySource.Settings["project"] != "next" {
		t.Fatal("key source merge")
	}
	selected, err := OperationalKeyProviderFrom(context.Background(), loaded.KeySource, "agent.example")
	if err != nil || selected != provider || calls != 1 {
		t.Fatalf("factory selection: %v", err)
	}
	loaded.Dnsid.Identity = &dnsid.IdentityConfig{Domain: "agent.example", GovernanceID: "account.example", EntityKeyURL: "https://account.example/ek", KeyURL: "https://agent.example/keys", StatusURL: "https://agent.example/status", LogRef: "c2sp-tlog:testnet:https://log.example#issuance_AAAAAAAAAAAAAAAAAAAAAA"}
	manager, err := Construct(context.Background(), loaded, Dependencies{})
	if err != nil || manager.KeyProvider() != provider || calls != 2 {
		t.Fatalf("Construct did not select linked provider: %v", err)
	}
	loaded.KeySource.Provider = "aws-kms" // unavailable; caller injection wins
	manager, err = Construct(context.Background(), loaded, Dependencies{KeyProvider: provider})
	if err != nil || manager.KeyProvider() != provider || calls != 2 {
		t.Fatalf("injection resolved displaced source: %v", err)
	}
}

func TestKeySource_InvalidSelectionsAndNoGenerationInConstruct(t *testing.T) {
	for _, source := range []KeySource{
		{Provider: "aws-kms", KeyRef: "key"},
		{Provider: "arbitrary/module", KeyRef: "key"},
		{Provider: "aws-kms", CliDirectory: "/keys"},
		{KeyRef: "key", Generation: &KeyGenerationConfig{Locator: "new", Algorithm: dnsid.JoseAlgES256}},
		{Generation: &KeyGenerationConfig{Locator: "new", Algorithm: "RS256"}},
		{Provider: "file", Settings: map[string]string{"secret": "x"}},
	} {
		wantArgumentError(t, ValidateKeySource(source))
	}
	_, err := OperationalKeyProviderFrom(context.Background(), KeySource{Generation: &KeyGenerationConfig{Locator: "new", Algorithm: dnsid.JoseAlgES256}}, "agent.example")
	wantArgumentError(t, err)
}
