package config

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
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
	if merged.Registration.OrganizationID != "other" || merged.KeySource.Provider != "" || merged.KeySource.KeyRef != "" || merged.KeySource.Settings["project"] != "next" {
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

func TestMerge_KeySourceReplacesOperationalGroup(t *testing.T) {
	cloud := KeySource{Provider: "aws-kms", KeyRef: "immutable-key", Settings: map[string]string{"region": "us-east-1"}}
	file := KeySource{CliDirectory: "/cli", KeyStorePath: "/store"}
	generation := KeySource{Generation: &KeyGenerationConfig{Locator: "initial", Algorithm: dnsid.JoseAlgES256}}
	for _, test := range []struct {
		name    string
		base    KeySource
		overlay KeySource
		want    KeySource
	}{
		{"file to cloud", file, cloud, cloud},
		{"cloud to file", cloud, file, file},
		{"existing to generation", cloud, generation, generation},
		{"generation to existing", generation, cloud, cloud},
		{"settings only", cloud, KeySource{Settings: map[string]string{}}, KeySource{Settings: map[string]string{}}},
		{"key reference only", cloud, KeySource{KeyRef: "/new-key"}, KeySource{KeyRef: "/new-key"}},
		{"provider only", cloud, KeySource{Provider: "file"}, KeySource{Provider: "file"}},
		{"absent source", cloud, KeySource{}, cloud},
		{"entity only", cloud, KeySource{EntityKeyPath: "/new-entity"}, cloud},
	} {
		t.Run(test.name, func(t *testing.T) {
			test.base.EntityKeyPath = "/entity"
			test.want.EntityKeyPath = "/entity"
			if test.overlay.EntityKeyPath != "" {
				test.want.EntityKeyPath = test.overlay.EntityKeyPath
			}
			got := Merge(Loaded{KeySource: test.base}, Loaded{KeySource: test.overlay}).KeySource
			if !reflect.DeepEqual(got, test.want) {
				t.Fatalf("merged source = %#v, want %#v", got, test.want)
			}
		})
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
