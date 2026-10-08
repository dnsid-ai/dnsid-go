package registration

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	dnsid "github.com/dnsid-ai/dnsid-go"
	"github.com/dnsid-ai/dnsid-go/config"
)

func TestReplayKeys_DesignVector(t *testing.T) {
	unicodeKey, err := digestStrings("A<&>\u2028🙂", "x")
	if err != nil || unicodeKey != "A1Rmp-SZV9TPEIwGGreMiO3T_z1p-tVUuV-zRY_Evsg" {
		t.Fatalf("JCS Unicode/HTML escaping: %s %v", unicodeKey, err)
	}
	state := &State{Scope: testScope(), OperationalKey: json.RawMessage(`{"kty":"OKP","crv":"Ed25519","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}`)}
	registration, issuance, err := state.replayKeys()
	if err != nil || registration != "2sWNUpI4tnAzJ3quPrT78uJNVdo96m4En3cZsggktcA" || issuance != "pxQMSC0k-V9nn9qLqMRDczyUxyNyQE87LbGuK5SEWGw" {
		t.Fatalf("design vector: %s %s %v", registration, issuance, err)
	}
	state.Name = "research-agent"
	other, _, err := state.replayKeys()
	if err != nil || other == registration {
		t.Fatal("name did not scope replay")
	}
}

func TestRegisterManagedIdentity_InvalidNamesBeforeEffects(t *testing.T) {
	for _, name := range []string{"", " \n", strings.Repeat("🧾", 256), string([]byte{0xff})} {
		f := newFixture(t)
		if _, err := RegisterManagedIdentity(context.Background(), name, f.loaded, "token", f.store, nil, f.options); err == nil {
			t.Fatalf("accepted name %q", name)
		}
		entries, err := os.ReadDir(f.store.Directory)
		if err != nil || len(entries) != 0 || f.registry.discoveryCalls != 0 || f.registry.registerCalls != 0 {
			t.Fatal("invalid name caused effects")
		}
	}
}

func TestFileRegistrationStore_IsolatesNamedScopes(t *testing.T) {
	store := NewFileRegistrationStore(filepath.Join(t.TempDir(), "state"))
	first := testScope()
	scopes := []Scope{first, {RegistryURL: "https://other.example", OrganizationID: first.OrganizationID, Name: first.Name}, {RegistryURL: first.RegistryURL, OrganizationID: "other-account", Name: first.Name}, {RegistryURL: first.RegistryURL, OrganizationID: first.OrganizationID, Name: "../../identity"}, {RegistryURL: first.RegistryURL, OrganizationID: first.OrganizationID, Name: "Billing-agent"}}
	var sessions []Session
	for _, scope := range scopes {
		session, err := store.Acquire(context.Background(), scope)
		if err != nil {
			t.Fatal(err)
		}
		sessions = append(sessions, session)
		if err := session.Save(context.Background(), &State{Scope: scope}); err != nil {
			t.Fatal(err)
		}
	}
	defer func() {
		for _, session := range sessions {
			session.Close()
		}
	}()
	_, err := store.Acquire(context.Background(), first)
	var busy *BusyError
	if !errors.As(err, &busy) {
		t.Fatalf("same tuple did not lock: %v", err)
	}
	for i, session := range sessions {
		state, err := session.Load(context.Background())
		if err != nil || state.Scope != scopes[i] {
			t.Fatal("state crossed tuple")
		}
	}
	if err := sessions[0].Save(context.Background(), &State{Scope: scopes[1]}); err == nil {
		t.Fatal("saved another tenant's state")
	}
}

func readyOnboarding(t *testing.T) *dnsid.OrganizationOnboardingResponse {
	t.Helper()
	var response dnsid.OrganizationOnboardingResponse
	if err := json.Unmarshal([]byte(`{"org_id":"11111111-1111-4111-8111-111111111111","governance_domain":"account.example","gi":{"domain":"account.example","state":"verified","gate_authorized":true},"ek":{"status":"verified"}}`), &response); err != nil {
		t.Fatal(err)
	}
	return &response
}

func TestRegisterManagedIdentity_AccountDiscovery(t *testing.T) {
	for _, behavior := range []string{"ready", "pending", "delegation", "conflict", "unavailable"} {
		t.Run(behavior, func(t *testing.T) {
			f := newFixture(t)
			f.loaded.Registration.OrganizationID = ""
			f.registry.onboarding = readyOnboarding(t)
			switch behavior {
			case "pending":
				f.registry.onboarding.GI.State = "pending"
			case "delegation":
				f.registry.onboarding.EK.Status = "pending"
			case "conflict":
				f.loaded.Registration.GovernanceID = "other.example"
			case "unavailable":
				f.registry.onboarding = nil
			}
			// The fixture registry reads the resolved tuple's durable intent.
			f.registry.f.loaded.Registration.OrganizationID = testScope().OrganizationID
			loaded := f.loaded
			loaded.Registration.OrganizationID = ""
			_, err := RegisterManagedIdentity(context.Background(), "billing-agent", loaded, "token", f.store, nil, f.options)
			if behavior == "ready" {
				if err != nil || f.registry.discoveryCalls != 1 || f.state().OrganizationID != testScope().OrganizationID {
					t.Fatalf("discovery: %v", err)
				}
				return
			}
			if err == nil || f.registry.registerCalls != 0 {
				t.Fatalf("unverified discovery caused creation: %v", err)
			}
			entries, readErr := os.ReadDir(f.store.Directory)
			if readErr != nil || len(entries) != 0 {
				t.Fatal("unverified organization caused storage effects")
			}
		})
	}
}

func TestRegisterManagedIdentity_FileGenerationUsesDurableLocator(t *testing.T) {
	f := newFixture(t)
	f.loaded.KeySource = config.KeySource{Provider: "file", EntityKeyPath: "must-not-read-private-entity-key", Generation: &config.KeyGenerationConfig{Locator: "initial-key", Algorithm: dnsid.JoseAlgES256}}
	if _, err := f.run(nil); err != nil {
		t.Fatal(err)
	}
	state := f.state()
	if state.KeyLocator == "operational-key.json" || state.KeyLocator == "" {
		t.Fatal("generation locator ignored")
	}
	if _, err := os.Stat(f.path(state.KeyLocator)); err != nil {
		t.Fatal(err)
	}
	if _, err := f.run(nil); err != nil || f.registry.registerCalls != 1 {
		t.Fatalf("locator did not recover original key: %v", err)
	}
}

func TestRegisterManagedIdentity_ResumeUsesCurrentApplicationPolicy(t *testing.T) {
	f := newFixture(t)
	if _, err := f.run(nil); err != nil {
		t.Fatal(err)
	}
	f.loaded.Dnsid.Verification.TrustedEntities = []dnsid.TrustedEntity{}
	result, err := f.run(nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := result.Manager.VerifyDomain(context.Background(), result.Registration.Domain); err == nil {
		t.Fatal("setup overrode the current application's deny-all policy")
	}
}

func TestRegisterManagedIdentity_MissingGIUsesSavedBinding(t *testing.T) {
	f := newFixture(t)
	if _, err := f.run(nil); err != nil {
		t.Fatal(err)
	}
	f.loaded.Registration.GovernanceID = ""
	if _, err := f.run(nil); err != nil || f.registry.discoveryCalls != 0 {
		t.Fatalf("saved GI required discovery: %v", err)
	}
}

func TestRegisterManagedIdentity_MissingProviderStopsBeforeDiscovery(t *testing.T) {
	f := newFixture(t)
	f.loaded.Registration.OrganizationID = ""
	f.loaded.KeySource = config.KeySource{Provider: "google-kms", KeyRef: "existing-key"}
	_, err := f.run(nil)
	var argument *dnsid.ArgumentError
	if !errors.As(err, &argument) || !strings.Contains(argument.Error(), "import") || f.registry.discoveryCalls != 0 {
		t.Fatalf("missing provider did not fail early: %v", err)
	}
	entries, readErr := os.ReadDir(f.store.Directory)
	if readErr != nil || len(entries) != 0 {
		t.Fatal("missing provider created state")
	}
}

func TestRegisterManagedIdentity_CompletedCompactionAndRetrievalFailure(t *testing.T) {
	f := newFixture(t)
	if _, err := f.run(nil); err != nil {
		t.Fatal(err)
	}
	state := f.state()
	if state.Input != nil || state.Creation != nil || !state.IssuanceCompacted || state.Issuance.Prepared != nil || len(state.Issuance.EntryBytes) != 0 || state.Issuance.EntryHash == "" {
		t.Fatal("completed recovery was not compacted")
	}
	f.reader.entryErr = errors.New("historical entry unavailable")
	if _, err := f.run(nil); err == nil {
		t.Fatal("missing history accepted")
	}
	if f.registry.registerCalls != 1 || f.registry.prepareCalls != 1 || f.registry.submitCalls != 1 {
		t.Fatal("missing history caused replacement or reissuance")
	}
}

func TestRegisterManagedIdentity_MatchingReplicaRecoversIssuance(t *testing.T) {
	f := newFixture(t)
	if _, err := f.run(nil); err != nil {
		t.Fatal(err)
	}
	original := f.state()
	provider, err := dnsid.NewLocalKeyProvider(f.path("operational-key.json"))
	if err != nil {
		t.Fatal(err)
	}
	f.store = NewFileRegistrationStore(filepath.Join(t.TempDir(), "replica"))
	f.options.Dependencies.KeyProvider = provider
	f.options.ProviderReference = "existing-key"
	f.loaded.KeySource = config.KeySource{Provider: "google-kms"} // displaced by injection
	if _, err := f.run(nil); err != nil {
		t.Fatal(err)
	}
	if f.registry.prepareCalls != 1 || f.registry.submitCalls != 1 || registrationKey(t, original) != registrationKey(t, f.state()) {
		t.Fatal("replica changed replay key or reissued")
	}
}
