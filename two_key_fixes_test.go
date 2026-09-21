package dnsid

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	dnsidlog "github.com/dnsid-ai/dnsid-go/log"
	"github.com/lestrrat-go/jwx/v3/jwk"
)

// --- Blocking 1: delegated-governance ek= mismatch ---

// --- Blocking 2: retained-key filtering ---

func TestGetKeySet_ExcludesRetainedKeys(t *testing.T) {
	kp := GenerateES256KeyProvider()
	originalKid, _ := kp.JWK().KeyID()

	// Generate and activate a new key (original becomes retained)
	newKid, err := kp.GenerateKey(JoseAlgES256)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	if err := kp.Activate(newKid); err != nil {
		t.Fatalf("Activate: %v", err)
	}

	manager, err := NewIdentityManager(Config{Identity: &IdentityConfig{
		Domain:       "agent.example.com",
		GovernanceID: "example.com",
		LogRef:       "test:agent",
		StatusURL:    "https://agent.example.com/status.json",
	}}, kp)
	if err != nil {
		t.Fatalf("NewIdentityManager: %v", err)
	}

	set := manager.GetKeySet()
	setJSON, _ := json.Marshal(set.Raw())
	if !strings.Contains(string(setJSON), newKid) {
		t.Fatal("GetKeySet should include active key")
	}
	if strings.Contains(string(setJSON), originalKid) {
		t.Fatal("GetKeySet should not include retained key")
	}
	if n := set.Raw().Len(); n != 1 {
		t.Fatalf("GetKeySet has %d keys, want 1", n)
	}
}

func TestGetEntityKeySet_ExcludesRetainedKeys(t *testing.T) {
	entityKP := GenerateES256KeyProvider()
	originalKid, _ := entityKP.JWK().KeyID()

	// Generate and activate a new entity key (original becomes retained)
	newKid, err := entityKP.GenerateKey(JoseAlgES256)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	if err := entityKP.Activate(newKid); err != nil {
		t.Fatalf("Activate: %v", err)
	}

	opKP := GenerateES256KeyProvider()

	manager, err := NewIdentityManager(Config{Identity: &IdentityConfig{
		Domain:       "agent.example.com",
		GovernanceID: "example.com",
		LogRef:       "test:agent",
		StatusURL:    "https://agent.example.com/status.json",
	}}, opKP, WithEntityKeyProvider(entityKP))
	if err != nil {
		t.Fatalf("NewIdentityManager: %v", err)
	}

	set := manager.GetEntityKeySet()
	if set == nil {
		t.Fatal("GetEntityKeySet returned nil")
	}
	setJSON, _ := json.Marshal(set.Raw())
	if !strings.Contains(string(setJSON), newKid) {
		t.Fatal("GetEntityKeySet should include active key")
	}
	if strings.Contains(string(setJSON), originalKid) {
		t.Fatal("GetEntityKeySet should not include retained key")
	}
	if n := set.Raw().Len(); n != 1 {
		t.Fatalf("GetEntityKeySet has %d keys, want 1", n)
	}
}

func TestGetEntityKeySet_NilWithoutEntityKey(t *testing.T) {
	kp := GenerateES256KeyProvider()
	manager, err := NewIdentityManager(Config{Identity: &IdentityConfig{
		Domain:       "agent.example.com",
		GovernanceID: "example.com",
		LogRef:       "test:agent",
		StatusURL:    "https://agent.example.com/status.json",
	}}, kp)
	if err != nil {
		t.Fatalf("NewIdentityManager: %v", err)
	}
	if manager.GetEntityKeySet() != nil {
		t.Fatal("GetEntityKeySet should return nil without EntityKey")
	}
}

// --- Should Address: stale PublicKey countersign ---

// rotatingKeyProvider wraps a KeyProvider and allows swapping the active key
// between the initial entity signature and the countersign call.
type rotatingKeyProvider struct {
	primary   *LocalKeyProvider
	secondary *LocalKeyProvider
	rotated   bool
}

func (r *rotatingKeyProvider) JWK(kid ...string) jwk.Key {
	if r.rotated {
		return r.secondary.JWK(kid...)
	}
	return r.primary.JWK(kid...)
}

func (r *rotatingKeyProvider) ListKeyIds() []string {
	if r.rotated {
		return r.secondary.ListKeyIds()
	}
	return r.primary.ListKeyIds()
}

func (r *rotatingKeyProvider) Sign(payload []byte) (*KeySignature, error) {
	if r.rotated {
		return r.secondary.Sign(payload)
	}
	return r.primary.Sign(payload)
}

func (r *rotatingKeyProvider) SignKey(kid string, payload []byte) (*KeySignature, error) {
	if key := r.primary.JWK(kid); key != nil {
		return r.primary.SignKey(kid, payload)
	}
	return r.secondary.SignKey(kid, payload)
}

func (r *rotatingKeyProvider) GenerateKey(alg JoseAlg) (string, error) {
	return r.primary.GenerateKey(alg)
}

func (r *rotatingKeyProvider) Activate(kid string) error {
	return r.primary.Activate(kid)
}

func (r *rotatingKeyProvider) Supersede(kid string) error {
	return r.primary.Supersede(kid)
}

func (r *rotatingKeyProvider) Purge(kid string) error {
	return r.primary.Purge(kid)
}

func TestSignAndWriteEvent_RejectsStaleCountersignKey(t *testing.T) {
	// Changing PublicKey after the entity signature would invalidate that
	// signature, so a stale pre-built issuance must fail instead.
	wl := &testWriteLog{}
	registry := dnsidlog.NewLogRegistry()
	if err := registry.Register("test", func(string) dnsidlog.LogReader { return wl }); err != nil {
		t.Fatalf("Register: %v", err)
	}

	// Two separate key providers simulating before/after rotation
	primaryKP := GenerateES256KeyProvider()
	secondaryKP := GenerateES256KeyProvider()
	staleKid, _ := primaryKP.JWK().KeyID()
	currentKid, _ := secondaryKP.JWK().KeyID()

	rkp := &rotatingKeyProvider{primary: primaryKP, secondary: secondaryKP, rotated: false}

	entityKP := GenerateES256KeyProvider()

	manager, err := NewIdentityManager(Config{Identity: &IdentityConfig{
		Domain:       "agent.example.com",
		GovernanceID: "example.com",
		LogRef:       "test:agent",
		StatusURL:    "https://agent.example.com/status.json",
	}}, rkp, WithEntityKeyProvider(entityKP), WithLogRegistry(registry))
	if err != nil {
		t.Fatalf("NewIdentityManager: %v", err)
	}

	// Build an event with stale PublicKey (from primaryKP before rotation)
	stalePubKey := primaryKP.JWK()
	entityKid, _ := entityKP.JWK().KeyID()
	event := dnsidlog.LogEvent{
		Type:                        dnsidlog.LogEventIssuance,
		Domain:                      "agent.example.com",
		InitialOperationalPublicKey: stalePubKey,
		InitialEntityPublicKey:      entityKP.JWK(),
		InitialOperationalKid:       staleKid,
		InitialEntityKid:            entityKid,
		InitialEntitySignature:      "already-signed-by-entity-key",
	}

	// Simulate rotation happening between entity sign and countersign
	rkp.rotated = true

	_, err = manager.SignAndWriteEvent(context.Background(), event)
	if err == nil || !strings.Contains(err.Error(), "does not match event key") {
		t.Fatalf("SignAndWriteEvent error = %v, want stale-key rejection (current kid %q)", err, currentKid)
	}
	if len(wl.events) != 0 {
		t.Fatalf("len(events) = %d, want 0", len(wl.events))
	}
}

// --- Delegated governance validation at generation time ---

func TestCreateTXTRecord_RejectsBadEKHost(t *testing.T) {
	// An explicit EntityKeyURL whose host does not equal gi= should be rejected
	// at config validation time.
	entityKP := GenerateES256KeyProvider()
	opKP := GenerateES256KeyProvider()

	manager, err := NewIdentityManager(Config{Identity: &IdentityConfig{
		Domain:       "agent.otherdomain.example",
		GovernanceID: "governance.example.com",
		LogRef:       "test:agent",
		StatusURL:    "https://agent.otherdomain.example/status.json",
		KeyURL:       "https://agent.otherdomain.example/ku.json",
		EntityKeyURL: "https://bad.unrelated.example/.well-known/entity-jwks.json",
	}}, opKP, WithEntityKeyProvider(entityKP))
	if err != nil {
		t.Fatalf("NewIdentityManager: %v", err)
	}
	_, err = manager.BuildUnsignedTXTRecord()
	if err == nil {
		t.Fatal("expected error: EntityKeyURL host not under gi= should be rejected")
	}
	if !strings.Contains(err.Error(), "EntityKeyURL host") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestIdentityConfig_RejectsNonDomainGIWithEntityKey(t *testing.T) {
	// The two-key profile (20260626) requires GovernanceID to be a domain name.
	entityKP := GenerateES256KeyProvider()
	opKP := GenerateES256KeyProvider()

	manager, err := NewIdentityManager(Config{Identity: &IdentityConfig{
		Domain:       "agent.example.com",
		GovernanceID: "urn:example:governance",
		LogRef:       "test:agent",
		StatusURL:    "https://agent.example.com/status.json",
		KeyURL:       "https://agent.example.com/ku.json",
		EntityKeyURL: "https://example.com/ek.json",
	}}, opKP, WithEntityKeyProvider(entityKP))
	if err != nil {
		t.Fatalf("NewIdentityManager: %v", err)
	}
	_, err = manager.BuildUnsignedTXTRecord()
	if err == nil {
		t.Fatal("expected error: non-domain GovernanceID with EntityKey should be rejected")
	}
	if !strings.Contains(err.Error(), "domain name") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestGenerateIssuanceEvent_RejectsIdenticalEKKU(t *testing.T) {
	// GenerateIssuanceEvent must reject when entity and operational keys are the same.
	wl := &testWriteLog{}
	registry := dnsidlog.NewLogRegistry()
	if err := registry.Register("test", func(string) dnsidlog.LogReader { return wl }); err != nil {
		t.Fatalf("Register: %v", err)
	}

	// Use the same key provider for both ek and ku
	sharedKP := GenerateES256KeyProvider()

	manager, err := NewIdentityManager(Config{Identity: &IdentityConfig{
		Domain:       "agent.example.com",
		GovernanceID: "example.com",
		LogRef:       "test:agent",
		StatusURL:    "https://agent.example.com/status.json",
	}}, sharedKP, WithEntityKeyProvider(sharedKP), WithLogRegistry(registry))
	if err != nil {
		t.Fatalf("NewIdentityManager: %v", err)
	}

	_, err = manager.GenerateIssuanceEvent(context.Background())
	if err == nil {
		t.Fatal("expected error: same key for ek and ku should be rejected")
	}
	if !strings.Contains(err.Error(), "distinct") {
		t.Fatalf("unexpected error: %v", err)
	}
}

// --- Round-trip: generate two-key record then verify through SDK verifier ---

func TestPublishClientControlledRecord_RejectsEKKUSameKey(t *testing.T) {
	// PublishClientControlledRecord must reject when entity key == operational key.
	kp := GenerateES256KeyProvider()

	manager, err := NewIdentityManager(Config{Identity: &IdentityConfig{
		Domain:       "agent.example.com",
		GovernanceID: "example.com",
		LogRef:       "test:agent",
		StatusURL:    "https://agent.example.com/status.json",
		KeyURL:       "https://agent.example.com/ku.json",
		EntityKeyURL: "https://example.com/ek.json",
	}}, kp, WithEntityKeyProvider(kp))
	if err != nil {
		// May fail at construction — either way the rejection is in place.
		if !strings.Contains(err.Error(), "distinct") {
			t.Fatalf("unexpected error: %v", err)
		}
		return
	}

	_, err = manager.PublishClientControlledRecord(context.Background(), &mockRegistryPublisher{})
	if err == nil {
		t.Fatal("expected error for ek==ku but got none")
	}
	if !strings.Contains(err.Error(), "distinct") {
		t.Fatalf("unexpected error: %v", err)
	}
}

// mockRegistryPublisher is a minimal RegistryPublisher for testing.
type mockRegistryPublisher struct{}

func (m *mockRegistryPublisher) GetRegistration(_ context.Context, domain string) (*AgentRegistration, error) {
	return &AgentRegistration{Domain: domain, PublicationAuthority: PublicationAuthorityClient}, nil
}

func (m *mockRegistryPublisher) CanonicalRecordContent(_ context.Context, _ string, _ string) (*CanonicalRecordContentResponse, error) {
	return &CanonicalRecordContentResponse{
		Canonical:  "ek=https://example.com/.well-known/entity-jwks.json;gi=example.com;ku=https://agent.example.com/.well-known/jwks.json;lr=algorand:ADDR;su=https://agent.example.com/status;v=dnsid-draft-01",
		SigningKid: "test-kid",
	}, nil
}

func (m *mockRegistryPublisher) PublishSignature(_ context.Context, _ string, _ string) (*PublishedRecord, error) {
	return &PublishedRecord{}, nil
}
