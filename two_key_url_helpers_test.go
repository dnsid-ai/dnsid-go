package dnsid

import (
	"context"
	"strings"
	"testing"

	dnsidlog "github.com/dnsid-ai/dnsid-go/log"
	"github.com/lestrrat-go/jwx/v3/jwk"
)

// --- Issue 1: Delegated governance ek= URL tests ---

func TestEntityKeyURL_DelegatedGovernance(t *testing.T) {
	// DNSid1 defines no default ek path.
	entityKP := GenerateES256KeyProvider()
	opKP := GenerateES256KeyProvider()

	manager, err := NewIdentityManager(Config{Identity: &IdentityConfig{
		Domain:       "agent.otherdomain.com",
		GovernanceID: "governance.example.com",
		LogRef:       "test:agent",
		StatusURL:    "https://agent.otherdomain.com/status.json",
	}}, opKP, WithEntityKeyProvider(entityKP))
	if err != nil {
		t.Fatalf("NewIdentityManager: %v", err)
	}

	got := manager.EntityKeyURL()
	want := ""
	if got != want {
		t.Fatalf("EntityKeyURL() = %q, want %q", got, want)
	}
}

func TestEntityKeyURL_SelfAccounted(t *testing.T) {
	// DNSid1 defines no default ek path.
	entityKP := GenerateES256KeyProvider()
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

	got := manager.EntityKeyURL()
	want := ""
	if got != want {
		t.Fatalf("EntityKeyURL() = %q, want %q", got, want)
	}
}

func TestEntityKeyURL_ExactSameDomain(t *testing.T) {
	// DNSid1 defines no default ek path.
	entityKP := GenerateES256KeyProvider()
	opKP := GenerateES256KeyProvider()

	manager, err := NewIdentityManager(Config{Identity: &IdentityConfig{
		Domain:       "example.com",
		GovernanceID: "example.com",
		LogRef:       "test:agent",
		StatusURL:    "https://example.com/status.json",
	}}, opKP, WithEntityKeyProvider(entityKP))
	if err != nil {
		t.Fatalf("NewIdentityManager: %v", err)
	}

	got := manager.EntityKeyURL()
	want := ""
	if got != want {
		t.Fatalf("EntityKeyURL() = %q, want %q", got, want)
	}
}

func TestEntityKeyURL_ExplicitOverride(t *testing.T) {
	// When EntityKeyURL is set explicitly, its path takes precedence.
	// DNSid1 requires its host to equal the GovernanceID domain.
	entityKP := GenerateES256KeyProvider()
	opKP := GenerateES256KeyProvider()

	manager, err := NewIdentityManager(Config{Identity: &IdentityConfig{
		Domain:       "agent.otherdomain.com",
		GovernanceID: "governance.example.com",
		LogRef:       "test:agent",
		StatusURL:    "https://agent.otherdomain.com/status.json",
		EntityKeyURL: "https://governance.example.com/custom/entity-jwks.json",
	}}, opKP, WithEntityKeyProvider(entityKP))
	if err != nil {
		t.Fatalf("NewIdentityManager: %v", err)
	}

	got := manager.EntityKeyURL()
	want := "https://governance.example.com/custom/entity-jwks.json"
	if got != want {
		t.Fatalf("EntityKeyURL() = %q, want %q", got, want)
	}
}

func TestEntityKeyURL_NilWithoutEntityKey(t *testing.T) {
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

	if got := manager.EntityKeyURL(); got != "" {
		t.Fatalf("EntityKeyURL() = %q, want empty for single-key profile", got)
	}
}

// --- Issue 2: OperationalKeyURL tests ---

func TestOperationalKeyURL_Default(t *testing.T) {
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

	got := manager.OperationalKeyURL()
	want := ""
	if got != want {
		t.Fatalf("OperationalKeyURL() = %q, want %q", got, want)
	}
}

func TestOperationalKeyURL_ExplicitOverride(t *testing.T) {
	kp := GenerateES256KeyProvider()
	manager, err := NewIdentityManager(Config{Identity: &IdentityConfig{
		Domain:       "agent.example.com",
		GovernanceID: "example.com",
		LogRef:       "test:agent",
		StatusURL:    "https://agent.example.com/status.json",
		KeyURL:       "https://agent.example.com/keys/operational.json",
	}}, kp)
	if err != nil {
		t.Fatalf("NewIdentityManager: %v", err)
	}

	got := manager.OperationalKeyURL()
	want := "https://agent.example.com/keys/operational.json"
	if got != want {
		t.Fatalf("OperationalKeyURL() = %q, want %q", got, want)
	}
}

func TestOperationalKeyURL_AlwaysAgentDomain(t *testing.T) {
	// DNSid1 defines no default ku path.
	entityKP := GenerateES256KeyProvider()
	opKP := GenerateES256KeyProvider()

	manager, err := NewIdentityManager(Config{Identity: &IdentityConfig{
		Domain:       "agent.otherdomain.com",
		GovernanceID: "governance.example.com",
		LogRef:       "test:agent",
		StatusURL:    "https://agent.otherdomain.com/status.json",
	}}, opKP, WithEntityKeyProvider(entityKP))
	if err != nil {
		t.Fatalf("NewIdentityManager: %v", err)
	}

	if got := manager.OperationalKeyURL(); got != "" {
		t.Fatalf("OperationalKeyURL() = %q, want empty", got)
	}
}

// --- Issue 2 continued: URL consistency between helpers and CreateTXTRecord ---

// --- Issue 3: Countersign key-version stability ---

func TestGenerateIssuanceEvent_CountersignKeySnapshot(t *testing.T) {
	// The operational key used for countersigning must be the one snapshotted
	// at event creation, not whatever is active when Sign is called.
	// We use two separate LocalKeyProviders behind a rotatingKeyProvider to
	// simulate rotation happening between entity-sign and countersign.
	primaryKP := GenerateES256KeyProvider()
	secondaryKP := GenerateES256KeyProvider()
	primaryKid, _ := primaryKP.JWK().KeyID()

	// Start with primary active
	rkp := &rotatingKeyProvider{primary: primaryKP, secondary: secondaryKP, rotated: false}

	entityKP := GenerateES256KeyProvider()

	wl := &testWriteLog{}
	registry := dnsidlog.NewLogRegistry()
	if err := registry.Register("test", func(string) dnsidlog.LogReader { return wl }); err != nil {
		t.Fatalf("Register: %v", err)
	}

	manager, err := NewIdentityManager(Config{Identity: &IdentityConfig{
		Domain:       "agent.example.com",
		GovernanceID: "example.com",
		LogRef:       "test:agent",
		StatusURL:    "https://agent.example.com/status.json",
	}}, rkp, WithEntityKeyProvider(entityKP), WithLogRegistry(registry))
	if err != nil {
		t.Fatalf("NewIdentityManager: %v", err)
	}

	// Generate issuance event with primary key active (no rotation during generation)
	_, err = manager.GenerateIssuanceEvent(context.Background())
	if err != nil {
		t.Fatalf("GenerateIssuanceEvent: %v", err)
	}

	if len(wl.events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(wl.events))
	}
	ev := wl.events[0]

	// The operational key in the event must match what was snapshotted
	if ev.InitialOperationalKid != primaryKid {
		t.Fatalf("event.Kid = %q, want snapshotted %q", ev.InitialOperationalKid, primaryKid)
	}
	if ev.InitialOperationalPublicKey == nil {
		t.Fatal("event.PublicKey is nil")
	}
	pubKid, _ := ev.InitialOperationalPublicKey.KeyID()
	if pubKid != primaryKid {
		t.Fatalf("event.PublicKey kid = %q, want %q", pubKid, primaryKid)
	}

	// Both signatures must be present
	if ev.InitialEntitySignature == "" {
		t.Fatal("entity signature (Sig) is empty")
	}
	if ev.InitialOperationalSignature == "" {
		t.Fatal("operational countersignature is empty")
	}
}

func TestGenerateIssuanceEvent_RejectsRotationMidGeneration(t *testing.T) {
	// If the operational key rotates between snapshotting and signing,
	// GenerateIssuanceEvent must return an error (not produce a mixed event).
	primaryKP := GenerateES256KeyProvider()
	secondaryKP := GenerateES256KeyProvider()

	entityKP := GenerateES256KeyProvider()

	wl := &testWriteLog{}
	registry := dnsidlog.NewLogRegistry()
	if err := registry.Register("test", func(string) dnsidlog.LogReader { return wl }); err != nil {
		t.Fatalf("Register: %v", err)
	}

	// rotatingOnSignKeyProvider rotates when Sign is called
	rotateOnSign := &rotateOnSignKeyProvider{
		primary:   primaryKP,
		secondary: secondaryKP,
	}

	manager, err := NewIdentityManager(Config{Identity: &IdentityConfig{
		Domain:       "agent.example.com",
		GovernanceID: "example.com",
		LogRef:       "test:agent",
		StatusURL:    "https://agent.example.com/status.json",
	}}, rotateOnSign, WithEntityKeyProvider(entityKP), WithLogRegistry(registry))
	if err != nil {
		t.Fatalf("NewIdentityManager: %v", err)
	}

	_, err = manager.GenerateIssuanceEvent(context.Background())
	if err == nil {
		t.Fatal("expected error when key rotates mid-generation, got nil")
	}
	if !strings.Contains(err.Error(), "rotated mid-generation") {
		t.Fatalf("unexpected error: %v", err)
	}
}

// rotateOnSignKeyProvider simulates a key rotation happening during the Sign call.
// The first Sign call uses primary; subsequent ones use secondary (simulating
// rotation between entity-sign and operational-countersign).
type rotateOnSignKeyProvider struct {
	primary   *LocalKeyProvider
	secondary *LocalKeyProvider
	signCount int
}

func (r *rotateOnSignKeyProvider) JWK(kid ...string) jwk.Key {
	// Before rotation, return primary; after first sign, return secondary for
	// the "active" key (no kid specified).
	if len(kid) > 0 && kid[0] != "" {
		// Try to find by specific kid in primary first
		k := r.primary.JWK(kid...)
		if k != nil {
			return k
		}
		return r.secondary.JWK(kid...)
	}
	if r.signCount > 0 {
		return r.secondary.JWK()
	}
	return r.primary.JWK()
}

func (r *rotateOnSignKeyProvider) ListKeyIds() []string {
	if r.signCount > 0 {
		return r.secondary.ListKeyIds()
	}
	return r.primary.ListKeyIds()
}

func (r *rotateOnSignKeyProvider) Sign(payload []byte) (*KeySignature, error) {
	r.signCount++
	// After the first sign (entity key signs first in the flow, then operational
	// key provider is called), simulate that the provider now uses secondary.
	return r.secondary.Sign(payload)
}

func (r *rotateOnSignKeyProvider) SignKey(kid string, payload []byte) (*KeySignature, error) {
	if key := r.primary.JWK(kid); key != nil {
		return r.primary.SignKey(kid, payload)
	}
	return r.secondary.SignKey(kid, payload)
}

func (r *rotateOnSignKeyProvider) GenerateKey(alg JoseAlg) (string, error) {
	return r.primary.GenerateKey(alg)
}

func (r *rotateOnSignKeyProvider) Activate(kid string) error {
	return r.primary.Activate(kid)
}

func (r *rotateOnSignKeyProvider) Supersede(kid string) error {
	return r.primary.Supersede(kid)
}

func (r *rotateOnSignKeyProvider) Purge(kid string) error {
	return r.primary.Purge(kid)
}
