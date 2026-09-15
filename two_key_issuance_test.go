package dnsid

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	dnsidlog "github.com/dnsid-ai/dnsid-go/log"
)

func TestGenerateIssuanceEvent_TwoKey(t *testing.T) {
	wl := &testWriteLog{}
	registry := dnsidlog.NewLogRegistry()
	if err := registry.Register("test", func(string) dnsidlog.LogReader { return wl }); err != nil {
		t.Fatalf("Register: %v", err)
	}

	entityKP := GenerateES256KeyProvider()
	opKP := GenerateES256KeyProvider()

	entityKid, _ := entityKP.JWK().KeyID()
	opKid, _ := opKP.JWK().KeyID()

	manager, err := NewIdentityManager(Config{Identity: &IdentityConfig{
		Domain:       "agent.example.com",
		GovernanceID: "example.com",
		LogRef:       "test:agent",
		StatusURL:    "https://agent.example.com/status.json",
	}}, opKP, WithEntityKeyProvider(entityKP), WithLogRegistry(registry))
	if err != nil {
		t.Fatalf("NewIdentityManager: %v", err)
	}

	ref, err := manager.GenerateIssuanceEvent(context.Background())
	if err != nil {
		t.Fatalf("GenerateIssuanceEvent: %v", err)
	}
	if ref != "test:1" {
		t.Fatalf("ref = %q, want test:1", ref)
	}
	if len(wl.events) != 1 {
		t.Fatalf("len(events) = %d, want 1", len(wl.events))
	}

	event := wl.events[0]

	// Check event type
	if event.Type != dnsidlog.LogEventIssuance {
		t.Fatalf("Type = %q, want ISSUANCE", event.Type)
	}

	// Check both keys are present
	if event.InitialOperationalPublicKey == nil {
		t.Fatal("PublicKey (operational) is nil")
	}
	if event.InitialEntityPublicKey == nil {
		t.Fatal("EntityPublicKey is nil")
	}

	// Check signing identifiers
	if event.InitialEntityKid != entityKid {
		t.Fatalf("SigningKid = %q, want entity kid %q", event.InitialEntityKid, entityKid)
	}
	if event.InitialOperationalKid != opKid {
		t.Fatalf("Kid = %q, want operational kid %q", event.InitialOperationalKid, opKid)
	}

	// Check both signatures are present and non-empty
	if event.InitialEntitySignature == "" {
		t.Fatal("Sig (entity signature) is empty")
	}
	if event.InitialOperationalSignature == "" {
		t.Fatal("OperationalCountersig is empty")
	}

	// Signatures should be different (different keys)
	if event.InitialEntitySignature == event.InitialOperationalSignature {
		t.Fatal("EntitySig and OperationalCountersig should be different")
	}

	// Check domain and governance
	if event.Domain != "agent.example.com" {
		t.Fatalf("Domain = %q, want agent.example.com", event.Domain)
	}
	if event.GovernanceID != "example.com" {
		t.Fatalf("GovernanceID = %q, want example.com", event.GovernanceID)
	}
}

func TestGenerateIssuanceEvent_TwoKeyTimestamp(t *testing.T) {
	wl := &testWriteLog{}
	registry := dnsidlog.NewLogRegistry()
	if err := registry.Register("test", func(string) dnsidlog.LogReader { return wl }); err != nil {
		t.Fatalf("Register: %v", err)
	}

	entityKP := GenerateES256KeyProvider()
	opKP := GenerateES256KeyProvider()

	manager, err := NewIdentityManager(Config{Identity: &IdentityConfig{
		Domain:       "agent.example.com",
		GovernanceID: "example.com",
		LogRef:       "test:agent",
		StatusURL:    "https://agent.example.com/status.json",
	}}, opKP, WithEntityKeyProvider(entityKP), WithLogRegistry(registry))
	if err != nil {
		t.Fatalf("NewIdentityManager: %v", err)
	}

	before := time.Now()
	_, err = manager.GenerateIssuanceEvent(context.Background())
	if err != nil {
		t.Fatalf("GenerateIssuanceEvent: %v", err)
	}
	after := time.Now()

	event := wl.events[0]
	if event.Timestamp.Nanosecond() != 0 {
		t.Fatalf("Timestamp %v does not have whole-second precision", event.Timestamp)
	}
	if event.Timestamp.Before(before.Truncate(time.Second)) || event.Timestamp.After(after.Truncate(time.Second)) {
		t.Fatalf("Timestamp %v not in [%v, %v]", event.Timestamp, before, after)
	}
}

func TestGenerateIssuanceEvent_TwoKeyConsistentSnapshot(t *testing.T) {
	// Verify that the operational key kid recorded in the event matches
	// the key used for the countersignature (race-freedom check).
	wl := &testWriteLog{}
	registry := dnsidlog.NewLogRegistry()
	if err := registry.Register("test", func(string) dnsidlog.LogReader { return wl }); err != nil {
		t.Fatalf("Register: %v", err)
	}

	entityKP := GenerateES256KeyProvider()
	opKP := GenerateES256KeyProvider()
	opKid, _ := opKP.JWK().KeyID()

	manager, err := NewIdentityManager(Config{Identity: &IdentityConfig{
		Domain:       "agent.example.com",
		GovernanceID: "example.com",
		LogRef:       "test:agent",
		StatusURL:    "https://agent.example.com/status.json",
	}}, opKP, WithEntityKeyProvider(entityKP), WithLogRegistry(registry))
	if err != nil {
		t.Fatalf("NewIdentityManager: %v", err)
	}

	_, err = manager.GenerateIssuanceEvent(context.Background())
	if err != nil {
		t.Fatalf("GenerateIssuanceEvent: %v", err)
	}

	event := wl.events[0]
	// The recorded Kid must be the operational key that was snapshotted.
	if event.InitialOperationalKid != opKid {
		t.Fatalf("Kid = %q, want snapshotted operational kid %q", event.InitialOperationalKid, opKid)
	}
	// OperationalCountersig must be non-empty (signed by the same snapshotted key).
	if event.InitialOperationalSignature == "" {
		t.Fatal("OperationalCountersig is empty")
	}
}

func TestGetEntityKeySet_TwoKey(t *testing.T) {
	entityKP := GenerateES256KeyProvider()
	opKP := GenerateES256KeyProvider()

	entityKid, _ := entityKP.JWK().KeyID()
	opKid, _ := opKP.JWK().KeyID()

	manager, err := NewIdentityManager(Config{Identity: &IdentityConfig{
		Domain:       "agent.example.com",
		GovernanceID: "example.com",
		LogRef:       "test:agent",
		StatusURL:    "https://agent.example.com/status.json",
	}}, opKP, WithEntityKeyProvider(entityKP))
	if err != nil {
		t.Fatalf("NewIdentityManager: %v", err)
	}

	// GetKeySet should return the operational key (ku).
	kuSet := manager.GetKeySet()
	if kuSet == nil {
		t.Fatal("GetKeySet returned nil")
	}
	kuJSON, _ := json.Marshal(kuSet.Raw())
	if !strings.Contains(string(kuJSON), opKid) {
		t.Fatalf("GetKeySet should contain operational kid %q", opKid)
	}
	if strings.Contains(string(kuJSON), entityKid) {
		t.Fatal("GetKeySet should NOT contain entity kid")
	}

	// GetEntityKeySet should return the entity key (ek).
	ekSet := manager.GetEntityKeySet()
	if ekSet == nil {
		t.Fatal("GetEntityKeySet returned nil")
	}
	ekJSON, _ := json.Marshal(ekSet.Raw())
	if !strings.Contains(string(ekJSON), entityKid) {
		t.Fatalf("GetEntityKeySet should contain entity kid %q", entityKid)
	}
	if strings.Contains(string(ekJSON), opKid) {
		t.Fatal("GetEntityKeySet should NOT contain operational kid")
	}
}

func TestCreateTXTRecord_RejectsEKKUSameKey(t *testing.T) {
	// Issue 1: CreateTXTRecord must reject when entity key == operational key.
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
		// May fail at construction time—either way ek==ku is rejected.
		if !strings.Contains(err.Error(), "distinct") {
			t.Fatalf("unexpected error: %v", err)
		}
		return
	}
	// CreateTXTRecord must reject same ek/ku.
	_, err = manager.CreateTXTRecord()
	if err == nil {
		t.Fatal("expected error for ek==ku but got none")
	}
	if !strings.Contains(err.Error(), "distinct") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestBuildUnsignedTXTRecord_RejectsDelegatedGovernanceEKOnAgentDomain(t *testing.T) {
	ekKP := GenerateES256KeyProvider()

	manager, err := NewIdentityManager(Config{Identity: &IdentityConfig{
		Domain:       "agent.other",
		GovernanceID: "gov.example",
		LogRef:       "test:agent",
		StatusURL:    "https://agent.other/status.json",
		KeyURL:       "https://agent.other/operational-jwks.json",
		EntityKeyURL: "https://agent.other/.well-known/entity-jwks.json",
	}}, GenerateES256KeyProvider(), WithEntityKeyProvider(ekKP))
	if err != nil {
		t.Fatalf("NewIdentityManager: %v", err)
	}
	_, err = manager.BuildUnsignedTXTRecord()
	if err == nil {
		t.Fatal("expected error for EntityKeyURL on agent domain not under gi")
	}
	if !strings.Contains(err.Error(), "EntityKeyURL") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestRevokeViaRegistry_DoesNotWriteLocalEvent(t *testing.T) {
	ekKP := GenerateES256KeyProvider()
	opKP := GenerateES256KeyProvider()

	localWrites := 0
	logStore := &twoKeyMockLog{
		canonicalFn: func(e dnsidlog.LogEvent) ([]byte, error) {
			return []byte("canonical-revocation"), nil
		},
		writeEventFn: func(ctx context.Context, e dnsidlog.LogEvent) (dnsidlog.LogRef, error) {
			localWrites++
			return "test:rev1", nil
		},
	}

	manager, err := NewIdentityManager(Config{Identity: &IdentityConfig{
		Domain:       "agent.example.com",
		GovernanceID: "example.com",
		LogRef:       "test:agent",
		StatusURL:    "https://agent.example.com/status.json",
	}}, opKP, WithEntityKeyProvider(ekKP))
	if err != nil {
		t.Fatalf("NewIdentityManager: %v", err)
	}
	manager.localLog = logStore

	client := &twoKeyMockRegistryClient{
		revokeAgentFn: func(ctx context.Context, domain string, req *RevokeAgentRequest) (*LifecycleResponse, error) {
			if req.AgentID != "ag_123" || req.Reason != RegistryRevocationReasonKeyCompromise {
				t.Fatalf("revocation request = %#v", req)
			}
			return &LifecycleResponse{Status: "revoked"}, nil
		},
	}

	_, err = manager.RevokeViaRegistry(context.Background(), client, "ag_123", RegistryRevocationReasonKeyCompromise)
	if err != nil {
		t.Fatalf("RevokeViaRegistry: %v", err)
	}
	if localWrites != 0 {
		t.Fatalf("local writes = %d, want 0", localWrites)
	}
}

// twoKeyMockLog implements dnsidlog.Log for testing.
type twoKeyMockLog struct {
	canonicalFn  func(dnsidlog.LogEvent) ([]byte, error)
	writeEventFn func(context.Context, dnsidlog.LogEvent) (dnsidlog.LogRef, error)
}

func (l *twoKeyMockLog) Canonical(e dnsidlog.LogEvent) ([]byte, error) { return l.canonicalFn(e) }
func (l *twoKeyMockLog) WriteEvent(ctx context.Context, e dnsidlog.LogEvent) (dnsidlog.LogRef, error) {
	return l.writeEventFn(ctx, e)
}

// twoKeyMockRegistryClient embeds fakeRegistryClient and overrides RevokeAgent.
type twoKeyMockRegistryClient struct {
	fakeRegistryClient
	revokeAgentFn func(context.Context, string, *RevokeAgentRequest) (*LifecycleResponse, error)
}

func (c *twoKeyMockRegistryClient) RevokeAgent(ctx context.Context, domain string, req *RevokeAgentRequest) (*LifecycleResponse, error) {
	return c.revokeAgentFn(ctx, domain, req)
}
