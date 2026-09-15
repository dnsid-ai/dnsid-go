package dnsid

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	dnsidlog "github.com/dnsid-ai/dnsid-go/log"
	"github.com/lestrrat-go/jwx/v3/jwk"
)

type testWriteLog struct {
	events     []dnsidlog.LogEvent
	canonicals []string
}

func (l *testWriteLog) Canonical(event dnsidlog.LogEvent) ([]byte, error) {
	canonical := fmt.Sprintf("%s:%s:signingKid=%s:kid=%s:sig=%s:opSig=%s", event.Type, event.Domain, event.InitialEntityKid, event.InitialOperationalKid, event.InitialEntitySignature, event.InitialOperationalSignature)
	l.canonicals = append(l.canonicals, canonical)
	return []byte(canonical), nil
}
func (l *testWriteLog) WriteEvent(_ context.Context, event dnsidlog.LogEvent) (dnsidlog.LogRef, error) {
	l.events = append(l.events, event)
	return dnsidlog.LogRef("test:1"), nil
}
func (l *testWriteLog) KeyTimestamp(context.Context, string, string) (time.Time, error) {
	return time.Now(), nil
}
func (l *testWriteLog) VerifyBilateralBinding(context.Context, dnsidlog.BilateralBindingInput) (dnsidlog.BilateralBinding, error) {
	return dnsidlog.BilateralBinding{}, nil
}
func (l *testWriteLog) VerifyOperationalContinuity(context.Context, string, string, string) error {
	return nil
}
func (l *testWriteLog) VerifyGovernanceRelationship(context.Context, string, string) error {
	return nil
}
func (l *testWriteLog) VerifyNonRevocation(context.Context, string, time.Time) (dnsidlog.LoggedStateEvidence, error) {
	return dnsidlog.LoggedStateEvidence{}, nil
}
func (l *testWriteLog) ReadEvent(context.Context, dnsidlog.LogRef) (dnsidlog.LogEvent, error) {
	return dnsidlog.LogEvent{}, nil
}
func (l *testWriteLog) RebuildHistory(context.Context, string) ([]dnsidlog.LogEvent, error) {
	return l.events, nil
}

type misorderedKeyProvider struct{ KeyProvider }

func (p misorderedKeyProvider) ListKeyIds() []string {
	ids := p.KeyProvider.ListKeyIds()
	return append([]string{"wrong-kid"}, ids...)
}

func TestLogRegistryAndSignAndWriteEvent(t *testing.T) {
	wl := &testWriteLog{}
	registry := dnsidlog.NewLogRegistry()
	if err := registry.Register("test", func(string) dnsidlog.LogReader { return wl }); err != nil {
		t.Fatalf("Register: %v", err)
	}
	kp := GenerateES256KeyProvider()
	entityKP := GenerateES256KeyProvider()
	activeKid, _ := kp.JWK().KeyID()
	entityKid, _ := entityKP.JWK().KeyID()
	manager, err := NewIdentityManager(Config{Identity: &IdentityConfig{Domain: "agent.example.com", GovernanceID: "example.com", LogRef: "test:agent", StatusURL: "https://agent.example.com/status.json"}}, misorderedKeyProvider{kp}, WithEntityKeyProvider(entityKP), WithLogRegistry(registry))
	if err != nil {
		t.Fatalf("NewIdentityManager: %v", err)
	}
	ref, err := manager.SignAndWriteEvent(context.Background(), dnsidlog.LogEvent{
		Type: dnsidlog.LogEventIssuance, Domain: "agent.example.com", Timestamp: time.Now(),
		InitialOperationalPublicKey: kp.JWK(), InitialEntityPublicKey: entityKP.JWK(),
	})
	if err != nil {
		t.Fatalf("SignAndWriteEvent: %v", err)
	}
	if ref != "test:1" || len(wl.events) != 1 || wl.events[0].InitialEntityKid != entityKid || wl.events[0].InitialEntitySignature == "" || wl.events[0].InitialOperationalKid != activeKid || wl.events[0].InitialOperationalSignature == "" {
		t.Fatalf("issuance not signed by entity and operational keys: ref=%q events=%#v", ref, wl.events)
	}

	ref, err = manager.SignAndWriteEvent(context.Background(), dnsidlog.LogEvent{Type: dnsidlog.LogEventRevocation, Domain: "agent.example.com", Timestamp: time.Now(), Reason: "keyCompromise"})
	if err != nil {
		t.Fatalf("SignAndWriteEvent revocation: %v", err)
	}
	if ref != "test:1" || len(wl.events) != 2 || wl.events[1].InitialEntityKid != entityKid || wl.events[1].InitialEntitySignature == "" {
		t.Fatalf("revocation not signed by entity key: ref=%q events=%#v", ref, wl.events)
	}
	if _, err := manager.SignAndWriteEvent(context.Background(), dnsidlog.LogEvent{Type: dnsidlog.LogEventRevocation, Domain: "agent.example.com", Timestamp: time.Now(), Reason: "owner_request"}); err == nil {
		t.Fatal("invalid revocation reason was written")
	}

	ref, err = manager.SignAndWriteEvent(context.Background(), dnsidlog.LogEvent{Type: dnsidlog.LogEventIssuance, Domain: "agent.example.com", Timestamp: time.Now(), InitialOperationalPublicKey: kp.JWK(), InitialEntityPublicKey: entityKP.JWK(), InitialEntityKid: "ae", InitialEntitySignature: "ae-sig", InitialOperationalSignature: "caller-countersig"})
	if err != nil {
		t.Fatalf("SignAndWriteEvent partially signed: %v", err)
	}
	if ref != "test:1" || len(wl.events) != 3 || wl.events[2].InitialEntityKid != "ae" || wl.events[2].InitialEntitySignature != "ae-sig" || wl.events[2].InitialOperationalKid != activeKid || wl.events[2].InitialOperationalSignature == "" || wl.events[2].InitialOperationalSignature == "caller-countersig" {
		t.Fatalf("partially signed event not completed: ref=%q activeKid=%q events=%#v", ref, activeKid, wl.events)
	}
	if got := wl.canonicals[len(wl.canonicals)-1]; !strings.Contains(got, "signingKid=ae:kid="+activeKid+":sig=ae-sig:opSig=") {
		t.Fatalf("countersig canonical = %q", got)
	}
}

func TestIdentityManager_RevokeViaRegistryDoesNotDuplicateRegistryAppend(t *testing.T) {
	wl := &testWriteLog{}
	registry := dnsidlog.NewLogRegistry()
	if err := registry.Register("test", func(string) dnsidlog.LogReader { return wl }); err != nil {
		t.Fatalf("Register: %v", err)
	}
	manager, err := NewIdentityManager(Config{Identity: &IdentityConfig{Domain: "agent.example.com", GovernanceID: "example.com", LogRef: "test:agent", StatusURL: "https://agent.example.com/status.json"}}, GenerateES256KeyProvider(), WithEntityKeyProvider(GenerateES256KeyProvider()), WithLogRegistry(registry))
	if err != nil {
		t.Fatalf("NewIdentityManager: %v", err)
	}
	client := &fakeRegistryClient{}
	resp, err := manager.RevokeViaRegistry(context.Background(), client, "ag_123", RegistryRevocationReasonKeyCompromise)
	if err != nil {
		t.Fatalf("RevokeViaRegistry: %v", err)
	}
	if resp.Status != "REVOKED" {
		t.Fatalf("response = %+v", resp)
	}
	if client.revokeRequest == nil || client.revokeRequest.AgentID != "ag_123" || client.revokeRequest.Reason != RegistryRevocationReasonKeyCompromise {
		t.Fatalf("revocation request = %#v", client.revokeRequest)
	}
	if len(wl.events) != 0 {
		t.Fatalf("local append duplicated registry-owned event: %#v", wl.events)
	}
}

func TestIdentityManager_RevokeViaRegistryRejectsInvalidReasonBeforeRegistryCall(t *testing.T) {
	manager, err := NewIdentityManager(Config{Identity: &IdentityConfig{Domain: "agent.example.com", GovernanceID: "example.com", LogRef: "test:agent", StatusURL: "https://agent.example.com/status.json"}}, GenerateES256KeyProvider(), WithEntityKeyProvider(GenerateES256KeyProvider()))
	if err != nil {
		t.Fatalf("NewIdentityManager: %v", err)
	}
	client := &fakeRegistryClient{}
	if _, err := manager.RevokeViaRegistry(context.Background(), client, "ag_123", RegistryRevocationReason("keyCompromise")); err == nil {
		t.Fatal("invalid revocation reason was accepted")
	}
	if client.revokes != 0 {
		t.Fatalf("registry called %d times for invalid reason", client.revokes)
	}
}

func TestIdentityManager_RevokeViaRegistryEvictsCache(t *testing.T) {
	manager, err := NewIdentityManager(Config{Identity: &IdentityConfig{Domain: "agent.example.com", GovernanceID: "example.com", LogRef: "test:agent", StatusURL: "https://agent.example.com/status.json"}}, GenerateES256KeyProvider(), WithEntityKeyProvider(GenerateES256KeyProvider()))
	if err != nil {
		t.Fatalf("NewIdentityManager: %v", err)
	}
	manager.cache.put(&VerifiedDomain{domain: "agent.example.com", dnsTTL: time.Hour, expiry: time.Now().Add(time.Hour)}, manager)

	resp, err := manager.RevokeViaRegistry(context.Background(), &fakeRegistryClient{}, "ag_123", RegistryRevocationReasonOwnerRequest)
	if err != nil {
		t.Fatalf("RevokeViaRegistry: %v", err)
	}
	if resp == nil || resp.Status != "REVOKED" {
		t.Fatalf("response = %+v", resp)
	}
	if cached := manager.cachedDomain("agent.example.com"); cached != nil {
		t.Fatalf("cache not evicted: %#v", cached)
	}
}

func TestDomainLogSnapshotAtPreservesVerifiedOrder(t *testing.T) {
	now := time.Now()
	key := GenerateES256KeyProvider().JWK()
	newKey := GenerateES256KeyProvider().JWK()
	issuance := lifecycleIssuance(t, "agent.example.com", key, now.Add(-time.Hour))
	rotation := lifecycleRotation(t, "agent.example.com", issuance.InitialOperationalThumbprint, newKey, now.Add(-2*time.Hour))
	log := dnsidlog.NewDomainLog("agent.example.com", []dnsidlog.LogEvent{
		issuance,
		rotation,
	})
	snapshot, err := log.SnapshotAt(now)
	if err != nil {
		t.Fatalf("SnapshotAt: %v", err)
	}
	if snapshot.ActiveKeyThumbprint != rotation.NewOperationalThumbprint {
		t.Fatalf("ActiveKeyThumbprint = %q, want %q", snapshot.ActiveKeyThumbprint, rotation.NewOperationalThumbprint)
	}
	if snapshot.Events[0].Type != dnsidlog.LogEventIssuance || snapshot.Events[1].Type != dnsidlog.LogEventKeyRotation {
		t.Fatalf("Events reordered: %+v", snapshot.Events)
	}
}

func TestDomainLogSnapshotAtRejectsNonPrefixBoundary(t *testing.T) {
	now := time.Now()
	key := GenerateES256KeyProvider().JWK()
	issuance := lifecycleIssuance(t, "agent.example.com", key, now.Add(-2*time.Hour))
	rotation := lifecycleRotation(t, "agent.example.com", issuance.InitialOperationalThumbprint, GenerateES256KeyProvider().JWK(), now.Add(time.Hour))

	snapshot, err := dnsidlog.NewDomainLog("agent.example.com", []dnsidlog.LogEvent{issuance, rotation}).SnapshotAt(now)
	if err != nil {
		t.Fatalf("SnapshotAt valid prefix: %v", err)
	}
	if len(snapshot.Events) != 1 || snapshot.Events[0].Type != dnsidlog.LogEventIssuance {
		t.Fatalf("Events = %+v, want issuance prefix", snapshot.Events)
	}

	revocation := dnsidlog.LogEvent{Type: dnsidlog.LogEventRevocation, Domain: "agent.example.com", Timestamp: now.Add(-time.Hour)}
	_, err = dnsidlog.NewDomainLog("agent.example.com", []dnsidlog.LogEvent{issuance, rotation, revocation}).SnapshotAt(now)
	if err == nil || !strings.Contains(err.Error(), "not a verified lifecycle prefix") {
		t.Fatalf("SnapshotAt error = %v, want non-prefix rejection", err)
	}
}

func TestDomainLogSnapshotAtRejectsForeignEvents(t *testing.T) {
	now := time.Now()
	key := GenerateES256KeyProvider().JWK()
	events := []dnsidlog.LogEvent{
		lifecycleIssuance(t, "agent.example.com", key, now.Add(-2*time.Hour)),
		{Type: dnsidlog.LogEventIssuance, Domain: "other.example.com", Timestamp: now.Add(time.Hour)},
	}

	_, err := dnsidlog.NewDomainLog("agent.example.com", events).SnapshotAt(now)
	if verificationCode(err) != "DOMAIN_MISMATCH" {
		t.Fatalf("SnapshotAt error = %v, want DOMAIN_MISMATCH", err)
	}
}

func TestDomainLogSnapshotAtRejectsMigrationInGenesis(t *testing.T) {
	now := time.Now()
	kp := GenerateES256KeyProvider()
	key := kp.JWK()
	jwk := &JWK{key: key}
	keyThumb, err := jwk.Thumbprint()
	if err != nil {
		t.Fatalf("InitialOperationalThumbprint: %v", err)
	}
	log := dnsidlog.NewDomainLog("agent.example.com", []dnsidlog.LogEvent{
		{Type: dnsidlog.LogEventMigration, Domain: "agent.example.com", InitialOperationalPublicKey: key, InitialOperationalThumbprint: keyThumb, GovernanceID: "example.com", PreviousLog: "c2sp-tlog:testnet:http://old/log#agent.example.com", FinalEntryRef: "c2sp-tlog:testnet:http://old/log#agent.example.com@3", Timestamp: now.Add(-time.Hour)},
	})
	_, err = log.SnapshotAt(now)
	if verificationCode(err) != "GENESIS_REQUIRED" {
		t.Fatalf("SnapshotAt error = %v, want GENESIS_REQUIRED", err)
	}
}

func TestDomainLogSnapshotAtEnforcesTerminalState(t *testing.T) {
	now := time.Now()
	kp := GenerateES256KeyProvider()
	key := kp.JWK()
	jwk := &JWK{key: key}
	keyThumb, err := jwk.Thumbprint()
	if err != nil {
		t.Fatalf("InitialOperationalThumbprint: %v", err)
	}
	log := dnsidlog.NewDomainLog("agent.example.com", []dnsidlog.LogEvent{
		lifecycleIssuance(t, "agent.example.com", key, now.Add(-3*time.Hour)),
		{Type: dnsidlog.LogEventRevocation, Domain: "agent.example.com", Reason: "keyCompromise", Timestamp: now.Add(-2 * time.Hour)},
		{Type: dnsidlog.LogEventKeyRotation, Domain: "agent.example.com", NewOperationalPublicKey: key, NewOperationalThumbprint: keyThumb, Timestamp: now.Add(-time.Hour)},
	})
	_, err = log.SnapshotAt(now)
	if err == nil || !strings.Contains(err.Error(), "after terminal state") {
		t.Fatalf("SnapshotAt error = %v, want terminal state rejection", err)
	}
}

func TestDomainLogSnapshotAtRejectsReissuanceAfterTerminalState(t *testing.T) {
	now := time.Now()
	firstKey := GenerateES256KeyProvider().JWK()
	secondKey := GenerateES256KeyProvider().JWK()
	events := []dnsidlog.LogEvent{
		lifecycleIssuance(t, "agent.example.com", firstKey, now.Add(-4*time.Hour)),
		{Type: dnsidlog.LogEventRetirement, Domain: "agent.example.com", Timestamp: now.Add(-3 * time.Hour)},
		lifecycleIssuance(t, "agent.example.com", secondKey, now.Add(-2*time.Hour)),
		{Type: dnsidlog.LogEventKeyRotation, Domain: "agent.example.com", NewOperationalPublicKey: secondKey, NewOperationalThumbprint: "rotated-thumb", Timestamp: now.Add(-time.Hour)},
	}

	_, err := dnsidlog.NewDomainLog("agent.example.com", events).SnapshotAt(now)
	if verificationCode(err) != "TERMINAL_STATE" {
		t.Fatalf("SnapshotAt error = %v, want TERMINAL_STATE", err)
	}
}

func TestDomainLogSnapshotAtRejectsReissuanceBeforeTerminalState(t *testing.T) {
	now := time.Now()
	key := GenerateES256KeyProvider().JWK()
	events := []dnsidlog.LogEvent{
		lifecycleIssuance(t, "agent.example.com", key, now.Add(-2*time.Hour)),
		lifecycleIssuance(t, "agent.example.com", key, now.Add(-time.Hour)),
	}

	_, err := dnsidlog.NewDomainLog("agent.example.com", events).SnapshotAt(now)
	if verificationCode(err) != "DUPLICATE_ISSUANCE" {
		t.Fatalf("SnapshotAt error = %v, want DUPLICATE_ISSUANCE", err)
	}
}

func TestDomainLogLifecycleConformance(t *testing.T) {
	now := time.Now()
	op1 := GenerateES256KeyProvider().JWK()
	op2 := GenerateES256KeyProvider().JWK()
	issuance := lifecycleIssuance(t, "agent.example.com", op1, now.Add(-3*time.Hour))
	rotation := lifecycleRotation(t, "agent.example.com", issuance.InitialOperationalThumbprint, op2, now.Add(-2*time.Hour))
	validMigration := dnsidlog.LogEvent{Type: dnsidlog.LogEventMigration, Domain: "agent.example.com", PreviousLog: "method-a:stream", NewLog: "method-b:stream", FinalEntryRef: "method-a:entry-10", Timestamp: now.Add(-time.Hour)}

	cases := []struct {
		name   string
		events []dnsidlog.LogEvent
		code   string
		state  dnsidlog.AgentState
		thumb  string
	}{
		{name: "issuance", events: []dnsidlog.LogEvent{issuance}, state: dnsidlog.AgentStateActive, thumb: issuance.InitialOperationalThumbprint},
		{name: "rotation continuity", events: []dnsidlog.LogEvent{issuance, rotation}, state: dnsidlog.AgentStateActive, thumb: rotation.NewOperationalThumbprint},
		{name: "rotation before genesis", events: []dnsidlog.LogEvent{rotation}, code: dnsidlog.VerificationCodeGenesisRequired},
		{name: "same role key", events: []dnsidlog.LogEvent{{Type: dnsidlog.LogEventIssuance, Domain: "agent.example.com", InitialEntityPublicKey: op1, InitialOperationalPublicKey: op1, InitialOperationalThumbprint: issuance.InitialOperationalThumbprint, Timestamp: issuance.Timestamp}}, code: dnsidlog.VerificationCodeInvalidIssuance},
		{name: "entity thumbprint mismatch", events: []dnsidlog.LogEvent{{Type: dnsidlog.LogEventIssuance, Domain: issuance.Domain, InitialEntityPublicKey: issuance.InitialEntityPublicKey, InitialEntityThumbprint: "wrong", InitialOperationalPublicKey: issuance.InitialOperationalPublicKey, InitialOperationalThumbprint: issuance.InitialOperationalThumbprint, Timestamp: issuance.Timestamp}}, code: dnsidlog.VerificationCodeInvalidIssuance},
		{name: "stale rotation", events: []dnsidlog.LogEvent{issuance, rotation, lifecycleRotation(t, "agent.example.com", issuance.InitialOperationalThumbprint, GenerateES256KeyProvider().JWK(), now.Add(-time.Hour))}, code: dnsidlog.VerificationCodeKeyContinuity},
		{name: "same key rotation", events: []dnsidlog.LogEvent{issuance, lifecycleRotation(t, "agent.example.com", issuance.InitialOperationalThumbprint, op1, now.Add(-time.Hour))}, code: dnsidlog.VerificationCodeKeyContinuity},
		{name: "migration", events: []dnsidlog.LogEvent{issuance, validMigration}, state: dnsidlog.AgentStateActive, thumb: issuance.InitialOperationalThumbprint},
		{name: "same log migration", events: []dnsidlog.LogEvent{issuance, {Type: dnsidlog.LogEventMigration, Domain: "agent.example.com", PreviousLog: "method-a:stream", NewLog: "method-a:stream", FinalEntryRef: "method-a:entry-10", Timestamp: now.Add(-time.Hour)}}, code: dnsidlog.VerificationCodeInvalidMigration},
		{name: "invalid revocation reason", events: []dnsidlog.LogEvent{issuance, {Type: dnsidlog.LogEventRevocation, Domain: "agent.example.com", Reason: "ownerRequest", Timestamp: now.Add(-time.Hour)}}, code: dnsidlog.VerificationCodeInvalidRevocationReason},
		{name: "unsupported event", events: []dnsidlog.LogEvent{issuance, {Type: dnsidlog.LogEventType("FUTURE_EVENT"), Domain: "agent.example.com", Timestamp: now.Add(-time.Hour)}}, code: dnsidlog.VerificationCodeUnsupportedEvent},
		{name: "terminal", events: []dnsidlog.LogEvent{issuance, {Type: dnsidlog.LogEventRetirement, Domain: "agent.example.com", Timestamp: now.Add(-time.Hour)}, rotation}, code: dnsidlog.VerificationCodeTerminalState},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			snapshot, err := dnsidlog.NewDomainLog("agent.example.com", tc.events).SnapshotAt(now)
			if got := verificationCode(err); got != tc.code {
				t.Fatalf("verification code = %q (%v), want %q", got, err, tc.code)
			}
			if tc.code == "" && (snapshot.HistoricalState != tc.state || snapshot.ActiveKeyThumbprint != tc.thumb) {
				t.Fatalf("snapshot = %+v, want state %s and thumb %s", snapshot, tc.state, tc.thumb)
			}
		})
	}
}

func lifecycleIssuance(t *testing.T, domain string, operational jwk.Key, timestamp time.Time) dnsidlog.LogEvent {
	t.Helper()
	thumb, err := (&JWK{key: operational}).Thumbprint()
	if err != nil {
		t.Fatalf("operational InitialOperationalThumbprint: %v", err)
	}
	entity := GenerateES256KeyProvider().JWK()
	entityThumb, err := (&JWK{key: entity}).Thumbprint()
	if err != nil {
		t.Fatalf("entity thumbprint: %v", err)
	}
	return dnsidlog.LogEvent{Type: dnsidlog.LogEventIssuance, Domain: domain, InitialEntityPublicKey: entity, InitialEntityThumbprint: entityThumb, InitialOperationalPublicKey: operational, InitialOperationalThumbprint: thumb, GovernanceID: "example.com", Timestamp: timestamp}
}

func lifecycleRotation(t *testing.T, domain, previousThumb string, next jwk.Key, timestamp time.Time) dnsidlog.LogEvent {
	t.Helper()
	thumb, err := (&JWK{key: next}).Thumbprint()
	if err != nil {
		t.Fatalf("new operational InitialOperationalThumbprint: %v", err)
	}
	return dnsidlog.LogEvent{Type: dnsidlog.LogEventKeyRotation, Domain: domain, PreviousOperationalThumbprint: previousThumb, NewOperationalPublicKey: next, NewOperationalThumbprint: thumb, Timestamp: timestamp}
}

func verificationCode(err error) string {
	type coded interface{ Code() string }
	var target coded
	if errors.As(err, &target) {
		return target.Code()
	}
	return ""
}
