package dnsid

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	dnsidlog "github.com/dnsid-ai/dnsid-go/log"
)

// acceptanceVerifier builds a verifier sharing the fixture's transport with
// its own verification policy and a private cache namespace.
func acceptanceVerifier(t *testing.T, f *coalescingFixture, v VerificationConfig) *IdentityManager {
	t.Helper()
	registry := dnsidlog.NewLogRegistry()
	if err := registry.Register("testlog", func(string) dnsidlog.LogReader { return &delegatingLogReader{} }); err != nil {
		t.Fatal(err)
	}
	m, err := NewIdentityManager(Config{Verification: v}, nil, WithDNSResolver(f.dns), WithHTTPSFetcher(f.https), WithLogRegistry(registry))
	if err != nil {
		t.Fatalf("NewIdentityManager: %v", err)
	}
	return m
}

// publishDelegated adds a record for domain accounted by gi (an unrelated
// domain) to the fixture and returns its entity and operational providers.
func publishDelegated(t *testing.T, f *coalescingFixture, domain, gi string) (entity, operational KeyProvider) {
	t.Helper()
	operational, entity = GenerateES256KeyProvider(), GenerateES256KeyProvider()
	publisher, err := NewIdentityManager(Config{Identity: &IdentityConfig{
		Domain: domain, GovernanceID: gi, LogRef: "testlog:agent",
		StatusURL: "https://" + domain + "/status", KeyURL: "https://" + domain + "/ku.json",
		EntityKeyURL: "https://" + gi + "/" + domain + "/ek.json",
	}}, operational, WithEntityKeyProvider(entity))
	if err != nil {
		t.Fatal(err)
	}
	record, err := publisher.CreateTXTRecord()
	if err != nil {
		t.Fatal(err)
	}
	ek, _ := json.Marshal(mustJWKSet(t, entity.JWK()))
	ku, _ := json.Marshal(mustJWKSet(t, operational.JWK()))
	f.dns.records["_dnsid."+domain] = []TXTRecordRData{{Value: record.Serialize(), TTL: time.Hour}}
	f.https.responses[record.EntityKeyURI] = ek
	f.https.responses[record.KeyURI] = ku
	f.https.responses[record.StatusURI] = json.RawMessage(freshStatus())
	f.records[domain] = record
	return entity, operational
}

func thumbprintOf(t *testing.T, kp KeyProvider) string {
	t.Helper()
	tp, err := (&JWK{key: kp.JWK()}).Thumbprint()
	if err != nil {
		t.Fatal(err)
	}
	return tp
}

func requireNotAccepted(t *testing.T, err error) *VerificationError {
	t.Helper()
	var ve *VerificationError
	if !errors.As(err, &ve) || ve.Code() != VerificationCodeCounterpartyNotAccepted {
		t.Fatalf("error = %v, want CounterpartyNotAccepted", err)
	}
	if ve.Transient() || !errors.Is(err, ErrCounterpartyNotAccepted) {
		t.Fatalf("denial must be permanent and match the sentinel: %v", err)
	}
	return ve
}

func TestVerificationConfig_RejectsInvalidPolicyBeforeNetwork(t *testing.T) {
	validPin := strings.Repeat("A", 43)
	cases := map[string]VerificationConfig{
		"negative interval":   {StatusCheckInterval: -time.Second},
		"invalid dnssec mode": {DNSSECMode: "disabled"},
		"invalid gi":          {TrustedEntities: []TrustedEntity{{GovernanceID: "not a domain"}}},
		"duplicate gi":        {TrustedEntities: []TrustedEntity{{GovernanceID: "Acme.Example"}, {GovernanceID: "acme.example."}}},
		"empty pins":          {TrustedEntities: []TrustedEntity{{GovernanceID: "acme.example", EntityKeyThumbprints: []string{}}}},
		"short pin":           {TrustedEntities: []TrustedEntity{{GovernanceID: "acme.example", EntityKeyThumbprints: []string{"abc"}}}},
		"padded pin":          {TrustedEntities: []TrustedEntity{{GovernanceID: "acme.example", EntityKeyThumbprints: []string{validPin + "="}}}},
		"duplicate pin":       {TrustedEntities: []TrustedEntity{{GovernanceID: "acme.example", EntityKeyThumbprints: []string{validPin, validPin}}}},
	}
	dns := &testDNSResolver{}
	for name, cfg := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := NewIdentityManager(Config{Verification: cfg}, nil, WithDNSResolver(dns))
			var argErr *ArgumentError
			if !errors.As(err, &argErr) {
				t.Fatalf("error = %v, want *ArgumentError", err)
			}
		})
	}
	if dns.calls != 0 {
		t.Fatalf("construction performed %d DNS lookups", dns.calls)
	}
}

func TestVerificationConfig_SnapshotIsSharedAcrossModesAndImmutable(t *testing.T) {
	entities := []TrustedEntity{{GovernanceID: "Acme.Example.", EntityKeyThumbprints: []string{strings.Repeat("A", 43)}}}
	v := VerificationConfig{StatusCheckInterval: time.Minute, TrustedEntities: entities}
	verifier, err := NewIdentityManager(Config{Verification: v}, nil)
	if err != nil {
		t.Fatal(err)
	}
	local, err := NewIdentityManager(Config{Verification: v, Identity: &IdentityConfig{
		Domain: "agent.example.com", GovernanceID: "example.com", LogRef: "algorand:ADDR", StatusURL: "https://agent.example.com/status.json",
	}}, GenerateES256KeyProvider())
	if err != nil {
		t.Fatal(err)
	}
	entities[0].GovernanceID = "evil.example"
	entities[0].EntityKeyThumbprints[0] = "tampered"
	for _, m := range []*IdentityManager{verifier, local} {
		got := m.verification
		if got.DNSSECMode != DNSSECModeAuto || got.StatusCheckInterval != time.Minute {
			t.Fatalf("defaults not applied: %+v", got)
		}
		if got.TrustedEntities[0].GovernanceID != "acme.example" || got.TrustedEntities[0].EntityKeyThumbprints[0] != strings.Repeat("A", 43) {
			t.Fatalf("snapshot leaked caller mutation: %+v", got.TrustedEntities)
		}
	}
	if _, err := NewIdentityManager(Config{}, GenerateES256KeyProvider()); err == nil {
		t.Fatal("verification-only manager accepted a KeyProvider")
	}
	if _, err := NewIdentityManager(Config{}, nil, WithEntityKeyProvider(GenerateES256KeyProvider())); err == nil {
		t.Fatal("verification-only manager accepted an entity KeyProvider")
	}
}

func TestVerifyDomain_AcceptancePolicyOmittedVersusEmpty(t *testing.T) {
	const domain = "agent.example"
	f := newCoalescingFixture(t, []string{domain}, nil)
	if _, err := acceptanceVerifier(t, f, VerificationConfig{}).VerifyDomain(context.Background(), domain); err != nil {
		t.Fatalf("nil allowlist must make no decision: %v", err)
	}
	denyAll := acceptanceVerifier(t, f, VerificationConfig{TrustedEntities: []TrustedEntity{}})
	_, err := denyAll.VerifyDomain(context.Background(), domain)
	ve := requireNotAccepted(t, err)
	if ve.VerifiedGovernanceID() != domain || ve.VerifiedEntityKeyThumbprint() == "" {
		t.Fatalf("denial lacks observed identity: gi=%q tp=%q", ve.VerifiedGovernanceID(), ve.VerifiedEntityKeyThumbprint())
	}
	if denyAll.cachedDomain(domain) == nil {
		t.Fatal("verified evidence must be cached even when acceptance denies")
	}
}

func TestVerifyDomain_AcceptanceMatchesExactGovernanceIDOnly(t *testing.T) {
	const self, delegated, gi = "acme.test", "bot.unrelated.example", "acme.test"
	f := newCoalescingFixture(t, []string{self}, nil)
	publishDelegated(t, f, delegated, gi)
	allow := acceptanceVerifier(t, f, VerificationConfig{TrustedEntities: []TrustedEntity{{GovernanceID: "ACME.test."}}})
	for _, d := range []string{self, delegated} {
		if _, err := allow.VerifyDomain(context.Background(), d); err != nil {
			t.Fatalf("exact gi with valid binding rejected for %s: %v", d, err)
		}
	}
	for name, cfg := range map[string]string{"parent": "test", "child": "sub.acme.test", "lookalike": "acme-test.test", "unrelated": "zzz.invalid"} {
		m := acceptanceVerifier(t, f, VerificationConfig{TrustedEntities: []TrustedEntity{{GovernanceID: cfg}}})
		_, err := m.VerifyDomain(context.Background(), delegated)
		ve := requireNotAccepted(t, err)
		if ve.VerifiedGovernanceID() != gi {
			t.Fatalf("%s: observed gi = %q", name, ve.VerifiedGovernanceID())
		}
		if name == "unrelated" && strings.Contains(ve.Error(), cfg) {
			t.Fatalf("error disclosed configured allowlist: %v", ve)
		}
	}
}

func TestVerifyDomain_AcceptancePinsCurrentEntityKey(t *testing.T) {
	const domain, gi = "bot.unrelated.example", "acme.example"
	f := newCoalescingFixture(t, nil, nil)
	entity, operational := publishDelegated(t, f, domain, gi)
	ekPin, kuPin, otherPin := thumbprintOf(t, entity), thumbprintOf(t, operational), thumbprintOf(t, GenerateES256KeyProvider())

	pinned := acceptanceVerifier(t, f, VerificationConfig{TrustedEntities: []TrustedEntity{{GovernanceID: gi, EntityKeyThumbprints: []string{otherPin, ekPin}}}})
	if _, err := pinned.VerifyDomain(context.Background(), domain); err != nil {
		t.Fatalf("matching pin rejected: %v", err)
	}
	for name, pins := range map[string][]string{"ku key": {kuPin}, "historical key": {otherPin}} {
		m := acceptanceVerifier(t, f, VerificationConfig{TrustedEntities: []TrustedEntity{{GovernanceID: gi, EntityKeyThumbprints: pins}}})
		_, err := m.VerifyDomain(context.Background(), domain)
		ve := requireNotAccepted(t, err)
		if ve.VerifiedEntityKeyThumbprint() != ekPin || strings.Contains(ve.Error(), pins[0]) {
			t.Fatalf("%s: denial = %v", name, ve)
		}
	}
}

func TestVerifyDomain_AcceptanceRunsOnEveryCachePath(t *testing.T) {
	const domain = "agent.example"
	f := newCoalescingFixture(t, []string{domain}, nil)
	m := acceptanceVerifier(t, f, VerificationConfig{StatusCheckInterval: time.Hour, TrustedEntities: []TrustedEntity{{GovernanceID: "other.example"}}})

	// Fresh lookup: denied, evidence cached.
	requireNotAccepted(t, mustErr(m.VerifyDomain(context.Background(), domain)))
	first := m.cachedDomain(domain)
	if first == nil {
		t.Fatal("fresh evidence not cached")
	}
	// Cache hit without refresh due: still denied, no new network work.
	requireNotAccepted(t, mustErr(m.VerifyDomain(context.Background(), domain)))
	if f.dns.callCount("_dnsid."+domain) != 1 || f.https.callCount(f.records[domain].StatusURI) != 1 {
		t.Fatal("cache hit performed network work")
	}
	// Status refresh due: refreshed evidence cached, still denied.
	first.lastStatusCheckAt = time.Now().Add(-2 * time.Hour)
	m.cache.put(first, m)
	requireNotAccepted(t, mustErr(m.VerifyDomain(context.Background(), domain)))
	refreshed := m.cachedDomain(domain)
	if refreshed == nil || !refreshed.lastStatusCheckAt.After(first.lastStatusCheckAt) || f.https.callCount(f.records[domain].StatusURI) != 2 {
		t.Fatal("status refresh evidence not cached after denial")
	}
	if !refreshed.expiry.Equal(first.expiry) {
		t.Fatal("status refresh extended identity expiry")
	}
	// Concurrent callers sharing coalesced work are each denied.
	m.EvictDomain(domain)
	var wg sync.WaitGroup
	errs := make(chan error, 8)
	for range 8 {
		wg.Add(1)
		go func() { defer wg.Done(); errs <- mustErr(m.VerifyDomain(context.Background(), domain)) }()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		requireNotAccepted(t, err)
	}
}

func mustErr(_ *VerifiedDomain, err error) error { return err }

func TestAwaitRegistryManagedPublication_SkipsAcceptanceButPublicVerifyDoesNot(t *testing.T) {
	const domain = "agent.example"
	f := newCoalescingFixture(t, []string{domain}, nil)
	operational, entity := GenerateES256KeyProvider(), GenerateES256KeyProvider()
	local, err := NewIdentityManager(Config{
		Identity: &IdentityConfig{
			Domain: domain, GovernanceID: domain, LogRef: "testlog:agent",
			StatusURL: "https://" + domain + "/status", KeyURL: "https://" + domain + "/ku.json",
			EntityKeyURL: "https://" + domain + "/ek.json",
		},
		Verification: VerificationConfig{TrustedEntities: []TrustedEntity{}},
	}, operational, WithEntityKeyProvider(entity), WithDNSResolver(f.dns), WithHTTPSFetcher(f.https), WithLogRegistry(f.manager.logRegistry))
	if err != nil {
		t.Fatal(err)
	}
	reader := &sequenceRegistrationReader{registrations: []*AgentRegistration{{
		Domain: domain, PublicationAuthority: PublicationAuthorityRegistry, RegistryStatus: RegistryStatusReady, DNSPublished: true,
	}}}
	if _, err := local.AwaitRegistryManagedPublication(context.Background(), reader, nil); err != nil {
		t.Fatalf("publication confirmation must not run acceptance: %v", err)
	}
	requireNotAccepted(t, mustErr(local.VerifyDomain(context.Background(), domain)))
}

// delegatingLogReader accepts every delegated governance relationship.
type delegatingLogReader struct{ coalescingLogReader }

func (*delegatingLogReader) VerifyGovernanceRelationship(context.Context, string, string) error {
	return nil
}

var _ dnsidlog.LogReader = (*delegatingLogReader)(nil)
