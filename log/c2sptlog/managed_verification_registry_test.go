package c2sptlog

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	dnsid "github.com/dnsid-ai/dnsid-go"
	"golang.org/x/mod/sumdb/note"
)

const (
	expectedManagedDevelopmentPolicy = `log log.dev.dnsid.ai+cad12acd+Afnd3sdzfp8nCXzDQchrnWn9QOox5AglR147bURESRqu
witness dnsid-witness-1 witness.dev.dnsid.ai/w1+50822ded+BAH9KuulelD3yZBDTneG46gKZY+OWwdUPBmLmq/YjOkO
quorum dnsid-witness-1
`
	expectedManagedDevelopmentBundleVerifierKey = "dnsid-stream-bundle+0c241174+AeuT9PKyiewb9hkzygvki7UuOs5ly2kfY/C4Tfh7/ix0"
	expectedManagedProductionPolicy             = `log log.dnsid.ai+f10a26bc+Aeo6u4o1XvQlcRczgY462ZdIGpm/ejBC2G3vSbyYYqqY
witness dnsid-witness-1 witness.dnsid.ai/w1+706fd4fb+BLqX21Sx9xG5+5vK7kSK5omcu9+2il20PLdfpOp8lQOJ
quorum dnsid-witness-1
`
	expectedManagedProductionBundleVerifierKey = "dnsid-stream-bundle+2e77a3f1+AbKj/zrAfK04/NM07Zj7kxP2YXbM5neT8ym6juXC2PXG"
)

func TestManagedDevelopmentCatalogEntryIsReviewedTrustProfile(t *testing.T) {
	entry := dnsidManagedTrustCatalog[0]
	if entry.scope != "public" || entry.logPrefix != "https://log.dev.dnsid.ai" {
		t.Fatalf("development catalog entry = %#v", entry)
	}
	profile, err := ParseTrustProfile([]byte(entry.trustProfileDocument))
	if err != nil {
		t.Fatal(err)
	}
	if profile.PolicyDocument != expectedManagedDevelopmentPolicy || len(profile.BundleVerifierKeys) != 1 || profile.BundleVerifierKeys[0] != expectedManagedDevelopmentBundleVerifierKey {
		t.Fatalf("unexpected pinned development trust profile: %+v", profile)
	}
}

func TestManagedProductionCatalogEntryIsReviewedTrustProfile(t *testing.T) {
	entry := dnsidManagedTrustCatalog[1]
	if entry.scope != "public" || entry.logPrefix != "https://log.dnsid.ai" || entry.trustProfileDocument == "" || entry.policyDocument != "" {
		t.Fatalf("production catalog entry = %#v, want exact trust-profile selector", entry)
	}
	profile, err := ParseTrustProfile([]byte(entry.trustProfileDocument))
	if err != nil {
		t.Fatalf("ParseTrustProfile: %v", err)
	}
	if profile.Version != 1 || profile.Scope != entry.scope || profile.LogPrefix != entry.logPrefix {
		t.Fatalf("production profile selector = v%d %q %q", profile.Version, profile.Scope, profile.LogPrefix)
	}
	if profile.PolicyDocument != expectedManagedProductionPolicy {
		t.Fatalf("production policy = %q, want %q", profile.PolicyDocument, expectedManagedProductionPolicy)
	}
	if len(profile.BundleVerifierKeys) != 1 || profile.BundleVerifierKeys[0] != expectedManagedProductionBundleVerifierKey {
		t.Fatalf("production bundle verifier keys = %#v", profile.BundleVerifierKeys)
	}
}

const (
	expectedManagedPartnersPolicy = `log log.partners.dnsid.ai+f0143e09+Ae5vrTVQUr0h2GKbeHq70ml37N+uVBsU4NpZD4qMqAu1
witness dnsid-witness-1 witness.partners.dnsid.ai/w1+a115eb67+BB0avWVeSelUBk2w8FtTbT+orf2i826q9VemA0jaXxg4
quorum dnsid-witness-1
`
	expectedManagedPartnersBundleVerifierKey = "dnsid-stream-bundle+b1e0b597+AQt9ol4cfwPHxdH4NHNRidsAvU2bYE7KVItOlBG/bsaZ"
)

func TestManagedPartnersCatalogEntryIsReviewedTrustProfile(t *testing.T) {
	entry := dnsidManagedTrustCatalog[2]
	if entry.scope != "public" || entry.logPrefix != "https://log.partners.dnsid.ai" || entry.trustProfileDocument == "" || entry.policyDocument != "" {
		t.Fatalf("partners catalog entry = %#v, want exact trust-profile selector", entry)
	}
	profile, err := ParseTrustProfile([]byte(entry.trustProfileDocument))
	if err != nil {
		t.Fatalf("ParseTrustProfile: %v", err)
	}
	if profile.Version != 1 || profile.Scope != entry.scope || profile.LogPrefix != entry.logPrefix {
		t.Fatalf("partners profile selector = v%d %q %q", profile.Version, profile.Scope, profile.LogPrefix)
	}
	if profile.PolicyDocument != expectedManagedPartnersPolicy {
		t.Fatalf("partners policy = %q, want %q", profile.PolicyDocument, expectedManagedPartnersPolicy)
	}
	if len(profile.BundleVerifierKeys) != 1 || profile.BundleVerifierKeys[0] != expectedManagedPartnersBundleVerifierKey {
		t.Fatalf("partners bundle verifier keys = %#v", profile.BundleVerifierKeys)
	}
}

// Live checkpoint captured on 2026-10-16, signed by the log and its witness.
func TestManagedPartnersPolicyVerifiesPartnerCheckpoint(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("testdata", "c2sp-partners-checkpoint.txt"))
	if err != nil {
		t.Fatal(err)
	}
	policy, err := ParsePolicy([]byte(expectedManagedPartnersPolicy))
	if err != nil {
		t.Fatal(err)
	}
	ref, err := ParseReference("c2sp-tlog:public:https://log.partners.dnsid.ai#EREREREREREREREREREREQ")
	if err != nil {
		t.Fatal(err)
	}
	proof, err := policy.verifyCheckpoint(ref, raw)
	if err != nil {
		t.Fatalf("pinned partners policy rejects the partner checkpoint: %v", err)
	}
	if proof.Checkpoint.Size != 172 || proof.CheckpointWitnessTime.IsZero() {
		t.Fatalf("partner checkpoint = size %d, witness time %v", proof.Checkpoint.Size, proof.CheckpointWitnessTime)
	}
}

// Reviewed service fixture from Identity-Digital/dnsid#2639, captured 2026-10-02.
func TestManagedPartnersProfileVerifiesPartnerStreamBundle(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("testdata", "c2sp-partners-stream-bundle.json"))
	if err != nil {
		t.Fatal(err)
	}
	profile, err := ParseTrustProfile([]byte(managedPartnersProfile))
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := note.NewVerifier(profile.BundleVerifierKeys[0])
	if err != nil {
		t.Fatal(err)
	}
	verified, err := VerifyStreamBundle(context.Background(), data, StreamBundleTrust{
		PolicyDocument:    []byte(profile.PolicyDocument),
		BundleVerifier:    verifier,
		Now:               func() time.Time { return time.Unix(1790958018-60, 0) },
		MaxBundleLifetime: managedVerificationFreshness,
		MaxCheckpointAge:  managedVerificationFreshness,
	})
	if err != nil {
		t.Fatalf("pinned partners profile rejects a partner-signed stream bundle: %v", err)
	}
	if verified.Reference.LogPrefix != "https://log.partners.dnsid.ai" || verified.LoggedState != "ACTIVE" || len(verified.Events) != 1 {
		t.Fatalf("unexpected partner bundle: %+v", verified)
	}
}

func TestNewDnsidManagedVerificationRegistrySelectsExactCatalogEntries(t *testing.T) {
	fetcher := &testBoundedFetcher{}
	store := NewMemoryTrustedC2spCheckpointStore()
	registry, err := NewDnsidManagedVerificationRegistry(context.Background(), DnsidManagedVerificationConfig{
		ResourceFetcher:        fetcher,
		TrustedCheckpointStore: store,
	})
	if err != nil {
		t.Fatalf("NewDnsidManagedVerificationRegistry: %v", err)
	}

	development := verificationClient(t, registry, "c2sp-tlog:public:https://log.dev.dnsid.ai#EREREREREREREREREREREQ")
	developmentSource, ok := development.source.(*fetchedStreamBundleSource)
	if !ok {
		t.Fatalf("development source = %#v, want preferred bundles with bounded raw fallback", development.source)
	}
	developmentFallback, fallbackOK := developmentSource.fallback.(*ScanSource)
	if !fallbackOK || developmentSource.fetcher != fetcher || developmentFallback.fetcher != fetcher || developmentSource.requireBundle {
		t.Fatalf("development source = %#v, want preferred bundles with bounded raw fallback", development.source)
	}
	if development.checkpointStore != store || development.policy.MaxCheckpointAge != managedVerificationFreshness || developmentSource.trust.MaxCheckpointAge != managedVerificationFreshness || developmentSource.trust.MaxBundleLifetime != managedVerificationFreshness || developmentSource.trust.TrustedCheckpointStore != store {
		t.Fatal("development reader does not use managed freshness and shared checkpoint store")
	}

	production := verificationClient(t, registry, "c2sp-tlog:public:https://log.dnsid.ai#EREREREREREREREREREREQ")
	productionSource, ok := production.source.(*fetchedStreamBundleSource)
	if !ok {
		t.Fatalf("production source = %#v, want preferred bundles with bounded raw fallback", production.source)
	}
	productionFallback, fallbackOK := productionSource.fallback.(*ScanSource)
	if !fallbackOK || productionSource.fetcher != fetcher || productionFallback.fetcher != fetcher || productionSource.requireBundle {
		t.Fatalf("production source = %#v, want preferred bundles with bounded raw fallback", production.source)
	}
	if production.checkpointStore != store || production.policy.MaxCheckpointAge != managedVerificationFreshness || productionSource.trust.MaxCheckpointAge != managedVerificationFreshness || productionSource.trust.MaxBundleLifetime != managedVerificationFreshness || productionSource.trust.TrustedCheckpointStore != store {
		t.Fatal("production reader does not use managed freshness and shared checkpoint store")
	}

	partners := verificationClient(t, registry, "c2sp-tlog:public:https://log.partners.dnsid.ai#EREREREREREREREREREREQ")
	partnersSource, ok := partners.source.(*fetchedStreamBundleSource)
	if !ok {
		t.Fatalf("partners source = %#v, want preferred bundles with bounded raw fallback", partners.source)
	}
	partnersFallback, fallbackOK := partnersSource.fallback.(*ScanSource)
	if !fallbackOK || partnersSource.fetcher != fetcher || partnersFallback.fetcher != fetcher || partnersSource.requireBundle {
		t.Fatalf("partners source = %#v, want preferred bundles with bounded raw fallback", partners.source)
	}
	if partners.checkpointStore != store || partners.policy.MaxCheckpointAge != managedVerificationFreshness || partnersSource.trust.MaxCheckpointAge != managedVerificationFreshness || partnersSource.trust.MaxBundleLifetime != managedVerificationFreshness || partnersSource.trust.TrustedCheckpointStore != store {
		t.Fatal("partners reader does not use managed freshness and shared checkpoint store")
	}
	if partners.policy.LogVerifier == nil || partners.policy.LogVerifier.Name() != "log.partners.dnsid.ai" || partners.policy.LogVerifier.KeyHash() != 0xf0143e09 {
		t.Fatal("partners reader does not use the pinned partner log key")
	}
}

func TestDnsidManagedVerificationRegistryRejectsUnknownAndNoncanonicalSelectors(t *testing.T) {
	registry, err := NewDnsidManagedVerificationRegistry(context.Background(), DnsidManagedVerificationConfig{
		ResourceFetcher: &testBoundedFetcher{},
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, lr := range []string{
		"c2sp-tlog:testnet:https://log.dev.dnsid.ai#EREREREREREREREREREREQ",
		"c2sp-tlog:public:https://log.example#EREREREREREREREREREREQ",
		"c2sp-tlog:public:https://log.dnsid.dev#EREREREREREREREREREREQ",
		"c2sp-tlog:public:https://log.dev.dnsid.ai.attacker.example#EREREREREREREREREREREQ",
		"c2sp-tlog:public:https://log.dev.dnsid.ai/#EREREREREREREREREREREQ",
		"c2sp-tlog:public:https://log.dev.dnsid.ai",
		"c2sp-tlog:testnet:https://log.partners.dnsid.ai#EREREREREREREREREREREQ",
		"c2sp-tlog:public:https://log.partners.dnsid.ai.attacker.example#EREREREREREREREREREREQ",
		"c2sp-tlog:public:https://partners.dnsid.ai#EREREREREREREREREREREQ",
	} {
		reader, err := registry.NewReader(lr)
		if err != nil {
			t.Fatalf("NewReader(%q): %v", lr, err)
		}
		if _, ok := reader.(errorReader); !ok {
			t.Errorf("NewReader(%q) = %T, want fail-closed error reader", lr, reader)
		}
	}
}

func TestDnsidManagedVerificationRegistryValidatesCatalog(t *testing.T) {
	development := dnsidManagedTrustCatalog[0]
	for _, test := range []struct {
		name    string
		catalog []managedTrustEntry
	}{
		{name: "duplicate selector", catalog: []managedTrustEntry{development, development}},
		{name: "profile selector mismatch", catalog: []managedTrustEntry{{scope: "public", logPrefix: "https://log.dnsid.ai", trustProfileDocument: managedDevelopmentProfile}}},
		{name: "policy selector mismatch", catalog: []managedTrustEntry{{scope: "public", logPrefix: "https://log.dev.dnsid.ai", policyDocument: expectedManagedProductionPolicy}}},
		{name: "multiple trust documents", catalog: []managedTrustEntry{{scope: "public", logPrefix: "https://log.dev.dnsid.ai", trustProfileDocument: managedDevelopmentProfile, policyDocument: expectedManagedProductionPolicy}}},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, err := newDnsidManagedVerificationRegistry(context.Background(), DnsidManagedVerificationConfig{
				ResourceFetcher: &testBoundedFetcher{},
			}, test.catalog)
			if err == nil {
				t.Fatal("managed registry accepted invalid catalog")
			}
		})
	}
}

func TestDnsidManagedVerificationRegistry_HonorsTransport(t *testing.T) {
	transport := dnsid.TransportConfig{CABundlePath: filepath.Join(t.TempDir(), "missing.pem")}
	if _, err := NewDnsidManagedVerificationRegistry(context.Background(), DnsidManagedVerificationConfig{Transport: transport}); err == nil {
		t.Fatal("deployment transport ignored")
	}
	if _, err := NewDnsidManagedVerificationRegistry(context.Background(), DnsidManagedVerificationConfig{Transport: transport, ResourceFetcher: &testBoundedFetcher{}}); err != nil {
		t.Fatal("explicit fetcher should override SDK transport:", err)
	}
}
