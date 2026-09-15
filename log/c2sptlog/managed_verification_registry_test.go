package c2sptlog

import (
	"context"
	"testing"
)

const (
	expectedManagedProductionPolicy = `log log.dnsid.ai+c4683585+AWZYC4OLE9KeRnpaI9xaHWwHUKoxgp/24ukzgVYlDwIt
witness dnsid-witness-1 witness.dnsid.ai/w1+b5ea211e+BH0nGTkjF4tYpkefsQhHNg0YagPvQ6H96Y3UBbXo7a/b
quorum dnsid-witness-1
`
	expectedManagedProductionBundleVerifierKey = "dnsid-stream-bundle+ee2b26d2+AWGLBe4LhJKumyDpH8VJ0vyATB081i1HseVeETu4TONR"
)

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

	development := verificationClient(t, registry, "c2sp-tlog:public:https://log.dnsid.dev#EREREREREREREREREREREQ")
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
}

func TestDnsidManagedVerificationRegistryRejectsUnknownAndNoncanonicalSelectors(t *testing.T) {
	registry, err := NewDnsidManagedVerificationRegistry(context.Background(), DnsidManagedVerificationConfig{
		ResourceFetcher: &testBoundedFetcher{},
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, lr := range []string{
		"c2sp-tlog:testnet:https://log.dnsid.dev#EREREREREREREREREREREQ",
		"c2sp-tlog:public:https://log.example#EREREREREREREREREREREQ",
		"c2sp-tlog:public:https://log.dnsid.dev.attacker.example#EREREREREREREREREREREQ",
		"c2sp-tlog:public:https://log.dnsid.dev/#EREREREREREREREREREREQ",
		"c2sp-tlog:public:https://log.dnsid.dev",
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
		{name: "policy selector mismatch", catalog: []managedTrustEntry{{scope: "public", logPrefix: "https://log.dnsid.dev", policyDocument: expectedManagedProductionPolicy}}},
		{name: "multiple trust documents", catalog: []managedTrustEntry{{scope: "public", logPrefix: "https://log.dnsid.dev", trustProfileDocument: managedDevelopmentProfile, policyDocument: expectedManagedProductionPolicy}}},
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
