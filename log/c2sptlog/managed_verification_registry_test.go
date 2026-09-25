package c2sptlog

import (
	"context"
	"testing"
)

const (
	expectedManagedDevelopmentPolicy = `log log.dev.dnsid.ai+cad12acd+Afnd3sdzfp8nCXzDQchrnWn9QOox5AglR147bURESRqu
witness dnsid-witness-1 witness.dev.dnsid.ai/w1+50822ded+BAH9KuulelD3yZBDTneG46gKZY+OWwdUPBmLmq/YjOkO
quorum dnsid-witness-1
`
	expectedManagedDevelopmentBundleVerifierKey = "dnsid-stream-bundle+0c241174+AeuT9PKyiewb9hkzygvki7UuOs5ly2kfY/C4Tfh7/ix0"
	expectedManagedProductionPolicy             = `log log.dnsid.ai+c4683585+AWZYC4OLE9KeRnpaI9xaHWwHUKoxgp/24ukzgVYlDwIt
witness dnsid-witness-1 witness.dnsid.ai/w1+b5ea211e+BH0nGTkjF4tYpkefsQhHNg0YagPvQ6H96Y3UBbXo7a/b
quorum dnsid-witness-1
`
	expectedManagedProductionBundleVerifierKey = "dnsid-stream-bundle+ee2b26d2+AWGLBe4LhJKumyDpH8VJ0vyATB081i1HseVeETu4TONR"
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
