package c2sptlog

import (
	"context"
	"encoding/json"
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
	// expectedManagedDevelopmentOverflowBundleVerifierKey signs dev bundles over the
	// 4096-byte KMS limit (Identity-Digital/dnsid#3286).
	expectedManagedDevelopmentOverflowBundleVerifierKey = "dnsid-stream-bundle+62f7f9fa+ATdOWF5P759HgvDod9mIC0r1nXhTtJ7x1Ws0fjTvqwDV"
	expectedManagedProductionPolicy                     = `log log.dnsid.ai+f10a26bc+Aeo6u4o1XvQlcRczgY462ZdIGpm/ejBC2G3vSbyYYqqY
witness dnsid-witness-1 witness.dnsid.ai/w1+706fd4fb+BLqX21Sx9xG5+5vK7kSK5omcu9+2il20PLdfpOp8lQOJ
quorum dnsid-witness-1
`
	expectedManagedProductionBundleVerifierKey = "dnsid-stream-bundle+2e77a3f1+AbKj/zrAfK04/NM07Zj7kxP2YXbM5neT8ym6juXC2PXG"
	// expectedManagedProductionOverflowBundleVerifierKey signs production bundles over the
	// 4096-byte KMS limit (Identity-Digital/dnsid#3286).
	expectedManagedProductionOverflowBundleVerifierKey = "dnsid-stream-bundle+0f5a76a0+AXavEa0+EGj/qZFH4QuAOeomigSukspWQHC7PrVJa7pj"
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
	if profile.PolicyDocument != expectedManagedDevelopmentPolicy || len(profile.BundleVerifierKeys) != 2 || profile.BundleVerifierKeys[0] != expectedManagedDevelopmentBundleVerifierKey || profile.BundleVerifierKeys[1] != expectedManagedDevelopmentOverflowBundleVerifierKey {
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
	if len(profile.BundleVerifierKeys) != 2 || profile.BundleVerifierKeys[0] != expectedManagedProductionBundleVerifierKey || profile.BundleVerifierKeys[1] != expectedManagedProductionOverflowBundleVerifierKey {
		t.Fatalf("production bundle verifier keys = %#v", profile.BundleVerifierKeys)
	}
}

const (
	expectedManagedPartnersPolicy = `log log.partners.dnsid.ai+f0143e09+Ae5vrTVQUr0h2GKbeHq70ml37N+uVBsU4NpZD4qMqAu1
witness dnsid-witness-1 witness.partners.dnsid.ai/w1+a115eb67+BB0avWVeSelUBk2w8FtTbT+orf2i826q9VemA0jaXxg4
quorum dnsid-witness-1
`
	expectedManagedPartnersBundleVerifierKey = "dnsid-stream-bundle+b1e0b597+AQt9ol4cfwPHxdH4NHNRidsAvU2bYE7KVItOlBG/bsaZ"
	// expectedManagedPartnersOverflowBundleVerifierKey signs partner bundles over the
	// 4096-byte KMS limit (Identity-Digital/dnsid#3286).
	expectedManagedPartnersOverflowBundleVerifierKey = "dnsid-stream-bundle+bc0d8136+AVfizbWWQD+s2N7OfpOeP7IaWF8nAeTqT4JpD03vKqc6"
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
	if len(profile.BundleVerifierKeys) != 2 || profile.BundleVerifierKeys[0] != expectedManagedPartnersBundleVerifierKey || profile.BundleVerifierKeys[1] != expectedManagedPartnersOverflowBundleVerifierKey {
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
		"c2sp-tlog:testnet:https://log.stg.dnsid.ai#EREREREREREREREREREREQ",
		"c2sp-tlog:public:https://log.stg.dnsid.ai.attacker.example#EREREREREREREREREREREQ",
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

// Reviewed service fixtures from Identity-Digital/dnsid#3286, captured
// 2026-11-10. The dev log signs a bundle of at most 4096 signed bytes with its
// KMS key and a larger one with a secret-held key, so the pinned development
// profile must accept both: a two-event stream signed by the KMS key and a
// three-event stream (issuance, key rotation, revocation) signed by the
// secret-held key. Each verifies at a clock just inside its expiry.
func TestManagedDevelopmentProfileVerifiesBundlesFromBothBundleKeys(t *testing.T) {
	profile, err := ParseTrustProfile([]byte(managedDevelopmentProfile))
	if err != nil {
		t.Fatal(err)
	}
	verifiers, err := profile.validate()
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		fixture, kid string
		events       int
	}{
		{"c2sp-dev-stream-bundle-kms-key.json", "dnsid-stream-bundle+0c241174", 2},
		{"c2sp-dev-stream-bundle-overflow-key.json", "dnsid-stream-bundle+62f7f9fa", 3},
	} {
		t.Run(tc.kid, func(t *testing.T) {
			data, err := os.ReadFile(filepath.Join("testdata", tc.fixture))
			if err != nil {
				t.Fatal(err)
			}
			var bundle struct {
				Expires int64 `json:"expires"`
				Sig     struct {
					Kid string `json:"kid"`
				} `json:"sig"`
			}
			if err := json.Unmarshal(data, &bundle); err != nil {
				t.Fatal(err)
			}
			if bundle.Sig.Kid != tc.kid {
				t.Fatalf("fixture kid = %q, want %q", bundle.Sig.Kid, tc.kid)
			}
			verified, err := VerifyStreamBundle(context.Background(), data, StreamBundleTrust{
				PolicyDocument:    []byte(profile.PolicyDocument),
				BundleVerifiers:   verifiers,
				Now:               func() time.Time { return time.Unix(bundle.Expires-60, 0) },
				MaxBundleLifetime: managedVerificationFreshness,
			})
			if err != nil {
				t.Fatalf("pinned development profile rejects a %s-signed stream bundle: %v", tc.kid, err)
			}
			if verified.Reference.LogPrefix != "https://log.dev.dnsid.ai" || verified.LoggedState != "REVOKED" || len(verified.Events) != tc.events || verified.SignerKeyID != tc.kid {
				t.Fatalf("unexpected development bundle: %s %s, %d events, signer %q", verified.Reference.LogPrefix, verified.LoggedState, len(verified.Events), verified.SignerKeyID)
			}
		})
	}
}

const (
	expectedManagedStagingPolicy = `log log.stg.dnsid.ai+f6ad3bd8+ARl6baGOUzNIH2QvsnlqA8C71WM4SYecXE7eAwmytAsL
witness dnsid-witness-1 witness.stg.dnsid.ai/w1+11a84cde+BEKB6hwsWXOm+PMnS7/JvO4i6bazjzJ8ojECphOTB3gt
quorum dnsid-witness-1
`
	expectedManagedStagingBundleVerifierKey = "dnsid-stream-bundle+65c31b14+AXCMTPR4I/fqOgSHge4AEMp+1pWcflDqC1YEDaHDe3Ps"
	// expectedManagedStagingOverflowBundleVerifierKey signs staging bundles over the
	// 4096-byte KMS limit (Identity-Digital/dnsid#3286).
	expectedManagedStagingOverflowBundleVerifierKey = "dnsid-stream-bundle+cdd64875+ATu1SYXvRiZPBUzrUJAfKHeMH3eHr3T22jKez/C3Yl1m"
)

func TestManagedStagingCatalogEntryIsReviewedTrustProfile(t *testing.T) {
	entry := dnsidManagedTrustCatalog[3]
	if entry.scope != "public" || entry.logPrefix != "https://log.stg.dnsid.ai" || entry.trustProfileDocument == "" || entry.policyDocument != "" {
		t.Fatalf("staging catalog entry = %#v, want exact trust-profile selector", entry)
	}
	profile, err := ParseTrustProfile([]byte(entry.trustProfileDocument))
	if err != nil {
		t.Fatalf("ParseTrustProfile: %v", err)
	}
	if profile.Version != 1 || profile.Scope != entry.scope || profile.LogPrefix != entry.logPrefix {
		t.Fatalf("staging profile selector = v%d %q %q", profile.Version, profile.Scope, profile.LogPrefix)
	}
	if profile.PolicyDocument != expectedManagedStagingPolicy {
		t.Fatalf("staging policy = %q, want %q", profile.PolicyDocument, expectedManagedStagingPolicy)
	}
	if len(profile.BundleVerifierKeys) != 2 || profile.BundleVerifierKeys[0] != expectedManagedStagingBundleVerifierKey || profile.BundleVerifierKeys[1] != expectedManagedStagingOverflowBundleVerifierKey {
		t.Fatalf("staging bundle verifier keys = %#v", profile.BundleVerifierKeys)
	}
}

func TestNewDnsidManagedVerificationRegistrySelectsStagingEntry(t *testing.T) {
	fetcher := &testBoundedFetcher{}
	store := NewMemoryTrustedC2spCheckpointStore()
	registry, err := NewDnsidManagedVerificationRegistry(context.Background(), DnsidManagedVerificationConfig{
		ResourceFetcher:        fetcher,
		TrustedCheckpointStore: store,
	})
	if err != nil {
		t.Fatal(err)
	}
	staging := verificationClient(t, registry, "c2sp-tlog:public:https://log.stg.dnsid.ai#EREREREREREREREREREREQ")
	stagingSource, ok := staging.source.(*fetchedStreamBundleSource)
	if !ok || stagingSource.fetcher != fetcher || stagingSource.requireBundle {
		t.Fatalf("staging source = %#v, want preferred bundles with bounded raw fallback", staging.source)
	}
	if staging.checkpointStore != store || staging.policy.MaxCheckpointAge != managedVerificationFreshness || stagingSource.trust.MaxBundleLifetime != managedVerificationFreshness {
		t.Fatal("staging reader does not use managed freshness and shared checkpoint store")
	}
	if staging.policy.LogVerifier == nil || staging.policy.LogVerifier.Name() != "log.stg.dnsid.ai" || staging.policy.LogVerifier.KeyHash() != 0xf6ad3bd8 {
		t.Fatal("staging reader does not use the pinned staging log key")
	}
}

// Reviewed service fixtures captured from log.stg.dnsid.ai on 2026-11-11
// (Identity-Digital/dnsid#3286): a one-event stream small enough for the KMS
// bundle key and a three-event stream (issuance, key rotation, revocation)
// over the 4096-byte KMS limit, signed by the secret-held key. Each verifies at
// a clock just inside its expiry with only the key its kid names.
func TestManagedStagingProfileVerifiesBundlesFromBothBundleKeys(t *testing.T) {
	profile, err := ParseTrustProfile([]byte(managedStagingProfile))
	if err != nil {
		t.Fatal(err)
	}
	verifiers, err := profile.validate()
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		fixture, kid, state string
		events              int
	}{
		{"c2sp-staging-stream-bundle-kms-key.json", "dnsid-stream-bundle+65c31b14", "ACTIVE", 1},
		{"c2sp-staging-stream-bundle-overflow-key.json", "dnsid-stream-bundle+cdd64875", "REVOKED", 3},
	} {
		t.Run(tc.kid, func(t *testing.T) {
			data, err := os.ReadFile(filepath.Join("testdata", tc.fixture))
			if err != nil {
				t.Fatal(err)
			}
			var bundle struct {
				Expires int64 `json:"expires"`
				Sig     struct {
					Kid string `json:"kid"`
				} `json:"sig"`
			}
			if err := json.Unmarshal(data, &bundle); err != nil {
				t.Fatal(err)
			}
			if bundle.Sig.Kid != tc.kid {
				t.Fatalf("fixture kid = %q, want %q", bundle.Sig.Kid, tc.kid)
			}
			verified, err := VerifyStreamBundle(context.Background(), data, StreamBundleTrust{
				PolicyDocument:    []byte(profile.PolicyDocument),
				BundleVerifiers:   verifiers,
				Now:               func() time.Time { return time.Unix(bundle.Expires-60, 0) },
				MaxBundleLifetime: managedVerificationFreshness,
			})
			if err != nil {
				t.Fatalf("pinned staging profile rejects a %s-signed stream bundle: %v", tc.kid, err)
			}
			if verified.Reference.LogPrefix != "https://log.stg.dnsid.ai" || verified.LoggedState != tc.state || len(verified.Events) != tc.events || verified.SignerKeyID != tc.kid {
				t.Fatalf("unexpected staging bundle: %s %s, %d events, signer %q", verified.Reference.LogPrefix, verified.LoggedState, len(verified.Events), verified.SignerKeyID)
			}
		})
	}
}
