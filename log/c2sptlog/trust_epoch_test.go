package c2sptlog

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	dnsid "github.com/dnsid-ai/dnsid-go"
	"golang.org/x/mod/sumdb/note"
)

func epochTestProfile(t *testing.T, name string) TrustProfile {
	t.Helper()
	vectors := buildTrustEpochVectors(t)
	profile, err := ParseTrustProfile([]byte(vectors.Profiles[name]))
	if err != nil {
		t.Fatal(err)
	}
	return profile
}

func TestNewVerificationRegistry_V2ProfileInstallsEpochs(t *testing.T) {
	profile := epochTestProfile(t, "v2-bounded")
	registry, err := NewVerificationRegistry(context.Background(), VerificationRegistryConfig{
		TrustProfile:      &profile,
		ResourceFetcher:   &testBoundedFetcher{},
		MaxBundleLifetime: time.Minute,
	})
	if err != nil {
		t.Fatalf("NewVerificationRegistry: %v", err)
	}
	client := verificationClient(t, registry, "c2sp-tlog:public:https://log.example#EREREREREREREREREREREQ")
	if len(client.policy.epochs) != 2 || client.policy.LogVerifier != nil {
		t.Fatalf("policy epochs = %d, log verifier = %v; want an epoch set", len(client.policy.epochs), client.policy.LogVerifier)
	}
	source, ok := client.source.(*fetchedStreamBundleSource)
	if !ok {
		t.Fatalf("source = %T", client.source)
	}
	if len(source.trust.Epochs) != 2 || source.trust.PolicyDocument != nil || len(source.trust.BundleVerifiers) != 0 {
		t.Fatalf("bundle trust = %+v, want epochs only", source.trust)
	}
	if source.trust.Epochs[0].MaxTreeSize != trustEpochVectorN || source.trust.Epochs[1].MinTreeSize != trustEpochVectorN {
		t.Fatalf("epoch bounds = %+v", source.trust.Epochs)
	}
	if _, ok := source.fallback.(*ScanSource); !ok {
		t.Fatalf("fallback = %T, want raw scanner over the epoch set", source.fallback)
	}
}

func TestNewVerificationRegistry_V1ProfileKeepsSinglePolicyPath(t *testing.T) {
	profile := epochTestProfile(t, "v1-legacy")
	registry, err := NewVerificationRegistry(context.Background(), VerificationRegistryConfig{
		TrustProfile:      &profile,
		ResourceFetcher:   &testBoundedFetcher{},
		MaxBundleLifetime: time.Minute,
	})
	if err != nil {
		t.Fatalf("NewVerificationRegistry: %v", err)
	}
	client := verificationClient(t, registry, "c2sp-tlog:public:https://log.example#EREREREREREREREREREREQ")
	if len(client.policy.epochs) != 0 || client.policy.LogVerifier == nil {
		t.Fatalf("v1 policy became an epoch set")
	}
	source := client.source.(*fetchedStreamBundleSource)
	if len(source.trust.Epochs) != 0 || string(source.trust.PolicyDocument) != profile.PolicyDocument || len(source.trust.BundleVerifiers) != 1 {
		t.Fatalf("v1 bundle trust = %+v", source.trust)
	}
}

func TestTrustProfile_V1MarshalIsUnchanged(t *testing.T) {
	profile := epochTestProfile(t, "v1-legacy")
	data, err := json.Marshal(profile)
	if err != nil {
		t.Fatal(err)
	}
	var members map[string]any
	if err := json.Unmarshal(data, &members); err != nil {
		t.Fatal(err)
	}
	if len(members) != 5 || members["epochs"] != nil {
		t.Fatalf("v1 marshal = %s", data)
	}
	epochs, err := profile.TrustEpochs()
	if err != nil || len(epochs) != 1 || epochs[0].ID != "" || epochs[0].MinTreeSize != 0 || epochs[0].MaxTreeSize != 0 {
		t.Fatalf("v1 TrustEpochs = %+v, %v", epochs, err)
	}
}

func TestTrustProfile_TrustEpochsRejectsInvalidStruct(t *testing.T) {
	profile := epochTestProfile(t, "v2-open")
	profile.PolicyDocument = profile.Epochs[0].PolicyDocument
	var argErr *dnsid.ArgumentError
	if _, err := profile.TrustEpochs(); !errors.As(err, &argErr) {
		t.Fatalf("error = %v, want argument error", err)
	}
}

func TestNewEpochPolicy_RejectsInvalidEpochSets(t *testing.T) {
	profile := epochTestProfile(t, "v2-open")
	epochs, err := profile.TrustEpochs()
	if err != nil {
		t.Fatal(err)
	}
	otherKey := newEpochLogKey(t, "other.example", 0x61)
	mismatched := append([]TrustEpoch(nil), epochs...)
	mismatched[1].PolicyDocument = []byte("log " + otherKey.vkey + "\nquorum none\n")
	tests := map[string][]TrustEpoch{
		"empty":           nil,
		"origin mismatch": mismatched,
		"duplicate id":    {epochs[0], {ID: epochs[0].ID, PolicyDocument: epochs[1].PolicyDocument, BundleVerifiers: epochs[1].BundleVerifiers}},
		"bounds reversed": {{ID: "a", PolicyDocument: epochs[0].PolicyDocument, MinTreeSize: 9, MaxTreeSize: 3}},
		"invalid policy":  {{ID: "a", PolicyDocument: []byte("quorum none\n")}},
	}
	for name, set := range tests {
		t.Run(name, func(t *testing.T) {
			var argErr *dnsid.ArgumentError
			if _, err := NewEpochPolicy(set); !errors.As(err, &argErr) {
				t.Fatalf("error = %v, want argument error", err)
			}
		})
	}
	policy, err := NewEpochPolicy(epochs)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewScanSource(policy, ScanSourceConfig{ResourceFetcher: &testBoundedFetcher{}}); err != nil {
		t.Fatalf("NewScanSource(epoch policy): %v", err)
	}
}

func TestVerifyStreamBundle_EpochsExcludeSinglePolicyTrust(t *testing.T) {
	vectors := buildTrustEpochVectors(t)
	profile := epochTestProfile(t, "v2-open")
	epochs, err := profile.TrustEpochs()
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := note.NewVerifier(vectors.Keys["legacy_bundle"])
	if err != nil {
		t.Fatal(err)
	}
	for name, trust := range map[string]StreamBundleTrust{
		"policy document":  {Epochs: epochs, PolicyDocument: epochs[0].PolicyDocument},
		"bundle verifier":  {Epochs: epochs, BundleVerifier: verifier},
		"bundle verifiers": {Epochs: epochs, BundleVerifiers: []note.Verifier{verifier}},
	} {
		t.Run(name, func(t *testing.T) {
			trust.MaxBundleLifetime = time.Minute
			_, err := VerifyStreamBundle(context.Background(), []byte(vectors.BundleCases[0].Bundle), trust)
			if err == nil || !strings.Contains(err.Error(), "mutually exclusive") {
				t.Fatalf("error = %v, want mutually exclusive", err)
			}
		})
	}
}

func TestVerifyStreamBundle_SharedBundleKeySelectsEpochByPolicyHash(t *testing.T) {
	vectors := buildTrustEpochVectors(t)
	profile := epochTestProfile(t, "v2-open")
	epochs, err := profile.TrustEpochs()
	if err != nil {
		t.Fatal(err)
	}
	// The successor epoch also accepts the legacy bundle key; a legacy bundle
	// must still resolve to the legacy epoch through its policy hash.
	epochs[1].BundleVerifiers = append(epochs[1].BundleVerifiers, epochs[0].BundleVerifiers...)
	epochs[0], epochs[1] = epochs[1], epochs[0]
	var bundle string
	for _, tc := range vectors.BundleCases {
		if tc.Name == "bundle-legacy-epoch-at-n" {
			bundle = tc.Bundle
		}
	}
	verified, err := VerifyStreamBundle(context.Background(), []byte(bundle), StreamBundleTrust{
		Epochs:            epochs,
		Now:               func() time.Time { return time.Unix(trustEpochVectorNow, 0) },
		MaxBundleLifetime: trustEpochVectorLifetime * time.Second,
		MaxCheckpointAge:  trustEpochVectorMaxAge * time.Second,
	})
	if err != nil {
		t.Fatalf("VerifyStreamBundle: %v", err)
	}
	if verified.TrustEpoch != trustEpochLegacyID {
		t.Fatalf("epoch = %q, want %q", verified.TrustEpoch, trustEpochLegacyID)
	}
}
