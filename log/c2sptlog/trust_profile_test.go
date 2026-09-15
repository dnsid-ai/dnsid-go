package c2sptlog

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	dnsid "github.com/dnsid-ai/dnsid-go"
	"golang.org/x/mod/sumdb/note"
)

func TestTrustProfileConfiguresRotationKeysAndExactLog(t *testing.T) {
	keys := make([]string, 2)
	for i := range keys {
		_, key, err := note.GenerateKey(rand.Reader, "dnsid-stream-bundle")
		if err != nil {
			t.Fatal(err)
		}
		keys[i] = key
	}
	raw, err := json.Marshal(TrustProfile{
		Version:            1,
		Scope:              "testnet",
		LogPrefix:          "https://tlog.example/log",
		PolicyDocument:     string(verificationPolicyDocument(t)),
		BundleVerifierKeys: keys,
	})
	if err != nil {
		t.Fatal(err)
	}
	profile, err := ParseTrustProfile(raw)
	if err != nil {
		t.Fatalf("ParseTrustProfile: %v", err)
	}
	registry, err := NewVerificationRegistry(context.Background(), VerificationRegistryConfig{
		TrustProfile:      &profile,
		MaxBundleLifetime: time.Minute,
	})
	if err != nil {
		t.Fatalf("NewVerificationRegistry: %v", err)
	}
	client := verificationClient(t, registry, "c2sp-tlog:testnet:https://tlog.example/log#identity-01")
	source, ok := client.source.(*fetchedStreamBundleSource)
	if !ok || len(source.trust.BundleVerifiers) != 2 {
		t.Fatalf("source = %#v, want two trusted bundle verifiers", client.source)
	}
	reader, err := registry.NewReader("c2sp-tlog:testnet:https://other.example/log#identity-01")
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := reader.(errorReader); !ok {
		t.Fatalf("mismatched reader = %T, want fail-closed error reader", reader)
	}
}

func TestParseTrustProfileRejectsInvalidDocuments(t *testing.T) {
	_, bundleKey, err := note.GenerateKey(rand.Reader, "dnsid-stream-bundle")
	if err != nil {
		t.Fatal(err)
	}
	valid := TrustProfile{
		Version:            1,
		Scope:              "testnet",
		LogPrefix:          "https://tlog.example/log",
		PolicyDocument:     string(verificationPolicyDocument(t)),
		BundleVerifierKeys: []string{bundleKey},
	}
	publicKey, err := signedNotePublicKey(bundleKey)
	if err != nil {
		t.Fatal(err)
	}
	overlappingLogKey, err := note.NewEd25519VerifierKey("tlog.example/log", ed25519.PublicKey(publicKey))
	if err != nil {
		t.Fatal(err)
	}
	marshal := func(profile TrustProfile) []byte {
		data, err := json.Marshal(profile)
		if err != nil {
			t.Fatal(err)
		}
		return data
	}
	tests := map[string][]byte{
		"unknown member":      []byte(`{"version":1,"scope":"testnet","log_prefix":"https://tlog.example/log","tlog_policy":"x","bundle_verifier_keys":[],"extra":true}`),
		"duplicate member":    []byte(`{"version":1,"version":1,"scope":"testnet","log_prefix":"https://tlog.example/log","tlog_policy":"x","bundle_verifier_keys":[]}`),
		"unsupported version": marshal(func() TrustProfile { p := valid; p.Version = 2; return p }()),
		"noncanonical prefix": marshal(func() TrustProfile { p := valid; p.LogPrefix += "/"; return p }()),
		"policy mismatch":     marshal(func() TrustProfile { p := valid; p.LogPrefix = "https://other.example/log"; return p }()),
		"invalid bundle key":  marshal(func() TrustProfile { p := valid; p.BundleVerifierKeys = []string{"bad"}; return p }()),
		"wrong bundle key name": marshal(func() TrustProfile {
			p := valid
			_, key, keyErr := note.GenerateKey(rand.Reader, "other")
			if keyErr != nil {
				t.Fatal(keyErr)
			}
			p.BundleVerifierKeys = []string{key}
			return p
		}()),
		"duplicate bundle key": marshal(func() TrustProfile { p := valid; p.BundleVerifierKeys = []string{bundleKey, bundleKey}; return p }()),
		"checkpoint key overlap": marshal(func() TrustProfile {
			p := valid
			p.PolicyDocument = fmt.Sprintf("log %s\nquorum none\n", overlappingLogKey)
			return p
		}()),
	}
	for name, data := range tests {
		t.Run(name, func(t *testing.T) {
			_, err := ParseTrustProfile(data)
			var parseErr *dnsid.ParseError
			if !errors.As(err, &parseErr) {
				t.Fatalf("error = %T %v, want *dnsid.ParseError", err, err)
			}
		})
	}
}

func TestVerificationRegistryRejectsTrustProfileMixedWithDirectTrust(t *testing.T) {
	profile := &TrustProfile{}
	_, err := NewVerificationRegistry(context.Background(), VerificationRegistryConfig{
		TrustProfile:   profile,
		PolicyDocument: []byte("policy"),
	})
	if err == nil || !strings.Contains(err.Error(), "mutually exclusive") {
		t.Fatalf("error = %v, want mutually exclusive trust error", err)
	}
}
