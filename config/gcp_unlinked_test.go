package config_test

import (
	"context"
	"crypto/ed25519"
	"errors"
	"os"
	"strings"
	"testing"

	dnsid "github.com/dnsid-ai/dnsid-go"
	"github.com/dnsid-ai/dnsid-go/config"
	"github.com/lestrrat-go/jwx/v3/jwk"
)

const gcpVersion = "projects/test-project/locations/global/keyRings/agents/cryptoKeys/signing/cryptoKeyVersions/1"

// Mode: fake-only (provider deliberately unlinked).
// Given a selected but unlinked provider, When opening, Then an actionable
// ArgumentError is returned without file fallback.
func TestGCPUnlinkedProviderHasBuildRemedy(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	p, err := config.OperationalKeyProviderFrom(context.Background(), config.KeySource{Provider: "google-kms", KeyRef: gcpVersion}, "agent.example")
	var argument *dnsid.ArgumentError
	if p != nil || !errors.As(err, &argument) {
		t.Fatalf("provider=%v error=%v; want nil provider and ArgumentError", p, err)
	}
	message := strings.ToLower(err.Error())
	for _, part := range []string{"google-kms", "import", "rebuild"} {
		if !strings.Contains(message, part) {
			t.Errorf("error %q lacks actionable %q", message, part)
		}
	}
	entries, err := os.ReadDir(home)
	if err != nil || len(entries) != 0 {
		t.Fatalf("local fallback wrote files: entries=%v error=%v", entries, err)
	}
}

type injectedGCPKey struct {
	dnsid.KeyProvider
	key jwk.Key
}

func (p *injectedGCPKey) JWK(...string) jwk.Key { return p.key }
func (p *injectedGCPKey) ListKeyIds() []string  { return []string{"injected"} }

// Mode: fake-only (injected provider; displaced GCP selection unavailable).
// Given an injected provider and conflicting displaced source, When constructing,
// Then the exact injected provider wins without inspecting the source.
func TestGCPInjectionBypassesUnavailableSource(t *testing.T) {
	key, err := jwk.Import(ed25519.PublicKey(make([]byte, ed25519.PublicKeySize)))
	if err != nil {
		t.Fatal(err)
	}
	if err := key.Set("kid", "injected"); err != nil {
		t.Fatal(err)
	}
	if err := key.Set("alg", "EdDSA"); err != nil {
		t.Fatal(err)
	}
	injected := &injectedGCPKey{key: key}
	m, err := config.Construct(context.Background(), config.Loaded{
		Dnsid:     dnsid.Config{Identity: &dnsid.IdentityConfig{Domain: "agent.example", GovernanceID: "example", LogRef: "test:entry", StatusURL: "https://agent.example/status", KeyURL: "https://agent.example/jwks", EntityKeyURL: "https://example/jwks"}},
		KeySource: config.KeySource{Provider: "google-kms", KeyRef: "invalid-displaced-reference", CliDirectory: "must-not-read", Settings: map[string]string{"unknown": "ignored"}},
	}, config.Dependencies{KeyProvider: injected})
	if err != nil {
		t.Fatalf("injected provider must displace GCP selection: %v", err)
	}
	if m.KeyProvider() != injected {
		t.Fatal("constructor replaced injected provider")
	}
}
