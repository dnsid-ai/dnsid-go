package config

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	dnsid "github.com/dnsid-ai/dnsid-go"
	"github.com/lestrrat-go/jwx/v3/jwk"
)

type constructionOwnedKey struct {
	dnsid.KeyProvider
	closes int
}

func (p *constructionOwnedKey) Close() error { p.closes++; return nil }

type cleanupPublicationDNS struct {
	calls int
	err   error
}

func (d *cleanupPublicationDNS) FetchTXT(context.Context, string) ([]dnsid.TXTRecordRData, dnsid.DNSSECState, error) {
	d.calls++
	return nil, dnsid.DNSSECStateUnsigned, d.err
}

// Mode: fake-only (close-counting provider and publication I/O; real constructor,
// owner signatures and publication verification).
// construction owns selected providers on failure, not caller-injected ones.
func TestConstruct_OperationalProviderOwnership(t *testing.T) {
	cfg := dnsid.Config{Identity: &dnsid.IdentityConfig{Domain: "agent.example.com", GovernanceID: "example.com", LogRef: "algorand:ADDR", StatusURL: "https://agent.example.com/status.json", KeyURL: "https://agent.example.com/ku.json", EntityKeyURL: "https://example.com/ek.json", PolicyFlags: []dnsid.PolicyFlag{"logchk"}}}
	// Preserve existing test registrations; registration is process-global.
	keyFactories.Lock()
	previous, existed := keyFactories.values["google-kms"]
	keyFactories.Unlock()
	t.Cleanup(func() {
		keyFactories.Lock()
		defer keyFactories.Unlock()
		if existed {
			keyFactories.values["google-kms"] = previous
		} else {
			delete(keyFactories.values, "google-kms")
		}
	})
	for _, scenario := range []string{"publication failure", "binding failure", "success", "selected later failure", "injected later failure", "injected success"} {
		t.Run(scenario, func(t *testing.T) {
			keyFactories.Lock()
			delete(keyFactories.values, "google-kms")
			keyFactories.Unlock()
			// Given independently established publication A and a closeable provider.
			a := dnsid.GenerateEd25519KeyProvider()
			provider := &constructionOwnedKey{KeyProvider: a}
			if scenario == "binding failure" {
				provider.KeyProvider = dnsid.GenerateEd25519KeyProvider()
			}
			deps := setupPublication(t, cfg, a)
			deps.EntityKeyProvider = dnsid.GenerateES256KeyProvider()
			opens := 0
			RegisterKeyProviderFactory("google-kms", KeyProviderFactory{Validate: func(KeySource) error { return nil }, Open: func(context.Context, KeySource, string) (dnsid.KeyProvider, error) { opens++; return provider, nil }})
			loaded := Loaded{Dnsid: cfg, KeySource: KeySource{Provider: "google-kms", KeyRef: "fixture-existing-key"}}
			publicationErr := errors.New("fixture publication unavailable")
			failedDNS := &cleanupPublicationDNS{err: publicationErr}
			if scenario == "publication failure" {
				deps.DNSResolver = failedDNS
			}
			laterFailure := scenario == "selected later failure" || scenario == "injected later failure"
			injected := scenario == "injected later failure" || scenario == "injected success"
			if laterFailure {
				deps.EntityKeyProvider = nil
				loaded.KeySource.EntityKeyPath = filepath.Join(t.TempDir(), "missing-entity.jwk")
			}
			if injected {
				deps.KeyProvider = provider
			}
			// When configuration constructs (and, for selected custody, binds) the manager.
			m, err := Construct(context.Background(), loaded, deps)
			wantFailure := scenario == "publication failure" || scenario == "binding failure" || laterFailure
			if wantFailure {
				if err == nil || m != nil {
					t.Fatalf("want nil manager and construction error: manager=%v err=%v", m != nil, err)
				}
				if scenario == "publication failure" && (failedDNS.calls == 0 || !errors.Is(err, publicationErr)) {
					t.Fatalf("wrong failure; DNS calls=%d err=%v", failedDNS.calls, err)
				}
				if scenario == "binding failure" {
					if !strings.Contains(err.Error(), "configured operational key does not match verified local publication") {
						t.Fatalf("not publication binding failure: %v", err)
					}
				}
				if laterFailure && !errors.Is(err, os.ErrNotExist) {
					t.Fatalf("not entity-file construction failure: %v", err)
				}
			} else {
				if err != nil || m == nil || m.KeyProvider() != provider {
					t.Fatalf("successful construction lost selected provider: manager=%v err=%v", m != nil, err)
				}
				if _, err := m.KeyProvider().Sign([]byte("successful construction remains usable")); err != nil {
					t.Fatal(err)
				}
			}
			wantOpens := 1
			if injected {
				wantOpens = 0
			}
			if opens != wantOpens {
				t.Fatalf("factory opens=%d want %d", opens, wantOpens)
			}
			// Then release only failed construction-owned custody, exactly once.
			wantCloses := 0
			if wantFailure && !injected {
				wantCloses = 1
			}
			if provider.closes != wantCloses {
				t.Fatalf("provider Close calls=%d, want %d (scenario=%s)", provider.closes, wantCloses, scenario)
			}
		})
	}
}

// Mode: fake-only factory and publication transports; real private keys, owner
// signatures and publication verification. A stable kid is not material binding.
func TestConstruct_FactoryOperationalKeyMaterialBinding(t *testing.T) {
	const kid = "fixture-stable-operational-key"
	fixedKey := func(private any) dnsid.KeyProvider {
		t.Helper()
		key, err := jwk.Import(private)
		if err != nil {
			t.Fatal(err)
		}
		if err := key.Set(jwk.KeyIDKey, kid); err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(t.TempDir(), "key.json")
		writeJSON(t, path, key)
		provider, err := dnsid.NewLocalKeyProvider(path)
		if err != nil {
			t.Fatal(err)
		}
		return provider
	}
	_, privateA, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_, privateB, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	privateEC, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	a, b, ec := fixedKey(privateA), fixedKey(privateB), fixedKey(privateEC)
	cfg := dnsid.Config{Identity: &dnsid.IdentityConfig{Domain: "agent.example.com", GovernanceID: "example.com", LogRef: "algorand:ADDR", StatusURL: "https://agent.example.com/status.json", KeyURL: "https://agent.example.com/ku.json", EntityKeyURL: "https://example.com/ek.json", PolicyFlags: []dnsid.PolicyFlag{"logchk"}}}
	// Authenticate publication A independently of startup factory selection.
	deps := setupPublication(t, cfg, a)
	deps.EntityKeyProvider = dnsid.GenerateES256KeyProvider()
	keyFactories.Lock()
	previous, existed := keyFactories.values["google-kms"]
	keyFactories.Unlock()
	t.Cleanup(func() {
		keyFactories.Lock()
		defer keyFactories.Unlock()
		if existed {
			keyFactories.values["google-kms"] = previous
		} else {
			delete(keyFactories.values, "google-kms")
		}
	})
	// Both algorithms have valid profile keys. Different algorithms necessarily
	// differ in material too: this is not isolated algorithm-only mutation proof.
	for _, tc := range []struct {
		name   string
		key    dnsid.KeyProvider
		reject bool
	}{
		{"matching kid and material", a, false},
		{"same kid and algorithm different material", b, true},
		{"same kid different supported algorithm", ec, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			keyFactories.Lock()
			delete(keyFactories.values, "google-kms")
			keyFactories.Unlock()
			provider := &constructionOwnedKey{KeyProvider: tc.key}
			opens := 0
			RegisterKeyProviderFactory("google-kms", KeyProviderFactory{Validate: func(KeySource) error { return nil }, Open: func(context.Context, KeySource, string) (dnsid.KeyProvider, error) { opens++; return provider, nil }})
			// No deps.KeyProvider injection: exercise authenticated configured startup.
			m, err := Construct(context.Background(), Loaded{Dnsid: cfg, KeySource: KeySource{Provider: "google-kms", KeyRef: "fixture-existing-key"}}, deps)
			if opens != 1 {
				t.Fatalf("factory opens=%d want 1", opens)
			}
			if tc.reject {
				if m != nil || err == nil || !strings.Contains(err.Error(), "configured operational key does not match verified local publication") {
					t.Fatalf("want publication binding rejection, manager=%v err=%v", m != nil, err)
				}
				if provider.closes != 1 {
					t.Fatalf("failed selected provider closes=%d want 1", provider.closes)
				}
				return
			}
			if err != nil || m == nil || m.KeyProvider() != provider {
				t.Fatalf("matching provider lost: manager=%v err=%v", m != nil, err)
			}
			if provider.closes != 0 {
				t.Fatalf("successful selected provider closes=%d want 0", provider.closes)
			}
			if _, err := m.KeyProvider().Sign([]byte("matching fixed-kid payload")); err != nil {
				t.Fatal(err)
			}
		})
	}
}
