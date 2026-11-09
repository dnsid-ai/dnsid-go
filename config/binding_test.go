package config_test

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"path/filepath"
	"testing"
	"time"

	dnsid "github.com/dnsid-ai/dnsid-go"
	"github.com/dnsid-ai/dnsid-go/config"
	dnsidlog "github.com/dnsid-ai/dnsid-go/log"
)

type consumerDNS struct{ record string }

func (d consumerDNS) FetchTXT(_ context.Context, name string) ([]dnsid.TXTRecordRData, dnsid.DNSSECState, error) {
	if name != "_dnsid.agent.example.com" {
		return nil, dnsid.DNSSECStateUnsigned, errors.New("unexpected DNS name")
	}
	return []dnsid.TXTRecordRData{{Value: d.record, TTL: time.Minute}}, dnsid.DNSSECStateUnsigned, nil
}

type consumerHTTP map[string]json.RawMessage

func (f consumerHTTP) FetchJSON(_ context.Context, url string, _ dnsid.FetchOptions) (json.RawMessage, *tls.Certificate, error) {
	b, ok := f[url]
	if !ok {
		return nil, nil, errors.New("unexpected publication URL: " + url)
	}
	return b, nil, nil
}

type consumerLog struct{}

func (*consumerLog) Canonical(dnsidlog.LogEvent) ([]byte, error) { return nil, nil }
func (*consumerLog) KeyTimestamp(context.Context, string, string) (time.Time, error) {
	return time.Now(), nil
}
func (*consumerLog) VerifyBilateralBinding(context.Context, dnsidlog.BilateralBindingInput) (dnsidlog.BilateralBinding, error) {
	return dnsidlog.BilateralBinding{}, nil
}
func (*consumerLog) VerifyOperationalContinuity(context.Context, string, string, string) error {
	return nil
}
func (*consumerLog) VerifyGovernanceRelationship(context.Context, string, string) error { return nil }
func (r *consumerLog) VerifyNonRevocation(context.Context, string, time.Time) (dnsidlog.LoggedStateEvidence, error) {
	return dnsidlog.LoggedStateEvidence{}, nil
}
func (*consumerLog) ReadEvent(context.Context, dnsidlog.LogRef) (dnsidlog.LogEvent, error) {
	return dnsidlog.LogEvent{}, nil
}
func (*consumerLog) RebuildHistory(context.Context, string) ([]dnsidlog.LogEvent, error) {
	return nil, nil
}

func publication(t *testing.T, m *dnsid.IdentityManager) (config.Dependencies, *consumerLog) {
	t.Helper()
	record, err := m.CreateTXTRecord()
	if err != nil {
		t.Fatal(err)
	}
	marshal := func(v any) json.RawMessage {
		b, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	reader := &consumerLog{}
	registry := dnsidlog.NewLogRegistry()
	if err := registry.Register("algorand", func(string) dnsidlog.LogReader { return reader }); err != nil {
		t.Fatal(err)
	}
	return config.Dependencies{DNSResolver: consumerDNS{record.Serialize()}, HTTPSFetcher: consumerHTTP{record.KeyURI: marshal(m.GetKeySet().Raw()), record.EntityKeyURI: marshal(m.GetEntityKeySet().Raw()), record.StatusURI: json.RawMessage(`{"state":"ACTIVE","lastTransitionAt":"` + time.Now().UTC().Format(time.RFC3339Nano) + `"}`)}, LogRegistry: registry}, reader
}

// Mode: fake-only (fixture DNS/HTTPS/log evidence, real file provider and core
// verification). Shared design 12: configuration cannot replace an established
// signer. Injected providers remain the explicit setup path, not guarded startup.
func TestConstruct_ConfigSelectedOperationalBinding(t *testing.T) {
	aPath := filepath.Join(t.TempDir(), "a.json")
	bPath := filepath.Join(t.TempDir(), "b.json")
	a, err := dnsid.LoadOrCreateLocalKeyProvider(aPath, dnsid.JoseAlgES256)
	if err != nil {
		t.Fatal(err)
	}
	b, err := dnsid.LoadOrCreateLocalKeyProvider(bPath, dnsid.JoseAlgES256)
	if err != nil {
		t.Fatal(err)
	}
	identity := &dnsid.IdentityConfig{Domain: "agent.example.com", GovernanceID: "example.com", LogRef: "algorand:ADDR", StatusURL: "https://agent.example.com/status.json", KeyURL: "https://agent.example.com/ku.json", EntityKeyURL: "https://example.com/ek.json", PolicyFlags: []dnsid.PolicyFlag{"logchk"}}
	entity := dnsid.GenerateES256KeyProvider()
	established, err := dnsid.NewIdentityManager(dnsid.Config{Identity: identity}, a, dnsid.WithEntityKeyProvider(entity))
	if err != nil {
		t.Fatal(err)
	}
	deps, _ := publication(t, established)
	deps.EntityKeyProvider = entity
	// Independently authenticate fixed publication A before selecting a startup key.
	verifyDeps := deps
	verifyDeps.EntityKeyProvider = nil
	verifier, err := config.Construct(context.Background(), config.Loaded{}, verifyDeps)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := verifier.VerifyDomain(context.Background(), identity.Domain); err != nil {
		t.Fatalf("established A invalid: %v", err)
	}
	for _, provider := range []string{"", "file"} {
		for _, tc := range []struct {
			name, path string
			reject     bool
		}{{"same A", aPath, false}, {"replacement B", bPath, true}} {
			t.Run(provider+"/"+tc.name, func(t *testing.T) {
				// Given established A, when only operational file selection changes.
				loaded := config.Loaded{Dnsid: dnsid.Config{Identity: identity}, KeySource: config.KeySource{Provider: provider, KeyStorePath: tc.path}}
				m, err := config.Construct(context.Background(), loaded, deps)
				// Then B never yields an application-signing manager; A remains usable.
				if tc.reject {
					if err == nil || m != nil {
						t.Fatalf("configured B enabled application signing against A: manager=%v err=%v", m != nil, err)
					}
					return
				}
				if err != nil {
					t.Fatal(err)
				}
				if m.KeyProvider().JWK() == nil {
					t.Fatal("matching A has no signing key")
				}
				if _, err := m.KeyProvider().Sign([]byte("matching A payload")); err != nil {
					t.Fatal(err)
				}
			})
		}
	}
	t.Run("injected provider wins", func(t *testing.T) {
		injected := deps
		injected.KeyProvider = b
		m, err := config.Construct(context.Background(), config.Loaded{Dnsid: dnsid.Config{Identity: identity}, KeySource: config.KeySource{Provider: "unavailable"}}, injected)
		if err != nil || m == nil || m.KeyProvider() != b {
			t.Fatalf("explicit injection changed: %v", err)
		}
	})
}
