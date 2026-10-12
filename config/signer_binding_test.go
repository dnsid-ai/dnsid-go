package config

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	dnsid "github.com/dnsid-ai/dnsid-go"
	dnsidlog "github.com/dnsid-ai/dnsid-go/log"
	"github.com/lestrrat-go/jwx/v3/jwk"
)

type publicationDNS string

func (r publicationDNS) FetchTXT(context.Context, string) ([]dnsid.TXTRecordRData, dnsid.DNSSECState, error) {
	return []dnsid.TXTRecordRData{{Value: string(r), TTL: time.Hour}}, dnsid.DNSSECStateValid, nil
}

type publicationHTTPS map[string]json.RawMessage

func (f publicationHTTPS) FetchJSON(_ context.Context, u string, _ dnsid.FetchOptions) (json.RawMessage, *tls.Certificate, error) {
	b, ok := f[u]
	if !ok {
		return nil, nil, errors.New("unexpected publication URL")
	}
	return b, nil, nil
}

type publicationLog struct{ dnsidlog.NoopLogReader }

func (publicationLog) KeyTimestamp(context.Context, string, string) (time.Time, error) {
	return time.Now().Add(-time.Hour), nil
}
func (publicationLog) VerifyGovernanceRelationship(context.Context, string, string) error { return nil }
func (publicationLog) VerifyLifecycleBinding(context.Context, dnsidlog.BilateralBindingInput, string) (dnsidlog.BilateralBinding, error) {
	return dnsidlog.BilateralBinding{}, nil
}

func publicationDependencies(t *testing.T, operational dnsid.KeyProvider, cfg dnsid.IdentityConfig) Dependencies {
	t.Helper()
	cfg.Domain, _ = dnsid.NormalizeFQDN(cfg.Domain)
	if cfg.GovernanceID == "" {
		cfg.GovernanceID = "example.com"
	}
	if cfg.LogRef == "" {
		cfg.LogRef = "m:1"
	}
	if cfg.StatusURL == "" {
		cfg.StatusURL = "https://api.example.com/s"
	}
	if cfg.KeyURL == "" {
		cfg.KeyURL = "https://" + cfg.Domain + "/ku"
	}
	if cfg.EntityKeyURL == "" {
		cfg.EntityKeyURL = "https://" + cfg.GovernanceID + "/ek"
	}
	entity := dnsid.GenerateES256KeyProvider()
	publisher, err := dnsid.NewIdentityManager(dnsid.Config{Identity: &cfg}, operational, dnsid.WithEntityKeyProvider(entity))
	if err != nil {
		t.Fatal(err)
	}
	record, err := publisher.CreateTXTRecord()
	if err != nil {
		t.Fatal(err)
	}
	marshalKeys := func(k jwk.Key) json.RawMessage {
		set := jwk.NewSet()
		if err := set.AddKey(k); err != nil {
			t.Fatal(err)
		}
		b, err := json.Marshal(set)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	status, _ := json.Marshal(dnsid.AgentStatus{State: dnsid.AgentStateActive, LastTransitionAt: time.Now().Add(-time.Hour)})
	registry := dnsidlog.NewLogRegistry()
	method, _, err := dnsidlog.ParseLogRef(cfg.LogRef)
	if err != nil {
		t.Fatal(err)
	}
	if err := registry.Register(method, func(string) dnsidlog.LogReader { return publicationLog{} }); err != nil {
		t.Fatal(err)
	}
	return Dependencies{DNSResolver: publicationDNS(record.Serialize()), HTTPSFetcher: publicationHTTPS{cfg.KeyURL: marshalKeys(operational.JWK()), cfg.EntityKeyURL: marshalKeys(entity.JWK()), cfg.StatusURL: status}, LogRegistry: registry}
}

func TestConstruct_ConfiguredSignerMustMatchPublication(t *testing.T) {
	published := dnsid.GenerateES256KeyProvider()
	identity := dnsid.IdentityConfig{Domain: "agent.example.com", GovernanceID: "example.com", LogRef: "m:1", StatusURL: "https://api.example.com/s"}
	deps := publicationDependencies(t, published, identity)
	// Construct must ignore the counterparty allowlist for local binding checks.
	loaded := Loaded{Dnsid: dnsid.Config{Identity: &identity, Verification: dnsid.VerificationConfig{TrustedEntities: []dnsid.TrustedEntity{}}}, KeySource: KeySource{Provider: "google-kms", KeyRef: "stable"}}
	selected := dnsid.KeyProvider(published)
	RegisterKeyProviderFactory("google-kms", KeyProviderFactory{Validate: func(KeySource) error { return nil }, Open: func(context.Context, KeySource, string) (dnsid.KeyProvider, error) { return selected, nil }})
	defer func() { keyFactories.Lock(); delete(keyFactories.values, "google-kms"); keyFactories.Unlock() }()
	if _, err := Construct(context.Background(), loaded, deps); err != nil {
		t.Fatal(err)
	}
	for _, change := range []string{"kid", "algorithm", "thumbprint"} {
		t.Run(change, func(t *testing.T) {
			key, _ := published.JWK().Clone()
			switch change {
			case "kid":
				key.Set(jwk.KeyIDKey, "different")
			case "algorithm":
				key.Set(jwk.AlgorithmKey, "EdDSA")
			case "thumbprint":
				key = dnsid.GenerateES256KeyProvider().JWK()
				kid, _ := published.JWK().KeyID()
				key.Set(jwk.KeyIDKey, kid)
			}
			selected = bindingKeyProvider{KeyProvider: published, key: key}
			_, err := Construct(context.Background(), loaded, deps)
			if err == nil || !strings.Contains(err.Error(), "explicit rotation") {
				t.Fatalf("configuration replaced signer: %v", err)
			}
		})
	}
	selected = published
	bad := deps
	record, err := dnsid.ParseTXTRecord(string(bad.DNSResolver.(publicationDNS)))
	if err != nil {
		t.Fatal(err)
	}
	bad.DNSResolver = publicationDNS(record.WithSignature("AAAA").Serialize())
	if _, err := Construct(context.Background(), loaded, bad); err == nil {
		t.Fatal("configured signer accepted an invalid signed publication")
	}
	// Caller injection displaces even unavailable or conflicting source settings.
	loaded.KeySource = KeySource{Provider: "unavailable", KeyRef: "changed"}
	deps.KeyProvider = published
	if _, err := Construct(context.Background(), loaded, deps); err != nil {
		t.Fatal(err)
	}
}

type bindingKeyProvider struct {
	dnsid.KeyProvider
	key jwk.Key
}

func (p bindingKeyProvider) JWK(...string) jwk.Key { return p.key }

func TestConstruct_TransportConflictsBeforePolicyFetch(t *testing.T) {
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { calls++ }))
	defer server.Close()
	for _, transport := range []dnsid.TransportConfig{{DNSServer: "1.1.1.1:53"}, {CABundlePath: "missing.pem"}, {PrivateAddressHosts: []string{".example"}}} {
		_, err := Construct(context.Background(), Loaded{Dnsid: dnsid.Config{Transport: transport}, LogTrust: LogTrust{PolicyURL: server.URL}}, Dependencies{DNSResolver: publicationDNS(""), HTTPSFetcher: publicationHTTPS{}})
		wantArgumentError(t, err)
	}
	if calls != 0 {
		t.Fatalf("fetched policy before conflict validation: %d", calls)
	}
}
