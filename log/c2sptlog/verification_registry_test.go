package c2sptlog

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	dnsid "github.com/dnsid-ai/dnsid-go"
	dnsidlog "github.com/dnsid-ai/dnsid-go/log"
	formatlog "github.com/transparency-dev/formats/log"
	"golang.org/x/mod/sumdb/note"
)

func TestNewVerificationRegistryFromDocumentConfiguresSafeDefaults(t *testing.T) {
	registry, err := NewVerificationRegistry(context.Background(), VerificationRegistryConfig{
		PolicyDocument: verificationPolicyDocument(t),
	})
	if err != nil {
		t.Fatalf("NewVerificationRegistry: %v", err)
	}
	first := verificationClient(t, registry, "c2sp-tlog:testnet:https://tlog.example/log#agent.example")
	second := verificationClient(t, registry, "c2sp-tlog:testnet:https://tlog.example/log#other.example")
	if _, ok := first.source.(*ScanSource); !ok {
		t.Fatalf("source = %T, want *ScanSource", first.source)
	}
	if _, ok := first.checkpointStore.(*MemoryTrustedC2spCheckpointStore); !ok {
		t.Fatalf("checkpoint store = %T, want *MemoryTrustedC2spCheckpointStore", first.checkpointStore)
	}
	if first.checkpointStore != second.checkpointStore {
		t.Fatal("factory readers do not share one checkpoint store")
	}
	if _, err := first.VerifyNonRevocation(context.Background(), "agent.example", time.Now()); err == nil {
		t.Fatal("VerifyNonRevocation succeeded without checkpoint freshness policy")
	} else {
		var verificationErr *dnsid.VerificationError
		if !errors.As(err, &verificationErr) || verificationErr.Transient() {
			t.Fatalf("VerifyNonRevocation error = %T %[1]v, want permanent fail-closed error", err)
		}
	}
	source := first.source.(*ScanSource)
	if source.maxEntryBundleBytes != 16_777_472 || entriesPerC2spBundle != 256 {
		t.Fatalf("bundle geometry = %d entries, %d bytes", entriesPerC2spBundle, source.maxEntryBundleBytes)
	}
	fetcher, ok := source.fetcher.(*httpBoundedResourceFetcher)
	if !ok || fetcher.client.Timeout <= 0 {
		t.Fatalf("default fetcher = %#v, want finite timeout", source.fetcher)
	}
}

func TestNewVerificationRegistryConfiguresRequiredStreamBundles(t *testing.T) {
	_, verifierKey, err := note.GenerateKey(rand.Reader, "bundle.example")
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := note.NewVerifier(verifierKey)
	if err != nil {
		t.Fatal(err)
	}
	registry, err := NewVerificationRegistry(context.Background(), VerificationRegistryConfig{
		PolicyDocument:      verificationPolicyDocument(t),
		BundleVerifiers:     []note.Verifier{verifier},
		MaxBundleLifetime:   10 * time.Minute,
		RequireStreamBundle: true,
	})
	if err != nil {
		t.Fatalf("NewVerificationRegistry: %v", err)
	}
	client := verificationClient(t, registry, "c2sp-tlog:testnet:https://tlog.example/log#agent.example")
	source, ok := client.source.(*fetchedStreamBundleSource)
	if !ok || source.fallback == nil || !source.requireBundle {
		t.Fatalf("source = %#v, want required bundles with raw event discovery", client.source)
	}
}

func TestNewVerificationRegistryAppliesFreshnessSkewLimitsAndStore(t *testing.T) {
	store := NewMemoryTrustedC2spCheckpointStore()
	registry, err := NewVerificationRegistry(context.Background(), VerificationRegistryConfig{
		PolicyDocument:         verificationPolicyDocument(t),
		CheckpointMaxAge:       2 * time.Hour,
		AllowedClockSkew:       3 * time.Minute,
		TrustedCheckpointStore: store,
		ScanSourceConfig: ScanSourceConfig{
			MaxTreeSize:         7,
			MaxCheckpointBytes:  11,
			MaxEntryBundleBytes: 13,
			MaxTotalEntryBytes:  17,
		},
	})
	if err != nil {
		t.Fatalf("NewVerificationRegistry: %v", err)
	}
	client := verificationClient(t, registry, "c2sp-tlog:testnet:https://tlog.example/log#agent.example")
	source := client.source.(*ScanSource)
	if client.policy.MaxCheckpointAge != 2*time.Hour || client.policy.ClockSkew != 3*time.Minute {
		t.Fatalf("policy freshness/skew = %v/%v", client.policy.MaxCheckpointAge, client.policy.ClockSkew)
	}
	if client.checkpointStore != store {
		t.Fatal("custom checkpoint store was not retained")
	}
	if source.maxTreeSize != 7 || source.maxCheckpointBytes != 11 || source.maxEntryBundleBytes != 13 || source.maxTotalEntryBytes != 17 {
		t.Fatalf("scanner limits = %#v", source)
	}
}

func TestNewVerificationRegistryFetchesPolicyAndResourcesWithOneFetcher(t *testing.T) {
	document := verificationPolicyDocument(t)
	var requested []string
	fetcher := &testBoundedFetcher{fetch: func(_ context.Context, rawURL string, _ int64) ([]byte, error) {
		requested = append(requested, rawURL)
		return document, nil
	}}
	registry, err := NewVerificationRegistry(context.Background(), VerificationRegistryConfig{
		PolicyURL:       "https://policy.example:8443/dnsid-policy",
		ResourceFetcher: fetcher,
	})
	if err != nil {
		t.Fatalf("NewVerificationRegistry: %v", err)
	}
	client := verificationClient(t, registry, "c2sp-tlog:testnet:https://tlog.example/log#agent.example")
	if client.source.(*ScanSource).fetcher != fetcher || len(requested) != 1 || requested[0] != "https://policy.example:8443/dnsid-policy" {
		t.Fatalf("fetcher/requests = %T %#v", client.source.(*ScanSource).fetcher, requested)
	}
}

func TestNewVerificationRegistryRejectsInvalidConfigurationBeforeFetching(t *testing.T) {
	document := verificationPolicyDocument(t)
	customTransport := scanRoundTripper(func(*http.Request) (*http.Response, error) { return nil, errors.New("unused") })
	tests := []struct {
		name   string
		config VerificationRegistryConfig
	}{
		{name: "missing source"},
		{name: "both sources", config: VerificationRegistryConfig{PolicyDocument: document, PolicyURL: "https://policy.example/dnsid-policy"}},
		{name: "plaintext URL", config: VerificationRegistryConfig{PolicyURL: "http://policy.example/dnsid-policy"}},
		{name: "URL userinfo", config: VerificationRegistryConfig{PolicyURL: "https://user@policy.example/dnsid-policy"}},
		{name: "URL fragment", config: VerificationRegistryConfig{PolicyURL: "https://policy.example/dnsid-policy#fragment"}},
		{name: "nonnumeric port", config: VerificationRegistryConfig{PolicyURL: "https://policy.example:notaport/dnsid-policy"}},
		{name: "out of range port", config: VerificationRegistryConfig{PolicyURL: "https://policy.example:70000/dnsid-policy"}},
		{name: "empty port", config: VerificationRegistryConfig{PolicyURL: "https://policy.example:/dnsid-policy"}},
		{name: "negative policy limit", config: VerificationRegistryConfig{PolicyDocument: document, MaxPolicyBytes: -1}},
		{name: "negative scan limit", config: VerificationRegistryConfig{PolicyDocument: document, ScanSourceConfig: ScanSourceConfig{MaxEntryBundleBytes: -1}}},
		{name: "oversized entry bundle limit", config: VerificationRegistryConfig{PolicyDocument: document, ScanSourceConfig: ScanSourceConfig{MaxEntryBundleBytes: defaultScanMaxBundleBytes + 1}}},
		{name: "negative max age", config: VerificationRegistryConfig{PolicyDocument: document, CheckpointMaxAge: -time.Second}},
		{name: "negative skew", config: VerificationRegistryConfig{PolicyDocument: document, AllowedClockSkew: -time.Second}},
		{name: "required bundle without verifier", config: VerificationRegistryConfig{PolicyDocument: document, RequireStreamBundle: true}},
		{name: "bundle without lifetime", config: VerificationRegistryConfig{PolicyDocument: document, BundleVerifiers: []note.Verifier{nil}}},
		{name: "nil bundle verifier", config: VerificationRegistryConfig{PolicyDocument: document, BundleVerifiers: []note.Verifier{nil}, MaxBundleLifetime: time.Minute}},
		{name: "negative bundle limit", config: VerificationRegistryConfig{PolicyDocument: document, MaxStreamBundleBytes: -1}},
		{name: "unsupported round tripper", config: VerificationRegistryConfig{PolicyDocument: document, ScanSourceConfig: ScanSourceConfig{Transport: customTransport}}},
		{name: "insufficient fetcher", config: VerificationRegistryConfig{PolicyDocument: document, ResourceFetcher: &testBoundedFetcher{guarantees: ResourceFetchGuarantees{HTTPSOnly: true}}}},
		{name: "conflicting fetcher transport", config: VerificationRegistryConfig{PolicyDocument: document, ResourceFetcher: &testBoundedFetcher{}, ScanSourceConfig: ScanSourceConfig{Transport: http.DefaultTransport}}},
		{name: "conflicting fetcher dnsid transport", config: VerificationRegistryConfig{PolicyDocument: document, ResourceFetcher: &testBoundedFetcher{}, Transport: dnsid.TransportConfig{DNSServer: "127.0.0.1:7753"}}},
		{name: "conflicting dnsid transport and http transport", config: VerificationRegistryConfig{PolicyDocument: document, Transport: dnsid.TransportConfig{DNSServer: "127.0.0.1:7753"}, ScanSourceConfig: ScanSourceConfig{Transport: http.DefaultTransport}}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := NewVerificationRegistry(context.Background(), test.config)
			if err == nil {
				t.Fatal("NewVerificationRegistry succeeded")
			}
			var argumentErr *dnsid.ArgumentError
			if !errors.As(err, &argumentErr) {
				t.Fatalf("error = %T %v, want *dnsid.ArgumentError", err, err)
			}
		})
	}
}

func TestNewVerificationRegistryDefensivelyBoundsCustomFetcherResponse(t *testing.T) {
	fetcher := &testBoundedFetcher{fetch: func(context.Context, string, int64) ([]byte, error) {
		return []byte("12345"), nil
	}}
	_, err := NewVerificationRegistry(context.Background(), VerificationRegistryConfig{
		PolicyURL:       "https://policy.example/dnsid-policy",
		MaxPolicyBytes:  4,
		ResourceFetcher: fetcher,
	})
	var fetchErr *ResourceFetchError
	if !errors.As(err, &fetchErr) || fetchErr.Kind != ResourceFetchResponseLimit || fetchErr.Transient() {
		t.Fatalf("error = %T %[1]v, want permanent response limit", err)
	}
}

// Transport applies the SDK transport controls to the policy fetch: with the
// server's CA trusted and private addresses allowed, a loopback policy URL that
// the default fetcher rejects (see the test below) succeeds.
func TestNewVerificationRegistryTransportReachesPrivatePolicyURL(t *testing.T) {
	document := verificationPolicyDocument(t)
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(document)
	}))
	t.Cleanup(server.Close)
	caPath := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(caPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}

	registry, err := NewVerificationRegistry(context.Background(), VerificationRegistryConfig{
		PolicyURL: server.URL + "/dnsid-policy",
		Transport: dnsid.TransportConfig{CABundlePath: caPath, AllowPrivateNetwork: true},
	})
	if err != nil {
		t.Fatalf("NewVerificationRegistry: %v", err)
	}
	if registry == nil {
		t.Fatal("NewVerificationRegistry returned nil")
	}
}

func TestNewVerificationRegistryDefaultFetcherRejectsUnsafePolicyDestination(t *testing.T) {
	_, err := NewVerificationRegistry(context.Background(), VerificationRegistryConfig{
		PolicyURL: "https://127.0.0.1/dnsid-policy",
	})
	var fetchErr *ResourceFetchError
	if !errors.As(err, &fetchErr) || fetchErr.Kind != ResourceFetchUnsafeDestination || fetchErr.Transient() {
		t.Fatalf("error = %T %[1]v, want permanent unsafe-destination error", err)
	}
}

func TestHTTPBoundedResourceFetcherClassifiesFailures(t *testing.T) {
	tests := []struct {
		name      string
		resp      *http.Response
		kind      ResourceFetchErrorKind
		max       int64
		transient bool
	}{
		{name: "redirect", resp: resourceResponse(http.StatusFound, ""), kind: ResourceFetchRedirect, max: 4},
		{name: "oversized", resp: resourceResponse(http.StatusOK, "12345"), kind: ResourceFetchResponseLimit, max: 4},
		{name: "last server error", resp: resourceResponse(599, ""), kind: ResourceFetchHTTPStatus, max: 4, transient: true},
		{name: "above server error range", resp: resourceResponse(600, ""), kind: ResourceFetchHTTPStatus, max: 4},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fetcher := &httpBoundedResourceFetcher{client: &http.Client{Transport: scanRoundTripper(func(req *http.Request) (*http.Response, error) {
				test.resp.Request = req
				return test.resp, nil
			}), CheckRedirect: rejectResourceRedirect}, httpsOnly: true}
			_, err := fetcher.FetchBounded(context.Background(), "https://resource.example/value", test.max)
			var fetchErr *ResourceFetchError
			if !errors.As(err, &fetchErr) || fetchErr.Kind != test.kind || fetchErr.Transient() != test.transient {
				t.Fatalf("error = %T %[1]v, want %s transient=%v", err, test.kind, test.transient)
			}
		})
	}
}

func TestHTTPBoundedResourceFetcherAcceptsExactLimit(t *testing.T) {
	fetcher := &httpBoundedResourceFetcher{client: &http.Client{Transport: scanRoundTripper(func(req *http.Request) (*http.Response, error) {
		response := resourceResponse(http.StatusOK, "1234")
		response.Request = req
		return response, nil
	})}, httpsOnly: true}
	body, err := fetcher.FetchBounded(context.Background(), "https://resource.example/value", 4)
	if err != nil {
		t.Fatalf("FetchBounded: %v", err)
	}
	if string(body) != "1234" {
		t.Fatalf("body = %q, want exact four-byte response", body)
	}
}

func TestNewVerificationRegistryDrivesIdentityManagerFromStandardResources(t *testing.T) {
	entity := dnsid.GenerateEd25519KeyProvider()
	operational := dnsid.GenerateES256KeyProvider()
	const (
		domain = "agent.example.com"
		lr     = "c2sp-tlog:testnet:https://tlog.example/log#identity-01"
		ekURL  = "https://example.com/entity-jwks.json"
		kuURL  = "https://agent.example.com/jwks.json"
		suURL  = "https://agent.example.com/status.json"
	)
	publisher, err := dnsid.NewIdentityManager(dnsid.Config{Identity: &dnsid.IdentityConfig{
		Domain: domain, GovernanceID: "example.com", LogRef: lr,
		EntityKeyURL: ekURL, KeyURL: kuURL, StatusURL: suURL,
	}}, operational, dnsid.WithEntityKeyProvider(entity))
	if err != nil {
		t.Fatalf("NewIdentityManager publisher: %v", err)
	}
	record, err := publisher.CreateTXTRecord()
	if err != nil {
		t.Fatalf("CreateTXTRecord: %v", err)
	}

	logClient, err := New(lr)
	if err != nil {
		t.Fatalf("New c2sp client: %v", err)
	}
	prepared, err := logClient.PrepareEvent(dnsidlog.LogEvent{
		Type: dnsidlog.LogEventIssuance, Domain: domain, GovernanceID: "example.com",
		Timestamp: time.Now().UTC(), InitialEntityPublicKey: entity.JWK(), InitialOperationalPublicKey: operational.JWK(),
	})
	if err != nil {
		t.Fatalf("PrepareEvent: %v", err)
	}
	prepared, err = logClient.SignPreparedEvent(context.Background(), prepared, SignerEntity, entity)
	if err != nil {
		t.Fatalf("SignPreparedEvent entity: %v", err)
	}
	prepared, err = logClient.SignPreparedEvent(context.Background(), prepared, SignerOperationalCountersignature, operational)
	if err != nil {
		t.Fatalf("SignPreparedEvent operational: %v", err)
	}
	entry, err := logClient.PreparedEntryBytes(context.Background(), prepared)
	if err != nil {
		t.Fatalf("PreparedEntryBytes: %v", err)
	}
	policyDocument, resources := standardResourceFixture(t, [][]byte{entry})
	resourceFetcher := &testBoundedFetcher{fetch: func(_ context.Context, rawURL string, _ int64) ([]byte, error) {
		parsed, err := url.Parse(rawURL)
		if err != nil {
			return nil, err
		}
		body, ok := resources[parsed.Path]
		if !ok {
			return nil, &ResourceFetchError{Kind: ResourceFetchHTTPStatus, URL: rawURL, HTTPStatus: http.StatusNotFound}
		}
		return append([]byte(nil), body...), nil
	}}
	registry, err := NewVerificationRegistry(context.Background(), VerificationRegistryConfig{
		PolicyDocument:  policyDocument,
		ResourceFetcher: resourceFetcher,
	})
	if err != nil {
		t.Fatalf("NewVerificationRegistry: %v", err)
	}
	ekJSON, _ := json.Marshal(publisher.GetEntityKeySet().Raw())
	kuJSON, _ := json.Marshal(publisher.GetKeySet().Raw())
	statusJSON, _ := json.Marshal(dnsid.AgentStatus{State: dnsid.AgentStateActive, LastTransitionAt: time.Now().UTC()})
	verifier, err := dnsid.NewVerifier(
		dnsid.WithDNSResolver(factoryDNSResolver{"_dnsid." + domain: {{Value: record.Serialize(), TTL: time.Minute}}}),
		dnsid.WithHTTPSFetcher(factoryHTTPSFetcher{ekURL: ekJSON, kuURL: kuJSON, suURL: statusJSON}),
		dnsid.WithLogRegistry(registry),
	)
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	verified, err := verifier.VerifyDomain(context.Background(), domain)
	if err != nil {
		t.Fatalf("VerifyDomain: %v", err)
	}
	if verified.Domain() != domain {
		t.Fatalf("verified domain = %q, want %q", verified.Domain(), domain)
	}
}

func TestScannerResourceLimitIsNonTransientAtLogBoundary(t *testing.T) {
	policy, _ := scanFixture(t, [][]byte{[]byte(issuanceEntry)})
	fetcher := &testBoundedFetcher{fetch: func(context.Context, string, int64) ([]byte, error) {
		return nil, &ResourceFetchError{Kind: ResourceFetchResponseLimit, MaximumBytes: 1}
	}}
	source, err := NewScanSource(policy, ScanSourceConfig{ResourceFetcher: fetcher})
	if err != nil {
		t.Fatalf("NewScanSource: %v", err)
	}
	client, err := New("c2sp-tlog:testnet:https://tlog.example/log#agent.example", WithSource(source), WithPolicy(policy))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	_, err = client.RebuildHistory(context.Background(), "agent.example")
	var verificationErr *dnsid.VerificationError
	if !errors.As(err, &verificationErr) || verificationErr.Transient() {
		t.Fatalf("error = %T %[1]v, want non-transient VerificationError", err)
	}
}

func verificationClient(t *testing.T, registry *dnsidlog.LogRegistry, lr string) *Client {
	t.Helper()
	reader, err := registry.NewReader(lr)
	if err != nil {
		t.Fatalf("NewReader: %v", err)
	}
	client, ok := reader.(*Client)
	if !ok {
		t.Fatalf("reader = %T, want *Client", reader)
	}
	return client
}

func standardResourceFixture(t *testing.T, entries [][]byte) ([]byte, map[string][]byte) {
	t.Helper()
	signerKey, verifierKey, err := note.GenerateKey(rand.Reader, "tlog.example/log")
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	signer, err := note.NewSigner(signerKey)
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}
	checkpoint := formatlog.Checkpoint{Origin: "tlog.example/log", Size: uint64(len(entries)), Hash: merkleRoot(entries)}
	signedCheckpoint, err := note.Sign(&note.Note{Text: string(checkpoint.Marshal())}, signer)
	if err != nil {
		t.Fatalf("Sign checkpoint: %v", err)
	}
	bundle := make([]byte, 0)
	tile := make([]byte, 0, len(entries)*32)
	for _, entry := range entries {
		bundle = append(bundle, byte(len(entry)>>8), byte(len(entry)))
		bundle = append(bundle, entry...)
		leaf := LeafHash(entry)
		tile = append(tile, leaf[:]...)
	}
	width := itoa(len(entries))
	return []byte(fmt.Sprintf("log %s\nquorum none\n", verifierKey)), map[string][]byte{
		"/log/checkpoint":                  signedCheckpoint,
		"/log/tile/entries/000.p/" + width: bundle,
		"/log/tile/0/000.p/" + width:       tile,
	}
}

func verificationPolicyDocument(t *testing.T) []byte {
	t.Helper()
	_, verifierKey, err := note.GenerateKey(rand.Reader, "tlog.example/log")
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	return []byte(fmt.Sprintf("log %s\nquorum none\n", verifierKey))
}

func resourceResponse(status int, body string) *http.Response {
	return &http.Response{StatusCode: status, Body: io.NopCloser(bytes.NewBufferString(body)), Header: make(http.Header)}
}

type factoryDNSResolver map[string][]dnsid.TXTRecordRData

func (r factoryDNSResolver) FetchTXT(_ context.Context, name string) ([]dnsid.TXTRecordRData, dnsid.DNSSECState, error) {
	return r[name], dnsid.DNSSECStateUnsigned, nil
}

type factoryHTTPSFetcher map[string]json.RawMessage

func (f factoryHTTPSFetcher) FetchJSON(_ context.Context, rawURL string, _ dnsid.FetchOptions) (json.RawMessage, *tls.Certificate, error) {
	body, ok := f[rawURL]
	if !ok {
		return nil, nil, fmt.Errorf("missing HTTPS fixture for %s", rawURL)
	}
	return body, nil, nil
}

type testBoundedFetcher struct {
	fetch      func(context.Context, string, int64) ([]byte, error)
	guarantees ResourceFetchGuarantees
}

func (f *testBoundedFetcher) FetchBounded(ctx context.Context, rawURL string, maximum int64) ([]byte, error) {
	if f.fetch == nil {
		return nil, errors.New("unexpected fetch")
	}
	return f.fetch(ctx, rawURL, maximum)
}

func (f *testBoundedFetcher) SecurityGuarantees() ResourceFetchGuarantees {
	if f.guarantees != (ResourceFetchGuarantees{}) {
		return f.guarantees
	}
	return ResourceFetchGuarantees{
		HTTPSOnly:                     true,
		RejectsRedirects:              true,
		ValidatesAllResolvedAddresses: true,
		ConnectsToValidatedAddress:    true,
		BoundsResponseDuringRead:      true,
	}
}
