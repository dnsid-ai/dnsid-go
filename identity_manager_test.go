package dnsid

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	dnsidlog "github.com/dnsid-ai/dnsid-go/log"
	"github.com/lestrrat-go/jwx/v3/jwk"
)

type testDNSResolver struct {
	records map[string][]TXTRecordRData
	state   DNSSECState
	calls   int
}

func (r *testDNSResolver) FetchTXT(_ context.Context, name string) ([]TXTRecordRData, DNSSECState, error) {
	r.calls++
	state := r.state
	if state == "" {
		state = DNSSECStateUnsigned
	}
	return r.records[name], state, nil
}

type testHTTPSFetcher struct {
	mu        sync.Mutex
	responses map[string]json.RawMessage
	errors    map[string]error
	options   map[string]FetchOptions
	certs     map[string]*tls.Certificate
}

type testLogReader struct {
	keyTimestamp          time.Time
	revoked               bool
	govErr                error
	govDomain             string
	govID                 string
	bindingErr            error
	bindingInput          dnsidlog.BilateralBindingInput
	bindingHit            bool
	continuityHit         bool
	nonRevocationCalls    int
	nonRevocationAt       time.Time
	nonRevocationEvidence dnsidlog.LoggedStateEvidence
}

func (r *testLogReader) Canonical(event dnsidlog.LogEvent) ([]byte, error) {
	return []byte(event.Type), nil
}
func (r *testLogReader) KeyTimestamp(context.Context, string, string) (time.Time, error) {
	if r.keyTimestamp.IsZero() {
		return time.Now(), nil
	}
	return r.keyTimestamp, nil
}
func (r *testLogReader) VerifyBilateralBinding(_ context.Context, input dnsidlog.BilateralBindingInput) (dnsidlog.BilateralBinding, error) {
	r.bindingHit = true
	r.bindingInput = input
	return dnsidlog.BilateralBinding{InitialOperationalThumbprint: "initial-operational"}, r.bindingErr
}
func (r *testLogReader) VerifyOperationalContinuity(context.Context, string, string, string) error {
	r.continuityHit = true
	return nil
}
func (r *testLogReader) VerifyGovernanceRelationship(_ context.Context, domain, governanceID string) error {
	r.govDomain = domain
	r.govID = governanceID
	return r.govErr
}
func (r *testLogReader) VerifyNonRevocation(_ context.Context, _ string, at time.Time) (dnsidlog.LoggedStateEvidence, error) {
	r.nonRevocationCalls++
	r.nonRevocationAt = at
	if r.revoked {
		return dnsidlog.LoggedStateEvidence{}, NewVerificationError(VerificationCodeLogError, false, "revoked in log", nil)
	}
	return r.nonRevocationEvidence, nil
}
func (r *testLogReader) ReadEvent(context.Context, dnsidlog.LogRef) (dnsidlog.LogEvent, error) {
	return dnsidlog.LogEvent{}, nil
}
func (r *testLogReader) RebuildHistory(context.Context, string) ([]dnsidlog.LogEvent, error) {
	return nil, nil
}

func (f *testHTTPSFetcher) FetchJSON(_ context.Context, rawURL string, opts FetchOptions) (json.RawMessage, *tls.Certificate, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.options != nil {
		f.options[rawURL] = opts
	}
	if err := f.errors[rawURL]; err != nil {
		return nil, nil, err
	}
	return f.responses[rawURL], f.certs[rawURL], nil
}

func TestIdentityManager_VerifyOnlyConstruction(t *testing.T) {
	m, err := NewVerifier()
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	if m.Domain() != "" || m.KeyProvider() != nil {
		t.Fatalf("NewVerifier returned local identity: domain=%q keyProvider=%T", m.Domain(), m.KeyProvider())
	}
	if _, err := m.CreateTXTRecord(); err == nil {
		t.Fatal("CreateTXTRecord succeeded without local identity")
	} else {
		var argumentErr *ArgumentError
		if !errors.As(err, &argumentErr) {
			t.Fatalf("CreateTXTRecord error = %T, want *ArgumentError", err)
		}
	}
	if _, err := NewIdentityManager(Config{Identity: &IdentityConfig{GovernanceID: "example.com"}}, nil); err == nil {
		t.Fatal("NewIdentityManager accepted local identity config without KeyProvider")
	}
}

func TestPublicationValidationRequiresBothRoleURLsAtBoundary(t *testing.T) {
	manager, err := NewIdentityManager(Config{Identity: &IdentityConfig{
		Domain: "agent.example.com", GovernanceID: "example.com", LogRef: "test:agent",
		StatusURL: "https://agent.example.com/status.json", KeyURL: "https://agent.example.com/ku.json",
	}}, GenerateES256KeyProvider(), WithEntityKeyProvider(GenerateES256KeyProvider()))
	if err != nil {
		t.Fatalf("NewIdentityManager: %v", err)
	}
	_, err = manager.BuildUnsignedTXTRecord()
	var argumentErr *ArgumentError
	if !errors.As(err, &argumentErr) || !strings.Contains(err.Error(), "KeyURL and EntityKeyURL") {
		t.Fatalf("BuildUnsignedTXTRecord error = %T %v, want *ArgumentError requiring both URLs", err, err)
	}
}

func TestIdentityConfigURLNamesPreserveTXTWireTags(t *testing.T) {
	manager, err := NewIdentityManager(Config{Identity: &IdentityConfig{
		Domain:       "agent.example.com",
		GovernanceID: "example.com",
		LogRef:       "test:agent",
		StatusURL:    "https://agent.example.com/status.json",
		KeyURL:       "https://agent.example.com/ku.json",
		EntityKeyURL: "https://example.com/ek.json",
	}}, GenerateEd25519KeyProvider(), WithEntityKeyProvider(GenerateEd25519KeyProvider()))
	if err != nil {
		t.Fatalf("NewIdentityManager: %v", err)
	}
	record, err := manager.BuildUnsignedTXTRecord()
	if err != nil {
		t.Fatalf("BuildUnsignedTXTRecord: %v", err)
	}
	const want = "ek=https://example.com/ek.json;gi=example.com;ku=https://agent.example.com/ku.json;lr=test:agent;su=https://agent.example.com/status.json;v=dnsid-draft-01"
	if got := string(record.CanonicalContent()); got != want {
		t.Fatalf("CanonicalContent = %q, want %q", got, want)
	}
}

type invalidPublicationKeyProvider struct {
	KeyProvider
	key jwk.Key
}

func (p invalidPublicationKeyProvider) JWK(kidOpt ...string) jwk.Key {
	return p.key
}

func TestIdentityManager_CreateTXTRecordRejectsInvalidPublicationJWK(t *testing.T) {
	base := GenerateEd25519KeyProvider()
	badKey, err := jwk.Import([]byte("not-a-dnsid-signing-key"))
	if err != nil {
		t.Fatalf("import oct JWK: %v", err)
	}
	kid := base.ListKeyIds()[0]
	if err := badKey.Set(jwk.KeyIDKey, kid); err != nil {
		t.Fatalf("set kid: %v", err)
	}

	manager, err := NewIdentityManager(Config{Identity: &IdentityConfig{
		Domain:       "agent.example.com",
		GovernanceID: "example.com",
		LogRef:       "algorand:ADDR",
		StatusURL:    "https://agent.example.com/status.json",
		KeyURL:       "https://agent.example.com/ku.json",
		EntityKeyURL: "https://example.com/ek.json",
	}}, invalidPublicationKeyProvider{KeyProvider: base, key: badKey}, WithEntityKeyProvider(GenerateES256KeyProvider()))
	if err != nil {
		t.Fatalf("NewIdentityManager: %v", err)
	}
	if _, err := manager.CreateTXTRecord(); err == nil || !strings.Contains(err.Error(), "must include alg") {
		t.Fatalf("CreateTXTRecord error = %v, want missing alg", err)
	}
	if raw := manager.GetKeySet().Raw(); raw.Len() != 0 {
		t.Fatalf("GetKeySet exposed %d invalid key(s), want 0", raw.Len())
	}
}

func TestDefaultHTTPSFetcherReturnsPeerCertificate(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer server.Close()

	msg, cert, err := (defaultHTTPSFetcher{client: server.Client()}).FetchJSON(context.Background(), server.URL, FetchOptions{})
	if err != nil {
		t.Fatalf("FetchJSON: %v", err)
	}
	if string(msg) != `{"ok":true}` {
		t.Fatalf("message = %s", msg)
	}
	if cert == nil || cert.Leaf == nil || cert.Leaf.NotAfter.IsZero() {
		t.Fatalf("certificate = %#v", cert)
	}
}

func TestDefaultHTTPSFetcherPreservesHTTPStatus(t *testing.T) {
	for _, status := range []int{http.StatusForbidden, http.StatusNoContent} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(status)
			}))
			defer server.Close()

			_, _, err := (defaultHTTPSFetcher{client: server.Client()}).FetchJSON(context.Background(), server.URL, FetchOptions{})
			var statusErr *httpStatusError
			if !errors.As(err, &statusErr) {
				t.Fatalf("FetchJSON error = %T, want *httpStatusError", err)
			}
			if statusErr.statusCode != status {
				t.Fatalf("HTTP status = %d, want %d", statusErr.statusCode, status)
			}
		})
	}
}

func TestFetchAgentStatusClassifiesHTTPStatusRetryability(t *testing.T) {
	const statusURL = "https://agent.example.com/status.json"
	tests := []struct {
		name      string
		status    int
		transient bool
	}{
		{name: "client failure", status: http.StatusNotFound, transient: false},
		{name: "server failure", status: http.StatusServiceUnavailable, transient: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			manager := &IdentityManager{https: &testHTTPSFetcher{errors: map[string]error{
				statusURL: &httpStatusError{statusCode: tt.status},
			}}}
			_, _, err := manager.fetchAgentStatus(context.Background(), statusURL)
			var verificationErr *VerificationError
			if !errors.As(err, &verificationErr) {
				t.Fatalf("fetchAgentStatus error = %T, want *VerificationError", err)
			}
			if verificationErr.Code() != VerificationCodeStatusUnavailable || verificationErr.Transient() != tt.transient {
				t.Fatalf("code = %q, transient = %v; want %q, %v", verificationErr.Code(), verificationErr.Transient(), VerificationCodeStatusUnavailable, tt.transient)
			}
		})
	}
}

func TestFetchHostAllowed(t *testing.T) {
	for _, tc := range []struct {
		host, allowed string
		boundary      bool
		want          bool
	}{
		{"example.com", "example.com", false, true},
		{"keys.example.com", "example.com", true, true},
		{"keys.example.com", "example.com", false, false},
		{"notexample.test", "example.com", true, false},
	} {
		if got := fetchHostAllowed(tc.host, tc.allowed, tc.boundary); got != tc.want {
			t.Errorf("fetchHostAllowed(%q, %q, %v) = %v, want %v", tc.host, tc.allowed, tc.boundary, got, tc.want)
		}
	}
}

func TestIdentityManagerDefaultHTTPClientIsReusableAndRedirectCopiesShareTransport(t *testing.T) {
	manager, err := NewVerifier()
	if err != nil {
		t.Fatal(err)
	}
	fetcher, ok := manager.https.(defaultHTTPSFetcher)
	if !ok || fetcher.client == nil || fetcher.client.Transport == nil {
		t.Fatalf("default HTTPS fetcher = %#v, want retained client and transport", manager.https)
	}
	first := clientWithRedirectPolicy(fetcher.client, "https://agent.example/ek", FetchOptions{RedirectPolicy: RedirectPolicyNone})
	second := clientWithRedirectPolicy(fetcher.client, "https://agent.example/ku", FetchOptions{RedirectPolicy: RedirectPolicySameHost})
	if first == second || first == fetcher.client || second == fetcher.client {
		t.Fatal("redirect policy must use per-request client copies")
	}
	if first.Transport != fetcher.client.Transport || second.Transport != fetcher.client.Transport {
		t.Fatal("per-request clients did not share the manager transport connection pool")
	}
}

func TestIdentityManagerHTTPClientTimeoutDefaultsAndPreservesExplicitValue(t *testing.T) {
	manager, err := NewVerifier()
	if err != nil {
		t.Fatal(err)
	}
	defaultFetcher := manager.https.(defaultHTTPSFetcher)
	if defaultFetcher.client.Timeout <= 0 {
		t.Fatalf("default timeout = %v, want finite timeout", defaultFetcher.client.Timeout)
	}

	base := &http.Client{Timeout: 47 * time.Second}
	manager, err = NewVerifier(WithHTTPClient(base))
	if err != nil {
		t.Fatal(err)
	}
	explicitFetcher := manager.https.(defaultHTTPSFetcher)
	if explicitFetcher.client == base {
		t.Fatal("WithHTTPClient retained and mutated the caller's client")
	}
	if explicitFetcher.client.Timeout != base.Timeout {
		t.Fatalf("timeout = %v, want explicit %v", explicitFetcher.client.Timeout, base.Timeout)
	}
}

func TestDefaultHTTPSFetcherRedirectPolicy(t *testing.T) {
	server := httptest.NewTLSServer(nil)
	server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/same-host":
			http.Redirect(w, r, server.URL+"/ok", http.StatusFound)
		case "/host-change":
			http.Redirect(w, r, "https://example.org/ok", http.StatusFound)
		case "/http":
			http.Redirect(w, r, "http://example.org/ok", http.StatusFound)
		default:
			_, _ = w.Write([]byte(`{"ok":true}`))
		}
	})
	defer server.Close()
	fetcher := defaultHTTPSFetcher{client: server.Client()}

	if _, _, err := fetcher.FetchJSON(context.Background(), server.URL+"/same-host", FetchOptions{RedirectPolicy: RedirectPolicyNone}); err == nil || !strings.Contains(err.Error(), "HTTP 302") {
		t.Fatalf("RedirectPolicyNone error = %v, want HTTP 302", err)
	}
	if _, _, err := fetcher.FetchJSON(context.Background(), server.URL+"/same-host", FetchOptions{RedirectPolicy: RedirectPolicySameHost}); err != nil {
		t.Fatalf("same-host redirect: %v", err)
	}
	if _, _, err := fetcher.FetchJSON(context.Background(), server.URL+"/host-change", FetchOptions{RedirectPolicy: RedirectPolicySameHost}); err == nil || !strings.Contains(err.Error(), "redirect host") {
		t.Fatalf("host-changing redirect error = %v, want redirect host error", err)
	}
	if _, _, err := fetcher.FetchJSON(context.Background(), server.URL+"/http", FetchOptions{RedirectPolicy: RedirectPolicyHTTPS}); err == nil || !strings.Contains(err.Error(), "must use https") {
		t.Fatalf("http redirect error = %v, want https error", err)
	}
}

func TestDefaultHTTPSFetcherRedirectPolicyDoesNotLeakConcurrently(t *testing.T) {
	server := httptest.NewTLSServer(nil)
	server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/redirect" {
			http.Redirect(w, r, server.URL+"/ok", http.StatusFound)
			return
		}
		_, _ = w.Write([]byte(`{"ok":true}`))
	})
	defer server.Close()
	fetcher := defaultHTTPSFetcher{client: server.Client()}

	start := make(chan struct{})
	errs := make(chan error, 64)
	for i := range 64 {
		go func(follow bool) {
			<-start
			policy := RedirectPolicyNone
			if follow {
				policy = RedirectPolicySameHost
			}
			_, _, err := fetcher.FetchJSON(context.Background(), server.URL+"/redirect", FetchOptions{RedirectPolicy: policy})
			if follow && err != nil {
				errs <- err
				return
			}
			var statusErr *httpStatusError
			if !follow && (!errors.As(err, &statusErr) || statusErr.statusCode != http.StatusFound) {
				errs <- errors.New("no-redirect request did not return HTTP 302")
				return
			}
			errs <- nil
		}(i%2 == 0)
	}
	close(start)
	for range 64 {
		if err := <-errs; err != nil {
			t.Fatal(err)
		}
	}
}

func TestIdentityManager_StatusTransportClassification(t *testing.T) {
	const statusURL = "https://agent.example/status"
	tests := []struct {
		name      string
		err       error
		code      VerificationCode
		transient bool
	}{
		{name: "network", err: errors.New("connection refused"), code: VerificationCodeStatusUnavailable, transient: true},
		{name: "TLS policy", err: errTLSPolicy, code: VerificationCodeTLSError, transient: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			manager := &IdentityManager{https: &testHTTPSFetcher{errors: map[string]error{statusURL: tt.err}}}
			_, _, err := manager.fetchAgentStatus(context.Background(), statusURL)
			var verificationErr *VerificationError
			if !errors.As(err, &verificationErr) {
				t.Fatalf("error = %T, want *VerificationError", err)
			}
			if verificationErr.Code() != tt.code || verificationErr.Transient() != tt.transient {
				t.Fatalf("code = %q, transient = %v; want %q, %v", verificationErr.Code(), verificationErr.Transient(), tt.code, tt.transient)
			}
		})
	}
}

func TestIdentityManagerTransportConfig(t *testing.T) {
	dns := &testDNSResolver{}
	var https testHTTPSFetcher
	server := TransportConfig{DNSServer: "127.0.0.1:5353"}
	bundle := TransportConfig{CABundlePath: "/does/not/exist.pem"}

	t.Run("DNSServer configures default resolver and fetcher", func(t *testing.T) {
		manager, err := NewIdentityManager(Config{Transport: server}, nil)
		if err != nil {
			t.Fatalf("NewIdentityManager: %v", err)
		}
		if _, ok := manager.dns.(customDNSServerResolver); !ok {
			t.Fatalf("dns = %#v, want customDNSServerResolver", manager.dns)
		}
		if fetcher, ok := manager.https.(defaultHTTPSFetcher); !ok || fetcher.client == nil {
			t.Fatalf("https = %#v, want default fetcher", manager.https)
		}
	})

	t.Run("DNSServer with only resolver injected configures fetcher", func(t *testing.T) {
		manager, err := NewIdentityManager(Config{Transport: server}, nil, WithDNSResolver(dns))
		if err != nil {
			t.Fatalf("NewIdentityManager: %v", err)
		}
		if manager.dns != dns {
			t.Fatalf("injected resolver was replaced: %#v", manager.dns)
		}
		if _, ok := manager.https.(defaultHTTPSFetcher); !ok {
			t.Fatalf("https = %#v, want default fetcher", manager.https)
		}
	})

	t.Run("DNSServer with only fetcher injected configures resolver", func(t *testing.T) {
		manager, err := NewIdentityManager(Config{Transport: server}, nil, WithHTTPSFetcher(&https))
		if err != nil {
			t.Fatalf("NewIdentityManager: %v", err)
		}
		if manager.https != &https {
			t.Fatalf("injected fetcher was replaced: %#v", manager.https)
		}
		if _, ok := manager.dns.(customDNSServerResolver); !ok {
			t.Fatalf("dns = %#v, want customDNSServerResolver", manager.dns)
		}
	})

	t.Run("DNSServer with both injected is rejected", func(t *testing.T) {
		_, err := NewIdentityManager(Config{Transport: server}, nil, WithDNSResolver(dns), WithHTTPSFetcher(&https))
		var argErr *ArgumentError
		if !errors.As(err, &argErr) {
			t.Fatalf("error = %v, want *ArgumentError", err)
		}
	})

	t.Run("CABundlePath with fetcher injected is rejected before reading the file", func(t *testing.T) {
		_, err := NewIdentityManager(Config{Transport: bundle}, nil, WithHTTPSFetcher(&https))
		var argErr *ArgumentError
		if !errors.As(err, &argErr) {
			t.Fatalf("error = %v, want *ArgumentError", err)
		}
	})

	t.Run("CABundlePath with http client injected is rejected", func(t *testing.T) {
		_, err := NewIdentityManager(Config{Transport: bundle}, nil, WithHTTPClient(&http.Client{}))
		var argErr *ArgumentError
		if !errors.As(err, &argErr) {
			t.Fatalf("error = %v, want *ArgumentError", err)
		}
	})

	t.Run("missing CA bundle is reported", func(t *testing.T) {
		_, err := NewIdentityManager(Config{Transport: bundle}, nil)
		if err == nil || !strings.Contains(err.Error(), "reading CA bundle") {
			t.Fatalf("error = %v, want CA bundle read error", err)
		}
	})
}

func freshStatus() string {
	return `{"state":"ACTIVE","lastTransitionAt":"` + time.Now().UTC().Format(time.RFC3339Nano) + `"}`
}

func TestVerifyDomainDefaultManagerAllowsUnknownDNSSECState(t *testing.T) {
	manager, err := NewIdentityManager(Config{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	manager.dns = &testDNSResolver{state: DNSSECStateUnknown}
	_, err = manager.VerifyDomain(context.Background(), "agent.example")
	var verificationErr *VerificationError
	if !errors.As(err, &verificationErr) || verificationErr.Code() != VerificationCodeRecordInvalid {
		t.Fatalf("VerifyDomain error = %v, want record_invalid after DNSSEC UNKNOWN was accepted", err)
	}
}

func TestEnforceDNSSECPolicy(t *testing.T) {
	tests := []struct {
		name  string
		mode  DNSSECMode
		state DNSSECState
		ok    bool
	}{
		{name: "auto valid", mode: DNSSECModeAuto, state: DNSSECStateValid, ok: true},
		{name: "auto unsigned", mode: DNSSECModeAuto, state: DNSSECStateUnsigned, ok: true},
		{name: "auto unknown", mode: DNSSECModeAuto, state: DNSSECStateUnknown, ok: true},
		{name: "auto empty is unknown", mode: DNSSECModeAuto, state: "", ok: true},
		{name: "auto failed", mode: DNSSECModeAuto, state: DNSSECStateFailed},
		{name: "auto invalid state", mode: DNSSECModeAuto, state: "BOGUS"},
		{name: "validated valid", mode: DNSSECModeValidated, state: DNSSECStateValid, ok: true},
		{name: "validated unsigned", mode: DNSSECModeValidated, state: DNSSECStateUnsigned, ok: true},
		{name: "validated unknown", mode: DNSSECModeValidated, state: DNSSECStateUnknown},
		{name: "validated failed", mode: DNSSECModeValidated, state: DNSSECStateFailed},
		{name: "required valid", mode: DNSSECModeRequired, state: DNSSECStateValid, ok: true},
		{name: "required unsigned", mode: DNSSECModeRequired, state: DNSSECStateUnsigned},
		{name: "required unknown", mode: DNSSECModeRequired, state: DNSSECStateUnknown},
		{name: "required failed", mode: DNSSECModeRequired, state: DNSSECStateFailed},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			manager := &IdentityManager{verification: VerificationConfig{DNSSECMode: tt.mode}}
			err := manager.enforceDNSSECPolicy(tt.state)
			if (err == nil) != tt.ok {
				t.Fatalf("enforceDNSSECPolicy(%s) error = %v, want success=%v", tt.state, err, tt.ok)
			}
			if err != nil {
				var verificationErr *VerificationError
				if !errors.As(err, &verificationErr) || verificationErr.Code() != VerificationCodeDNSSECFailed {
					t.Fatalf("error = %v, want dnssec_failed", err)
				}
			}
		})
	}
}

func TestNewIdentityManagerRejectsInvalidDNSSECMode(t *testing.T) {
	_, err := NewIdentityManager(Config{Verification: VerificationConfig{DNSSECMode: "disabled"}}, nil)
	if err == nil || !strings.Contains(err.Error(), "invalid DNSSEC mode") {
		t.Fatalf("NewIdentityManager error = %v, want invalid DNSSEC mode", err)
	}
}

func TestFetchAgentStatus_AcceptsOldActiveTransition(t *testing.T) {
	const statusURL = "https://agent.example/status"
	transition := time.Now().Add(-365 * 24 * time.Hour).UTC()
	manager := &IdentityManager{https: &testHTTPSFetcher{responses: map[string]json.RawMessage{
		statusURL: json.RawMessage(`{"state":"ACTIVE","lastTransitionAt":"` + transition.Format(time.RFC3339Nano) + `"}`),
	}}}

	status, _, err := manager.fetchAgentStatus(context.Background(), statusURL)
	if err != nil {
		t.Fatalf("fetchAgentStatus rejected a freshly fetched long-lived ACTIVE status: %v", err)
	}
	if !status.LastTransitionAt.Equal(transition) {
		t.Fatalf("LastTransitionAt = %v, want %v", status.LastTransitionAt, transition)
	}
}

func TestFetchAgentStatus_RejectsFutureTransition(t *testing.T) {
	const statusURL = "https://agent.example/status"
	transition := time.Now().Add(time.Hour).UTC()
	manager := &IdentityManager{https: &testHTTPSFetcher{responses: map[string]json.RawMessage{
		statusURL: json.RawMessage(`{"state":"ACTIVE","lastTransitionAt":"` + transition.Format(time.RFC3339Nano) + `"}`),
	}}}

	_, _, err := manager.fetchAgentStatus(context.Background(), statusURL)
	var verificationErr *VerificationError
	if !errors.As(err, &verificationErr) || verificationErr.Code() != VerificationCodeStatusNotActive {
		t.Fatalf("future transition error = %v, want status_not_active", err)
	}
}

func TestVerifiedDomainExpiry_HasNoStatusFreshnessCap(t *testing.T) {
	now := time.Now()
	want := now.Add(48 * time.Hour)
	if got := verifiedDomainExpiry(now, 48*time.Hour, "", time.Time{}, nil, nil); !got.Equal(want) {
		t.Fatalf("Expiry = %v, want DNS TTL deadline %v", got, want)
	}
}

func TestVerifyLogEvidence_IsCallerControlled(t *testing.T) {
	at := time.Unix(1782345600, 0).UTC()
	reader := &testLogReader{nonRevocationEvidence: dnsidlog.LoggedStateEvidence{CompleteThrough: "42"}}
	cache := NewIdentityCache(time.Hour)
	manager := &IdentityManager{verification: VerificationConfig{StatusCheckInterval: time.Hour}, cache: cache}
	cache.put(&VerifiedDomain{
		dnsTTL: time.Hour, dnsExpiresAt: time.Now().Add(time.Hour),
		domain:            "agent.example",
		record:            &TXTRecord{Flags: []string{string(PolicyFlagLogCheck)}},
		status:            &AgentStatus{State: AgentStateActive, LastTransitionAt: time.Now().Add(-365 * 24 * time.Hour)},
		lastStatusCheckAt: time.Now(),
		logReader:         reader,
		expiry:            time.Now().Add(time.Hour),
	}, manager)

	vd, err := manager.VerifyDomain(context.Background(), "agent.example")
	if err != nil {
		t.Fatalf("VerifyDomain: %v", err)
	}
	if !vd.RequiresLogCheck() {
		t.Fatal("RequiresLogCheck = false, want true")
	}
	if reader.nonRevocationCalls != 0 {
		t.Fatalf("VerifyDomain performed %d operation-level log checks", reader.nonRevocationCalls)
	}

	evidence, err := vd.VerifyLogEvidence(context.Background(), at)
	if err != nil {
		t.Fatalf("VerifiedDomain.VerifyLogEvidence: %v", err)
	}
	if evidence.CompleteThrough != "42" || reader.nonRevocationCalls != 1 || !reader.nonRevocationAt.Equal(at) {
		t.Fatalf("VerifyLogEvidence = %#v, calls=%d, at=%v", evidence, reader.nonRevocationCalls, reader.nonRevocationAt)
	}

	reader.revoked = true
	before := time.Now()
	_, err = manager.VerifyLogEvidence(context.Background(), vd, time.Time{})
	var verificationErr *VerificationError
	if !errors.As(err, &verificationErr) || verificationErr.Code() != VerificationCodeLogError {
		t.Fatalf("revocation error = %v, want log_error", err)
	}
	if reader.nonRevocationAt.Before(before) {
		t.Fatalf("zero at used %v, want current time", reader.nonRevocationAt)
	}
}

func TestVerifiedDomainRequiresLogCheck_NilSafe(t *testing.T) {
	var vd *VerifiedDomain
	if vd.RequiresLogCheck() {
		t.Fatal("nil VerifiedDomain requires log check")
	}
}
