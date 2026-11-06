package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	dnsid "github.com/dnsid-ai/dnsid-go"
	"github.com/dnsid-ai/dnsid-go/config"
	"github.com/dnsid-ai/dnsid-go/httpsig"
	dnsidlog "github.com/dnsid-ai/dnsid-go/log"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"golang.org/x/net/dns/dnsmessage"
)

// Accepting lifecycle evidence is deliberately fake: these tests exercise real
// owner/operational crypto and transport, NOT C2SP inclusion/checkpoint proof.
type startupLog struct{}

func (*startupLog) Canonical(dnsidlog.LogEvent) ([]byte, error) { return nil, nil }
func (*startupLog) KeyTimestamp(context.Context, string, string) (time.Time, error) {
	return time.Now(), nil
}
func (*startupLog) VerifyBilateralBinding(context.Context, dnsidlog.BilateralBindingInput) (dnsidlog.BilateralBinding, error) {
	return dnsidlog.BilateralBinding{}, nil
}
func (*startupLog) VerifyOperationalContinuity(context.Context, string, string, string) error {
	return nil
}
func (*startupLog) VerifyGovernanceRelationship(context.Context, string, string) error { return nil }
func (*startupLog) VerifyNonRevocation(context.Context, string, time.Time) (dnsidlog.LoggedStateEvidence, error) {
	return dnsidlog.LoggedStateEvidence{}, nil
}
func (*startupLog) ReadEvent(context.Context, dnsidlog.LogRef) (dnsidlog.LogEvent, error) {
	return dnsidlog.LogEvent{}, nil
}
func (*startupLog) RebuildHistory(context.Context, string) ([]dnsidlog.LogEvent, error) {
	return nil, nil
}
func startupRegistry(t *testing.T) *dnsidlog.LogRegistry {
	t.Helper()
	r := dnsidlog.NewLogRegistry()
	if err := r.Register("algorand", func(string) dnsidlog.LogReader { return &startupLog{} }); err != nil {
		t.Fatal(err)
	}
	return r
}
func TestA2AStartupChild(t *testing.T) {
	if os.Getenv("DNSID_TEST_A2A_CHILD") != "1" {
		t.Skip("subprocess entry only")
	}
	os.Args = os.Args[:1]
	if peer := os.Getenv("DNSID_TEST_PEER"); peer != "" {
		os.Args = append(os.Args, peer)
	}
	if err := runWithDependencies(config.Dependencies{LogRegistry: startupRegistry(t)}); err != nil {
		fmt.Fprintln(os.Stderr, "a2a:", err)
		os.Exit(1)
	}
}

type startupFixture struct {
	env         []string
	client      *http.Client
	base        string
	unavailable chan struct{}
	release     chan struct{}
	once        sync.Once
	mode        atomic.Value
	statusRead  chan struct{}
	observed    chan struct{}
	stop        func()
	manager     *dnsid.IdentityManager
	keys        dnsid.KeyProvider
	public      string
	childURL    string
	other       any
}

func (f *startupFixture) publish() { f.once.Do(func() { close(f.release) }) }
func startupDNS(t *testing.T, record string) string {
	t.Helper()
	c, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	go func() {
		b := make([]byte, 4096)
		for {
			n, a, err := c.ReadFrom(b)
			if err != nil {
				return
			}
			var p dnsmessage.Parser
			h, err := p.Start(b[:n])
			if err != nil {
				continue
			}
			q, err := p.Question()
			if err != nil {
				continue
			}
			m := dnsmessage.Message{Header: dnsmessage.Header{ID: h.ID, Response: true, RecursionAvailable: true}, Questions: []dnsmessage.Question{q}}
			rh := dnsmessage.ResourceHeader{Name: q.Name, Type: q.Type, Class: dnsmessage.ClassINET, TTL: 60}
			switch q.Type {
			case dnsmessage.TypeA:
				m.Answers = []dnsmessage.Resource{{Header: rh, Body: &dnsmessage.AResource{A: [4]byte{127, 0, 0, 1}}}}
			case dnsmessage.TypeTXT:
				if q.Name.String() == "_dnsid.example.com." {
					var chunks []string
					for s := record; s != ""; {
						n := min(200, len(s))
						chunks = append(chunks, s[:n])
						s = s[n:]
					}
					m.Answers = []dnsmessage.Resource{{Header: rh, Body: &dnsmessage.TXTResource{TXT: chunks}}}
				}
			}
			wire, err := m.Pack()
			if err == nil {
				_, _ = c.WriteTo(wire, a)
			}
		}
	}()
	return c.LocalAddr().String()
}
func newStartupFixture(t *testing.T) *startupFixture {
	t.Helper()
	f := &startupFixture{unavailable: make(chan struct{}, 1), release: make(chan struct{}), statusRead: make(chan struct{}, 1), observed: make(chan struct{}, 32)}
	f.mode.Store("valid")
	t.Cleanup(f.publish)
	// Reserve a child listener address, then close it: ku is genuinely refused
	// before the actual run starts (no alternate application success handler).
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	_ = l.Close()
	upstream, _ := url.Parse(fmt.Sprintf("http://127.0.0.1:%d", port))
	f.childURL = upstream.String()
	proxy := httputil.NewSingleHostReverseProxy(upstream)
	proxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
		select {
		case f.unavailable <- struct{}{}:
		default:
		}
		http.Error(w, "child unavailable", http.StatusBadGateway)
	}
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "private.jwk")
	kp, err := dnsid.LoadOrCreateLocalKeyProvider(keyPath, dnsid.JoseAlgES256)
	if err != nil {
		t.Fatal(err)
	}
	owner := dnsid.GenerateES256KeyProvider()
	var entity any
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/ek":
			_ = json.NewEncoder(w).Encode(entity)
		case "/status":
			select {
			case f.statusRead <- struct{}{}:
			default:
			}
			select {
			case <-f.release:
				_ = json.NewEncoder(w).Encode(map[string]any{"state": "ACTIVE", "lastTransitionAt": time.Now().UTC()})
			case <-r.Context().Done():
			}
		case "/.well-known/jwks.json":
			switch f.mode.Load().(string) {
			case "mismatch":
				_ = json.NewEncoder(w).Encode(f.other)
			case "corrupt":
				_, _ = w.Write([]byte(`{"keys":`))
			case "unavailable":
				http.Error(w, "publication unavailable", 503)
			default:
				proxy.ServeHTTP(w, r)
			}
			select {
			case f.observed <- struct{}{}:
			default:
			}
		default:
			proxy.ServeHTTP(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	f.base = srv.URL
	public := strings.Replace(srv.URL, "127.0.0.1", "example.com", 1)
	id := &dnsid.IdentityConfig{Domain: "example.com", GovernanceID: "example.com", LogRef: "algorand:ADDR", KeyURL: public + "/.well-known/jwks.json", EntityKeyURL: public + "/ek", StatusURL: public + "/status"}
	m, err := dnsid.NewIdentityManager(dnsid.Config{Identity: id}, kp, dnsid.WithEntityKeyProvider(owner))
	if err != nil {
		t.Fatal(err)
	}
	entity = m.GetEntityKeySet().Raw()
	rec, err := m.CreateTXTRecord()
	if err != nil {
		t.Fatal(err)
	}
	// Draft-01 sg is bare base64url; do not manufacture an alg: prefix.
	if strings.ContainsAny(rec.Signature, ":=") {
		t.Fatal("owner record signature is not draft-01 bare base64url")
	}
	ca := filepath.Join(dir, "ca.pem")
	if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}), 0600); err != nil {
		t.Fatal(err)
	}
	f.client = srv.Client()
	f.client.Timeout = 2 * time.Second
	f.keys = kp
	f.public = public
	// The alternative publication is independently owner-valid and has a
	// different operational thumbprint, even though its kid is copied below.
	otherKey := dnsid.GenerateES256KeyProvider().JWK()
	kid, _ := kp.JWK().KeyID()
	if err := otherKey.Set(jwk.KeyIDKey, kid); err != nil {
		t.Fatal(err)
	}
	otherSet := jwk.NewSet()
	if err := otherSet.AddKey(otherKey); err != nil {
		t.Fatal(err)
	}
	f.other = otherSet
	f.manager, err = dnsid.NewIdentityManager(dnsid.Config{Transport: dnsid.TransportConfig{DNSServer: startupDNS(t, rec.Serialize()), CABundlePath: ca, PrivateAddressHosts: []string{"example.com"}}}, nil, dnsid.WithLogRegistry(startupRegistry(t)))
	if err != nil {
		t.Fatal(err)
	}
	f.env = []string{"DNSID_TEST_A2A_CHILD=1", "DNSID_DOMAIN=example.com", "DNSID_GOVERNANCE_ID=example.com", "DNSID_LOG_REF=algorand:ADDR", "DNSID_KU_URL=" + id.KeyURL, "DNSID_EK_URL=" + id.EntityKeyURL, "DNSID_STATUS_URL=" + id.StatusURL, "DNSID_KEY_STORE=" + keyPath, "DNSID_AGENT_PORT=" + fmt.Sprint(port), "DNSID_CA_BUNDLE=" + ca, "DNSID_PRIVATE_HOSTS=example.com", "DNSID_DNS_SERVER=" + startupDNS(t, rec.Serialize())}
	return f
}
func (f *startupFixture) get(path string) (*http.Response, error) { return f.client.Get(f.base + path) }
func startA2A(t *testing.T, f *startupFixture) (<-chan error, func() string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	t.Cleanup(cancel)
	out, err := os.CreateTemp(t.TempDir(), "child-output")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = out.Close() })
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestA2AStartupChild$")
	for _, e := range os.Environ() {
		if !strings.HasPrefix(e, "DNSID_") {
			cmd.Env = append(cmd.Env, e)
		}
	}
	cmd.Env = append(cmd.Env, f.env...)
	cmd.Stdout = out
	cmd.Stderr = out
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	f.stop = func() { _ = cmd.Process.Signal(syscall.SIGTERM) }
	done := make(chan error, 1)
	exited := make(chan struct{})
	go func() { done <- cmd.Wait(); close(exited) }()
	t.Cleanup(func() {
		_ = cmd.Process.Signal(syscall.SIGTERM)
		select {
		case <-exited:
		case <-time.After(6 * time.Second):
			_ = cmd.Process.Kill()
			t.Error("child did not shut down within cancellation bound")
		}
	})
	return done, func() string { b, _ := os.ReadFile(out.Name()); return string(b) }
}

// Mode: fake-only DNS/HTTPS/lifecycle service; real owner signatures, persisted
// operational keys, TLS, SDK verification, subprocess and actual run listener.
// Given client-owned ku initially refused, When actual run starts, Then public
// JWKS becomes available before status publication is released.
func TestA2AStartup_BootstrapJWKSBeforePublication(t *testing.T) {
	f := newStartupFixture(t)
	resp, err := f.get("/.well-known/jwks.json")
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != 502 {
		t.Fatalf("pre-start ku status=%d want refused upstream 502", resp.StatusCode)
	}
	select {
	case <-f.unavailable:
	default:
		t.Fatal("ku refusal was not observed")
	}
	done, output := startA2A(t, f)
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	for {
		select {
		case err := <-done:
			t.Fatalf("actual run exited before bootstrap JWKS became available (publication still withheld): %v\n%s", err, output())
		case <-ctx.Done():
			t.Fatalf("bootstrap JWKS never became available before publication release: %s", output())
		default:
		}
		resp, err := f.get("/.well-known/jwks.json")
		if err == nil {
			body, _ := io.ReadAll(resp.Body)
			_ = resp.Body.Close()
			if resp.StatusCode == 200 {
				var set struct {
					Keys []json.RawMessage `json:"keys"`
				}
				if json.Unmarshal(body, &set) != nil || len(set.Keys) != 1 {
					t.Fatalf("bootstrap JWKS is not one public operational key: %s", body)
				}
				return
			}
		}
	}
}

func awaitBootstrap(t *testing.T, f *startupFixture, done <-chan error, output func() string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	for {
		select {
		case err := <-done:
			t.Fatalf("actual run exited before bootstrap JWKS became available: %v\n%s", err, output())
		case <-ctx.Done():
			t.Fatalf("bootstrap JWKS unavailable: %s", output())
		default:
		}
		r, err := (&http.Client{Timeout: time.Second}).Get(f.childURL + "/.well-known/jwks.json")
		if err == nil {
			_ = r.Body.Close()
			if r.StatusCode == 200 {
				return
			}
		}
	}
}
func (f *startupFixture) exchange(t *testing.T, path, method string, payload []byte) (*http.Response, *http.Request) {
	t.Helper()
	signer, err := dnsid.NewIdentityManager(dnsid.Config{Identity: &dnsid.IdentityConfig{Domain: "example.com", GovernanceID: "example.com", LogRef: "algorand:ADDR", KeyURL: f.public + "/.well-known/jwks.json", EntityKeyURL: f.public + "/ek", StatusURL: f.public + "/status"}}, f.keys)
	if err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequest(method, "https://example.com"+path, bytes.NewReader(payload))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("A2A-Version", "1.0")
	req.Header.Set("A2A-Extensions", extensionURI)
	signed, err := httpsig.NewFromIdentityManagerKeyProvider(signer, httpsig.Config{}).CreateSignedHTTPRequest(req, httpsig.SigningOptions{Label: "a2a", Tag: "a2a-dnsid-http-sig-v1", ExpiresIn: time.Minute, AdditionalComponents: []string{"content-type", "a2a-version", "a2a-extensions"}, ResponseSignature: &httpsig.ResponseSignatureOptions{ExpectedDomain: "example.com", AdditionalComponents: []httpsig.ComponentIdentifier{{Name: "content-type"}}}})
	if err != nil {
		t.Fatal(err)
	}
	wire := signed.Clone(signed.Context())
	u, _ := url.Parse(f.base + path)
	wire.URL = u
	resp, err := f.client.Do(wire)
	if err != nil {
		t.Fatal(err)
	}
	return resp, signed
}
func assertNoApplicationSignature(t *testing.T, f *startupFixture) {
	t.Helper()
	for _, path := range []string{agentCardPath, "/"} {
		method := http.MethodGet
		if path == "/" {
			method = http.MethodPost
		}
		r, _ := f.exchange(t, path, method, []byte(`{"jsonrpc":"2.0","id":"probe","method":"SendMessage","params":{"message":{"messageId":"probe","role":"ROLE_USER","parts":[{"text":"must not echo"}]}}}`))
		b, _ := io.ReadAll(r.Body)
		_ = r.Body.Close()
		if r.StatusCode/100 == 2 || r.Header.Get("Signature") != "" || r.Header.Get("Signature-Input") != "" || bytes.Contains(b, []byte(`"signatures"`)) || bytes.Contains(b, []byte(`verified sender`)) {
			t.Fatalf("unbound application route %s authorized/signs: status=%d headers=%v body=%s", path, r.StatusCode, r.Header, b)
		}
	}
}
func assertStopped(t *testing.T, f *startupFixture, done <-chan error, output func() string) {
	t.Helper()
	f.stop()
	select {
	case <-done:
	case <-time.After(6 * time.Second):
		t.Fatalf("cancellation did not bound shutdown: %s", output())
	}
	r, err := f.get("/.well-known/jwks.json")
	if err == nil {
		_ = r.Body.Close()
		if r.StatusCode != 502 {
			t.Fatalf("listener survived child shutdown: HTTP %d", r.StatusCode)
		}
	}
}

// Mode: fake-only lifecycle/DNS/HTTPS fixture. Given withheld status evidence,
// When publication is explicitly released, Then actual run progresses from
// unsigned bootstrap to an owner-bound signed card and authenticated echo.
func TestA2AStartup_ReleasedPublicationEnablesSignedExchange(t *testing.T) {
	f := newStartupFixture(t)
	done, output := startA2A(t, f)
	awaitBootstrap(t, f, done, output)
	select {
	case <-f.statusRead:
	case <-time.After(5 * time.Second):
		t.Fatal("verification never requested status evidence")
	}
	assertNoApplicationSignature(t, f)
	f.publish()
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	var card []byte
	for {
		r, _ := f.exchange(t, agentCardPath, http.MethodGet, nil)
		body, _ := io.ReadAll(r.Body)
		_ = r.Body.Close()
		if r.StatusCode == 200 {
			card = body
			break
		}
		select {
		case err := <-done:
			t.Fatalf("run exited before authenticated readiness: %v\n%s", err, output())
		case <-ctx.Done():
			t.Fatalf("signed card never ready: %s", output())
		default:
		}
	}
	// Verify the detached card JWS with the independently selected public key,
	// not with a key copied from the returned card or a fake signature verifier.
	var object map[string]any
	if err := json.Unmarshal(card, &object); err != nil {
		t.Fatal(err)
	}
	sigs, ok := object["signatures"].([]any)
	if !ok || len(sigs) != 1 {
		t.Fatalf("card missing one detached signature: %s", card)
	}
	sig := sigs[0].(map[string]any)
	delete(object, "signatures")

	protected := sig["protected"].(string)
	raw, err := base64.RawURLEncoding.DecodeString(sig["signature"].(string))
	if err != nil || len(raw) != 64 {
		t.Fatal("invalid card signature encoding")
	}
	// Card normalization removes empty protobuf fields. Returned card retains
	// those fields, so apply its documented normalization before crypto check.
	canonical, err := canonicalizeAgentCard(object)
	if err != nil {
		t.Fatal(err)
	}
	hash := sha256.Sum256([]byte(protected + "." + base64.RawURLEncoding.EncodeToString(canonical)))
	var pub ecdsa.PublicKey
	if err := jwk.Export(f.keys.JWK(), &pub); err != nil {
		t.Fatal(err)
	}
	if !ecdsa.Verify(&pub, hash[:], new(big.Int).SetBytes(raw[:32]), new(big.Int).SetBytes(raw[32:])) {
		t.Fatal("agent card signature failed independent ES256 verification")
	}
	r, req := f.exchange(t, "/", http.MethodPost, []byte(`{"jsonrpc":"2.0","id":"roundtrip","method":"SendMessage","params":{"message":{"messageId":"msg","role":"ROLE_USER","parts":[{"text":"real crypto hello"}]}}}`))
	vd, err := httpsig.NewFromIdentityManager(f.manager, nil, httpsig.Config{}).VerifySignedHTTPResponse(context.Background(), req, r, httpsig.ResponseSignatureOptions{ExpectedDomain: "example.com", AdditionalComponents: []httpsig.ComponentIdentifier{{Name: "content-type"}}})
	if err != nil {
		t.Fatalf("authenticated response verification: %v", err)
	}
	defer r.Body.Close()
	body, _ := io.ReadAll(r.Body)
	if r.StatusCode != 200 || vd.Domain() != "example.com" || !bytes.Contains(body, []byte("verified sender: example.com")) || !bytes.Contains(body, []byte("real crypto hello")) {
		t.Fatalf("authenticated echo missing: status=%d body=%s", r.StatusCode, body)
	}
	assertStopped(t, f, done, output)
}

// Mode: fake-only. Each release moves a blocked real verification attempt to
// explicit invalid evidence; a subsequent KU observation is the progress fence,
// never a sleep. Application probes negotiate real response signatures.
func TestA2AStartup_InvalidPublicationNeverAuthorizes(t *testing.T) {
	for _, mode := range []string{"mismatch", "corrupt", "unavailable"} {
		t.Run(mode, func(t *testing.T) {
			f := newStartupFixture(t)
			f.mode.Store(mode)
			done, output := startA2A(t, f)
			awaitBootstrap(t, f, done, output)
			// Malformed/unreachable ku may cancel the concurrent status read
			// before it starts; only valid-but-mismatched ku needs that fence.
			if mode == "mismatch" {
				select {
				case <-f.statusRead:
				case <-time.After(5 * time.Second):
					t.Fatal("verification never requested status")
				}
			}
			assertNoApplicationSignature(t, f)
			for len(f.observed) > 0 {
				<-f.observed
			}
			f.mode.Store(mode)
			f.publish()
			select {
			case <-f.observed:
			case err := <-done:
				t.Fatalf("run terminated instead of bounded publication retry: %v\n%s", err, output())
			case <-time.After(5 * time.Second):
				t.Fatal("no fresh KU read after fixture release")
			}
			assertNoApplicationSignature(t, f)
			assertStopped(t, f, done, output)
		})
	}
}

// Mode: fake-only. Given publication never releases, When SIGTERM cancels the
// actual run, Then no signed application readiness and no listener survives.
func TestA2AStartup_CancelBeforePublication(t *testing.T) {
	f := newStartupFixture(t)
	done, output := startA2A(t, f)
	awaitBootstrap(t, f, done, output)
	assertNoApplicationSignature(t, f)
	assertStopped(t, f, done, output)
}
