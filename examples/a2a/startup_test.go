package main

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
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
	"syscall"
	"testing"
	"time"

	dnsid "github.com/dnsid-ai/dnsid-go"
	"github.com/dnsid-ai/dnsid-go/config"
	dnsidlog "github.com/dnsid-ai/dnsid-go/log"
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
			rh := dnsmessage.ResourceHeader{Name: q.Name, Type: q.Type, Class: dnsmessage.ClassINET, TTL: 0}
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
	f := &startupFixture{unavailable: make(chan struct{}, 1), release: make(chan struct{})}
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
			case <-f.release:
				_ = json.NewEncoder(w).Encode(map[string]any{"state": "ACTIVE", "lastTransitionAt": time.Now().UTC()})
			case <-r.Context().Done():
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
