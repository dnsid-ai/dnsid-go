package webbotauth

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/dnsid-ai/dnsid-go"
	"github.com/dnsid-ai/dnsid-go/internal/netguard"
)

type conformanceMessage struct {
	Method     string
	URL        string
	Status     int
	Headers    map[string]string
	BodyBase64 *string
}

func (m conformanceMessage) body(t *testing.T) []byte {
	t.Helper()
	if m.BodyBase64 == nil {
		return nil
	}
	body, err := base64.StdEncoding.DecodeString(*m.BodyBase64)
	if err != nil {
		t.Fatal(err)
	}
	return body
}

func (m conformanceMessage) request(t *testing.T) *http.Request {
	t.Helper()
	req, err := http.NewRequest(m.Method, m.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	if m.BodyBase64 != nil {
		req.Body = io.NopCloser(bytes.NewReader(m.body(t)))
	}
	for name, value := range m.Headers {
		req.Header.Set(name, value)
	}
	return req
}

type conformanceScenario struct {
	Now, FinishedAt                                int64
	ClockSkew                                      int64
	SignerDomain, TrustedDiscoveryURI              string
	DNSidExists, AcceptanceAllowed                 bool
	CurrentKu                                      []map[string]any
	CacheHit                                       bool
	CachedAt                                       int64
	ResolvedAddresses                              []string
	Redirects                                      []struct{ URL string }
	DirectoryTLSValid, RequiresMTLS                bool
	ReplayEnabled, NonceSeen, ReplayStoreAvailable bool
}

func conformanceTLS(t *testing.T, domain string) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), DNSNames: []string{domain},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

func TestWBA_SharedVerificationVectors(t *testing.T) {
	data, err := os.ReadFile("../testdata/webbotauth/web-bot-auth.json")
	if err != nil {
		t.Fatal(err)
	}
	var corpus struct {
		Domain                string
		Key                   map[string]any
		VerificationDefaults  json.RawMessage
		Requests, Directories map[string]struct{ Message conformanceMessage }
		VerificationCases     []struct {
			ID    string
			Input struct {
				Request, Directory string
				Verification       json.RawMessage
			}
			Expect struct {
				OK           bool
				SignerDomain string
			}
		}
	}
	if err := json.Unmarshal(data, &corpus); err != nil {
		t.Fatal(err)
	}
	corpus.Key["d"], corpus.Key["alg"], corpus.Key["use"] = corpus.Key["seed"], "EdDSA", "sig"
	delete(corpus.Key, "seed")
	keyJSON, _ := json.Marshal(corpus.Key)
	keyPath := filepath.Join(t.TempDir(), "key.json")
	if err := os.WriteFile(keyPath, keyJSON, 0600); err != nil {
		t.Fatal(err)
	}
	kp, err := dnsid.NewLocalKeyProvider(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range corpus.VerificationCases {
		t.Run(tc.ID, func(t *testing.T) {
			var scenario conformanceScenario
			if err := json.Unmarshal(corpus.VerificationDefaults, &scenario); err != nil {
				t.Fatal(err)
			}
			if err := json.Unmarshal(tc.Input.Verification, &scenario); err != nil {
				t.Fatal(err)
			}
			if scenario.CacheHit && scenario.CachedAt < scenario.Now {
				t.Skip("directory HTTP-cache reuse is not supported; repeated fresh discovery is tested instead")
			}
			f := newWBAFixtureWithKey(t, !scenario.AcceptanceAllowed && !scenario.CacheHit, scenario.RequiresMTLS, corpus.Domain, kp)
			request := corpus.Requests[tc.Input.Request].Message
			directory := corpus.Directories[tc.Input.Directory].Message
			var clock atomic.Int64
			clock.Store(scenario.Now)
			f.checker.now = func() time.Time { return time.Unix(clock.Load(), 0) }
			f.checker.cfg = Config{}.WithClockSkew(time.Duration(scenario.ClockSkew) * time.Second)
			f.opts.SignerDomain = scenario.SignerDomain
			f.opts.DirectoryURL = "https://" + corpus.Domain + DirectoryPath
			var discoveries atomic.Int64
			server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				discoveries.Add(1)
				clock.Store(scenario.FinishedAt)
				if len(scenario.Redirects) > 0 {
					w.Header().Set("Location", scenario.Redirects[0].URL)
					w.WriteHeader(http.StatusFound)
					return
				}
				for name, value := range directory.Headers {
					w.Header().Set(name, value)
				}
				w.WriteHeader(directory.Status)
				_, _ = w.Write(directory.body(t))
			}))
			server.TLS = &tls.Config{Certificates: []tls.Certificate{conformanceTLS(t, corpus.Domain)}}
			server.StartTLS()
			defer server.Close()
			base := server.Client().Transport.(*http.Transport).Clone()
			if !scenario.DirectoryTLSValid {
				base.TLSClientConfig = nil
			}
			resolve := func(context.Context, string) ([]net.IPAddr, error) {
				var addresses []net.IPAddr
				for _, address := range scenario.ResolvedAddresses {
					addresses = append(addresses, net.IPAddr{IP: net.ParseIP(address)})
				}
				return addresses, nil
			}
			transport := netguard.SafeDialerTransportFrom(base, resolve,
				func(ctx context.Context, network, _ string) (net.Conn, error) {
					return (&net.Dialer{}).DialContext(ctx, network, server.Listener.Addr().String())
				}, netguard.Policy{})
			transport.DisableCompression = true
			defer transport.CloseIdleConnections()
			f.checker.client.Transport = transport
			seen := map[string]bool{}
			if scenario.ReplayEnabled {
				f.opts.Replay = func(_ context.Context, domain, keyID, nonce string, until time.Time) error {
					if !scenario.ReplayStoreAvailable {
						return errors.New("replay store unavailable")
					}
					key := domain + "/" + keyID + "/" + nonce
					if seen[key] {
						return errors.New("nonce already used")
					}
					seen[key] = true
					return nil
				}
			}
			if scenario.CacheHit || scenario.NonceSeen {
				if _, err := f.checker.VerifyWebBotAuthSignedRequest(context.Background(), request.request(t), f.opts); err != nil {
					t.Fatalf("warm-up: %v", err)
				}
			}
			kuURI := f.dns.record.KeyURI
			if !scenario.DNSidExists {
				f.dns.record = nil
			}
			if scenario.CacheHit && !scenario.AcceptanceAllowed {
				f.checker.resolver = newWBAFixtureWithKey(t, true, false, corpus.Domain, kp).manager
			}
			keys := make([]map[string]any, len(scenario.CurrentKu))
			for i, public := range scenario.CurrentKu {
				key := make(map[string]any, len(public)+2)
				for name, value := range public {
					key[name] = value
				}
				key["alg"], key["kid"] = "EdDSA", "fixture-ku"
				keys[i] = key
			}
			ku, _ := json.Marshal(map[string]any{"keys": keys})
			f.https.documents[kuURI] = ku
			f.manager.EvictDomain(corpus.Domain)
			vd, err := f.checker.VerifyWebBotAuthSignedRequest(context.Background(), request.request(t), f.opts)
			if (err == nil) != tc.Expect.OK {
				t.Fatalf("expected ok=%v, got %v", tc.Expect.OK, err)
			}
			if tc.Expect.OK && (vd == nil || vd.Domain() != tc.Expect.SignerDomain) {
				t.Fatal("wrong verified signer")
			}
			var argumentErr *dnsid.ArgumentError
			if !tc.Expect.OK && errors.As(err, &argumentErr) {
				t.Fatalf("adapter argument failure is not verification coverage: %v", err)
			}
			if scenario.CacheHit && discoveries.Load() != 2 {
				t.Fatalf("expected two fresh discoveries, got %d", discoveries.Load())
			}
		})
	}
}
