package webbotauth

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/dnsid-ai/dnsid-go"
	"github.com/dnsid-ai/dnsid-go/httpsig"
	dnsidlog "github.com/dnsid-ai/dnsid-go/log"
)

type wbaDNS struct{ record *dnsid.TXTRecord }

func (d wbaDNS) FetchTXT(context.Context, string) ([]dnsid.TXTRecordRData, dnsid.DNSSECState, error) {
	return []dnsid.TXTRecordRData{{Value: d.record.Serialize(), TTL: time.Minute}}, dnsid.DNSSECStateUnsigned, nil
}

type wbaHTTPS map[string]json.RawMessage

func (h wbaHTTPS) FetchJSON(_ context.Context, uri string, _ dnsid.FetchOptions) (json.RawMessage, *tls.Certificate, error) {
	return h[uri], nil, nil
}

type wbaLog struct{}

func (wbaLog) Canonical(dnsidlog.LogEvent) ([]byte, error) { return nil, nil }
func (wbaLog) KeyTimestamp(context.Context, string, string) (time.Time, error) {
	return time.Now(), nil
}
func (wbaLog) VerifyBilateralBinding(context.Context, dnsidlog.BilateralBindingInput) (dnsidlog.BilateralBinding, error) {
	return dnsidlog.BilateralBinding{}, nil
}
func (wbaLog) VerifyOperationalContinuity(context.Context, string, string, string) error { return nil }
func (wbaLog) VerifyGovernanceRelationship(context.Context, string, string) error        { return nil }
func (wbaLog) VerifyNonRevocation(context.Context, string, time.Time) (dnsidlog.LoggedStateEvidence, error) {
	return dnsidlog.LoggedStateEvidence{}, nil
}
func (wbaLog) ReadEvent(context.Context, dnsidlog.LogRef) (dnsidlog.LogEvent, error) {
	return dnsidlog.LogEvent{}, nil
}
func (wbaLog) RebuildHistory(context.Context, string) ([]dnsidlog.LogEvent, error) { return nil, nil }

type wbaRoundTrip func(*http.Request) (*http.Response, error)

func (f wbaRoundTrip) RoundTrip(req *http.Request) (*http.Response, error) { return f(req) }

type wbaFixture struct {
	signer  *Profile
	checker *Profile
	request *http.Request
	manager *dnsid.IdentityManager
	opts    VerificationOptions
}

func newWBAFixture(t *testing.T, denied, mtls bool) *wbaFixture {
	t.Helper()
	kp, ek := dnsid.GenerateEd25519KeyProvider(), dnsid.GenerateEd25519KeyProvider()
	identity := &dnsid.IdentityConfig{Domain: "bot.example.com", GovernanceID: "example.com", LogRef: "test:agent", KeyURL: "https://bot.example.com/ku", EntityKeyURL: "https://example.com/ek", StatusURL: "https://bot.example.com/status"}
	if mtls {
		identity.PolicyFlags = []dnsid.PolicyFlag{dnsid.PolicyFlagMTLS}
	}
	issuer, err := dnsid.NewIdentityManager(dnsid.Config{Identity: identity}, kp, dnsid.WithEntityKeyProvider(ek))
	if err != nil {
		t.Fatal(err)
	}
	record, err := issuer.CreateTXTRecord()
	if err != nil {
		t.Fatal(err)
	}
	ku, _ := json.Marshal(issuer.GetKeySet().Raw())
	entity, _ := json.Marshal(issuer.GetEntityKeySet().Raw())
	registry := dnsidlog.NewLogRegistry()
	if err := registry.Register("test", func(string) dnsidlog.LogReader { return wbaLog{} }); err != nil {
		t.Fatal(err)
	}
	cfg := dnsid.Config{}
	if denied {
		cfg.Verification.TrustedEntities = []dnsid.TrustedEntity{}
	}
	manager, err := dnsid.NewIdentityManager(cfg, nil, dnsid.WithDNSResolver(wbaDNS{record}), dnsid.WithHTTPSFetcher(wbaHTTPS{
		record.KeyURI: ku, record.EntityKeyURI: entity, record.StatusURI: json.RawMessage(`{"state":"ACTIVE","lastTransitionAt":"` + time.Now().UTC().Format(time.RFC3339Nano) + `"}`),
	}), dnsid.WithLogRegistry(registry))
	if err != nil {
		t.Fatal(err)
	}
	signer := NewFromIdentityManager(issuer, Config{})
	checker := NewVerifier(manager, Config{})
	checker.client = &http.Client{Transport: wbaRoundTrip(func(req *http.Request) (*http.Response, error) {
		return signer.ServeHttpMessageSignaturesDirectory(req)
	})}
	req, _ := http.NewRequest(http.MethodPost, "https://target.example/path", strings.NewReader("hello"))
	signed, err := signer.CreateWebBotAuthSignedRequest(req, SigningOptions{})
	if err != nil {
		t.Fatal(err)
	}
	return &wbaFixture{signer, checker, signed, manager, VerificationOptions{SignerDomain: "bot.example.com"}}
}

func TestProfile_VerifyWebBotAuthSignedRequest(t *testing.T) {
	f := newWBAFixture(t, false, false)
	for i := 0; i < 2; i++ {
		vd, err := f.checker.VerifyWebBotAuthSignedRequest(context.Background(), f.request, f.opts)
		if err != nil {
			t.Fatal(err)
		}
		if vd.Domain() != f.opts.SignerDomain {
			t.Fatal(vd.Domain())
		}
		body, _ := io.ReadAll(f.request.Body)
		if string(body) != "hello" {
			t.Fatal(string(body))
		}
		f.request.Body = io.NopCloser(bytes.NewReader(body))
	}
}

func TestProfile_WBANonDefaultLabelsAndOptionalDiscovery(t *testing.T) {
	for _, mode := range []string{"different-label", "default-type", "directory-path", "jwks-uri", "no-agent", "origin-policy"} {
		t.Run(mode, func(t *testing.T) {
			f := newWBAFixture(t, false, false)
			inputs, _ := httpsig.ParseSignatureInput(f.request.Header.Get("Signature-Input"))
			params := inputs["sig1"]
			params.Parameters = nil
			switch mode {
			case "different-label":
				f.checker.client = &http.Client{Transport: wbaRoundTrip(func(req *http.Request) (*http.Response, error) {
					res, err := f.signer.ServeHttpMessageSignaturesDirectory(req)
					if err != nil {
						return nil, err
					}
					inputs, _ := httpsig.ParseSignatureInput(res.Header.Get("Signature-Input"))
					directory := inputs["sig1"]
					directory.Label = "directory"
					res.Header.Del("Signature-Input")
					res.Header.Del("Signature")
					return res, httpsig.SignHTTPMessage(res, directory, f.signer.keys)
				})}
				params.Label = "bot"
				f.request.Header.Del("Signature-Input")
				f.request.Header.Del("Signature")
				f.request.Header.Set("Signature-Agent", `agent="https://bot.example.com";type=directory`)
				for i, c := range params.Components {
					if c.Name == "signature-agent" {
						params.Components[i].Params["key"] = "agent"
					}
				}
			case "default-type":
				f.request.Header.Set("Signature-Agent", `sig1="https://bot.example.com"`)
			case "directory-path":
				f.request.Header.Set("Signature-Agent", `sig1="https://bot.example.com/ignored?q=x#fragment";type=directory`)
			case "jwks-uri":
				f.request.Header.Set("Signature-Agent", `sig1="https://bot.example.com/custom";type=jwks_uri`)
			case "no-agent":
				f.request.Header.Del("Signature-Agent")
				params.Components = params.Components[:2]
			case "origin-policy":
				f.opts.SignerDomain = ""
				f.opts.AllowSignatureAgentDomain = true
			}
			if err := httpsig.SignHTTPMessage(f.request, params, f.signer.keys); err != nil {
				t.Fatal(err)
			}
			if _, err := f.checker.VerifyWebBotAuthSignedRequest(context.Background(), f.request, f.opts); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestProfile_WBARejectsInvalidEvidence(t *testing.T) {
	for _, mode := range []string{"request-signature", "request-content", "request-tag", "request-thumbprint", "request-expired", "request-lifetime", "request-created", "request-coverage", "agent-coverage", "untrusted-origin", "cross-host", "directory-signature", "directory-content", "directory-tag", "directory-thumbprint", "directory-expired", "directory-coverage", "directory-status", "directory-type", "directory-only", "rotated-key", "ambiguous", "cancelled", "mtls"} {
		t.Run(mode, func(t *testing.T) {
			f := newWBAFixture(t, false, mode == "mtls")
			ctx := context.Background()
			inputs, _ := httpsig.ParseSignatureInput(f.request.Header.Get("Signature-Input"))
			params := inputs["sig1"]
			params.Parameters = nil
			switch mode {
			case "request-signature":
				f.request.Header.Set("Signature", "sig1=:AAAA:")
			case "request-content":
				f.request.Body = io.NopCloser(strings.NewReader("changed"))
			case "request-tag":
				params.Tag = "other"
			case "request-thumbprint":
				params.KeyID = "bad"
			case "request-expired":
				params.Created = time.Now().Add(-time.Hour).Unix()
				params.Expires = params.Created + 60
			case "request-lifetime":
				params.Expires = params.Created + 301
			case "request-created":
				params.Created = 0
			case "request-coverage":
				params.Components = params.Components[1:]
			case "agent-coverage":
				params.Components = params.Components[:2]
			case "untrusted-origin":
				f.opts.SignerDomain = ""
			case "cross-host":
				f.opts.SignerDomain = "other.example"
			case "directory-only":
				f.checker.resolver = wbaResolverFunc(func(context.Context, string) (*dnsid.VerifiedDomain, error) {
					return nil, errors.New("no DNSid identity")
				})
			case "rotated-key":
				other := newWBAFixture(t, false, false)
				f.checker.resolver = other.manager
			case "ambiguous":
				params.Label = "other"
			case "cancelled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}
			if strings.HasPrefix(mode, "request-") && mode != "request-signature" && mode != "request-content" || mode == "agent-coverage" || mode == "ambiguous" {
				f.request.Header.Del("Signature-Input")
				if mode == "ambiguous" {
					original, _ := f.signer.CreateWebBotAuthSignedRequest(f.request, SigningOptions{})
					f.request = original
				}
				if err := httpsig.SignHTTPMessage(f.request, params, f.signer.keys); err != nil {
					t.Fatal(err)
				}
			}
			if strings.HasPrefix(mode, "directory-") && mode != "directory-only" {
				f.checker.client = &http.Client{Transport: wbaRoundTrip(func(req *http.Request) (*http.Response, error) {
					res, err := f.signer.ServeHttpMessageSignaturesDirectory(req)
					if err != nil {
						return nil, err
					}
					inputs, _ := httpsig.ParseSignatureInput(res.Header.Get("Signature-Input"))
					dp := inputs["sig1"]
					dp.Parameters = nil
					switch mode {
					case "directory-signature":
						res.Header.Set("Signature", "sig1=:AAAA:")
					case "directory-content":
						res.Body = io.NopCloser(strings.NewReader(`{"keys":[]}`))
					case "directory-tag":
						dp.Tag = "other"
					case "directory-thumbprint":
						dp.KeyID = "bad"
					case "directory-expired":
						dp.Created = time.Now().Add(-time.Hour).Unix()
						dp.Expires = dp.Created + 60
					case "directory-coverage":
						dp.Components = dp.Components[1:]
					case "directory-status":
						res.StatusCode = 302
					case "directory-type":
						res.Header.Set("Content-Type", "application/json")
					}
					if mode == "directory-tag" || mode == "directory-thumbprint" || mode == "directory-expired" || mode == "directory-coverage" {
						res.Header.Del("Signature-Input")
						err = httpsig.SignHTTPMessage(res, dp, f.signer.keys)
					}
					return res, err
				})}
			}
			if _, err := f.checker.VerifyWebBotAuthSignedRequest(ctx, f.request, f.opts); err == nil {
				t.Fatal("invalid evidence accepted")
			}
		})
	}
}

type wbaResolverFunc func(context.Context, string) (*dnsid.VerifiedDomain, error)

func (f wbaResolverFunc) VerifyDomain(ctx context.Context, domain string) (*dnsid.VerifiedDomain, error) {
	return f(ctx, domain)
}

func TestProfile_WBAVerifiesServerRequestsWithExplicitDefaultPort(t *testing.T) {
	f := newWBAFixture(t, false, false)
	f.signer.cfg.DirectoryURL = "https://bot.example.com:443"
	f.checker.client = &http.Client{Transport: wbaRoundTrip(func(req *http.Request) (*http.Response, error) {
		serverReq := req.Clone(req.Context())
		serverReq.URL.Scheme, serverReq.URL.Host = "", ""
		serverReq.RequestURI = req.URL.RequestURI()
		serverReq.TLS = &tls.ConnectionState{}
		return f.signer.ServeHttpMessageSignaturesDirectory(serverReq)
	})}
	req, _ := http.NewRequest(http.MethodPost, "https://target.example:443/path", strings.NewReader("hello"))
	signed, err := f.signer.CreateWebBotAuthSignedRequest(req, SigningOptions{})
	if err != nil {
		t.Fatal(err)
	}
	signed.URL.Scheme, signed.URL.Host = "", ""
	signed.RequestURI = "/path"
	signed.TLS = &tls.ConnectionState{}
	if _, err := f.checker.VerifyWebBotAuthSignedRequest(context.Background(), signed, f.opts); err != nil {
		t.Fatal(err)
	}
}

func TestProfile_WBAAcceptanceAndReplayFailClosed(t *testing.T) {
	f := newWBAFixture(t, true, false)
	if _, err := f.checker.VerifyWebBotAuthSignedRequest(context.Background(), f.request, f.opts); !errors.Is(err, dnsid.ErrCounterpartyNotAccepted) {
		t.Fatalf("acceptance: %v", err)
	}
	f = newWBAFixture(t, false, false)
	seen := false
	f.opts.Replay = func(_ context.Context, domain, key, nonce string, until time.Time) error {
		if domain != f.opts.SignerDomain || key == "" || nonce == "" || !until.After(time.Now()) {
			t.Fatal("invalid replay input")
		}
		if seen {
			return errors.New("replay")
		}
		seen = true
		return nil
	}
	if _, err := f.checker.VerifyWebBotAuthSignedRequest(context.Background(), f.request, f.opts); err != nil {
		t.Fatal(err)
	}
	if _, err := f.checker.VerifyWebBotAuthSignedRequest(context.Background(), f.request, f.opts); err == nil {
		t.Fatal("replay accepted")
	}
	f.opts.Replay = func(context.Context, string, string, string, time.Time) error { return errors.New("store unavailable") }
	if _, err := f.checker.VerifyWebBotAuthSignedRequest(context.Background(), f.request, f.opts); err == nil {
		t.Fatal("store failure accepted")
	}
	f.opts.Replay = nil
	denied := newWBAFixture(t, true, false)
	f.checker.resolver = denied.manager
	if _, err := f.checker.VerifyWebBotAuthSignedRequest(context.Background(), f.request, f.opts); !errors.Is(err, dnsid.ErrCounterpartyNotAccepted) {
		t.Fatalf("repeat-call acceptance: %v", err)
	}
}

func TestProfile_WBAForwardsApplicationPeer(t *testing.T) {
	f := newWBAFixture(t, false, false)
	cert := &x509.Certificate{DNSNames: []string{"bot.example.com"}}
	f.request.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}, VerifiedChains: [][]*x509.Certificate{{cert}}}
	spy := &wbaPeerResolver{IdentityResolver: f.manager, t: t, cert: cert}
	f.checker.resolver = spy
	if _, err := f.checker.VerifyWebBotAuthSignedRequest(context.Background(), f.request, f.opts); err != nil {
		t.Fatal(err)
	}
	if !spy.called {
		t.Fatal("peer options not forwarded")
	}
}

type wbaPeerResolver struct {
	dnsid.IdentityResolver
	t      *testing.T
	cert   *x509.Certificate
	called bool
}

func (r *wbaPeerResolver) VerifyDomainWithOptions(ctx context.Context, domain string, opts dnsid.VerifyDomainOpts) (*dnsid.VerifiedDomain, error) {
	r.called = true
	if opts.PeerCertificate != r.cert || len(opts.VerifiedPeerCertificateChains) != 1 || opts.VerifiedPeerCertificateChains[0][0] != r.cert {
		r.t.Fatal("wrong application peer")
	}
	return r.VerifyDomain(ctx, domain)
}

func TestProfile_WBARejectsPrivateDiscoveryAndRedirects(t *testing.T) {
	p := NewVerifier(nil, Config{})
	if p.client.Transport.(*http.Transport).TLSClientConfig != nil {
		t.Fatal("discovery inherited application TLS settings")
	}
	for _, uri := range []string{"https://127.0.0.1/", "https://[::1]/", "https://10.0.0.1/", "https://169.254.169.254/"} {
		if res, err := p.client.Get(uri); err == nil {
			res.Body.Close()
			t.Fatalf("unsafe URI accepted: %s", uri)
		}
	}
	if err := p.client.CheckRedirect(&http.Request{}, nil); err != http.ErrUseLastResponse {
		t.Fatal("redirects not disabled")
	}
}
