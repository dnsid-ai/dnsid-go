package httpsig

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/dnsid-ai/dnsid-go"
	dnsidlog "github.com/dnsid-ai/dnsid-go/log"
)

type responseDNS struct {
	testDNSResolver
	calls int
}

func (r *responseDNS) FetchTXT(ctx context.Context, name string) ([]dnsid.TXTRecordRData, dnsid.DNSSECState, error) {
	r.calls++
	return r.testDNSResolver.FetchTXT(ctx, name)
}

type responseFetcher struct {
	testHTTPSFetcher
	failures map[string]error
}

func (f *responseFetcher) FetchJSON(ctx context.Context, rawURL string, opts dnsid.FetchOptions) (json.RawMessage, *tls.Certificate, error) {
	if err := f.failures[rawURL]; err != nil {
		return nil, nil, err
	}
	return f.testHTTPSFetcher.FetchJSON(ctx, rawURL, opts)
}

type responseLogReader struct {
	testLogReader
	bindingError error
}

func (r *responseLogReader) VerifyBilateralBinding(context.Context, dnsidlog.BilateralBindingInput) (dnsidlog.BilateralBinding, error) {
	return dnsidlog.BilateralBinding{}, r.bindingError
}

func responseCoreFixture(t *testing.T, verification dnsid.VerificationConfig, flags []dnsid.PolicyFlag) (*responseFixture, *responseDNS, *responseFetcher, *responseLogReader, string) {
	t.Helper()
	keys, entity := dnsid.GenerateES256KeyProvider(), dnsid.GenerateES256KeyProvider()
	cfg := dnsid.IdentityConfig{Domain: "agent.example.com", GovernanceID: "example.com", LogRef: "algorand:ADDR", StatusURL: "https://agent.example.com/status.json", KeyURL: "https://agent.example.com/ku.json", EntityKeyURL: "https://example.com/ek.json", PolicyFlags: flags}
	issuer, err := dnsid.NewIdentityManager(dnsid.Config{Identity: &cfg}, keys, dnsid.WithEntityKeyProvider(entity))
	if err != nil {
		t.Fatal(err)
	}
	record, err := issuer.CreateTXTRecord()
	if err != nil {
		t.Fatal(err)
	}
	operational, _ := json.Marshal(issuer.GetKeySet().Raw())
	entityBytes, _ := json.Marshal(issuer.GetEntityKeySet().Raw())
	dns := &responseDNS{testDNSResolver: testDNSResolver{records: map[string][]dnsid.TXTRecordRData{"_dnsid.agent.example.com": {{Value: record.Serialize(), TTL: time.Minute}}}}}
	fetcher := &responseFetcher{testHTTPSFetcher: testHTTPSFetcher{responses: map[string]json.RawMessage{cfg.KeyURL: operational, cfg.EntityKeyURL: entityBytes, cfg.StatusURL: json.RawMessage(`{"state":"ACTIVE","lastTransitionAt":"2020-01-01T00:00:00Z"}`)}}, failures: map[string]error{}}
	reader := &responseLogReader{}
	registry := dnsidlog.NewLogRegistry()
	if err := registry.Register("algorand", func(string) dnsidlog.LogReader { return reader }); err != nil {
		t.Fatal(err)
	}
	manager, err := dnsid.NewIdentityManager(dnsid.Config{Verification: verification}, nil, dnsid.WithDNSResolver(dns), dnsid.WithHTTPSFetcher(fetcher), dnsid.WithLogRegistry(registry))
	if err != nil {
		t.Fatal(err)
	}
	f := &responseFixture{signer: NewFromIdentityManager(issuer, keys, Config{}), checker: NewFromIdentityManager(manager, nil, Config{}), keys: keys, opts: ResponseSignatureOptions{ExpectedDomain: issuer.Domain()}}
	return f, dns, fetcher, reader, cfg.StatusURL
}

func TestNegotiatedResponse_CoreAcceptanceStatusAndLifecycle(t *testing.T) {
	for _, scenario := range []string{"acceptance-cache-hit", "revocation-cache-hit", "lifecycle", "status-unavailable"} {
		t.Run(scenario, func(t *testing.T) {
			verification := dnsid.VerificationConfig{TrustedEntities: []dnsid.TrustedEntity{{GovernanceID: "example.com"}}}
			if scenario == "acceptance-cache-hit" {
				verification.TrustedEntities = []dnsid.TrustedEntity{}
			}
			f, dns, fetcher, reader, statusURL := responseCoreFixture(t, verification, nil)
			req := f.request(t)
			if scenario == "revocation-cache-hit" {
				res := f.response(t, req)
				if _, err := f.checker.VerifySignedHTTPResponse(context.Background(), req, res, f.opts); err != nil {
					t.Fatal(err)
				}
				res.Body.Close()
				fetcher.responses[statusURL] = json.RawMessage(`{"state":"REVOKED","lastTransitionAt":"2020-01-01T00:00:00Z","revocationReason":"keyCompromise"}`)
			}
			if scenario == "lifecycle" {
				reader.bindingError = errors.New("invalid bilateral lifecycle proof")
			}
			if scenario == "status-unavailable" {
				fetcher.failures[statusURL] = &net.DNSError{Err: "timeout", Name: "agent.example.com", IsTimeout: true}
			}
			attempts := 1
			if scenario == "acceptance-cache-hit" {
				attempts = 2
			}
			for range attempts {
				res := f.response(t, req)
				vd, err := f.checker.VerifySignedHTTPResponse(context.Background(), req, res, f.opts)
				var verificationError *dnsid.VerificationError
				if vd != nil || !errors.As(err, &verificationError) {
					t.Fatalf("core denial escaped: %v", err)
				}
				if scenario == "acceptance-cache-hit" && verificationError.Code() != dnsid.VerificationCodeCounterpartyNotAccepted {
					t.Fatal(err)
				}
				if scenario == "revocation-cache-hit" && verificationError.Code() != dnsid.VerificationCodeStatusNotActive {
					t.Fatal(err)
				}
				if scenario == "status-unavailable" && (!verificationError.Transient() || verificationError.Code() != dnsid.VerificationCodeStatusUnavailable) {
					t.Fatalf("lost acquisition classification: %v", err)
				}
			}
			if scenario == "acceptance-cache-hit" && dns.calls != 1 {
				t.Fatalf("second denial did not exercise cached evidence: DNS=%d", dns.calls)
			}
		})
	}
}

func TestNegotiatedResponse_MTLSCurrentPeerIncludingCacheHits(t *testing.T) {
	f, dns, _, _, _ := responseCoreFixture(t, dnsid.VerificationConfig{}, []dnsid.PolicyFlag{dnsid.PolicyFlagMTLS})
	req := f.request(t)
	good := &x509.Certificate{DNSNames: []string{f.opts.ExpectedDomain}}
	wrong := &x509.Certificate{DNSNames: []string{"another.example"}}
	res := f.response(t, req)
	opts := dnsid.VerifyDomainOpts{PeerCertificate: good, VerifiedPeerCertificateChains: [][]*x509.Certificate{{good}}}
	if _, err := f.checker.VerifySignedHTTPResponse(context.Background(), req, res, f.opts, opts); err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	for _, name := range []string{"missing", "wrong", "previous-connection", "unverified-certificate", "current"} {
		t.Run(name, func(t *testing.T) {
			res := f.response(t, req)
			switch name {
			case "wrong":
				res.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{wrong}, VerifiedChains: [][]*x509.Certificate{{wrong}}}
			case "previous-connection":
				res.Request = req.Clone(req.Context())
				res.Request.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{good}, VerifiedChains: [][]*x509.Certificate{{good}}}
			case "unverified-certificate":
				res.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{good}}
			case "current":
				res.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{good}, VerifiedChains: [][]*x509.Certificate{{good}}}
			}
			vd, err := f.checker.VerifySignedHTTPResponse(context.Background(), req, res, f.opts)
			if name == "current" {
				if err != nil || vd == nil {
					t.Fatal(err)
				}
				res.Body.Close()
				return
			}
			var verification *dnsid.VerificationError
			if vd != nil || !errors.As(err, &verification) || verification.Code() != dnsid.VerificationCodeTLSError {
				t.Fatalf("invalid peer accepted: %v", err)
			}
		})
	}
	if dns.calls != 1 {
		t.Fatalf("did not exercise identity cache: DNS=%d", dns.calls)
	}
}

func TestNegotiatedResponse_UnsupportedResponseKinds(t *testing.T) {
	f := newResponseFixture(t)
	for _, name := range []string{"informational", "switching-protocols", "tunnel", "upgrade-header"} {
		t.Run(name, func(t *testing.T) {
			req := f.request(t)
			params := responseParamsForRequest(t, f, req)
			res := responseMessage("response content")
			switch name {
			case "informational":
				res.StatusCode = http.StatusEarlyHints
			case "switching-protocols":
				res.StatusCode = http.StatusSwitchingProtocols
			case "tunnel":
				req.Method = http.MethodConnect
			case "upgrade-header":
				res.Header.Set("Upgrade", "websocket")
			}
			if signed, err := f.signer.SignRequestedHTTPResponse(req, res); err == nil || signed != nil {
				t.Fatal("unsupported response signed")
			}
			// Use the primitive to produce a cryptographically valid unsupported final kind.
			res.Header.Set("Content-Digest", contentDigest([]byte("response content")))
			res.Header.Set("Cache-Control", "no-store")
			resignResponse(t, f, req, res, params)
			assertResponseRejected(t, f, req, res)
		})
	}
}

func TestNegotiatedResponse_ResourceBoundsAndOwnedCleanup(t *testing.T) {
	for _, name := range []string{"signature", "signature-input", "combined-headers", "negotiation", "target", "response-body", "expired-budget", "canceled"} {
		t.Run(name, func(t *testing.T) {
			f := newResponseFixture(t)
			req := f.request(t)
			res := f.response(t, req)
			original := &closeTrackingBody{Reader: strings.NewReader("response content")}
			res.Body = original
			counter := &countingResolver{IdentityResolver: f.checker.resolver}
			f.checker.resolver = counter
			ctx := context.Background()
			switch name {
			case "signature":
				res.Header.Set("Signature", res.Header.Get("Signature")+", other=:"+base64.StdEncoding.EncodeToString(make([]byte, 12<<10))+":")
			case "signature-input":
				res.Header.Set("Signature-Input", res.Header.Get("Signature-Input")+`, other=("@status");x="`+strings.Repeat("x", 8192)+`";y="`+strings.Repeat("y", 8192)+`"`)
			case "combined-headers":
				res.Header.Set("X-Oversized", strings.Repeat("x", 1<<20))
			case "negotiation":
				req.Header.Set("Accept-Signature", req.Header.Get("Accept-Signature")+strings.Repeat(" ", 16<<10))
			case "target":
				req.URL.Path = "/" + strings.Repeat("x", 64<<10)
				resignResponse(t, f, req, res, responseParams(t, res))
			case "response-body":
				body := make([]byte, (8<<20)+1)
				original.Reader = bytes.NewReader(body)
				res.Header.Set("Content-Digest", contentDigest(body))
				resignResponse(t, f, req, res, responseParams(t, res))
			case "expired-budget":
				var cancel context.CancelFunc
				ctx, cancel = context.WithDeadline(ctx, time.Now().Add(-time.Second))
				defer cancel()
			case "canceled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}
			vd, err := f.checker.VerifySignedHTTPResponse(ctx, req, res, f.opts)
			if err == nil || vd != nil || !original.closed {
				t.Fatalf("bounded rejection/cleanup failed: %v closed=%v", err, original.closed)
			}
			if name != "response-body" && name != "expired-budget" && name != "canceled" && counter.calls != 0 {
				t.Fatal("oversized metadata reached resolver")
			}
		})
	}
}

func TestNegotiatedResponse_NoStoreAndDigestMustBeVerified(t *testing.T) {
	f := newResponseFixture(t)
	for _, name := range []string{"wrong-digest", "missing-sha256", "malformed-digest", "trailing-digest-input"} {
		t.Run(name, func(t *testing.T) {
			req := f.request(t)
			res := f.response(t, req)
			switch name {
			case "wrong-digest":
				res.Header.Set("Content-Digest", contentDigest([]byte("different")))
			case "missing-sha256":
				res.Header.Set("Content-Digest", "other=:YQ==:")
			case "malformed-digest":
				res.Header.Set("Content-Digest", "sha-256=token")
			case "trailing-digest-input":
				res.Header.Set("Content-Digest", res.Header.Get("Content-Digest")+" junk")
			}
			resignResponse(t, f, req, res, responseParams(t, res))
			assertResponseRejected(t, f, req, res)
		})
	}
}
