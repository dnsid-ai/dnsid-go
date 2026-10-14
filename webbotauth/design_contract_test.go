package webbotauth

import (
	"compress/gzip"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/dnsid-ai/dnsid-go"
	"github.com/dnsid-ai/dnsid-go/httpsig"
	"github.com/dnsid-ai/dnsid-go/internal/netguard"
	"github.com/lestrrat-go/jwx/v3/jwk"
)

func TestDirectoryKey_ValidatesMetadata(t *testing.T) {
	public, err := wbaJWK(dnsid.GenerateEd25519KeyProvider().JWK())
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name  string
		ops   any
		valid bool
	}{
		{"verify", []string{"verify"}, true},
		{"sign-and-verify", []string{"sign", "verify"}, true},
		{"string", "verify", false},
		{"null", nil, false},
		{"empty", []string{}, false},
		{"encrypt", []string{"encrypt"}, false},
		{"sign-only", []string{"sign"}, false},
		{"duplicate", []string{"verify", "verify"}, false},
		{"mixed", []string{"verify", "encrypt"}, false},
		{"non-string", []any{"verify", true}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			public["key_ops"] = tc.ops
			body, _ := json.Marshal(map[string]any{"keys": []any{public}})
			key, err := directoryKey(body, public["kid"].(string))
			if (err == nil) != tc.valid {
				t.Fatalf("valid=%v: %v", tc.valid, err)
			}
			if tc.valid {
				if ops, present := key.KeyOps(); !present || len(ops) == 0 {
					t.Fatal("key_ops restrictions discarded")
				}
			}
		})
	}
}

func TestWBA_RequiredComponents(t *testing.T) {
	for _, mode := range []string{"default", "missing", "covered", "wrong-parameter", "malformed", "unknown", "duplicate", "response", "too-many"} {
		t.Run(mode, func(t *testing.T) {
			f := newWBAFixture(t, false, false)
			f.request.Method, f.request.URL.Path = http.MethodDelete, "/other"
			f.opts.RequiredComponents = []httpsig.ComponentIdentifier{{Name: "@method"}, {Name: "@path"}}
			argumentError := false
			switch mode {
			case "default":
				f.opts.RequiredComponents = nil
			case "covered":
				inputs, _ := httpsig.ParseSignatureInput(f.request.Header.Get("Signature-Input"))
				params := inputs["sig1"]
				params.Components = append(params.Components, f.opts.RequiredComponents...)
				if err := httpsig.SignHTTPMessage(f.request, params, f.signer.keys); err != nil {
					t.Fatal(err)
				}
			case "wrong-parameter":
				f.opts.RequiredComponents = []httpsig.ComponentIdentifier{{Name: "signature-agent", Params: map[string]any{"key": "other"}}}
			case "malformed":
				f.opts.RequiredComponents = []httpsig.ComponentIdentifier{{Name: "@query-param"}}
				argumentError = true
			case "unknown":
				f.opts.RequiredComponents = []httpsig.ComponentIdentifier{{Name: "@unknown"}}
				argumentError = true
			case "duplicate":
				f.opts.RequiredComponents = []httpsig.ComponentIdentifier{{Name: "@method"}, {Name: "@method"}}
				argumentError = true
			case "response":
				f.opts.RequiredComponents = []httpsig.ComponentIdentifier{{Name: "@authority", Params: map[string]any{"req": true}}}
				argumentError = true
			case "too-many":
				f.opts.RequiredComponents = make([]httpsig.ComponentIdentifier, 129)
				argumentError = true
			}
			if mode != "default" && mode != "covered" {
				f.checker.client.Transport = wbaRoundTrip(func(*http.Request) (*http.Response, error) {
					t.Fatal("invalid policy or missing coverage reached discovery")
					return nil, nil
				})
			}
			_, err := f.checker.VerifyWebBotAuthSignedRequest(context.Background(), f.request, f.opts)
			valid := mode == "default" || mode == "covered"
			if (err == nil) != valid {
				t.Fatalf("valid=%v: %v", valid, err)
			}
			var ae *dnsid.ArgumentError
			if argumentError && !errors.As(err, &ae) {
				t.Fatalf("expected ArgumentError, got %v", err)
			}
		})
	}
}

func TestWBA_ConfigExplicitPresence(t *testing.T) {
	for _, cfg := range []Config{
		Config{}.WithSignatureTTL(0), Config{}.WithDirectorySignatureTTL(0),
		{SignatureTTL: time.Nanosecond}, {DirectorySignatureTTL: 301 * time.Second},
		Config{}.WithClockSkew(-1),
	} {
		f := newWBAFixture(t, false, false)
		f.checker.cfg = cfg
		f.checker.client.Transport = wbaRoundTrip(func(*http.Request) (*http.Response, error) {
			t.Fatal("invalid configuration reached discovery")
			return nil, nil
		})
		_, err := f.checker.VerifyWebBotAuthSignedRequest(context.Background(), f.request, f.opts)
		var ae *dnsid.ArgumentError
		if !errors.As(err, &ae) {
			t.Fatalf("expected ArgumentError, got %v", err)
		}
	}
	f := newWBAFixture(t, false, false)
	if _, err := f.signer.CreateWebBotAuthSignedRequest(f.request, SigningOptions{}.WithTTL(0)); err == nil {
		t.Fatal("explicit zero TTL accepted")
	}
	if _, err := New("bot.example.com", f.signer.keys, Config{DirectoryURL: "https://bot.example.com/custom"}).CreateWebBotAuthSignedRequest(f.request, SigningOptions{}); err == nil {
		t.Fatal("custom endpoint implicitly selected jwks_uri")
	}
	inputs, _ := httpsig.ParseSignatureInput(f.request.Header.Get("Signature-Input"))
	params := inputs["sig1"]
	f.checker.now = func() time.Time { return time.Unix(params.Expires, 0).Add(time.Second) }
	if err := f.checker.validTime(params); err != nil {
		t.Fatal(err)
	}
	f.checker.cfg = Config{}.WithClockSkew(0)
	if err := f.checker.validTime(params); err == nil {
		t.Fatal("explicit zero skew applied default tolerance")
	}
}

func TestWBA_SelectionAndResponseStatus(t *testing.T) {
	for _, mode := range []string{"incomplete-request", "incomplete-directory", "invalid-request-candidate", "invalid-directory-candidate", "directory-status-component"} {
		t.Run(mode, func(t *testing.T) {
			f := newWBAFixture(t, false, false)
			modify := func(header http.Header, kp dnsid.KeyProvider, message any) {
				inputs, _ := httpsig.ParseSignatureInput(header.Get("Signature-Input"))
				params := inputs["sig1"]
				params.Label = "other"
				if err := httpsig.SignHTTPMessage(message, params, kp); err != nil {
					t.Fatal(err)
				}
				if strings.HasPrefix(mode, "incomplete") {
					// Retain the complete original and omit only the added signature.
					header.Set("Signature", strings.Split(header.Get("Signature"), ",")[0])
				} else {
					parts := strings.Split(header.Get("Signature"), ",")
					header.Set("Signature", parts[0]+", other=:AAAA:")
				}
			}
			if strings.Contains(mode, "directory") || mode == "directory-status-component" {
				f.checker.client.Transport = wbaRoundTrip(func(req *http.Request) (*http.Response, error) {
					res, err := f.signer.ServeHttpMessageSignaturesDirectory(req)
					if err != nil {
						return nil, err
					}
					if mode == "directory-status-component" {
						inputs, _ := httpsig.ParseSignatureInput(res.Header.Get("Signature-Input"))
						params := inputs["sig1"]
						params.Components = append(params.Components, httpsig.ComponentIdentifier{Name: "@status"})
						err = httpsig.SignHTTPMessage(res, params, f.signer.keys)
					} else {
						modify(res.Header, f.signer.keys, res)
					}
					return res, err
				})
			} else {
				modify(f.request.Header, f.signer.keys, f.request)
			}
			_, err := f.checker.VerifyWebBotAuthSignedRequest(context.Background(), f.request, f.opts)
			valid := strings.HasPrefix(mode, "incomplete") || mode == "directory-status-component"
			if (err == nil) != valid {
				t.Fatalf("valid=%v: %v", valid, err)
			}
		})
	}
}

func TestWBA_ZeroTTLAndRepeatedDiscovery(t *testing.T) {
	for _, mode := range []string{"zero-ttl", "reused-zero-ttl", "acceptance", "rotation", "auxiliary"} {
		t.Run(mode, func(t *testing.T) {
			f := newWBAFixture(t, false, false)
			f.dns.ttl = 0
			discoveries := 0
			f.checker.client.Transport = wbaRoundTrip(func(req *http.Request) (*http.Response, error) {
				discoveries++
				return f.signer.ServeHttpMessageSignaturesDirectory(req)
			})
			vd, err := f.checker.VerifyWebBotAuthSignedRequest(context.Background(), f.request, f.opts)
			if err != nil {
				t.Fatal(err)
			}
			switch mode {
			case "reused-zero-ttl":
				f.checker.resolver = wbaResolverFunc(func(context.Context, string) (*dnsid.VerifiedDomain, error) { return vd, nil })
			case "acceptance":
				f.checker.resolver = newWBAFixture(t, true, false).manager
			case "rotation", "auxiliary":
				current := dnsid.GenerateEd25519KeyProvider().JWK()
				keys := []jwk.Key{current}
				if mode == "auxiliary" {
					old, _ := f.signer.keys.JWK().Clone()
					if err := old.Set(jwk.KeyUsageKey, "enc"); err != nil {
						t.Fatal(err)
					}
					keys = append(keys, old)
				}
				body, _ := json.Marshal(map[string]any{"keys": keys})
				f.https.documents[f.dns.record.KeyURI] = body
			}
			_, err = f.checker.VerifyWebBotAuthSignedRequest(context.Background(), f.request, f.opts)
			if (err == nil) != (mode == "zero-ttl") {
				t.Fatalf("mode=%s: %v", mode, err)
			}
			if mode == "auxiliary" && !strings.Contains(err.Error(), "not the current DNSid ku key") {
				t.Fatalf("auxiliary key did not reach current-key binding: %v", err)
			}
			if discoveries != 2 {
				t.Fatalf("discoveries=%d, want 2", discoveries)
			}
			if mode == "zero-ttl" && f.dns.calls != 2 {
				t.Fatalf("DNS lookups=%d, want 2", f.dns.calls)
			}
		})
	}
}

func TestWBA_ZeroTTLCertificateExpiresDuringReplay(t *testing.T) {
	for _, role := range []string{"runtime", "record-signing"} {
		t.Run(role, func(t *testing.T) {
			f := newWBAFixture(t, false, false)
			f.dns.ttl = 0
			deadline := time.Now().Add(500 * time.Millisecond)
			replayCalled := false
			uri := f.dns.record.KeyURI
			if role == "record-signing" {
				uri = f.dns.record.EntityKeyURI
			}
			f.https.certs[uri] = &tls.Certificate{Leaf: &x509.Certificate{NotBefore: time.Now().Add(-time.Hour), NotAfter: deadline}}
			f.opts.Replay = func(context.Context, string, string, string, time.Time) error {
				replayCalled = true
				time.Sleep(time.Until(deadline.Add(time.Millisecond)))
				return nil
			}
			_, err := f.checker.VerifyWebBotAuthSignedRequest(context.Background(), f.request, f.opts)
			var ve *dnsid.VerificationError
			if !replayCalled || !errors.As(err, &ve) || ve.Code() != dnsid.VerificationCodeTLSError {
				t.Fatalf("expected TLS expiry after replay, got %v (replay=%v)", err, replayCalled)
			}
		})
	}
}

func TestWBA_DirectoryAvailabilityClassification(t *testing.T) {
	for _, tc := range []struct {
		name      string
		err       error
		status    int
		transient bool
	}{
		{"timeout", context.DeadlineExceeded, 0, true},
		{"unavailable", nil, 503, true},
		{"unsafe", &netguard.UnsafeDestinationError{Message: "private destination"}, 0, false},
		{"tls", &tls.CertificateVerificationError{Err: x509.UnknownAuthorityError{}}, 0, false},
		{"tls-alert", tls.AlertError(40), 0, false},
		{"tls-protocol", errors.New("tls: server selected unsupported protocol version"), 0, false},
		{"not-found", nil, 404, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newWBAFixture(t, false, false)
			f.checker.client.Transport = wbaRoundTrip(func(req *http.Request) (*http.Response, error) {
				if tc.err != nil {
					return nil, tc.err
				}
				res, err := f.signer.ServeHttpMessageSignaturesDirectory(req)
				res.StatusCode = tc.status
				return res, err
			})
			_, err := f.checker.VerifyWebBotAuthSignedRequest(context.Background(), f.request, f.opts)
			var ve *dnsid.VerificationError
			if !errors.As(err, &ve) || ve.Transient() != tc.transient {
				t.Fatalf("transient=%v: %v", tc.transient, err)
			}
		})
	}
}

func TestWBA_DirectoryRejectsContentCoding(t *testing.T) {
	f := newWBAFixture(t, false, false)
	if !NewVerifier(f.manager, Config{}).client.Transport.(*http.Transport).DisableCompression {
		t.Fatal("transparent decompression enabled")
	}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.Header.Get("Accept-Encoding") != "identity" {
			t.Error("uncoded content not requested")
		}
		res, err := f.signer.ServeHttpMessageSignaturesDirectory(req)
		if err != nil {
			t.Error(err)
			return
		}
		defer res.Body.Close()
		for name, values := range res.Header {
			w.Header()[name] = values
		}
		w.Header().Set("Content-Encoding", "gzip")
		writer := gzip.NewWriter(w)
		_, _ = io.Copy(writer, res.Body)
		_ = writer.Close()
	}))
	defer server.Close()
	client := server.Client()
	transport := client.Transport.(*http.Transport)
	transport.DisableCompression = true
	transport.TLSClientConfig.ServerName = "example.com"
	transport.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, server.Listener.Addr().String())
	}
	f.checker.client = client
	if _, err := f.checker.VerifyWebBotAuthSignedRequest(context.Background(), f.request, f.opts); err == nil {
		t.Fatal("coded directory accepted")
	}
}

func TestWBA_SigningPreservesBodyClose(t *testing.T) {
	f := newWBAFixture(t, false, false)
	for _, closeOriginal := range []bool{false, true} {
		original := &closeTrackingBody{Reader: strings.NewReader("hello")}
		req, _ := http.NewRequest(http.MethodPost, "https://target.example/path", original)
		signed, err := f.signer.CreateWebBotAuthSignedRequest(req, SigningOptions{})
		if err != nil {
			t.Fatal(err)
		}
		if original.closed {
			t.Fatal("signing closed caller-owned body")
		}
		body := signed.Body
		if closeOriginal {
			body = req.Body
		}
		if err := body.Close(); err != nil {
			t.Fatal(err)
		}
		if !original.closed {
			t.Fatal("closing replay body did not close original reader")
		}
	}
}
