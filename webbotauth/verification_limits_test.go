package webbotauth

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/dnsid-ai/dnsid-go"
	"github.com/dnsid-ai/dnsid-go/httpsig"
)

func TestDirectoryKey_RejectsInvalidPublicJWK(t *testing.T) {
	key := dnsid.GenerateEd25519KeyProvider().JWK()
	public, err := wbaJWK(key)
	if err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"private", "private-null", "thumbprint", "algorithm", "coordinate", "duplicate", "count", "depth", "duplicate-json"} {
		t.Run(mode, func(t *testing.T) {
			m := map[string]any{}
			for k, v := range public {
				m[k] = v
			}
			keys := []map[string]any{m}
			switch mode {
			case "private":
				m["d"] = "secret"
			case "private-null":
				m["d"] = nil
			case "thumbprint":
				m["kid"] = "wrong"
			case "algorithm":
				m["alg"] = "EdDSA"
			case "coordinate":
				m["x"] = "short"
			case "duplicate":
				keys = append(keys, m)
			case "count":
				for len(keys) < 65 {
					keys = append(keys, m)
				}
			}
			body, _ := json.Marshal(map[string]any{"keys": keys})
			if mode == "depth" {
				body = []byte(`{"keys":` + strings.Repeat("[", 65) + strings.Repeat("]", 65) + `}`)
			}
			if mode == "duplicate-json" {
				body = []byte(`{"keys":[],"keys":[]}`)
			}
			if _, err := directoryKey(body, public["kid"].(string)); err == nil {
				t.Fatal("invalid directory accepted")
			}
		})
	}
}

func TestWBAContent_LimitsAndCancellation(t *testing.T) {
	large := newWBAFixture(t, false, false)
	large.request.Header.Set("X-Large", strings.Repeat("x", (1<<20)+1))
	if _, err := large.checker.VerifyWebBotAuthSignedRequest(context.Background(), large.request, large.opts); err == nil {
		t.Fatal("oversized request metadata accepted")
	}
	if _, err := boundedContent(context.Background(), io.NopCloser(strings.NewReader("12345")), 4); err == nil {
		t.Fatal("oversized body accepted")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	reader, writer := io.Pipe()
	defer writer.Close()
	if _, err := boundedContent(ctx, reader, 4); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("blocked read did not preserve deadline error: %v", err)
	}
	f := newWBAFixture(t, false, false)
	f.request.Body = io.NopCloser(strings.NewReader(strings.Repeat("x", (8<<20)+1)))
	if _, err := f.checker.VerifyWebBotAuthSignedRequest(context.Background(), f.request, f.opts); err == nil {
		t.Fatal("oversized request accepted")
	}
	f = newWBAFixture(t, false, false)
	f.checker.client = &http.Client{Transport: wbaRoundTrip(func(req *http.Request) (*http.Response, error) {
		res, err := f.signer.ServeHttpMessageSignaturesDirectory(req)
		res.Body = io.NopCloser(strings.NewReader(strings.Repeat("x", (1<<20)+1)))
		return res, err
	})}
	if _, err := f.checker.VerifyWebBotAuthSignedRequest(context.Background(), f.request, f.opts); err == nil {
		t.Fatal("oversized directory accepted")
	}
}

func TestWBA_RechecksExpiryAfterVerificationWork(t *testing.T) {
	f := newWBAFixture(t, false, false)
	f.checker.cfg = Config{}.WithClockSkew(0)
	inputs, _ := httpsig.ParseSignatureInput(f.request.Header.Get("Signature-Input"))
	params := inputs["sig1"]
	params.Parameters = nil
	params.Expires = time.Now().Unix() + 2
	if err := httpsig.SignHTTPMessage(f.request, params, f.signer.keys); err != nil {
		t.Fatal(err)
	}
	f.checker.resolver = wbaResolverFunc(func(ctx context.Context, domain string) (*dnsid.VerifiedDomain, error) {
		vd, err := f.manager.VerifyDomain(ctx, domain)
		time.Sleep(time.Until(time.Unix(params.Expires, 0).Add(time.Millisecond)))
		return vd, err
	})
	if _, err := f.checker.VerifyWebBotAuthSignedRequest(context.Background(), f.request, f.opts); err == nil {
		t.Fatal("accepted request that expired during identity resolution")
	}
}

func TestWBA_ReplayRequiresNonce(t *testing.T) {
	f := newWBAFixture(t, false, false)
	inputs, _ := httpsig.ParseSignatureInput(f.request.Header.Get("Signature-Input"))
	params := inputs["sig1"]
	params.Parameters = nil
	params.Nonce = ""
	if err := httpsig.SignHTTPMessage(f.request, params, f.signer.keys); err != nil {
		t.Fatal(err)
	}
	f.opts.Replay = func(context.Context, string, string, string, time.Time) error {
		t.Fatal("empty nonce reached replay store")
		return nil
	}
	if _, err := f.checker.VerifyWebBotAuthSignedRequest(context.Background(), f.request, f.opts); err == nil {
		t.Fatal("empty nonce accepted with replay policy")
	}
}

func TestWBA_DiscoveryRejectsInvalidPolicy(t *testing.T) {
	params := httpsig.SignatureParams{Components: []httpsig.ComponentIdentifier{{Name: "signature-agent", Params: map[string]any{"key": "agent"}}}}
	for _, agent := range []string{
		`agent="http://bot.example.com"`,
		`"https://bot.example.com"`,
		`agent="https://bot.example.com";type=cimd`,
		`agent="https://bot.example.com";type="directory"`,
		`agent="https://bot.example.com";type=other`,
		`agent="https://bot.example.com";type=directory;type=jwks_uri`,
		`agent="https://bot.example.com", agent="https://bot.example.com"`,
		`agent="https://user@bot.example.com"`,
		`agent="https://other.example.com"`,
		`other="https://bot.example.com"`,
		strings.Repeat("x", 65536),
	} {
		h := http.Header{"Signature-Agent": {agent}}
		if _, _, err := discovery(h, params, VerificationOptions{SignerDomain: "bot.example.com"}); err == nil {
			t.Fatalf("accepted %q", agent)
		}
	}
}

func TestWBA_RequiresCoveredOriginBeforeDiscovery(t *testing.T) {
	for _, suffix := range []string{"missing", "uncovered", "/", "/custom", "?q=x", "?", "#fragment", "#", "unsupported"} {
		t.Run(suffix, func(t *testing.T) {
			f := newWBAFixture(t, false, false)
			f.opts.DirectoryURL = "https://bot.example.com" + DirectoryPath
			switch suffix {
			case "missing":
				f.request.Header.Del("Signature-Agent")
			case "uncovered":
				inputs, _ := httpsig.ParseSignatureInput(f.request.Header.Get("Signature-Input"))
				params := inputs["sig1"]
				params.Components = params.Components[:2]
				if err := httpsig.SignHTTPMessage(f.request, params, f.signer.keys); err != nil {
					t.Fatal(err)
				}
			case "unsupported":
				f.request.Header.Set("Signature-Agent", `sig1="https://bot.example.com";type=cimd`)
			default:
				f.request.Header.Set("Signature-Agent", `sig1="https://bot.example.com`+suffix+`";type=directory`)
			}
			f.checker.client.Transport = wbaRoundTrip(func(*http.Request) (*http.Response, error) {
				t.Fatal("invalid discovery reached the network")
				return nil, nil
			})
			if _, err := f.checker.VerifyWebBotAuthSignedRequest(context.Background(), f.request, f.opts); err == nil {
				t.Fatal("accepted missing, uncovered, or invalid discovery")
			}
		})
	}
}

func TestWBA_KeyedContentDigestRequiresSuppliedContent(t *testing.T) {
	for _, mode := range []string{"missing", "explicit-empty", "keyed-empty-mismatch", "keyed-only-with-body"} {
		t.Run(mode, func(t *testing.T) {
			f := newWBAFixture(t, false, false)
			f.request.Body = nil
			f.request.ContentLength = 0
			if mode != "keyed-empty-mismatch" {
				f.request.Header.Set("Content-Digest", "sha-256=:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=:")
			}
			inputs, _ := httpsig.ParseSignatureInput(f.request.Header.Get("Signature-Input"))
			params := inputs["sig1"]
			for i := range params.Components {
				if params.Components[i].Name == "content-digest" {
					params.Components[i].Params = map[string]any{"key": "sha-256"}
				}
			}
			if err := httpsig.SignHTTPMessage(f.request, params, f.signer.keys); err != nil {
				t.Fatal(err)
			}
			switch mode {
			case "explicit-empty", "keyed-empty-mismatch":
				f.request.Body = http.NoBody
			case "keyed-only-with-body":
				f.request.Body = io.NopCloser(strings.NewReader(""))
			}
			_, err := f.checker.VerifyWebBotAuthSignedRequest(context.Background(), f.request, f.opts)
			if mode == "explicit-empty" {
				if err != nil {
					t.Fatal(err)
				}
			} else if err == nil {
				t.Fatal("keyed digest accepted without supplied content or exact digest coverage")
			}
		})
	}
}

func TestWBA_DirectoryPreservesStatusAndRequestContext(t *testing.T) {
	for _, invalidStatusSignature := range []bool{false, true} {
		f := newWBAFixture(t, false, false)
		f.checker.client = &http.Client{Transport: wbaRoundTrip(func(req *http.Request) (*http.Response, error) {
			res, err := f.signer.ServeHttpMessageSignaturesDirectory(req)
			if err != nil {
				return nil, err
			}
			inputs, _ := httpsig.ParseSignatureInput(res.Header.Get("Signature-Input"))
			params := inputs["sig1"]
			params.Components = append(params.Components,
				httpsig.ComponentIdentifier{Name: "@status"},
				httpsig.ComponentIdentifier{Name: "@path", Params: map[string]any{"req": true}},
			)
			if invalidStatusSignature {
				res.StatusCode = http.StatusCreated
			}
			err = httpsig.SignHTTPMessage(res, params, f.signer.keys)
			res.StatusCode = http.StatusOK
			res.Request = nil
			return res, err
		})}
		_, err := f.checker.VerifyWebBotAuthSignedRequest(context.Background(), f.request, f.opts)
		if (err != nil) != invalidStatusSignature {
			t.Fatalf("invalidStatusSignature=%v: %v", invalidStatusSignature, err)
		}
	}
}

func TestWBA_SuppliedEmptyContentAndAuthorization(t *testing.T) {
	f := newWBAFixture(t, false, false)
	req, _ := http.NewRequest(http.MethodPost, "https://target.example/", nil)
	req.Body = io.NopCloser(strings.NewReader(""))
	req.Header.Set("Authorization", "Bearer existing")
	signed, err := f.signer.CreateWebBotAuthSignedRequest(req, SigningOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if signed.Header.Get("Authorization") != "Bearer existing" {
		t.Fatal("Authorization replaced")
	}
	if _, err := f.checker.VerifyWebBotAuthSignedRequest(context.Background(), signed, f.opts); err != nil {
		t.Fatal(err)
	}
}

type closeTrackingBody struct {
	io.Reader
	closed bool
}

func (b *closeTrackingBody) Close() error {
	b.closed = true
	return nil
}

func TestWBA_VerificationPreservesBodyClose(t *testing.T) {
	for _, invalid := range []bool{false, true} {
		f := newWBAFixture(t, false, false)
		content := "hello"
		if invalid {
			content = "changed"
		}
		original := &closeTrackingBody{Reader: strings.NewReader(content)}
		f.request.Body = original
		_, err := f.checker.VerifyWebBotAuthSignedRequest(context.Background(), f.request, f.opts)
		if (err != nil) != invalid {
			t.Fatalf("invalid=%v: %v", invalid, err)
		}
		if original.closed {
			t.Fatal("verification closed caller-owned body")
		}
		if err := f.request.Body.Close(); err != nil {
			t.Fatal(err)
		}
		if !original.closed {
			t.Fatal("closing request body did not close original reader")
		}
	}
}

func TestWBA_NoAcceptanceFallbackOnResolverError(t *testing.T) {
	f := newWBAFixture(t, false, false)
	expected := errors.New("acceptance backend unavailable")
	f.checker.resolver = wbaResolverFunc(func(context.Context, string) (*dnsid.VerifiedDomain, error) { return nil, expected })
	if _, err := f.checker.VerifyWebBotAuthSignedRequest(context.Background(), f.request, f.opts); !errors.Is(err, expected) {
		t.Fatalf("error=%v", err)
	}
}
