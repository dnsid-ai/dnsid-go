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
	if _, err := boundedContent(ctx, reader, 4); err == nil {
		t.Fatal("blocked read ignored deadline")
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
	f.checker.cfg.ClockSkew = time.Nanosecond
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
