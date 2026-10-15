package webbotauth

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/dnsid-ai/dnsid-go"
	"github.com/dnsid-ai/dnsid-go/httpsig"
	"github.com/lestrrat-go/jwx/v3/jwk"
)

func TestProfile_SnapshotsSignatureAgentFlag(t *testing.T) {
	for _, initial := range []bool{false, true} {
		flag := initial
		cfg := Config{IncludeSignatureAgent: &flag}
		p := New("bot.example.com", dnsid.GenerateEd25519KeyProvider(), cfg)
		profiles := []*Profile{p, NewVerifier(nil, cfg), NewFromIdentityManager(nil, cfg)}
		flag = !initial
		for _, profile := range profiles {
			if *profile.cfg.IncludeSignatureAgent != initial || profile.cfg.IncludeSignatureAgent == &flag {
				t.Fatal("constructor retained caller-owned configuration")
			}
		}
		req, _ := http.NewRequest(http.MethodGet, "https://target.example/", nil)
		signed, err := p.CreateWebBotAuthSignedRequest(req, SigningOptions{})
		if !initial {
			if err == nil {
				t.Fatal("accepted disabled Signature-Agent")
			}
			continue
		}
		if err != nil || signed.Header.Get("Signature-Agent") == "" {
			t.Fatalf("caller mutation changed the profile: %v", err)
		}
	}
}

func TestProfile_CreateWebBotAuthSignedRequest(t *testing.T) {
	p := New("bot.example.com", dnsid.GenerateEd25519KeyProvider(), Config{})
	req, _ := http.NewRequest(http.MethodGet, "https://target.example/", nil)
	signed, err := p.CreateWebBotAuthSignedRequest(req, SigningOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if got := signed.Header.Get("Signature-Agent"); got != `sig1="https://bot.example.com";type=directory` {
		t.Fatalf("Signature-Agent = %q", got)
	}
	input := signed.Header.Get("Signature-Input")
	if !strings.Contains(input, `tag="web-bot-auth"`) || !strings.Contains(input, `"signature-agent";key="sig1"`) || strings.Contains(input, `;sf`) {
		t.Fatalf("Signature-Input = %q", input)
	}
	if signed.Header.Get("Signature") == "" {
		t.Fatal("missing Signature")
	}
}

func TestProfile_ServeHttpMessageSignaturesDirectory(t *testing.T) {
	p := New("bot.example.com", dnsid.GenerateEd25519KeyProvider(), Config{})
	req, _ := http.NewRequest(http.MethodGet, "https://bot.example.com"+DirectoryPath, nil)
	res, err := p.ServeHttpMessageSignaturesDirectory(req)
	if err != nil {
		t.Fatal(err)
	}
	if got := res.Header.Get("Content-Type"); got != DirectoryContentType {
		t.Fatalf("Content-Type = %q", got)
	}
	body, _ := io.ReadAll(res.Body)
	var jwks struct {
		Keys []map[string]any `json:"keys"`
	}
	if err := json.Unmarshal(body, &jwks); err != nil || len(jwks.Keys) != 1 || jwks.Keys[0]["alg"] != "ed25519" || jwks.Keys[0]["use"] != "sig" || jwks.Keys[0]["d"] != nil {
		t.Fatalf("directory body = %s err=%v", body, err)
	}
	if kid, _ := jwks.Keys[0]["kid"].(string); kid == "" || !strings.Contains(res.Header.Get("Signature-Input"), `keyid="`+kid+`"`) {
		t.Fatalf("directory kid not used as keyid: body=%s input=%q", body, res.Header.Get("Signature-Input"))
	}
	if input := res.Header.Get("Signature-Input"); !strings.Contains(input, `tag="http-message-signatures-directory"`) || !strings.Contains(input, `"@authority";req`) || !strings.Contains(input, `"content-type"`) {
		t.Fatalf("Signature-Input = %q", input)
	}
}

func TestProfile_WebBotAuthRejectsES256(t *testing.T) {
	p := New("bot.example.com", dnsid.GenerateES256KeyProvider(), Config{})
	req, _ := http.NewRequest(http.MethodGet, "https://target.example/", nil)
	if _, err := p.CreateWebBotAuthSignedRequest(req, SigningOptions{}); err == nil {
		t.Fatal("accepted ES256 WBA signer")
	}
}

func TestWBAJWKRejectsUnsupportedKey(t *testing.T) {
	if jwkMap, err := wbaJWK(dnsid.GenerateES256KeyProvider().JWK()); err == nil || jwkMap != nil {
		t.Fatalf("wbaJWK accepted ES256 key: map=%v err=%v", jwkMap, err)
	}
}

func TestProfile_WebBotAuthValidatesAdditionalComponents(t *testing.T) {
	p := New("bot.example.com", dnsid.GenerateEd25519KeyProvider(), Config{})
	req, _ := http.NewRequest(http.MethodGet, "https://target.example/", nil)
	disabled := false
	for _, opts := range []SigningOptions{
		{SignatureAgent: &disabled},
		{AdditionalComponentIDs: []httpsig.ComponentIdentifier{{Name: "@query-param"}}},
		{AdditionalComponents: []string{"Signature"}},
		{AdditionalComponentIDs: []httpsig.ComponentIdentifier{{Name: "signature", Params: map[string]any{"key": "inner"}}}},
		{AdditionalComponents: []string{"signature-input"}},
	} {
		_, err := p.CreateWebBotAuthSignedRequest(req, opts)
		var ae *dnsid.ArgumentError
		if !errors.As(err, &ae) {
			t.Fatalf("expected ArgumentError for %+v: %v", opts, err)
		}
	}
}

func TestProfile_SignatureAgentCustomURLUsesExplicitType(t *testing.T) {
	p := New("bot.example.com", dnsid.GenerateEd25519KeyProvider(), Config{DirectoryURL: "https://keys.example/custom.json?q=x#fragment", SignatureAgentType: "jwks_uri"})
	req, _ := http.NewRequest(http.MethodGet, "https://target.example/", nil)
	signed, err := p.CreateWebBotAuthSignedRequest(req, SigningOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if got := signed.Header.Get("Signature-Agent"); got != `sig1="https://keys.example/custom.json?q=x#fragment";type=jwks_uri` {
		t.Fatalf("Signature-Agent = %q", got)
	}
}

func TestProfile_WebBotAuthRejectsOutOfBoundsConfiguration(t *testing.T) {
	req, _ := http.NewRequest(http.MethodGet, "https://target.example/", nil)
	for name, cfg := range map[string]Config{
		"request ttl":             {SignatureTTL: 5*time.Minute + time.Second},
		"directory ttl":           {DirectorySignatureTTL: 5*time.Minute + time.Second},
		"clock skew":              {ClockSkew: -time.Second},
		"subsecond request ttl":   {SignatureTTL: time.Millisecond},
		"subsecond directory ttl": {DirectorySignatureTTL: time.Millisecond},
	} {
		t.Run(name, func(t *testing.T) {
			p := New("bot.example.com", dnsid.GenerateEd25519KeyProvider(), cfg)
			if _, err := p.CreateWebBotAuthSignedRequest(req, SigningOptions{}); err == nil {
				t.Fatal("accepted invalid WBA configuration")
			}
		})
	}
	p := New("bot.example.com", dnsid.GenerateEd25519KeyProvider(), Config{})
	if _, err := p.CreateWebBotAuthSignedRequest(req, SigningOptions{TTL: -time.Second}); err == nil {
		t.Fatal("accepted negative per-request TTL")
	}
}

func TestProfile_SignatureAgentDirectoryRequiresOrigin(t *testing.T) {
	for _, suffix := range []string{"/custom", "/", "?q=x", "?", "#fragment", "#"} {
		p := New("bot.example.com", dnsid.GenerateEd25519KeyProvider(), Config{
			DirectoryURL: "https://bot.example.com" + suffix,
		})
		req, _ := http.NewRequest(http.MethodGet, "https://target.example/", nil)
		if _, err := p.CreateWebBotAuthSignedRequest(req, SigningOptions{}); err == nil {
			t.Fatalf("accepted non-origin directory URI: %s", suffix)
		}
	}
}

func TestProfile_DirectoryPublishesActiveKeyOnly(t *testing.T) {
	kp := dnsid.GenerateEd25519KeyProvider()
	old := kp.ListKeyIds()[0]
	newKid, err := kp.GenerateKey(dnsid.JoseAlgEdDSA)
	if err != nil {
		t.Fatal(err)
	}
	if err := kp.Activate(newKid); err != nil {
		t.Fatal(err)
	}
	p := New("bot.example.com", kp, Config{})
	req, _ := http.NewRequest(http.MethodGet, "https://bot.example.com"+DirectoryPath, nil)
	res, err := p.ServeHttpMessageSignaturesDirectory(req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(res.Body)
	var jwks struct {
		Keys []map[string]any `json:"keys"`
	}
	if err := json.Unmarshal(body, &jwks); err != nil || len(jwks.Keys) != 1 {
		t.Fatalf("directory body = %s err=%v", body, err)
	}
	if old == newKid { // impossible, keeps the test honest without over-checking thumbprints.
		t.Fatal("test generated duplicate kids")
	}
}

type nilLookupKeyProvider struct{ dnsid.KeyProvider }

func (p nilLookupKeyProvider) JWK(kid ...string) jwk.Key {
	if len(kid) > 0 {
		return nil
	}
	return p.KeyProvider.JWK(kid...)
}

type rotatingKeyProvider struct {
	dnsid.KeyProvider
	rotated bool
}

func (p *rotatingKeyProvider) Sign(payload []byte) (*dnsid.KeySignature, error) {
	if !p.rotated {
		p.rotated = true
		kid, err := p.GenerateKey(dnsid.JoseAlgEdDSA)
		if err != nil {
			return nil, err
		}
		if err := p.Activate(kid); err != nil {
			return nil, err
		}
	}
	return p.KeyProvider.Sign(payload)
}

func TestProfile_WebBotAuthMissingActiveKeyDoesNotPanic(t *testing.T) {
	p := New("bot.example.com", nilLookupKeyProvider{dnsid.GenerateEd25519KeyProvider()}, Config{})
	req, _ := http.NewRequest(http.MethodGet, "https://target.example/", nil)
	if _, err := p.CreateWebBotAuthSignedRequest(req, SigningOptions{}); err == nil {
		t.Fatal("accepted missing active JWK")
	}
	if _, err := p.ServeHttpMessageSignaturesDirectory(req); err == nil {
		t.Fatal("served directory with missing active JWK")
	}
}

func TestProfile_WebBotAuthRejectsSignerMetadataDrift(t *testing.T) {
	kp := &rotatingKeyProvider{KeyProvider: dnsid.GenerateEd25519KeyProvider()}
	p := New("bot.example.com", kp, Config{})
	req, _ := http.NewRequest(http.MethodGet, "https://target.example/", nil)
	if _, err := p.CreateWebBotAuthSignedRequest(req, SigningOptions{}); err == nil {
		t.Fatal("accepted signature from rotated active key")
	}
}
