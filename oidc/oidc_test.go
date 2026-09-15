package oidc

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/dnsid-ai/dnsid-go"
	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
)

type fakeResolver struct {
	domain string
	peer   dnsid.VerifyDomainOpts
	delay  time.Duration
}

func (r *fakeResolver) VerifyDomainWithOptions(ctx context.Context, domain string, opts dnsid.VerifyDomainOpts) (*dnsid.VerifiedDomain, error) {
	r.peer = opts
	time.Sleep(r.delay)
	return r.VerifyDomain(ctx, domain)
}

func (r *fakeResolver) VerifyDomain(_ context.Context, domain string) (*dnsid.VerifiedDomain, error) {
	r.domain = domain
	return &dnsid.VerifiedDomain{}, nil
}

func TestCreateOIDCAssertion(t *testing.T) {
	p := New(nil, "Example.COM", dnsid.GenerateEd25519KeyProvider(), Config{})
	jwt, err := p.CreateOIDCAssertion(OIDCAssertionOptions{Issuer: "https://issuer.example", AdditionalClaims: map[string]any{"env": "test"}})
	if err != nil {
		t.Fatal(err)
	}
	claims := unverifiedClaims(jwt)
	if claims["iss"] != "example.com" || claims["sub"] != "example.com" || claims["fqdn"] != "example.com" {
		t.Fatalf("claims = %#v", claims)
	}
	if aud, ok := audienceList(claims["aud"]); !ok || len(aud) != 1 || aud[0] != "https://issuer.example" {
		t.Fatalf("aud = %#v", claims["aud"])
	}
	if _, err := p.CreateOIDCAssertion(OIDCAssertionOptions{Issuer: "https://issuer.example", AdditionalClaims: map[string]any{"iss": "bad"}}); err == nil {
		t.Fatal("reserved claim override succeeded")
	}
	if _, err := p.CreateOIDCAssertion(OIDCAssertionOptions{Issuer: "https://issuer.example", AdditionalClaims: map[string]any{"bad": func() {}}}); err == nil {
		t.Fatal("non-marshalable claim accepted")
	}
}

func TestDiscoverRejectsCrossOriginEndpoint(t *testing.T) {
	p := New(nil, "example.com", nil, Config{AllowHTTPLoopbackIssuer: true})
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(DiscoveryDocument{Issuer: "http://" + r.Host, TokenEndpoint: "http://evil.example/token", JWKSURI: "http://" + r.Host + "/jwks"})
	}))
	defer ts.Close()
	if _, err := p.DiscoverOIDCIssuer(context.Background(), ts.URL); err == nil {
		t.Fatal("cross-origin token endpoint accepted")
	}
}

func TestSetHTTPClientInstallsSafeTransport(t *testing.T) {
	base := &http.Client{Timeout: time.Second, Transport: http.DefaultTransport}
	p := New(nil, "example.com", nil, Config{})
	p.SetHTTPClient(base)
	if p.client.Timeout != base.Timeout || p.client.Transport == base.Transport {
		t.Fatalf("client was not safely wrapped: %#v", p.client)
	}
	if err := p.client.CheckRedirect(nil, nil); !errors.Is(err, http.ErrUseLastResponse) {
		t.Fatalf("redirect policy = %v", err)
	}
}

func TestAllowHTTPLoopbackIssuerWorksWithDefaultClient(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(DiscoveryDocument{Issuer: "http://" + r.Host, TokenEndpoint: "http://" + r.Host + "/token", JWKSURI: "http://" + r.Host + "/jwks"})
	}))
	defer ts.Close()
	p := New(nil, "example.com", nil, Config{AllowHTTPLoopbackIssuer: true})
	if _, err := p.DiscoverOIDCIssuer(context.Background(), ts.URL); err != nil {
		t.Fatal(err)
	}
}

func TestAllowHTTPLoopbackIssuerHandlesCustomDefaultTransport(t *testing.T) {
	orig := http.DefaultTransport
	http.DefaultTransport = http.NewFileTransport(http.Dir("."))
	t.Cleanup(func() { http.DefaultTransport = orig })

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(DiscoveryDocument{Issuer: "http://" + r.Host, TokenEndpoint: "http://" + r.Host + "/token", JWKSURI: "http://" + r.Host + "/jwks"})
	}))
	defer ts.Close()
	p := New(nil, "example.com", nil, Config{AllowHTTPLoopbackIssuer: true})
	if _, err := p.DiscoverOIDCIssuer(context.Background(), ts.URL); err != nil {
		t.Fatal(err)
	}
}

func TestReadLimitedRejectsOversize(t *testing.T) {
	if _, err := readLimited(strings.NewReader(strings.Repeat("x", maxOIDCResponseBytes+1))); err == nil {
		t.Fatal("oversize response accepted")
	}
}

func TestValidateIssuerAllowsPathAndRejectsAmbiguity(t *testing.T) {
	if _, err := validateIssuerRoot("http://localhost", false); err == nil {
		t.Fatal("accepted loopback HTTP without opt-in")
	}
	if _, err := validateIssuerRoot("http://localhost/issuer1", true); err != nil {
		t.Fatal(err)
	}
	if _, err := validateIssuerRoot("https://issuer.example/issuer1/", false); err == nil {
		t.Fatal("accepted trailing slash")
	}
	if _, err := validateIssuerRoot("https://issuer.example/issuer1?x=1", false); err == nil {
		t.Fatal("accepted query")
	}
	if _, err := validateIssuerRoot("https://user:pass@issuer.example", false); err == nil {
		t.Fatal("accepted issuer userinfo")
	}
	if err := validateSameOriginEndpoint("https://user:pass@issuer.example/token", "https://issuer.example", "token_endpoint"); err == nil {
		t.Fatal("accepted endpoint userinfo")
	}
}

func TestExchangeOIDCTokenPostsJWTBearerForm(t *testing.T) {
	kp := dnsid.GenerateEd25519KeyProvider()
	var got url.Values
	var issuer string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		issuer = "http://" + r.Host
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			json.NewEncoder(w).Encode(DiscoveryDocument{Issuer: issuer, TokenEndpoint: issuer + "/token", JWKSURI: issuer + "/jwks"})
		case "/token":
			r.ParseForm()
			got = r.Form
			json.NewEncoder(w).Encode(map[string]any{"access_token": "tok", "token_type": "Bearer"})
		default:
			http.NotFound(w, r)
		}
	}))
	defer ts.Close()
	p := New(nil, "example.com", kp, Config{AllowHTTPLoopbackIssuer: true})
	resp, err := p.ExchangeOIDCToken(context.Background(), OIDCTokenExchangeOptions{Issuer: ts.URL, Audience: "rp.example"})
	if err != nil {
		t.Fatal(err)
	}
	if resp.AccessToken != "tok" || got.Get("grant_type") != grantJWTBearer || got.Get("audience") != "rp.example" || got.Get("scope") != "openid" || got.Get("assertion") == "" {
		t.Fatalf("resp=%#v form=%#v", resp, got)
	}
}

func TestExchangeOIDCTokenRejectsMalformedPrebuiltAssertion(t *testing.T) {
	p := New(nil, "example.com", nil, Config{AllowHTTPLoopbackIssuer: true})
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(DiscoveryDocument{Issuer: "http://" + r.Host, TokenEndpoint: "http://" + r.Host + "/token", JWKSURI: "http://" + r.Host + "/jwks"})
	}))
	defer ts.Close()
	if _, err := p.ExchangeOIDCToken(context.Background(), OIDCTokenExchangeOptions{Issuer: ts.URL, Audience: "rp.example", Assertion: "not-a-jwt"}); err == nil {
		t.Fatal("malformed assertion accepted")
	}
	badAud := unsignedJWT(t, map[string]any{"aud": []any{ts.URL, 123}})
	if _, err := p.ExchangeOIDCToken(context.Background(), OIDCTokenExchangeOptions{Issuer: ts.URL, Audience: "rp.example", Assertion: badAud}); err == nil {
		t.Fatal("mixed-type assertion audience accepted")
	}
}

func TestValidateTimesRequiresNumericExpAndIAT(t *testing.T) {
	now := time.Now().Unix()
	for name, claims := range map[string]map[string]any{
		"missing exp":    {"iat": float64(now)},
		"string exp":     {"exp": "nope", "iat": float64(now)},
		"missing iat":    {"exp": float64(now + 60)},
		"string iat":     {"exp": float64(now + 60), "iat": "nope"},
		"exp before iat": {"exp": float64(now), "iat": float64(now + 60)},
		"string nbf":     {"exp": float64(now + 60), "iat": float64(now), "nbf": "nope"},
	} {
		t.Run(name, func(t *testing.T) {
			if err := validateTimes(claims, 0); err == nil {
				t.Fatal("accepted invalid time claims")
			}
		})
	}
}

func TestVerifyOIDCTokenRS256(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := jwk.Import(&priv.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	pub.Set(jwk.KeyIDKey, "kid1")
	pub.Set(jwk.AlgorithmKey, jwa.RS256())
	set := jwk.NewSet()
	set.AddKey(pub)

	resolver := &fakeResolver{}
	var issuer string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		issuer = "http://" + r.Host + "/issuer1"
		switch r.URL.Path {
		case "/issuer1/.well-known/openid-configuration":
			json.NewEncoder(w).Encode(DiscoveryDocument{Issuer: issuer, TokenEndpoint: issuer + "/token", JWKSURI: issuer + "/jwks"})
		case "/issuer1/jwks":
			json.NewEncoder(w).Encode(set)
		default:
			http.NotFound(w, r)
		}
	}))
	defer ts.Close()

	issuer = ts.URL + "/issuer1"
	p := New(resolver, "rp.example", nil, Config{AllowedIssuers: []string{issuer}, AllowHTTPLoopbackIssuer: true})
	claims := map[string]any{"iss": issuer, "sub": "subject.example", "aud": []string{"rp.example"}, "iat": time.Now().Unix(), "exp": time.Now().Add(time.Minute).Unix()}
	tok := signRS256Test(t, priv, claims)
	peer := dnsid.VerifyDomainOpts{VerifiedPeerCertificateChains: [][]*x509.Certificate{{{DNSNames: []string{"subject.example"}}}}}
	got, err := p.VerifyOIDCToken(context.Background(), tok, VerifyOIDCTokenOptions{Issuer: issuer, Audience: "rp.example", Peer: peer})
	if err != nil {
		t.Fatal(err)
	}
	if got.Subject != "subject.example" || resolver.domain != "subject.example" {
		t.Fatalf("got=%#v resolver=%q", got, resolver.domain)
	}

	if len(resolver.peer.VerifiedPeerCertificateChains) != 1 {
		t.Fatal("OIDC dropped invocation peer evidence")
	}
	resolver.delay = 50 * time.Millisecond
	claims["exp"] = float64(time.Now().UnixNano())/1e9 + .03
	if _, err := p.VerifyOIDCToken(context.Background(), signRS256Test(t, priv, claims), VerifyOIDCTokenOptions{Issuer: issuer, Audience: "rp.example", Peer: peer}); err == nil {
		t.Fatal("OIDC token expired during subject verification")
	}
	resolver.delay = 0
	claims["exp"] = time.Now().Add(time.Minute).Unix()
	claims["aud"] = []string{"rp.example", "other.example"}
	if _, err := p.VerifyOIDCToken(context.Background(), signRS256Test(t, priv, claims), VerifyOIDCTokenOptions{Issuer: issuer, Audience: "rp.example"}); err == nil {
		t.Fatal("multi-audience token accepted")
	}

	claims["aud"] = []any{"rp.example", 123}
	if _, err := p.VerifyOIDCToken(context.Background(), signRS256Test(t, priv, claims), VerifyOIDCTokenOptions{Issuer: issuer, Audience: "rp.example"}); err == nil {
		t.Fatal("mixed-type audience token accepted")
	}

	claims["aud"] = []string{"rp.example"}
	if _, err := p.VerifyOIDCToken(context.Background(), signRS256HeaderTest(t, priv, map[string]any{"alg": "RS256", "kid": "kid1", "typ": "JWT", "crit": []string{"exp"}}, claims), VerifyOIDCTokenOptions{Issuer: issuer, Audience: "rp.example"}); err == nil {
		t.Fatal("critical header accepted")
	}

	badUse, _ := jwk.Import(&priv.PublicKey)
	badUse.Set(jwk.KeyIDKey, "kid1")
	badUse.Set(jwk.AlgorithmKey, jwa.RS256())
	badUse.Set(jwk.KeyUsageKey, string(jwk.ForEncryption))
	set = jwk.NewSet()
	set.AddKey(badUse)
	if _, err := p.VerifyOIDCToken(context.Background(), signRS256Test(t, priv, claims), VerifyOIDCTokenOptions{Issuer: issuer, Audience: "rp.example"}); err == nil {
		t.Fatal("encryption-use JWKS key accepted")
	}

	dup, _ := jwk.Import(&priv.PublicKey)
	dup.Set(jwk.KeyIDKey, "kid1")
	dup.Set(jwk.AlgorithmKey, jwa.RS256())
	set = jwk.NewSet()
	set.AddKey(pub)
	set.AddKey(dup)
	if _, err := p.VerifyOIDCToken(context.Background(), signRS256Test(t, priv, claims), VerifyOIDCTokenOptions{Issuer: issuer, Audience: "rp.example"}); err == nil {
		t.Fatal("duplicate JWKS kid accepted")
	}

	badOps, _ := jwk.Import(&priv.PublicKey)
	badOps.Set(jwk.KeyIDKey, "kid1")
	badOps.Set(jwk.AlgorithmKey, jwa.RS256())
	badOps.Set(jwk.KeyOpsKey, jwk.KeyOperationList{jwk.KeyOpEncrypt})
	set = jwk.NewSet()
	set.AddKey(badOps)
	if _, err := p.VerifyOIDCToken(context.Background(), signRS256Test(t, priv, claims), VerifyOIDCTokenOptions{Issuer: issuer, Audience: "rp.example"}); err == nil {
		t.Fatal("incompatible key_ops JWKS key accepted")
	}
}

func unsignedJWT(t *testing.T, claims map[string]any) string {
	t.Helper()
	header, _ := json.Marshal(map[string]any{"alg": "none"})
	payload, _ := json.Marshal(claims)
	return base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(payload) + "."
}

func signRS256Test(t *testing.T, priv *rsa.PrivateKey, claims map[string]any) string {
	t.Helper()
	return signRS256HeaderTest(t, priv, map[string]any{"alg": "RS256", "kid": "kid1", "typ": "JWT"}, claims)
}

func signRS256HeaderTest(t *testing.T, priv *rsa.PrivateKey, headerClaims, claims map[string]any) string {
	t.Helper()
	header, _ := json.Marshal(headerClaims)
	payload, _ := json.Marshal(claims)
	input := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(payload)
	sum := sha256.Sum256([]byte(input))
	sig, err := rsa.SignPKCS1v15(rand.Reader, priv, crypto.SHA256, sum[:])
	if err != nil {
		t.Fatal(err)
	}
	return input + "." + base64.RawURLEncoding.EncodeToString(sig)
}
