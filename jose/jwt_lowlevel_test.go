package jose

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/dnsid-ai/dnsid-go"
	"github.com/dnsid-ai/dnsid-go/internal/cryptoutil"
	"github.com/dnsid-ai/dnsid-go/internal/joseutil"
	"github.com/lestrrat-go/jwx/v3/jwk"
	jwxjwt "github.com/lestrrat-go/jwx/v3/jwt"
)

func verifyJWT(token string, keys jwk.Set, cfg jwtConfig, opts VerifyJWTOptions) (*Claims, error) {
	header, parts, err := parseJWSProtectedHeader(token)
	if err != nil {
		return nil, dnsid.NewVerificationError(dnsid.VerificationCodeMalformedToken, false, "dnsid: malformed token", err)
	}
	if err := verifyJWTSignature(header, parts, keys); err != nil {
		return nil, err
	}
	return validateJWTClaims(parts.payload, cfg, opts)
}

func testJWTConfig() jwtConfig {
	return jwtConfig{Domain: "test.example.com", DefaultTokenLifetime: 5 * time.Minute, MaxTokenLifetime: 15 * time.Minute, ClockSkew: 30 * time.Second}
}

func jwksForKey(kp dnsid.KeyProvider) jwk.Set {
	key := kp.JWK()
	_ = jwk.AssignKeyID(key)
	set := jwk.NewSet()
	_ = set.AddKey(key)
	return set
}

func TestJWTNormalizesFQDNAudience(t *testing.T) {
	kp := dnsid.GenerateES256KeyProvider()
	token, err := createJWT(jwtConfig{
		Domain:               "issuer.example.com",
		DefaultTokenLifetime: time.Minute,
		MaxTokenLifetime:     15 * time.Minute,
		ClockSkew:            time.Second,
	}, kp, JWTOptions{Audience: "Relying-Party.Example.COM."})
	if err != nil {
		t.Fatal(err)
	}
	claims, err := verifyJWT(token, jwksForKey(kp), jwtConfig{MaxTokenLifetime: 15 * time.Minute, ClockSkew: time.Second}, VerifyJWTOptions{ExpectedAudience: "relying-party.example.com"})
	if err != nil {
		t.Fatal(err)
	}
	if len(claims.Audiences) != 1 || claims.Audiences[0] != "relying-party.example.com" {
		t.Fatalf("audience = %q, want normalized FQDN", claims.Audiences)
	}
}

func TestJWTES256RoundTripAndHeaderRejections(t *testing.T) {
	peerKP := newES256TestKeyProvider(t)
	peerCfg := testJWTConfig()
	peerCfg.Domain = "peer-es256.example.com"
	tokenStr, err := createJWT(peerCfg, peerKP, JWTOptions{Audience: "test.example.com"})
	if err != nil {
		t.Fatalf("createJWT: %v", err)
	}
	header := decodeJWTHeader(t, tokenStr)
	if header["alg"] != "ES256" {
		t.Fatalf("alg = %v, want ES256", header["alg"])
	}
	if header["kid"] == "" {
		t.Fatal("ES256 JWT missing kid")
	}
	claims, err := verifyJWT(tokenStr, jwksForKey(peerKP), testJWTConfig(), VerifyJWTOptions{ExpectedAudience: "test.example.com"})
	if err != nil {
		t.Fatalf("verifyJWT: %v", err)
	}
	if claims.Issuer != peerCfg.Domain {
		t.Fatalf("issuer = %q, want %q", claims.Issuer, peerCfg.Domain)
	}
	parsed, err := jwxjwt.Parse([]byte(tokenStr), jwxjwt.WithVerify(false), jwxjwt.WithValidate(false))
	if err != nil {
		t.Fatalf("parse created JWT: %v", err)
	}
	if nbf, ok := parsed.NotBefore(); !ok || nbf.IsZero() {
		t.Fatal("CreateJWT did not set nbf")
	}
	var fqdn string
	if err := parsed.Get("fqdn", &fqdn); err == nil {
		t.Fatalf("CreateJWT emitted unexpected fqdn claim %q", fqdn)
	}
	rejections := map[string]map[string]any{
		"alg none":    {"alg": "none", "typ": "JWT", "kid": header["kid"]},
		"alg HS256":   {"alg": "HS256", "typ": "JWT", "kid": header["kid"]},
		"missing kid": {"alg": "ES256", "typ": "JWT"},
		"bad typ":     {"alg": "ES256", "typ": "not-jwt", "kid": header["kid"]},
		"crit":        {"alg": "ES256", "typ": "JWT", "kid": header["kid"], "crit": []string{"exp"}},
		"jku":         {"alg": "ES256", "typ": "JWT", "kid": header["kid"], "jku": "https://evil.example/jwks.json"},
	}
	for name, hdr := range rejections {
		t.Run(name, func(t *testing.T) {
			tampered := replaceJWTHeader(t, tokenStr, hdr)
			if _, err := verifyJWT(tampered, jwksForKey(peerKP), testJWTConfig(), VerifyJWTOptions{}); !errors.Is(err, dnsid.ErrMalformedToken) {
				t.Fatalf("verifyJWT header rejection err = %v, want ErrMalformedToken", err)
			}
		})
	}

	t.Run("DER signature", func(t *testing.T) {
		parts := strings.Split(tokenStr, ".")
		signingInput := []byte(parts[0] + "." + parts[1])
		hash := sha256.Sum256(signingInput)
		der, err := ecdsa.SignASN1(rand.Reader, peerKP.priv, hash[:])
		if err != nil {
			t.Fatal(err)
		}
		parts[2] = base64.RawURLEncoding.EncodeToString(der)
		if _, err := verifyJWT(strings.Join(parts, "."), jwksForKey(peerKP), testJWTConfig(), VerifyJWTOptions{}); err == nil {
			t.Fatal("verifyJWT accepted DER-formatted ES256 signature")
		}
	})

	t.Run("wrong curve family", func(t *testing.T) {
		edKP := dnsid.GenerateEd25519KeyProvider()
		edKey := edKP.JWK()
		_ = edKey.Set(jwk.KeyIDKey, header["kid"])
		if _, err := verifyJWT(tokenStr, jwkSet(t, edKey), testJWTConfig(), VerifyJWTOptions{}); err == nil {
			t.Fatal("verifyJWT accepted ES256 token against Ed25519 key")
		}
	})
}

func TestVerifyJWT_RequiresDesignClaims(t *testing.T) {
	kp := dnsid.GenerateEd25519KeyProvider()
	cfg := testJWTConfig()
	cfg.Domain = "claims.example.com"

	sign := func(tok jwxjwt.Token) string {
		t.Helper()
		kid, alg, err := joseutil.ActiveSigningMetadata(kp)
		if err != nil {
			t.Fatal(err)
		}
		out, err := signJWTCompact(tok, kp, kid, alg)
		if err != nil {
			t.Fatal(err)
		}
		return out
	}

	missingIAT, err := jwxjwt.NewBuilder().Issuer(cfg.Domain).Subject(cfg.Domain).Audience([]string{"aud.example.com"}).Expiration(time.Now().Add(time.Minute)).Build()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := verifyJWT(sign(missingIAT), jwksForKey(kp), cfg, VerifyJWTOptions{}); !errors.Is(err, dnsid.ErrInvalidClaims) {
		t.Fatalf("missing iat err = %v, want ErrInvalidClaims", err)
	}

	subMismatch, err := jwxjwt.NewBuilder().Issuer(cfg.Domain).Subject("other.example.com").Audience([]string{"aud.example.com"}).IssuedAt(time.Now()).Expiration(time.Now().Add(time.Minute)).Build()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := verifyJWT(sign(subMismatch), jwksForKey(kp), cfg, VerifyJWTOptions{}); !errors.Is(err, dnsid.ErrInvalidClaims) {
		t.Fatalf("sub mismatch err = %v, want ErrInvalidClaims", err)
	}
}

type es256TestKeyProvider struct {
	kid  string
	alg  dnsid.JoseAlg
	priv *ecdsa.PrivateKey
	jwk  jwk.Key
}

func newES256TestKeyProvider(t *testing.T) *es256TestKeyProvider {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	key, err := jwk.Import(&priv.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	kid := "test-es256"
	_ = key.Set(jwk.KeyIDKey, kid)
	_ = key.Set(jwk.AlgorithmKey, "ES256")
	_ = key.Set(jwk.KeyUsageKey, string(jwk.ForSignature))
	return &es256TestKeyProvider{kid: kid, alg: dnsid.JoseAlgES256, priv: priv, jwk: key}
}

func (p *es256TestKeyProvider) JWK(kidOpt ...string) jwk.Key {
	if len(kidOpt) > 0 && kidOpt[0] != p.kid {
		return nil
	}
	return p.jwk
}
func (p *es256TestKeyProvider) ListKeyIds() []string { return []string{p.kid} }
func (p *es256TestKeyProvider) Sign(payload []byte) (*dnsid.KeySignature, error) {
	return p.SignKey(p.kid, payload)
}
func (p *es256TestKeyProvider) SignKey(kid string, payload []byte) (*dnsid.KeySignature, error) {
	if kid != p.kid {
		return nil, errors.New("key not found")
	}
	sig, err := cryptoutil.SignES256(p.priv, payload)
	if err != nil {
		return nil, err
	}
	return &dnsid.KeySignature{Kid: p.kid, Alg: p.alg, Signature: sig}, nil
}
func (p *es256TestKeyProvider) GenerateKey(dnsid.JoseAlg) (string, error) {
	return "", errors.New("not implemented")
}
func (p *es256TestKeyProvider) Activate(string) error  { return errors.New("not implemented") }
func (p *es256TestKeyProvider) Supersede(string) error { return errors.New("not implemented") }
func (p *es256TestKeyProvider) Purge(string) error     { return errors.New("not implemented") }

func TestCreateJWSRejectsKidContainingFragmentSeparator(t *testing.T) {
	kp := newES256TestKeyProvider(t)
	kp.kid = "bad#kid"
	_ = kp.jwk.Set(jwk.KeyIDKey, kp.kid)
	profile := New(nil, "issuer.example.com", kp, Config{})

	_, err := profile.CreateJWS([]byte("payload"))
	var argErr *dnsid.ArgumentError
	if !errors.As(err, &argErr) {
		t.Fatalf("CreateJWS error = %v, want ArgumentError", err)
	}
}

func jwkSet(t *testing.T, keys ...jwk.Key) jwk.Set {
	t.Helper()
	set := jwk.NewSet()
	for _, key := range keys {
		if err := set.AddKey(key); err != nil {
			t.Fatal(err)
		}
	}
	return set
}

func decodeJWTHeader(t *testing.T, tokenStr string) map[string]any {
	t.Helper()
	parts := strings.Split(tokenStr, ".")
	if len(parts) != 3 {
		t.Fatalf("JWT has %d parts", len(parts))
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		t.Fatal(err)
	}
	var header map[string]any
	if err := json.Unmarshal(raw, &header); err != nil {
		t.Fatal(err)
	}
	return header
}

func replaceJWTHeader(t *testing.T, tokenStr string, header map[string]any) string {
	t.Helper()
	parts := strings.Split(tokenStr, ".")
	if len(parts) != 3 {
		t.Fatalf("JWT has %d parts", len(parts))
	}
	raw, err := json.Marshal(header)
	if err != nil {
		t.Fatal(err)
	}
	parts[0] = base64.RawURLEncoding.EncodeToString(raw)
	return strings.Join(parts, ".")
}

var _ dnsid.KeyProvider = (*es256TestKeyProvider)(nil)
