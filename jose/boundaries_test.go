package jose

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/dnsid-ai/dnsid-go"
)

type boundaryResolver struct {
	inner dnsid.IdentityResolver
	calls int
	delay time.Duration
}

func (r *boundaryResolver) VerifyDomain(ctx context.Context, domain string) (*dnsid.VerifiedDomain, error) {
	r.calls++
	time.Sleep(r.delay)
	return r.inner.VerifyDomain(ctx, domain)
}

func signRawToken(t *testing.T, kp dnsid.KeyProvider, header, payload string) string {
	t.Helper()
	input := base64.RawURLEncoding.EncodeToString([]byte(header)) + "." + base64.RawURLEncoding.EncodeToString([]byte(payload))
	sig, err := kp.Sign([]byte(input))
	if err != nil {
		t.Fatal(err)
	}
	return input + "." + base64.RawURLEncoding.EncodeToString(sig.Signature)
}

func TestVerifyJWT_StrictBoundariesBeforeDiscovery(t *testing.T) {
	_, kp, manager, _ := testManagers(t)
	kid, _ := kp.JWK().KeyID()
	header := fmt.Sprintf(`{"alg":"ES256","kid":%q}`, kid)
	now := float64(time.Now().UnixNano()) / 1e9
	claims := fmt.Sprintf(`{"iss":"agent.example.com","sub":"agent.example.com","aud":"rp.example","iat":%f,"exp":%f}`, now-1, now+60)
	cases := []struct{ name, header, claims string }{
		{"crit", fmt.Sprintf(`{"alg":"ES256","kid":%q,"crit":[]}`, kid), claims},
		{"b64 false", fmt.Sprintf(`{"alg":"ES256","kid":%q,"b64":false}`, kid), claims},
		{"duplicate header", fmt.Sprintf(`{"alg":"ES256","alg":"ES256","kid":%q}`, kid), claims},
		{"duplicate claim", header, claims[:len(claims)-1] + `,"iss":"agent.example.com"}`},
		{"invalid jti", header, claims[:len(claims)-1] + `,"jti":123}`},
	}
	for _, name := range []string{"iat", "exp", "nbf"} {
		for _, value := range []any{"123", true, nil} {
			var raw map[string]any
			if err := json.Unmarshal([]byte(claims), &raw); err != nil {
				t.Fatal(err)
			}
			raw[name] = value
			b, _ := json.Marshal(raw)
			cases = append(cases, struct{ name, header, claims string }{fmt.Sprintf("%s/%v", name, value), header, string(b)})
		}
	}
	var raw map[string]any
	_ = json.Unmarshal([]byte(claims), &raw)
	raw["aud"] = []any{"rp.example", 1}
	mixed, _ := json.Marshal(raw)
	cases = append(cases, struct{ name, header, claims string }{"mixed audience", header, string(mixed)})
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := &boundaryResolver{inner: manager}
			p := New(r, "", nil, Config{})
			if _, _, err := p.VerifyJWT(context.Background(), signRawToken(t, kp, tc.header, tc.claims), VerifyJWTOptions{ExpectedAudience: "rp.example"}); err == nil {
				t.Fatal("accepted malformed signed token")
			}
			if r.calls != 0 {
				t.Fatal("discovered domain before validating input")
			}
		})
	}
}

func TestVerifyJWT_ExpirySkewAndTrustedAudience(t *testing.T) {
	_, kp, manager, _ := testManagers(t)
	kid, _ := kp.JWK().KeyID()
	header := fmt.Sprintf(`{"alg":"ES256","kid":%q}`, kid)
	token := func(iat, exp float64) string {
		return signRawToken(t, kp, header, fmt.Sprintf(`{"iss":"agent.example.com","sub":"agent.example.com","aud":"rp.example","iat":%.9f,"exp":%.9f}`, iat, exp))
	}
	now := float64(time.Now().UnixNano()) / 1e9
	p := New(manager, "", nil, Config{}.WithClockSkew(0))
	for _, tok := range []string{token(now+1, now+60), token(now-10, now), token(now, now)} {
		if _, _, err := p.VerifyJWT(context.Background(), tok, VerifyJWTOptions{ExpectedAudience: "rp.example"}); err == nil {
			t.Fatal("invalid time accepted")
		}
	}
	var argument *dnsid.ArgumentError
	if _, _, err := p.VerifyJWT(context.Background(), token(now-1, now+60)); !errors.As(err, &argument) {
		t.Fatalf("missing audience: %v", err)
	}
	if _, _, err := p.VerifyJWT(context.Background(), token(now-1, now+60), VerifyJWTOptions{ExpectedAudience: "rp.example"}); err != nil {
		t.Fatal(err)
	}
	r := &boundaryResolver{inner: manager, delay: 40 * time.Millisecond}
	p = New(r, "rp.example", nil, Config{})
	now = float64(time.Now().UnixNano()) / 1e9
	if _, _, err := p.VerifyJWT(context.Background(), token(now-1, now+.02)); err == nil {
		t.Fatal("token expired during discovery accepted with default skew")
	}
}

func TestJOSE_CurrentPeerOnCachedJWTAndJWS(t *testing.T) {
	issuer, kp, manager, _ := testManagers(t, dnsid.PolicyFlagMTLS)
	signer := NewFromIdentityManager(issuer, kp, Config{})
	verifier := New(manager, "rp.example", nil, Config{})
	jwt, err := signer.CreateJWT(JWTOptions{Audience: "rp.example"})
	if err != nil {
		t.Fatal(err)
	}
	jws, err := signer.CreateJWS([]byte("opaque"))
	if err != nil {
		t.Fatal(err)
	}
	peer := dnsid.VerifyDomainOpts{VerifiedPeerCertificateChains: [][]*x509.Certificate{{{DNSNames: []string{"agent.example.com"}}}}}
	for range 2 {
		if _, _, err := verifier.VerifyJWT(context.Background(), jwt, VerifyJWTOptions{Peer: peer}); err != nil {
			t.Fatal(err)
		}
		if _, _, err := verifier.VerifyJWS(context.Background(), jws, peer); err != nil {
			t.Fatal(err)
		}
		if _, _, err := verifier.VerifyJWT(context.Background(), jwt); err == nil {
			t.Fatal("cached JWT skipped current peer")
		}
		if _, _, err := verifier.VerifyJWS(context.Background(), jws); err == nil {
			t.Fatal("cached JWS skipped current peer")
		}
	}
}

func TestJOSE_ExplicitExpiryAndConfig(t *testing.T) {
	issuer, kp, _, _ := testManagers(t)
	for _, cfg := range []Config{{MaxLifetime: -1}, {ClockSkew: -1}, Config{}.WithMaxLifetime(0)} {
		if _, err := NewFromIdentityManager(issuer, kp, cfg).CreateJWT(JWTOptions{Audience: "rp.example"}); err == nil {
			t.Fatal("invalid config accepted")
		}
	}
	p := NewFromIdentityManager(issuer, kp, Config{})
	for _, expiry := range []time.Duration{0, -1, time.Nanosecond} {
		if _, err := p.CreateJWT((JWTOptions{Audience: "rp.example"}).WithExpiry(expiry)); err == nil {
			t.Fatal("explicit invalid expiry accepted")
		}
	}
}
