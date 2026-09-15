package oidc

import (
	"encoding/base64"
	"fmt"
	"math"
	"testing"
	"time"

	"github.com/dnsid-ai/dnsid-go"
)

func TestOIDC_StrictCompactAndDateBoundaries(t *testing.T) {
	for _, header := range []string{`{"alg":"RS256","alg":"RS256","kid":"key"}`, `null`, `[]`, `{"alg":"RS256","kid":"key","x":{"a":1,"a":2}}`} {
		token := base64.RawURLEncoding.EncodeToString([]byte(header)) + ".e30.AA"
		if _, _, err := parseUnverifiedJWT(token); err == nil {
			t.Fatalf("accepted header %s", header)
		}
	}
	for _, v := range []any{"0", true, nil, math.NaN(), math.Inf(1)} {
		if _, ok := unixTime(v); ok {
			t.Fatalf("coerced %v", v)
		}
	}
	for _, v := range []float64{0, .125, -.125} {
		ts, ok := unixTime(v)
		if !ok || float64(ts.UnixNano())/1e9 != v {
			t.Fatalf("fraction/zero lost: %v", v)
		}
	}
	now := float64(time.Now().UnixNano()) / 1e9
	for _, claims := range []map[string]any{{"iat": now - 1, "exp": now}, {"iat": now + .1, "exp": now + 60}, {"iat": now - 1, "exp": now + 60, "nbf": now + .1}} {
		if err := validateTimes(claims, 0); err == nil {
			t.Fatalf("accepted invalid time %v", claims)
		}
	}
	if err := validateTimes(map[string]any{"iat": now - 1, "exp": now}, time.Hour); err == nil {
		t.Fatal("skew extended expiry")
	}
	for _, cfg := range []Config{{ClockSkew: -1}, {AssertionLifetime: -1}, {MaxAssertionLifetime: -1}, Config{}.WithAssertionLifetime(0), Config{}.WithMaxAssertionLifetime(0)} {
		if _, err := New(nil, "example.com", dnsid.GenerateES256KeyProvider(), cfg).CreateOIDCAssertion(OIDCAssertionOptions{Issuer: "https://issuer.example"}); err == nil {
			t.Fatalf("accepted invalid config: %v", cfg)
		}
	}
	p := New(nil, "example.com", dnsid.GenerateES256KeyProvider(), Config{}.WithClockSkew(0))
	if p.clockSkew() != 0 {
		t.Fatal("explicit zero skew defaulted")
	}
	for _, expiry := range []time.Duration{0, -1, time.Nanosecond} {
		t.Run(fmt.Sprint(expiry), func(t *testing.T) {
			if _, err := p.CreateOIDCAssertion((OIDCAssertionOptions{Issuer: "https://issuer.example"}).WithExpiry(expiry)); err == nil {
				t.Fatal("invalid explicit expiry accepted")
			}
		})
	}
}
