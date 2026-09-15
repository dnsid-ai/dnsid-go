package oidc

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	dnsid "github.com/dnsid-ai/dnsid-go"
)

func TestTokenExchangeErrorIsTyped(t *testing.T) {
	var err error = &TokenExchangeError{StatusCode: 400, Code: "invalid_grant", Description: "agent tier not eligible for this issuer"}
	var te *TokenExchangeError
	if !errors.As(err, &te) || te.Code != "invalid_grant" {
		t.Fatalf("errors.As failed on %v", err)
	}
	if got, want := err.Error(), "dnsid: OIDC token exchange failed: invalid_grant agent tier not eligible for this issuer"; got != want {
		t.Fatalf("message %q, want %q", got, want)
	}
	if got := (&TokenExchangeError{StatusCode: 503}).Error(); got != "dnsid: OIDC token exchange failed: HTTP 503" {
		t.Fatalf("bodyless message %q", got)
	}
}

// refusingIssuer serves discovery and a token endpoint that answers status
// with body, the way an issuer refuses an exchange.
func refusingIssuer(t *testing.T, status int, body string) *httptest.Server {
	t.Helper()
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		issuer := "http://" + r.Host
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			json.NewEncoder(w).Encode(DiscoveryDocument{Issuer: issuer, TokenEndpoint: issuer + "/token", JWKSURI: issuer + "/jwks"})
		case "/token":
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(status)
			w.Write([]byte(body))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(ts.Close)
	return ts
}

func TestExchangeOIDCTokenReturnsTypedErrorOnRefusal(t *testing.T) {
	ts := refusingIssuer(t, http.StatusBadRequest, `{"error":"invalid_grant","error_description":"agent tier not eligible for this issuer"}`)
	p := New(nil, "example.com", dnsid.GenerateEd25519KeyProvider(), Config{AllowHTTPLoopbackIssuer: true})
	_, err := p.ExchangeOIDCToken(context.Background(), OIDCTokenExchangeOptions{Issuer: ts.URL, Audience: "rp.example"})
	var te *TokenExchangeError
	if !errors.As(err, &te) {
		t.Fatalf("want *TokenExchangeError, got %T: %v", err, err)
	}
	if te.StatusCode != http.StatusBadRequest || te.Code != "invalid_grant" || te.Description != "agent tier not eligible for this issuer" {
		t.Fatalf("unexpected fields: %+v", te)
	}
}

func TestExchangeOIDCTokenTypedErrorWithoutRFC6749Body(t *testing.T) {
	ts := refusingIssuer(t, http.StatusServiceUnavailable, "upstream unavailable")
	p := New(nil, "example.com", dnsid.GenerateEd25519KeyProvider(), Config{AllowHTTPLoopbackIssuer: true})
	_, err := p.ExchangeOIDCToken(context.Background(), OIDCTokenExchangeOptions{Issuer: ts.URL, Audience: "rp.example"})
	var te *TokenExchangeError
	if !errors.As(err, &te) {
		t.Fatalf("want *TokenExchangeError, got %T: %v", err, err)
	}
	if te.StatusCode != http.StatusServiceUnavailable || te.Code != "" || te.Description != "" {
		t.Fatalf("unexpected fields: %+v", te)
	}
	if err.Error() != "dnsid: OIDC token exchange failed: HTTP 503" {
		t.Fatalf("message %q", err.Error())
	}
}
