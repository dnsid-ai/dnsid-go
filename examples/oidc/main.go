package main

import (
	"context"
	"fmt"
	"os"
	"time"

	dnsid "github.com/dnsid-ai/dnsid-go"
	"github.com/dnsid-ai/dnsid-go/oidc"
)

func main() {
	if len(os.Args) != 3 {
		fmt.Fprintf(os.Stderr, "usage: %s <issuer-url> <audience>\n", os.Args[0])
		os.Exit(2)
	}
	issuer, audience := os.Args[1], os.Args[2]

	idm, err := dnsid.NewIdentityManagerFromDnsid("", dnsid.Config{})
	if err != nil {
		die("creating identity manager from ~/.dnsid", err)
	}

	profile := oidc.NewFromIdentityManagerKeyProvider(idm, oidc.Config{})

	assertion, err := profile.CreateOIDCAssertion(oidc.OIDCAssertionOptions{Issuer: issuer})
	if err != nil {
		die("creating OIDC assertion", err)
	}
	fmt.Println("acting as:", idm.Domain())
	fmt.Println("signed assertion:", assertion)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	token, err := profile.ExchangeOIDCToken(ctx, oidc.OIDCTokenExchangeOptions{
		Issuer:    issuer,
		Audience:  audience,
		Assertion: assertion,
	})
	if err != nil {
		die("exchanging OIDC token", err)
	}

	fmt.Println("\ntoken response:")
	fmt.Println("access_token:", token.AccessToken)
	if token.IDToken != "" {
		fmt.Println("id_token:", token.IDToken)
	}
	fmt.Println("token_type:", token.TokenType)
	fmt.Println("expires_in:", token.ExpiresIn)
	fmt.Println("scope:", token.Scope)
}

func die(action string, err error) {
	fmt.Fprintf(os.Stderr, "%s failed: %v\n", action, err)
	os.Exit(1)
}
