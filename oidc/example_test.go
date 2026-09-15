package oidc_test

import (
	"context"
	"fmt"
	"log"
	"time"

	dnsid "github.com/dnsid-ai/dnsid-go"
	"github.com/dnsid-ai/dnsid-go/oidc"
)

// ExampleProfile_GetOIDCToken mints a DNSid OIDC token: the profile signs a
// JWT-bearer assertion with the agent's operational key and exchanges it at
// the issuer's token endpoint.
//
// It requires an agent identity on disk (created with `dnsid auth login` and
// `dnsid init`, see QUICKSTART.md) and a reachable OIDC issuer, so it has no
// Output and is compiled but not run by go test.
func ExampleProfile_GetOIDCToken() {
	// Load the agent identity from ~/.dnsid. The manager can both verify
	// domains and sign as the agent.
	idm, err := dnsid.NewIdentityManagerFromDnsid("", dnsid.Config{})
	if err != nil {
		log.Fatal(err)
	}

	profile := oidc.NewFromIdentityManagerKeyProvider(idm, oidc.Config{})

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	tok, err := profile.GetOIDCToken(ctx, oidc.OIDCTokenExchangeOptions{
		Issuer:   "https://issuer.example",
		Audience: "https://api.example",
	})
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("token_type:", tok.TokenType)
	fmt.Println("expires_in:", tok.ExpiresIn)
}
