// Package oidc mints and verifies DNSid OIDC tokens.
//
// The package implements an OIDC federation profile on top of core DNSid
// identity verification. An agent proves control of its domain-anchored
// identity by signing a JWT-bearer assertion with its operational key; an
// OIDC issuer exchanges that assertion for tokens; and a relying party
// verifies an issued token against the issuer's published JWKS and, by
// default, verifies the token subject as a DNSid domain through a
// dnsid.IdentityResolver.
//
// Profile is the main entry type. Construct one with New,
// NewFromIdentityManager, or NewFromIdentityManagerKeyProvider, then mint
// tokens with GetOIDCToken (or CreateOIDCAssertion plus ExchangeOIDCToken)
// and verify presented tokens with VerifyOIDCToken:
//
//	idm, err := dnsid.NewIdentityManagerFromDnsid("", dnsid.Config{})
//	if err != nil {
//		log.Fatal(err)
//	}
//	profile := oidc.NewFromIdentityManagerKeyProvider(idm, oidc.Config{
//		AllowedIssuers: []string{"https://issuer.example"},
//	})
//
//	// Agent side: mint a token from an OIDC issuer.
//	token, err := profile.GetOIDCToken(ctx, oidc.OIDCTokenExchangeOptions{
//		Issuer:   "https://issuer.example",
//		Audience: "https://api.example",
//	})
//
//	// Relying-party side: verify a presented token. The token's issuer
//	// must appear in Config.AllowedIssuers.
//	subject, err := profile.VerifyOIDCToken(ctx, token.AccessToken, oidc.VerifyOIDCTokenOptions{
//		Issuer:   "https://issuer.example",
//		Audience: "https://api.example",
//	})
//
// All issuer traffic uses SSRF-safe transport, never follows redirects, caps
// response sizes, and requires HTTPS issuers whose discovery endpoints are
// same-origin with the issuer (Config.AllowHTTPLoopbackIssuer relaxes the
// HTTPS requirement for loopback issuers during local development).
//
// See https://docs.dnsid.ai for protocol guides and account setup.
package oidc
