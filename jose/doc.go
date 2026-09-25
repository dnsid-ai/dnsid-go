// Package jose implements the DNSid JOSE profile: creating and verifying
// DNSid JWTs and compact JWS objects signed with an agent's operational key.
//
// The main entry type is Profile. A Profile combines an identity resolver
// (usually a dnsid.IdentityManager), a local agent domain, and a
// dnsid.KeyProvider. The resolver is required for verification; the local
// domain and key provider are required for signing. Config bounds token
// lifetime and clock skew; its zero value applies the profile defaults.
//
// A typical round trip mints a JWT as the local agent and verifies a peer's
// token by resolving the issuer's DNSid identity record from DNS:
//
//	profile := jose.NewFromIdentityManagerKeyProvider(idm, jose.Config{})
//
//	token, err := profile.CreateJWT(jose.JWTOptions{Audience: "bob.example.com"})
//	// ... send token to bob.example.com ...
//
//	vd, claims, err := profile.VerifyJWT(ctx, token, jose.VerifyJWTOptions{ExpectedAudience: "bob.example.com"})
//	// At the receiving side, Bob must verify against its own expected audience.
//	// vd identifies the verified issuer domain; claims holds the parsed JWT.
//
// CreateJWS and VerifyJWS provide the same flow for compact JWS over
// arbitrary payloads.
//
// See https://docs.dnsid.ai for protocol guides and account setup.
package jose
