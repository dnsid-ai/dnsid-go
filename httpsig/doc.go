// Package httpsig implements RFC 9421 HTTP Message Signatures for DNSid
// agents: signing outbound HTTP requests with an agent's operational key and
// verifying inbound signatures against the signer's published DNSid identity.
//
// The main entry type is Profile. A Profile combines an identity resolver
// (usually a dnsid.IdentityManager), a local agent domain, and a
// dnsid.KeyProvider. The resolver is required for verification; the local
// domain and key provider are required for signing. Config bounds signature
// freshness; its zero value applies the profile defaults.
//
// A typical exchange signs a request on one side and verifies it on the
// other:
//
//	signer := httpsig.NewFromIdentityManagerKeyProvider(idm, httpsig.Config{})
//
//	req, _ := http.NewRequest(http.MethodGet, "https://api.example.com/data", nil)
//	signed, err := signer.CreateSignedHTTPRequest(req, httpsig.SigningOptions{})
//	// ... dispatch signed; the receiver runs:
//
//	vd, err := verifier.VerifyHTTPRequest(ctx, signed)
//	// vd identifies the verified signer domain.
//
// CreateSignedHTTPClient wraps an *http.Client so every outbound request is
// signed automatically. Lower-level helpers (BuildSignatureInput,
// SignHTTPMessage, ParseSignatureInput, ParseSignature) expose the RFC 9421
// signature base and header handling used by other DNSid profiles such as
// Web Bot Auth.
//
// See https://docs.dnsid.ai for protocol guides and account setup.
package httpsig
