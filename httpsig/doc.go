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
//	req, _ := http.NewRequest(http.MethodGet, "https://api.example/data", nil)
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
// Response authentication is opt-in; a signed request alone does not authenticate
// its responder. Enable SigningOptions.ResponseSignature with a locally selected
// ResponseSignatureOptions.ExpectedDomain to request and require a DNSid signed
// response. The expected agent domain may differ from the HTTP host. Configure
// entity acceptance separately on the resolver. HTTPS is required, and responder
// authentication happens only after the request has been sent.
//
// The server calls SignRequestedHTTPResponse after verifying the caller and
// authorizing the operation, before sending the finalized status, headers, and
// content. It uses the operational key, covers the originating request signature
// fields, sets SHA-256 Content-Digest, and adds Cache-Control: no-store. It does
// not authorize callers or permit unsigned fallback on signing errors.
//
// CreateSignedHTTPClient verifies responses automatically, including errors and
// redirects. Negotiated mode uses HTTP/1 without connection reuse, automatic
// redirects/replays, transparent content decoding, or response caching. Custom
// round trippers reject because the SDK cannot configure their retry/cache policy.
// Standalone CreateSignedHTTPRequest callers must retain an unmodified prepared
// request and independent original response-policy snapshot, then call
// VerifySignedHTTPResponse with trusted current-server peer evidence. Never use
// echoed request metadata, a discovery certificate, or a previous connection's
// certificate as that snapshot or evidence.
//
// Only covered fields are authenticated. Content-Type, Content-Encoding, and
// Location are not covered by default; request them through AdditionalComponents
// when application behavior depends on them. Middleware must finalize content
// coding before signing and must not alter covered bytes afterward.
//
// Negotiation and signature fields are capped at 16 KiB each, combined headers
// at 1 MiB, request-target inputs at 64 KiB, and response content at 8 MiB. The
// nonce is canonical unpadded base64url, 43 to 1024 characters, decoding to at
// least 32 bytes. Parsing permits at most 128 labels/components and 64 parameters.
// Sending, reads, and verification share a finite request context budget (default
// 30 seconds). Custom body readers/providers must be finite and interruptible;
// hosts must impose read deadlines. HEAD, 204, 205, and 304 digest empty content;
// an unavailable ordinary body is rejected, not treated as empty.
//
// See https://docs.dnsid.ai for protocol guides and account setup.
package httpsig
