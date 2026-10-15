// Package webbotauth implements the constrained DNSid Web Bot Auth profile
// targeting published draft-ietf-webbotauth-httpsig-protocol-00, including
// its directory format, using package httpsig. Unpublished editor changes
// are not the baseline; typed discovery and directory JWK alg="ed25519" remain.
// It signs and verifies requests and signed key directories using Ed25519.
// This is not a generic WBA verifier or a partner interoperability claim.
//
// The main entry type is Profile. A Profile holds the agent's domain and its
// dnsid.KeyProvider; Config controls the Signature-Agent header, the key
// directory URL, and signature lifetimes, and its zero value applies the
// profile defaults. Signature-Agent is always required and covered. Directory
// discovery requires an HTTPS origin with no path (including /), query, or
// fragment; jwks_uri identifies a direct HTTPS endpoint. Trusted caller policy
// does not replace signed discovery. Directory creation times cannot be in the
// future, even within the configured request clock skew.
//
// A typical caller signs a request and lets the origin discover its key
// through the Signature-Agent header:
//
//	profile := webbotauth.NewFromIdentityManager(idm, webbotauth.Config{})
//
//	req, _ := http.NewRequest(http.MethodGet, "https://target.example/search?q=dnsid", nil)
//	signed, err := profile.CreateWebBotAuthSignedRequest(req, webbotauth.SigningOptions{})
//	// signed carries Signature-Agent, Signature-Input, and Signature headers.
//
// ServeHttpMessageSignaturesDirectory produces the signed key directory
// response that origins fetch from DirectoryPath to obtain the agent's
// public key. Request signing preserves existing Authorization fields.
// Directories are backdated by min(5, TTL-1) seconds without extending their
// lifetime, and emit bounded max-age with must-revalidate. Disable CDN stale
// serving, stale-while-revalidate, and stale-if-error for this endpoint.
// Only the current DNSid operational key is accepted, without rotation overlap.
// After both signatures pass, a key mismatch permits one DNSid refresh per
// domain per five seconds. Failed attempts consume the allowance. Suppressed,
// failed, or still-mismatched refreshes reject; caches can still delay rotation.
//
// VerifyWebBotAuthSignedRequest authenticates both signatures and binds the
// directory key to the current DNSid ku key through a RefreshingIdentityResolver,
// including its configured accountable-entity acceptance. NewVerifier requires
// no local identity. Discovery uses public-address-only, Web-PKI HTTPS with no
// redirects, content coding, or directory caching. Each invocation sends an
// unconditional no-cache GET; fresh directory key misses are not retried.
// Discovery must not identify authenticated ku, including query/fragment variants.
// Discovery availability
// failures are transient; invalid evidence and unsafe destinations are not.
// Supply a trusted SignerDomain or explicitly
// permit the signed discovery host to identify it; cross-host delegation is
// unsupported. Pass the current application peer's verified certificate chains
// for fl=mtls, not the directory server's certificate.
//
// Verification has a finite shared deadline, bounded content and directory
// inputs, and a caller-supplied ReplayPolicy hook. Without a replay policy,
// valid signatures can be reused until expiry. Required @authority coverage
// alone does not bind the method or path. Signers can cover additional
// components; recipients require them through VerificationOptions.RequiredComponents.
// Extra signing coverage does not make a recipient require it.
//
// WBA reuses ku, which also authorizes KEY_ROTATION. Unrestricted signing-node
// key access therefore permits identity rotation, not just forged requests;
// keeping ek off the fleet does not remove rotation authority. Use the shared
// managed rotation/recovery flow, pause request and directory signing during
// recovery, and revoke/reissue suspected compromised keys rather than rotate.
// Without fl=mtls, validated HTTPS retrieval of ku supplies agent-domain TLS
// evidence; the crawler itself need not accept inbound connections. With fl=mtls,
// hosted resource certificates do not replace current application-peer evidence.
//
// See https://docs.dnsid.ai for protocol guides and account setup.
package webbotauth
