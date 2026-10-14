// Package webbotauth implements the constrained DNSid Web Bot Auth profile
// targeting draft-meunier-webbotauth-httpsig-protocol-00 and
// draft-meunier-webbotauth-httpsig-directory-00 using package httpsig.
// It signs and verifies requests and signed key directories using Ed25519.
// This is not a generic WBA verifier or a partner interoperability claim.
//
// The main entry type is Profile. A Profile holds the agent's domain and its
// dnsid.KeyProvider; Config controls the Signature-Agent header, the key
// directory URL, and signature lifetimes, and its zero value applies the
// profile defaults.
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
//
// VerifyWebBotAuthSignedRequest authenticates both signatures and binds the
// directory key to the current DNSid ku key through an IdentityResolver,
// including its configured accountable-entity acceptance. NewVerifier requires
// no local identity. Discovery uses public-address-only, Web-PKI HTTPS with no
// redirects, content coding, or directory caching. Discovery availability
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
// See https://docs.dnsid.ai for protocol guides and account setup.
package webbotauth
