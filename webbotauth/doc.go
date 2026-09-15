// Package webbotauth implements the Web Bot Auth profile
// (draft-meunier-webbotauth-httpsig-protocol) on top of package httpsig: it
// signs HTTP requests with RFC 9421 HTTP Message Signatures tagged
// "web-bot-auth" so an origin can verify the caller is a specific DNSid
// agent. The signing key must be Ed25519.
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
// public key.
//
// See https://docs.dnsid.ai for protocol guides and account setup.
package webbotauth
