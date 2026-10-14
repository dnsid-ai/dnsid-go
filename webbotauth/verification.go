package webbotauth

import (
	"bytes"
	"context"
	"crypto"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"net/url"
	"strings"
	"time"

	wbahttpsig "github.com/WebDecoy/web-bot-auth/httpsig"
	"github.com/dnsid-ai/dnsid-go"
	"github.com/dnsid-ai/dnsid-go/httpsig"
	"github.com/dnsid-ai/dnsid-go/internal/httputil"
	"github.com/dnsid-ai/dnsid-go/internal/joseutil"
	"github.com/dnsid-ai/dnsid-go/internal/jsonutil"
	"github.com/dnsid-ai/dnsid-go/internal/netguard"
	"github.com/forcebit/http-message-signatures-rfc9421-go/pkg/digest"
	"github.com/forcebit/http-message-signatures-rfc9421-go/pkg/sfv"
	"github.com/lestrrat-go/jwx/v3/jwk"
)

// ReplayPolicy must atomically reject a repeated (domain, keyID, nonce), retain
// it until retainUntil, and fail closed on store errors.
type ReplayPolicy func(ctx context.Context, domain, keyID, nonce string, retainUntil time.Time) error

// VerificationOptions supplies trusted discovery and current application-peer
// evidence. Cross-host delegation is not supported.
type VerificationOptions struct {
	SignerDomain string
	// DirectoryURL is a trusted direct HTTPS directory endpoint. Without a
	// Signature-Agent, it defaults to the well-known path on SignerDomain.
	DirectoryURL string
	// AllowSignatureAgentDomain permits the signed discovery origin host to
	// identify the signer when SignerDomain is absent. Default is false.
	AllowSignatureAgentDomain bool
	Peer                      dnsid.VerifyDomainOpts
	// RequiredComponents requires exact coverage, including parameter values,
	// beyond the profile minimum. Nil adds no requirements. Policy is validated
	// before content reads or discovery; request-only components are required.
	RequiredComponents []httpsig.ComponentIdentifier
	// Replay is optional. Without it, valid requests can be reused until expiry.
	Replay ReplayPolicy
}

// NewVerifier constructs a verification-only profile with public-address-only,
// Web-PKI HTTPS discovery. Redirects are rejected. No local key is required.
func NewVerifier(resolver dnsid.IdentityResolver, cfg Config) *Profile {
	transport := dnsid.SafeDialerTransport()
	// Discovery must not inherit disabled Web PKI or application client keys.
	transport.TLSClientConfig = nil
	transport.DisableCompression = true
	client := &http.Client{
		Transport: transport,
		Timeout:   dnsid.DefaultVerificationTimeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	return &Profile{resolver: resolver, client: client, cfg: cfg}
}

func directoryFetchError(err error) error {
	if errors.Is(err, context.Canceled) {
		return err
	}
	var certificateErr *tls.CertificateVerificationError
	var unsafeErr *netguard.UnsafeDestinationError
	var recordErr tls.RecordHeaderError
	var alertErr tls.AlertError
	if errors.As(err, &certificateErr) || errors.As(err, &recordErr) || errors.As(err, &alertErr) || strings.Contains(err.Error(), "tls:") {
		return dnsid.NewVerificationError(dnsid.VerificationCodeTLSError, false, "dnsid: Web Bot Auth directory TLS failure", err)
	}
	if errors.As(err, &unsafeErr) {
		return dnsid.NewVerificationError(dnsid.VerificationCodeSignatureInvalid, false, "dnsid: Web Bot Auth unsafe discovery destination", err)
	}
	return dnsid.NewVerificationError(dnsid.VerificationCodeJWKSUnavailable, true, "dnsid: Web Bot Auth directory unavailable", err)
}

func wbaError(message string) error {
	return dnsid.NewVerificationError(dnsid.VerificationCodeSignatureInvalid, false, "dnsid: Web Bot Auth "+message, nil)
}

// VerifyWebBotAuthSignedRequest verifies a request, its signed directory, and
// current DNSid ku binding and acceptance. It does not grant permissions.
// The operation has the shared verification deadline, 1 MiB request metadata,
// 8 MiB request content, 1 MiB directory, 64 directory keys, and 64 JSON nesting
// levels. Directories are not cached; DNSid acceptance and current key binding
// run on every call.
// Supplied body readers must unblock on Close; resolver and replay callbacks
// must honor ctx. Signature fields use the shared parser's 64 KiB and 128-label
// limits, with at most 128 components per signature.
func (p *Profile) VerifyWebBotAuthSignedRequest(ctx context.Context, req *http.Request, opts VerificationOptions) (*dnsid.VerifiedDomain, error) {
	if p == nil || p.resolver == nil || req == nil || p.client == nil {
		return nil, dnsid.NewArgumentError("dnsid: WBA verification requires a request and IdentityResolver", nil)
	}
	if err := p.validateConfig(); err != nil {
		return nil, err
	}
	if len(opts.RequiredComponents) > 128 {
		return nil, dnsid.NewArgumentError("dnsid: too many required WBA components", nil)
	}
	var required []httpsig.ComponentIdentifier
	for _, c := range opts.RequiredComponents {
		if err := httpsig.AppendComponent(&required, c); err != nil {
			return nil, err
		}
		if required[len(required)-1].Name == "@status" || c.Params["req"] == true {
			return nil, dnsid.NewArgumentError("dnsid: WBA coverage policy requires request components", nil)
		}
	}
	ctx, cancel := dnsid.VerificationContext(ctx)
	defer cancel()
	metadataSize := len(req.Method) + len(req.Host) + len(req.RequestURI)
	if u := req.URL; u != nil {
		metadataSize += len(u.Scheme) + len(u.Host) + len(u.Path) + len(u.RawPath) + len(u.RawQuery) + len(u.Opaque) + len(u.Fragment) + len(u.RawFragment)
		if u.User != nil {
			password, _ := u.User.Password()
			metadataSize += len(u.User.Username()) + len(password)
		}
	}
	for name, values := range req.Header {
		metadataSize += len(name)
		for _, value := range values {
			metadataSize += len(value)
		}
	}
	if metadataSize > 1<<20 {
		return nil, wbaError("request metadata exceeds size limit")
	}
	params, signature, err := selectSignature(req.Header, "web-bot-auth", "")
	if err != nil {
		return nil, err
	}
	if err := p.validTime(params); err != nil {
		return nil, err
	}
	if !covers(params, "@authority", nil) {
		return nil, wbaError("requires exact @authority coverage")
	}
	for _, c := range required {
		if !covers(params, c.Name, c.Params) {
			return nil, wbaError("missing required request coverage")
		}
	}
	if err := verifyContent(ctx, req.Header, &req.Body, params, 8<<20); err != nil {
		return nil, err
	}
	domain, endpoint, err := discovery(req.Header, params, opts)
	if err != nil {
		return nil, err
	}
	directoryReq, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	directoryReq.Header.Set("Accept-Encoding", "identity")
	res, err := p.client.Do(directoryReq)
	if err != nil {
		return nil, directoryFetchError(err)
	}
	defer res.Body.Close()
	res.Request = directoryReq
	if res.StatusCode == http.StatusRequestTimeout || res.StatusCode == http.StatusTooManyRequests || res.StatusCode >= 500 {
		return nil, dnsid.NewVerificationError(dnsid.VerificationCodeJWKSUnavailable, true, "dnsid: Web Bot Auth directory temporarily unavailable", nil)
	}
	if _, coded := res.Header["Content-Encoding"]; coded || res.Uncompressed {
		return nil, wbaError("coded directories are unsupported")
	}
	mediaType, _, err := mime.ParseMediaType(res.Header.Get("Content-Type"))
	if err != nil || res.StatusCode != http.StatusOK || mediaType != DirectoryContentType {
		return nil, wbaError("invalid directory status or media type")
	}
	body, err := boundedContent(ctx, res.Body, 1<<20)
	if err != nil {
		var verificationErr *dnsid.VerificationError
		if errors.As(err, &verificationErr) {
			return nil, err
		}
		return nil, directoryFetchError(err)
	}
	res.Body = io.NopCloser(bytes.NewReader(body))
	key, err := directoryKey(body, params.KeyID)
	if err != nil {
		return nil, err
	}
	dirParams, dirSignature, err := selectSignature(res.Header, "http-message-signatures-directory", params.KeyID)
	if err != nil {
		return nil, err
	}
	if err := p.validTime(dirParams); err != nil {
		return nil, err
	}
	for _, c := range []httpsig.ComponentIdentifier{
		{Name: "@authority", Params: map[string]any{"req": true}},
		{Name: "content-type"}, {Name: "cache-control"}, {Name: "content-digest"},
	} {
		if !covers(dirParams, c.Name, c.Params) {
			return nil, wbaError("missing directory coverage")
		}
	}
	if err := verifyContent(ctx, res.Header, &res.Body, dirParams, 1<<20); err != nil {
		return nil, err
	}
	if err := verifyMessage(res, dirParams, dirSignature, key); err != nil {
		return nil, err
	}
	if err := verifyMessage(req, params, signature, key); err != nil {
		return nil, err
	}
	peer := opts.Peer
	if req.TLS != nil {
		if peer.PeerCertificate == nil && len(req.TLS.PeerCertificates) > 0 {
			peer.PeerCertificate = req.TLS.PeerCertificates[0]
		}
		if peer.VerifiedPeerCertificateChains == nil {
			peer.VerifiedPeerCertificateChains = req.TLS.VerifiedChains
		}
	}
	identityStartedAt := time.Now()
	vd, err := dnsid.VerifyIdentity(ctx, p.resolver, domain, peer)
	if err != nil {
		return nil, err
	}
	if vd == nil || vd.Domain() != domain || vd.KeySet() == nil || vd.Record() == nil {
		return nil, wbaError("missing DNSid identity")
	}
	current, err := vd.KeySet().CurrentOperationalSigningKey(vd.Record().Version)
	if err != nil {
		return nil, err
	}
	thumb, err := current.Thumbprint()
	if err != nil || thumb != params.KeyID || current.Alg() != dnsid.JoseAlgEdDSA {
		return nil, wbaError("directory key is not the current DNSid ku key")
	}
	if err := p.validTime(params); err != nil {
		return nil, err
	}
	if err := p.validTime(dirParams); err != nil {
		return nil, err
	}
	if err := vd.CheckFreshness(identityStartedAt); err != nil {
		return nil, err
	}
	if opts.Replay != nil {
		if params.Nonce == "" {
			return nil, wbaError("replay policy requires a nonce")
		}
		if err := opts.Replay(ctx, domain, params.KeyID, params.Nonce, time.Unix(params.Expires, 0).Add(p.clockSkew())); err != nil {
			return nil, err
		}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := p.validTime(params); err != nil {
		return nil, err
	}
	if err := p.validTime(dirParams); err != nil {
		return nil, err
	}
	if err := vd.CheckFreshness(identityStartedAt); err != nil {
		return nil, err
	}
	return vd, nil
}

func selectSignature(header http.Header, tag, keyID string) (httpsig.SignatureParams, []byte, error) {
	inputs, err := httpsig.ParseSignatureInput(strings.Join(header.Values("Signature-Input"), ", "))
	if err != nil {
		return httpsig.SignatureParams{}, nil, err
	}
	signatures, err := httpsig.ParseSignature(strings.Join(header.Values("Signature"), ", "))
	if err != nil {
		return httpsig.SignatureParams{}, nil, err
	}
	var selected httpsig.SignatureParams
	var signature []byte
	count := 0
	for label, params := range inputs {
		if params.Tag != tag || (keyID != "" && params.KeyID != keyID) {
			continue
		}
		sig, ok := signatures[label]
		if !ok {
			continue
		}
		selected, signature = params, sig
		count++
	}
	if count != 1 {
		return selected, nil, wbaError("requires one unambiguous tagged signature")
	}
	return selected, signature, nil
}

func (p *Profile) currentTime() time.Time {
	if p.now != nil {
		return p.now()
	}
	return time.Now()
}

func (p *Profile) clockSkew() time.Duration {
	if p.cfg.ClockSkew == 0 && !p.cfg.clockSkewSet {
		return 5 * time.Second
	}
	return p.cfg.ClockSkew
}

func (p *Profile) validTime(params httpsig.SignatureParams) error {
	created, expires := false, false
	for _, parameter := range params.Parameters {
		created = created || parameter.Name == "created"
		expires = expires || parameter.Name == "expires"
	}
	thumb, err := base64.RawURLEncoding.Strict().DecodeString(params.KeyID)
	if err != nil || len(thumb) != 32 || base64.RawURLEncoding.EncodeToString(thumb) != params.KeyID || params.Alg != "ed25519" {
		return wbaError("invalid thumbprint or algorithm")
	}
	now := p.currentTime()
	if !created || !expires || params.Created > params.Expires || params.Expires-params.Created > 300 ||
		time.Unix(params.Created, 0).After(now.Add(p.clockSkew())) || !now.Before(time.Unix(params.Expires, 0).Add(p.clockSkew())) {
		return wbaError("signature outside validity window")
	}
	return nil
}

func covers(params httpsig.SignatureParams, name string, want map[string]any) bool {
	for _, c := range params.Components {
		if c.Name != name || len(c.Params) != len(want) {
			continue
		}
		match := true
		for k, v := range want {
			if c.Params[k] != v {
				match = false
			}
		}
		if match {
			return true
		}
	}
	return false
}

func boundedContent(ctx context.Context, body io.ReadCloser, maximum int64) ([]byte, error) {
	stop := context.AfterFunc(ctx, func() { _ = body.Close() })
	defer stop()
	data, err := io.ReadAll(io.LimitReader(body, maximum+1))
	if ctxErr := ctx.Err(); ctxErr != nil {
		return nil, ctxErr
	}
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > maximum {
		return nil, wbaError("content exceeds size limit")
	}
	return data, nil
}

func verifyContent(ctx context.Context, header http.Header, body *io.ReadCloser, params httpsig.SignatureParams, maximum int64) error {
	hasBody := *body != nil && *body != http.NoBody
	covered := covers(params, "content-digest", nil)
	if hasBody && !covered {
		return wbaError("content-digest is not covered")
	}
	if !covered {
		return nil
	}
	if *body == nil {
		return wbaError("covered content-digest has no supplied content")
	}
	data, err := boundedContent(ctx, *body, maximum)
	if err != nil {
		return err
	}
	*body = httputil.ReplayBody(data, *body)
	if err := digest.VerifyContentDigestBytes(data, strings.Join(header.Values("Content-Digest"), ", "), []string{"sha-256"}); err != nil {
		return wbaError("content-digest mismatch")
	}
	return nil
}

func verifyMessage(message any, params httpsig.SignatureParams, signature []byte, key jwk.Key) error {
	base, err := httpsig.BuildSignatureInput(message, params)
	if err != nil {
		return err
	}
	if !joseutil.VerifySignature(joseutil.ProtectedHeader{Alg: dnsid.JoseAlgEdDSA}, joseutil.SignatureParts{SigningInput: []byte(base), Signature: signature}, []jwk.Key{key}) {
		return wbaError("invalid signature")
	}
	return nil
}

func directoryKey(body []byte, keyID string) (jwk.Key, error) {
	object, err := jsonutil.DecodeObject(body, true)
	if err != nil {
		return nil, err
	}
	keys, ok := object["keys"].([]any)
	if !ok || len(keys) == 0 || len(keys) > 64 {
		return nil, wbaError("invalid directory key count")
	}
	var selected jwk.Key
	seen := map[string]bool{}
	for _, value := range keys {
		m, ok := value.(map[string]any)
		_, private := m["d"]
		if !ok || private || m["kty"] != "OKP" || m["crv"] != "Ed25519" {
			return nil, wbaError("invalid public directory key")
		}
		if alg, present := m["alg"]; present && alg != "ed25519" {
			return nil, wbaError("invalid directory algorithm")
		}
		if use, present := m["use"]; present && use != "sig" {
			return nil, wbaError("invalid directory key use")
		}
		x, ok := m["x"].(string)
		xBytes, err := base64.RawURLEncoding.Strict().DecodeString(x)
		if !ok || err != nil || len(xBytes) != 32 || base64.RawURLEncoding.EncodeToString(xBytes) != x {
			return nil, wbaError("invalid Ed25519 public material")
		}
		if raw, present := m["key_ops"]; present {
			ops, ok := raw.([]any)
			seenOps, verify := map[string]bool{}, false
			if !ok {
				return nil, wbaError("invalid directory key operations")
			}
			for _, value := range ops {
				op, ok := value.(string)
				if !ok || (op != "sign" && op != "verify") || seenOps[op] {
					return nil, wbaError("invalid directory key operations")
				}
				seenOps[op] = true
				verify = verify || op == "verify"
			}
			if !verify {
				return nil, wbaError("directory key excludes verification")
			}
		}
		// Translate the WBA algorithm without discarding JWK restrictions.
		m["alg"] = string(dnsid.JoseAlgEdDSA)
		public, err := json.Marshal(m)
		if err != nil {
			return nil, err
		}
		key, err := jwk.ParseKey(public)
		if err != nil {
			return nil, err
		}
		thumb, err := key.Thumbprint(crypto.SHA256)
		if err != nil {
			return nil, err
		}
		id := base64.RawURLEncoding.EncodeToString(thumb)
		if m["kid"] != id || seen[id] {
			return nil, wbaError("wrong or duplicate directory thumbprint")
		}
		seen[id] = true
		if id == keyID {
			selected = key
		}
	}
	if selected == nil {
		return nil, wbaError("request key not found in directory")
	}
	return selected, nil
}

func discovery(header http.Header, params httpsig.SignatureParams, opts VerificationOptions) (string, string, error) {
	raw, kind := opts.DirectoryURL, "jwks_uri"
	if values := header.Values("Signature-Agent"); len(values) > 0 {
		input := strings.Join(values, ", ")
		limits := sfv.DefaultLimits()
		if len(input) > limits.MaxInputLength {
			return "", "", wbaError("Signature-Agent exceeds size limit")
		}
		members, err := wbahttpsig.ParseDictionaryHeader(input)
		if err != nil {
			return "", "", err
		}
		if len(members) > limits.MaxDictionaryMembers {
			return "", "", wbaError("Signature-Agent exceeds member limit")
		}
		seen := map[string]bool{}
		for _, member := range members {
			if seen[member.Key] {
				return "", "", wbaError("duplicate Signature-Agent member")
			}
			seen[member.Key] = true
		}
		dict, err := sfv.NewParser(input, sfv.DefaultLimits()).ParseDictionary()
		if err != nil {
			return "", "", err
		}
		member := ""
		for _, c := range params.Components {
			if c.Name != "signature-agent" {
				continue
			}
			key, ok := c.Params["key"].(string)
			if !ok || len(c.Params) != 1 || member != "" {
				return "", "", wbaError("requires one exact Signature-Agent member")
			}
			member = key
		}
		item, ok := dict.Values[member].(sfv.Item)
		if !ok || member == "" {
			return "", "", wbaError("missing covered Signature-Agent member")
		}
		raw, ok = item.Value.(string)
		if !ok {
			return "", "", wbaError("invalid Signature-Agent URI")
		}
		kind = "directory"
		typeSeen := false
		for _, parameter := range item.Parameters {
			if parameter.Key != "type" {
				continue
			}
			token, ok := parameter.Value.(sfv.Token)
			if !ok || typeSeen {
				return "", "", wbaError("invalid discovery type")
			}
			kind, typeSeen = token.Value, true
		}
	}
	domain := opts.SignerDomain
	if domain != "" {
		var err error
		domain, err = dnsid.NormalizeFQDN(domain)
		if err != nil {
			return "", "", err
		}
	}
	if raw == "" && domain != "" {
		raw = "https://" + domain + DirectoryPath
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || (kind != "directory" && kind != "jwks_uri") {
		return "", "", wbaError("invalid HTTPS discovery")
	}
	host, err := dnsid.NormalizeFQDN(u.Hostname())
	if err != nil {
		return "", "", err
	}
	if domain == "" && opts.AllowSignatureAgentDomain && len(header.Values("Signature-Agent")) > 0 {
		domain = host
	}
	if domain == "" || host != domain {
		return "", "", wbaError("discovery host not approved as signer")
	}
	if kind == "directory" {
		u.Path, u.RawPath, u.RawQuery, u.Fragment = DirectoryPath, "", "", ""
		u.ForceQuery = false
	}
	if u.Fragment != "" {
		return "", "", wbaError("discovery endpoint contains fragment")
	}
	return domain, u.String(), nil
}
