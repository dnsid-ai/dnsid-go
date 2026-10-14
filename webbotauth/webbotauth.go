package webbotauth

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/dnsid-ai/dnsid-go"
	"github.com/dnsid-ai/dnsid-go/httpsig"
	"github.com/dnsid-ai/dnsid-go/internal/httputil"
	"github.com/dnsid-ai/dnsid-go/internal/joseutil"
	"github.com/forcebit/http-message-signatures-rfc9421-go/pkg/digest"
	"github.com/forcebit/http-message-signatures-rfc9421-go/pkg/sfv"
	"github.com/lestrrat-go/jwx/v3/jwk"
)

const (
	// DirectoryPath is the well-known HTTP path where a Web Bot Auth key
	// directory is served.
	DirectoryPath = "/.well-known/http-message-signatures-directory"

	// DirectoryContentType is the media type of a Web Bot Auth key
	// directory response.
	DirectoryContentType = "application/http-message-signatures-directory+json"
)

// Config contains Web Bot Auth profile defaults. The zero value applies the
// profile defaults.
type Config struct {
	// DirectoryURL overrides the URI advertised in Signature-Agent. Empty
	// means "https://<domain>". Directory discovery requires an origin URI;
	// jwks_uri discovery uses this as the direct endpoint.
	DirectoryURL string

	// SignatureAgentType controls discovery interpretation. Empty means
	// "directory". A direct custom endpoint requires "jwks_uri".
	SignatureAgentType string

	// SignatureTTL is the default request signature lifetime (the distance
	// from the created to the expires parameter). Zero means the default of
	// 1 minute; WithSignatureTTL records explicit presence and rejects zero.
	// Nonzero values below 1 second or above 5 minutes are invalid.
	SignatureTTL time.Duration

	// IncludeSignatureAgent controls whether signed requests carry a
	// Signature-Agent header covered by the signature. Nil means true.
	IncludeSignatureAgent *bool

	// DirectorySignatureTTL is the signature lifetime for key directory
	// responses. Zero means the default of 5 minutes; WithDirectorySignatureTTL
	// records explicit presence and rejects zero. Nonzero values below 1 second
	// or above 5 minutes are invalid.
	DirectorySignatureTTL time.Duration

	// ClockSkew is the WBA verification tolerance. Negative values are
	// invalid. Zero means omitted (5 seconds); WithClockSkew(0) sets strict zero.
	ClockSkew time.Duration

	signatureTTLSet          bool
	directorySignatureTTLSet bool
	clockSkewSet             bool
}

// WithSignatureTTL specifies an explicit positive request signature lifetime.
func (c Config) WithSignatureTTL(ttl time.Duration) Config {
	c.SignatureTTL, c.signatureTTLSet = ttl, true
	return c
}

// WithDirectorySignatureTTL specifies an explicit positive directory lifetime.
func (c Config) WithDirectorySignatureTTL(ttl time.Duration) Config {
	c.DirectorySignatureTTL, c.directorySignatureTTLSet = ttl, true
	return c
}

// WithClockSkew specifies verification tolerance, including explicit zero.
func (c Config) WithClockSkew(skew time.Duration) Config {
	c.ClockSkew, c.clockSkewSet = skew, true
	return c
}

// SigningOptions configures Web Bot Auth request signing.
type SigningOptions struct {
	// AdditionalComponents lists extra component names to cover beyond the
	// profile's defaults. Unknown names cause signing to fail.
	AdditionalComponents []string

	// AdditionalComponentIDs lists extra components, with parameters, to
	// cover beyond the profile's defaults.
	AdditionalComponentIDs []httpsig.ComponentIdentifier

	// SignatureAgent, when non-nil, overrides Config.IncludeSignatureAgent
	// for this request.
	SignatureAgent *bool

	// TTL overrides Config.SignatureTTL. Zero means omitted; WithTTL records
	// explicit presence and rejects zero.
	TTL    time.Duration
	ttlSet bool
}

// WithTTL specifies an explicit positive request signature lifetime.
func (o SigningOptions) WithTTL(ttl time.Duration) SigningOptions {
	o.TTL, o.ttlSet = ttl, true
	return o
}

// Profile signs and verifies DNSid Web Bot Auth requests and serves signed
// key directories. The signing key must be Ed25519. Verification requires an
// IdentityResolver, supplied through NewVerifier or NewFromIdentityManager.
type Profile struct {
	domain   string
	keys     dnsid.KeyProvider
	cfg      Config
	resolver dnsid.IdentityResolver
	client   *http.Client
	now      func() time.Time
}

type identityManager interface {
	Domain() string
	KeyProvider() dnsid.KeyProvider
}

type jwkWithError interface {
	JWKWithError(kid ...string) (jwk.Key, error)
}

// New constructs a Web Bot Auth profile that signs as domain using kp.
// The domain is normalized to a FQDN when possible. Signing fails unless
// kp's active key is Ed25519.
func New(domain string, kp dnsid.KeyProvider, cfg Config) *Profile {
	if d, err := dnsid.NormalizeFQDN(domain); err == nil {
		domain = d
	}
	return &Profile{domain: domain, keys: kp, cfg: cfg}
}

// NewFromIdentityManager constructs a Web Bot Auth profile from an
// IdentityManager-like core manager, using its domain and KeyProvider. A nil
// manager yields a profile whose signing operations fail.
func NewFromIdentityManager(manager identityManager, cfg Config) *Profile {
	if manager == nil {
		return New("", nil, cfg)
	}
	p := New(manager.Domain(), manager.KeyProvider(), cfg)
	if resolver, ok := manager.(dnsid.IdentityResolver); ok {
		p.resolver = resolver
		p.client = NewVerifier(resolver, cfg).client
	}
	return p
}

// CreateWebBotAuthSignedRequest returns a signed clone of req carrying
// Signature-Input and Signature headers tagged "web-bot-auth", plus a
// Signature-Agent header unless disabled by configuration. Requests with a
// body also gain a covered Content-Digest header. The profile's active key
// must be Ed25519.
func (p *Profile) CreateWebBotAuthSignedRequest(req *http.Request, opts SigningOptions) (*http.Request, error) {
	if req == nil {
		return nil, dnsid.NewArgumentError("dnsid: nil HTTP request", nil)
	}
	if err := p.validateConfig(); err != nil {
		return nil, err
	}
	ttl := opts.TTL
	if ttl == 0 && !opts.ttlSet {
		ttl = p.cfg.SignatureTTL
		if ttl == 0 {
			ttl = time.Minute
		}
	}
	if ttl < time.Second || ttl > 5*time.Minute {
		return nil, dnsid.NewArgumentError("dnsid: Web Bot Auth signature TTL must be positive and no greater than 5 minutes", nil)
	}
	kid, alg, key, err := p.activeWBAKey("signing")
	if err != nil {
		return nil, err
	}
	thumb, err := key.Thumbprint(crypto.SHA256)
	if err != nil {
		return nil, fmt.Errorf("dnsid: computing WBA key thumbprint: %w", err)
	}
	thumbID := base64.RawURLEncoding.EncodeToString(thumb)
	httpAlg, err := httpsig.JoseAlgToHTTPSigAlg(alg)
	if err != nil {
		return nil, err
	}
	signed := req.Clone(req.Context())
	components := []httpsig.ComponentIdentifier{{Name: "@authority"}}
	if webBotAuthRequestHasBody(req) {
		body, err := boundedContent(req.Context(), req.Body, 8<<20)
		if err != nil {
			return nil, fmt.Errorf("dnsid: reading request body: %w", err)
		}
		original := req.Body
		req.Body = httputil.ReplayBody(body, original)
		signed.Body = httputil.ReplayBody(body, original)
		signed.ContentLength = int64(len(body))
		signed.Header.Set("Content-Digest", contentDigest(body))
		components = append(components, httpsig.ComponentIdentifier{Name: "content-digest"})
	}
	if p.includeSignatureAgent(opts) {
		agentValue, err := p.signatureAgentValue()
		if err != nil {
			return nil, err
		}
		signed.Header.Set("Signature-Agent", agentValue)
		components = append(components, httpsig.ComponentIdentifier{Name: "signature-agent", Params: map[string]any{"key": "sig1"}})
	}
	for _, name := range opts.AdditionalComponents {
		if err := httpsig.AppendComponent(&components, httpsig.ComponentIdentifier{Name: name}); err != nil {
			return nil, err
		}
	}
	for _, component := range opts.AdditionalComponentIDs {
		if err := httpsig.AppendComponent(&components, component); err != nil {
			return nil, err
		}
	}
	now := p.currentTime().Unix()
	nonce, err := randomNonce()
	if err != nil {
		return nil, err
	}
	err = httpsig.SignHTTPMessage(signed, httpsig.SignatureParams{
		Label:             "sig1",
		Components:        components,
		KeyID:             thumbID,
		Alg:               httpAlg,
		Created:           now,
		Expires:           now + int64(ttl/time.Second),
		Nonce:             nonce,
		Tag:               "web-bot-auth",
		ExpectedSignerKid: kid,
		ExpectedSignerAlg: alg,
	}, p.keys)
	return signed, err
}

// ServeHttpMessageSignaturesDirectory builds the signed key directory
// response containing the profile's active public key. req is recorded as
// the response's originating request so the signature can cover @authority.
func (p *Profile) ServeHttpMessageSignaturesDirectory(req *http.Request) (*http.Response, error) {
	if err := p.validateConfig(); err != nil {
		return nil, err
	}
	kid, alg, key, err := p.activeWBAKey("directory signing")
	if err != nil {
		return nil, err
	}
	thumb, err := key.Thumbprint(crypto.SHA256)
	if err != nil {
		return nil, fmt.Errorf("dnsid: computing WBA key thumbprint: %w", err)
	}
	thumbID := base64.RawURLEncoding.EncodeToString(thumb)
	httpAlg, err := httpsig.JoseAlgToHTTPSigAlg(alg)
	if err != nil {
		return nil, err
	}
	jwkMap, err := wbaJWK(key)
	if err != nil {
		return nil, err
	}
	keys := []map[string]any{jwkMap}
	body, err := json.Marshal(map[string]any{"keys": keys})
	if err != nil {
		return nil, err
	}
	ttl := p.cfg.DirectorySignatureTTL
	if ttl <= 0 {
		ttl = 5 * time.Minute
	}
	res := &http.Response{
		StatusCode: http.StatusOK,
		Header: http.Header{
			"Content-Type":   {DirectoryContentType},
			"Cache-Control":  {"max-age=" + strconv.Itoa(int(ttl/time.Second))},
			"Content-Digest": {contentDigest(body)},
		},
		Body:          io.NopCloser(bytes.NewReader(body)),
		ContentLength: int64(len(body)),
		Request:       req,
	}
	now := p.currentTime().Unix()
	nonce, err := randomNonce()
	if err != nil {
		return nil, err
	}
	err = httpsig.SignHTTPMessage(res, httpsig.SignatureParams{
		Label: "sig1",
		Components: []httpsig.ComponentIdentifier{
			{Name: "@authority", Params: map[string]any{"req": true}},
			{Name: "content-type"},
			{Name: "cache-control"},
			{Name: "content-digest"},
		},
		KeyID:             thumbID,
		Alg:               httpAlg,
		Created:           now,
		Expires:           now + int64(ttl/time.Second),
		Nonce:             nonce,
		Tag:               "http-message-signatures-directory",
		ExpectedSignerKid: kid,
		ExpectedSignerAlg: alg,
	}, p.keys)
	return res, err
}

func (p *Profile) activeWBAKey(usage string) (string, dnsid.JoseAlg, jwk.Key, error) {
	kid, alg, err := joseutil.ActiveSigningMetadata(p.keys)
	if err != nil {
		return "", "", nil, err
	}
	if alg != dnsid.JoseAlgEdDSA {
		return "", "", nil, dnsid.NewArgumentError(fmt.Sprintf("dnsid: Web Bot Auth %s requires Ed25519", usage), nil)
	}
	key, err := activeJWK(p.keys, kid)
	if err != nil {
		return "", "", nil, err
	}
	return kid, alg, key, nil
}

func activeJWK(kp dnsid.KeyProvider, kid string) (jwk.Key, error) {
	if withErr, ok := kp.(jwkWithError); ok {
		key, err := withErr.JWKWithError(kid)
		if err != nil {
			return nil, err
		}
		if key == nil {
			return nil, fmt.Errorf("dnsid: KeyProvider returned no JWK for active kid %q", kid)
		}
		return key, nil
	}
	key := kp.JWK(kid)
	if key == nil {
		return nil, fmt.Errorf("dnsid: KeyProvider returned no JWK for active kid %q", kid)
	}
	return key, nil
}

func (p *Profile) includeSignatureAgent(opts SigningOptions) bool {
	include := true
	if p.cfg.IncludeSignatureAgent != nil {
		include = *p.cfg.IncludeSignatureAgent
	}
	if opts.SignatureAgent != nil {
		include = *opts.SignatureAgent
	}
	return include
}

func (p *Profile) signatureAgentValue() (string, error) {
	raw := p.cfg.DirectoryURL
	if raw == "" {
		if p.domain == "" {
			return "", dnsid.NewArgumentError("dnsid: Web Bot Auth directory URL requires local domain", nil)
		}
		raw = "https://" + p.domain
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Fragment != "" {
		return "", dnsid.NewArgumentError("dnsid: Web Bot Auth Signature-Agent must be https", nil)
	}
	discoveryType := p.cfg.SignatureAgentType
	if discoveryType == "" {
		discoveryType = "directory"
	}
	if discoveryType != "directory" && discoveryType != "jwks_uri" {
		return "", dnsid.NewArgumentError("dnsid: unsupported Web Bot Auth Signature-Agent type", nil)
	}
	if discoveryType == "directory" {
		if (u.EscapedPath() != "" && u.EscapedPath() != "/") || u.RawQuery != "" || u.ForceQuery {
			return "", dnsid.NewArgumentError("dnsid: Web Bot Auth directory Signature-Agent must be an origin URI", nil)
		}
		u.Path, u.RawPath, u.RawQuery = "", "", ""
		raw = u.String()
	}
	item := sfv.Item{Value: raw, Parameters: []sfv.Parameter{{Key: "type", Value: sfv.Token{Value: discoveryType}}}}
	return sfv.SerializeDictionary(&sfv.Dictionary{Keys: []string{"sig1"}, Values: map[string]interface{}{"sig1": item}})
}

func wbaJWK(key jwk.Key) (map[string]any, error) {
	if key == nil {
		return nil, dnsid.NewArgumentError("dnsid: missing Web Bot Auth JWK", nil)
	}
	alg, ok := joseutil.AlgForJWK(key)
	if !ok {
		return nil, dnsid.NewArgumentError("dnsid: unsupported Web Bot Auth JWK", nil)
	}
	if alg != dnsid.JoseAlgEdDSA {
		return nil, dnsid.NewArgumentError("dnsid: Web Bot Auth JWK requires Ed25519", nil)
	}
	thumb, err := key.Thumbprint(crypto.SHA256)
	if err != nil {
		return nil, fmt.Errorf("dnsid: computing WBA key thumbprint: %w", err)
	}
	var source map[string]any
	jwkBytes, err := json.Marshal(key)
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(jwkBytes, &source); err != nil {
		return nil, err
	}
	jwkMap := map[string]any{"kty": source["kty"], "crv": source["crv"], "x": source["x"]}
	jwkMap["alg"] = "ed25519"
	jwkMap["kid"] = base64.RawURLEncoding.EncodeToString(thumb)
	jwkMap["use"] = "sig"
	return jwkMap, nil
}

func (p *Profile) validateConfig() error {
	if (p.cfg.signatureTTLSet && p.cfg.SignatureTTL == 0) || p.cfg.SignatureTTL < 0 || (p.cfg.SignatureTTL > 0 && p.cfg.SignatureTTL < time.Second) || p.cfg.SignatureTTL > 5*time.Minute {
		return dnsid.NewArgumentError("dnsid: Web Bot Auth signature TTL must be positive and no greater than 5 minutes", nil)
	}
	if (p.cfg.directorySignatureTTLSet && p.cfg.DirectorySignatureTTL == 0) || p.cfg.DirectorySignatureTTL < 0 || (p.cfg.DirectorySignatureTTL > 0 && p.cfg.DirectorySignatureTTL < time.Second) || p.cfg.DirectorySignatureTTL > 5*time.Minute {
		return dnsid.NewArgumentError("dnsid: Web Bot Auth directory signature TTL must be positive and no greater than 5 minutes", nil)
	}
	if p.cfg.ClockSkew < 0 {
		return dnsid.NewArgumentError("dnsid: Web Bot Auth clock skew must not be negative", nil)
	}
	return nil
}

func contentDigest(body []byte) string {
	sum, _ := digest.ComputeDigest(body, "sha-256")
	out, _ := digest.FormatContentDigest(map[string][]byte{"sha-256": sum})
	return out
}

func webBotAuthRequestHasBody(req *http.Request) bool {
	return req != nil && req.Body != nil && req.Body != http.NoBody
}

func randomNonce() (string, error) {
	var b [64]byte
	if _, err := cryptoRandRead(b[:]); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b[:]), nil
}

var cryptoRandRead = rand.Read
