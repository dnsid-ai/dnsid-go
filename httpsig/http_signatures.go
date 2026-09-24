package httpsig

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	wbahttpsig "github.com/WebDecoy/web-bot-auth/httpsig"
	"github.com/dnsid-ai/dnsid-go"
	"github.com/dnsid-ai/dnsid-go/internal/joseutil"
	"github.com/forcebit/http-message-signatures-rfc9421-go/pkg/digest"
	"github.com/forcebit/http-message-signatures-rfc9421-go/pkg/sfv"
	"github.com/lestrrat-go/jwx/v3/jwk"
)

const dnsidHTTPSigLabel = "sig1"

// Config contains HTTP Message Signatures profile policy. The zero value
// applies the profile defaults.
type Config struct {
	// MaxAge bounds signature freshness during verification: a signature's
	// created parameter must be no older than MaxAge, and when an expires
	// parameter is present its distance from created must not exceed
	// MaxAge. Zero means the default of 5 minutes; negative is invalid.
	MaxAge time.Duration

	// ClockSkew is the tolerance applied to signature timestamp checks
	// during verification. Zero means the default of 5 seconds; negative is
	// invalid.
	ClockSkew time.Duration

	clockSkewSet bool
}

// WithClockSkew returns a copy configured with skew, including an explicit
// zero value. This distinguishes strict zero-skew verification from Config's
// zero-value default of 5 seconds.
func (c Config) WithClockSkew(skew time.Duration) Config {
	c.ClockSkew = skew
	c.clockSkewSet = true
	return c
}

// ComponentIdentifier identifies an RFC 9421 covered component.
type ComponentIdentifier struct {
	// Name is the component name, such as "@method", "@authority", or a
	// lowercase field name like "content-digest".
	Name string

	// Params holds RFC 9421 component parameters. This SDK supports the
	// req, key, and name parameters in their profile-defined contexts.
	Params map[string]any

	// ParamOrder preserves the serialization order of Params keys.
	ParamOrder []string

	// Raw is retained for source compatibility. Parsed and constructed
	// identifiers are always serialized canonically from Name and Params.
	// Deprecated: raw component serialization is not part of RFC 9421's
	// parsed data model.
	Raw string
}

// SignatureParameter is one ordered RFC 8941 parameter on a Signature-Input
// inner list. Value is an RFC 8941 bare item: bool, int64, string, []byte, or
// sfv.Token.
type SignatureParameter struct {
	Name  string
	Value any
}

// SignatureParams contains one RFC 9421 Signature-Input member.
type SignatureParams struct {
	// Label is the member's dictionary key in Signature-Input and
	// Signature. Empty means the profile default label "sig1".
	Label string

	// Components lists the covered components in signature-base order.
	Components []ComponentIdentifier

	// KeyID and Alg are the RFC 9421 keyid and alg signature parameters.
	// This SDK uses "<domain>#<kid>" key identifiers and the algorithm
	// names "ed25519" and "ecdsa-p256-sha256".
	KeyID, Alg string

	// Created and Expires are the created and expires signature parameters
	// as Unix timestamps. Zero means the parameter is absent.
	Created, Expires int64

	// Nonce and Tag are the nonce and tag signature parameters. Empty
	// means the parameter is absent.
	Nonce, Tag string

	// Parameters is the complete ordered Signature-Input parameter list.
	// Parsed values always populate this field, including unknown registered
	// extensions. When nil, the typed fields above are serialized in their
	// historical order for source compatibility with constructed values.
	Parameters []SignatureParameter

	// RawSignatureInputMember is retained for source compatibility and is
	// ignored. RFC 9421 signature bases canonically serialize the parsed data
	// model rather than reusing an arbitrary raw header substring.
	// Deprecated: use Parameters.
	RawSignatureInputMember string

	// ExpectedSignerKid and ExpectedSignerAlg, when non-empty, make
	// SignHTTPMessage fail if the KeyProvider signs with a different key
	// id or algorithm (for example after a concurrent key rotation).
	ExpectedSignerKid string
	ExpectedSignerAlg dnsid.JoseAlg
}

// SigningOptions configures HTTP request signing.
type SigningOptions struct {
	// Label identifies the Signature-Input dictionary member. Empty uses sig1.
	Label string

	// ExpiresIn adds an expires parameter relative to created. Zero omits it.
	ExpiresIn time.Duration

	// Tag adds the RFC 9421 tag signature parameter.
	Tag string

	// AdditionalComponents lists extra component names to cover beyond the
	// profile's defaults. Unknown names cause signing to fail.
	AdditionalComponents []string

	// AdditionalComponentIDs lists extra components, with parameters, to
	// cover beyond the profile's defaults.
	AdditionalComponentIDs []ComponentIdentifier
}

// Profile implements the DNSid HTTP Message Signatures profile.
type Profile struct {
	resolver    dnsid.IdentityResolver
	localDomain string
	keys        dnsid.KeyProvider
	cfg         Config
}

type identityManager interface {
	dnsid.IdentityResolver
	Domain() string
}

type identityManagerWithKeyProvider interface {
	identityManager
	KeyProvider() dnsid.KeyProvider
}

// New constructs an HTTP Message Signatures profile.
func New(resolver dnsid.IdentityResolver, localDomain string, kp dnsid.KeyProvider, cfg Config) *Profile {
	if localDomain != "" {
		if d, err := dnsid.NormalizeFQDN(localDomain); err == nil {
			localDomain = d
		}
	}
	return &Profile{resolver: resolver, localDomain: localDomain, keys: kp, cfg: cfg}
}

// NewFromIdentityManager constructs a profile from an IdentityManager-like core manager.
func NewFromIdentityManager(manager identityManager, kp dnsid.KeyProvider, cfg Config) *Profile {
	localDomain := ""
	if manager != nil {
		localDomain = manager.Domain()
	}
	return New(manager, localDomain, kp, cfg)
}

// NewFromIdentityManagerKeyProvider constructs a profile from a manager that exposes its KeyProvider.
func NewFromIdentityManagerKeyProvider(manager identityManagerWithKeyProvider, cfg Config) *Profile {
	if manager == nil {
		return New(nil, "", nil, cfg)
	}
	return New(manager, manager.Domain(), manager.KeyProvider(), cfg)
}

// CreateSignedHTTPRequest signs req using the DNSid HTTP Message Signatures profile.
func (p *Profile) CreateSignedHTTPRequest(req *http.Request, opts SigningOptions) (*http.Request, error) {
	if req == nil {
		return nil, dnsid.NewArgumentError("dnsid: nil HTTP request", nil)
	}
	if err := p.requireLocalIdentity(); err != nil {
		return nil, err
	}
	if _, err := p.httpSignatureConfig(); err != nil {
		return nil, err
	}
	kid, alg, err := joseutil.ActiveSigningMetadata(p.keys)
	if err != nil {
		return nil, err
	}
	httpAlg, err := JoseAlgToHTTPSigAlg(alg)
	if err != nil {
		return nil, err
	}
	if strings.Contains(kid, "#") {
		return nil, dnsid.NewArgumentError("dnsid: signing key kid must not contain '#'", nil)
	}
	signed := req.Clone(req.Context())
	components := []ComponentIdentifier{{Name: "@method"}, {Name: "@authority"}, {Name: "@target-uri"}}
	if httpRequestHasBody(req) {
		body, err := readBoundedBody(req.Body)
		if err != nil {
			return nil, fmt.Errorf("dnsid: reading request body: %w", err)
		}
		req.Body = io.NopCloser(bytes.NewReader(body))
		signed.Body = io.NopCloser(bytes.NewReader(body))
		signed.ContentLength = int64(len(body))
		signed.Header.Set("Content-Digest", contentDigest(body))
		components = append(components, ComponentIdentifier{Name: "content-digest"})
	}
	for _, component := range opts.AdditionalComponents {
		if err := AppendComponent(&components, ComponentIdentifier{Name: component}); err != nil {
			return nil, err
		}
	}
	for _, component := range opts.AdditionalComponentIDs {
		if err := AppendComponent(&components, component); err != nil {
			return nil, err
		}
	}
	if opts.ExpiresIn < 0 {
		return nil, dnsid.NewArgumentError("dnsid: HTTP signature expiry must not be negative", nil)
	}
	created := time.Now().Unix()
	expires := int64(0)
	if opts.ExpiresIn > 0 {
		expires = time.Unix(created, 0).Add(opts.ExpiresIn).Unix()
	}
	keyID := p.localDomain + "#" + kid
	nonce, err := randomHTTPSignatureNonce()
	if err != nil {
		return nil, err
	}
	label := opts.Label
	if label == "" {
		label = dnsidHTTPSigLabel
	}
	params := SignatureParams{Label: label, Components: components, Created: created, Expires: expires, KeyID: keyID, Alg: httpAlg, Nonce: nonce, Tag: opts.Tag}
	base, err := BuildSignatureInput(signed, params)
	if err != nil {
		return nil, err
	}
	sig, err := p.keys.Sign([]byte(base))
	if err != nil {
		return nil, err
	}
	if sig.Kid != kid || sig.Alg != alg {
		return nil, fmt.Errorf("active signing key did not match HTTP signature metadata")
	}
	inner, err := signatureParamsInnerList(params)
	if err != nil {
		return nil, err
	}
	if err := setStructuredDictionaryMember(signed.Header, "Signature-Input", params.Label, inner); err != nil {
		return nil, err
	}
	if err := setStructuredDictionaryMember(signed.Header, "Signature", params.Label, sfv.Item{Value: sig.Signature}); err != nil {
		return nil, err
	}
	return signed, nil
}

// CreateSignedHTTPClient wraps base so outbound requests are signed before dispatch.
func (p *Profile) CreateSignedHTTPClient(base *http.Client, opts SigningOptions) *http.Client {
	if base == nil {
		base = http.DefaultClient
	}
	client := *base
	transport := base.Transport
	if transport == nil {
		transport = http.DefaultTransport
	}
	client.Transport = httpRoundTripperFunc(func(req *http.Request) (*http.Response, error) {
		signed, err := p.CreateSignedHTTPRequest(req, opts)
		if err != nil {
			return nil, err
		}
		return transport.RoundTrip(signed)
	})
	return &client
}

// VerifyHTTPRequest verifies a DNSid HTTP Message Signature and returns the verified signer domain.
// At most two eligible signatures may be supplied; applications should also rate-limit inbound requests.
func (p *Profile) VerifyHTTPRequest(ctx context.Context, req *http.Request) (*dnsid.VerifiedDomain, error) {
	ctx, cancel := dnsid.VerificationContext(ctx)
	defer cancel()
	if req == nil {
		return nil, dnsid.NewArgumentError("dnsid: nil HTTP request", nil)
	}
	candidates, err := parseHTTPSignatureHeaders(req)
	if err != nil {
		return nil, err
	}
	var verified *dnsid.VerifiedDomain
	var lastErr error
	for _, parsed := range candidates {
		vd, err := p.verifyParsedHTTPRequest(ctx, req, parsed)
		if err != nil {
			lastErr = err
			continue
		}
		if verified != nil {
			return nil, dnsid.NewVerificationError(dnsid.VerificationCodeMalformedToken, false, "dnsid: multiple valid HTTP signatures", nil)
		}
		verified = vd
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if verified != nil {
		return verified, nil
	}
	if lastErr != nil {
		return nil, lastErr
	}
	return nil, dnsid.NewVerificationError(dnsid.VerificationCodeSignatureInvalid, false, "dnsid: invalid HTTP signature", nil)
}

func (p *Profile) verifyParsedHTTPRequest(ctx context.Context, req *http.Request, parsed *parsedHTTPSignature) (*dnsid.VerifiedDomain, error) {
	cfg, err := p.httpSignatureConfig()
	if err != nil {
		return nil, err
	}
	now := time.Now()
	created := time.Unix(parsed.created, 0)
	if created.After(now.Add(cfg.ClockSkew)) || now.Sub(created) > cfg.MaxAge {
		return nil, dnsid.NewVerificationError(dnsid.VerificationCodeTokenExpired, false, "dnsid: HTTP signature is outside freshness window", nil)
	}
	if parsed.hasExpires && parsed.expires < parsed.created {
		return nil, dnsid.NewVerificationError(dnsid.VerificationCodeTokenExpired, false, "dnsid: HTTP signature expires before created", nil)
	}
	if parsed.hasExpires && now.After(time.Unix(parsed.expires, 0).Add(cfg.ClockSkew)) {
		return nil, dnsid.NewVerificationError(dnsid.VerificationCodeTokenExpired, false, "dnsid: HTTP signature has expired", nil)
	}
	if parsed.hasExpires && parsed.expires-parsed.created > int64(cfg.MaxAge/time.Second) {
		return nil, dnsid.NewVerificationError(dnsid.VerificationCodeTokenExpired, false, "dnsid: HTTP signature expires lifetime exceeds maximum", nil)
	}
	if err := requireHTTPComponents(req, parsed.components); err != nil {
		return nil, err
	}
	domain, kid, err := joseutil.SplitDNSIDKid(parsed.keyID)
	if err != nil {
		return nil, dnsid.NewVerificationError(dnsid.VerificationCodeMalformedToken, false, fmt.Sprintf("dnsid: malformed HTTP signature keyid: %v", err), nil)
	}
	vd, err := dnsid.VerifyIdentity(ctx, p.resolver, domain, dnsid.VerifyDomainOpts{
		PeerCertificate:               peerCertificateFromRequest(req),
		VerifiedPeerCertificateChains: verifiedPeerCertificateChainsFromRequest(req),
	})
	if err != nil {
		return nil, err
	}
	key, ok := joseutil.LookupJWKByKid(vd.KeySet().Raw(), kid)
	if !ok || !joseutil.SigningKeyEligible(key) {
		return nil, dnsid.NewVerificationError(dnsid.VerificationCodeKeyNotFound, false, fmt.Sprintf("dnsid: HTTP signature kid %q not found for %s", kid, domain), nil)
	}
	keyAlg, ok := joseutil.AlgForJWK(key)
	if !ok || !joseutil.JWKMatchesAlg(key, keyAlg) {
		return nil, dnsid.NewVerificationError(dnsid.VerificationCodeSignatureInvalid, false, "dnsid: HTTP signature key alg mismatch", nil)
	}
	expectedAlg, err := JoseAlgToHTTPSigAlg(keyAlg)
	if err != nil || (parsed.httpAlg != "" && parsed.httpAlg != expectedAlg) {
		return nil, dnsid.NewVerificationError(dnsid.VerificationCodeSignatureInvalid, false, "dnsid: HTTP signature alg mismatch", err)
	}
	base, err := BuildSignatureInput(req, SignatureParams{Label: parsed.label, Components: parsed.components, KeyID: parsed.keyID, Alg: parsed.httpAlg, Created: parsed.created, Expires: parsed.expires, Parameters: parsed.parameters})
	if err != nil {
		return nil, err
	}
	parts := joseutil.SignatureParts{SigningInput: []byte(base), Signature: parsed.signature}
	if !joseutil.VerifySignature(joseutil.ProtectedHeader{Alg: keyAlg, Kid: kid}, parts, []jwk.Key{key}) {
		return nil, dnsid.NewVerificationError(dnsid.VerificationCodeSignatureInvalid, false, "dnsid: invalid HTTP signature", nil)
	}
	return vd, nil
}

func (p *Profile) httpSignatureConfig() (Config, error) {
	cfg := p.cfg
	if cfg.MaxAge < 0 {
		return Config{}, dnsid.NewArgumentError("dnsid: HTTP signature max age must be positive", nil)
	}
	if cfg.ClockSkew < 0 {
		return Config{}, dnsid.NewArgumentError("dnsid: HTTP signature clock skew must not be negative", nil)
	}
	if cfg.MaxAge == 0 {
		cfg.MaxAge = 5 * time.Minute
	}
	if cfg.ClockSkew == 0 && !cfg.clockSkewSet {
		cfg.ClockSkew = 5 * time.Second
	}
	return cfg, nil
}

// String serializes a component identifier as it appears in Signature-Input.
func (c ComponentIdentifier) String() string {
	return c.serialize()
}

func (c ComponentIdentifier) serialize() string {
	item, err := componentItem(c)
	if err != nil {
		return strings.ToLower(strings.TrimSpace(c.Name))
	}
	out, err := sfv.SerializeItem(item)
	if err != nil {
		return strings.ToLower(strings.TrimSpace(c.Name))
	}
	return out
}

func componentItem(c ComponentIdentifier) (sfv.Item, error) {
	if err := validateComponentIdentifier(c); err != nil {
		return sfv.Item{}, err
	}
	item := sfv.Item{Value: strings.ToLower(strings.TrimSpace(c.Name))}
	seen := map[string]bool{}
	order := append([]string{}, c.ParamOrder...)
	order = append(order, "req", "key", "name")
	for _, key := range order {
		if seen[key] {
			continue
		}
		seen[key] = true
		v, ok := c.Params[key]
		if !ok {
			continue
		}
		switch x := v.(type) {
		case bool, string:
			item.Parameters = append(item.Parameters, sfv.Parameter{Key: key, Value: x})
		default:
			return sfv.Item{}, fmt.Errorf("dnsid: unsupported HTTP signature component parameter")
		}
	}
	return item, nil
}

// ParseComponentIdentifier parses the subset of component identifiers this SDK emits.
func ParseComponentIdentifier(s string) ComponentIdentifier {
	c, _ := parseComponentIdentifier(s)
	return c
}

func parseComponentIdentifier(s string) (ComponentIdentifier, error) {
	item, err := sfv.NewParser(s, sfv.DefaultLimits()).ParseItem()
	if err != nil {
		return ComponentIdentifier{}, dnsid.NewVerificationError(dnsid.VerificationCodeMalformedToken, false, "dnsid: malformed HTTP signature component", err)
	}
	name, ok := item.Value.(string)
	if !ok {
		return ComponentIdentifier{}, dnsid.NewVerificationError(dnsid.VerificationCodeMalformedToken, false, "dnsid: malformed HTTP signature component", nil)
	}
	c := ComponentIdentifier{Name: strings.TrimSpace(name)}
	if c.Name == "" {
		return ComponentIdentifier{}, dnsid.NewVerificationError(dnsid.VerificationCodeMalformedToken, false, "dnsid: empty HTTP signature component", nil)
	}
	for _, param := range item.Parameters {
		k := param.Key
		if k != "req" && k != "key" && k != "name" {
			return ComponentIdentifier{}, dnsid.NewVerificationError(dnsid.VerificationCodeMalformedToken, false, "dnsid: unsupported HTTP signature component parameter", nil)
		}
		if c.Params == nil {
			c.Params = map[string]any{}
		}
		v := param.Value
		if k == "req" {
			if value, ok := v.(bool); !ok || !value {
				return ComponentIdentifier{}, dnsid.NewVerificationError(dnsid.VerificationCodeMalformedToken, false, "dnsid: malformed HTTP signature component parameter", nil)
			}
		} else if _, ok := v.(string); !ok {
			return ComponentIdentifier{}, dnsid.NewVerificationError(dnsid.VerificationCodeMalformedToken, false, "dnsid: malformed HTTP signature component parameter", nil)
		}
		c.Params[k] = v
		c.ParamOrder = append(c.ParamOrder, k)
	}
	if err := validateComponentIdentifier(c); err != nil {
		return ComponentIdentifier{}, err
	}
	c.Name = strings.ToLower(c.Name)
	return c, nil
}

// BuildSignatureInput builds the RFC 9421 signature base for requests or responses.
func BuildSignatureInput(msg any, params SignatureParams) (string, error) {
	if params.Label == "" {
		params.Label = dnsidHTTPSigLabel
	}
	inner, err := signatureParamsInnerList(params)
	if err != nil {
		return "", err
	}
	member, err := sfv.SerializeInnerList(inner)
	if err != nil {
		return "", err
	}
	lines := make([]string, 0, len(params.Components)+1)
	seen := []ComponentIdentifier{}
	for _, component := range params.Components {
		if err := validateComponentIdentifier(component); err != nil {
			return "", err
		}
		if containsComponent(seen, component) {
			return "", dnsid.NewVerificationError(dnsid.VerificationCodeMalformedToken, false, "dnsid: duplicate HTTP signature component "+component.Name, nil)
		}
		seen = append(seen, component)
		value, err := httpSignatureComponentValue(msg, component)
		if err != nil {
			return "", err
		}
		item, err := componentItem(component)
		if err != nil {
			return "", err
		}
		identifier, err := sfv.SerializeItem(item)
		if err != nil {
			return "", err
		}
		lines = append(lines, fmt.Sprintf("%s: %s", identifier, value))
	}
	lines = append(lines, `"@signature-params": `+member)
	return strings.Join(lines, "\n"), nil
}

// SignHTTPMessage signs a request or response and sets Signature-Input/Signature.
func SignHTTPMessage(msg any, params SignatureParams, kp dnsid.KeyProvider) error {
	if params.Label == "" {
		params.Label = dnsidHTTPSigLabel
	}
	base, err := BuildSignatureInput(msg, params)
	if err != nil {
		return err
	}
	sig, err := kp.Sign([]byte(base))
	if err != nil {
		return err
	}
	if (params.ExpectedSignerKid != "" && sig.Kid != params.ExpectedSignerKid) || (params.ExpectedSignerAlg != "" && sig.Alg != params.ExpectedSignerAlg) {
		return fmt.Errorf("dnsid: active signing key did not match HTTP signature metadata")
	}
	header := http.Header(nil)
	//nolint:bodyclose // msg is a caller-owned message being signed, not a response we fetched; closing it here would break the caller.
	if res := responseFromMessage(msg); res != nil {
		header = res.Header
	} else if req := requestFromMessage(msg); req != nil {
		header = req.Header
	}
	if header == nil {
		return fmt.Errorf("dnsid: unsupported HTTP message %T", msg)
	}
	inner, err := signatureParamsInnerList(params)
	if err != nil {
		return err
	}
	if err := setStructuredDictionaryMember(header, "Signature-Input", params.Label, inner); err != nil {
		return err
	}
	return setStructuredDictionaryMember(header, "Signature", params.Label, sfv.Item{Value: sig.Signature})
}

func contentDigest(body []byte) string {
	sum, _ := digest.ComputeDigest(body, "sha-256")
	out, _ := digest.FormatContentDigest(map[string][]byte{"sha-256": sum})
	return out
}

func httpSignatureComponentValue(msg any, component ComponentIdentifier) (string, error) {
	component.Name = strings.ToLower(strings.TrimSpace(component.Name))
	if err := validateComponentIdentifier(component); err != nil {
		return "", err
	}
	//nolint:bodyclose // msg is a caller-owned message being inspected for component values, not a response we fetched.
	req, res := requestFromMessage(msg), responseFromMessage(msg)
	if component.Params["req"] == true {
		if req != nil {
			return "", dnsid.NewVerificationError(dnsid.VerificationCodeMalformedToken, false, "dnsid: req parameter is invalid for request signatures", nil)
		}
		if res == nil || res.Request == nil {
			return "", dnsid.NewVerificationError(dnsid.VerificationCodeMalformedToken, false, "dnsid: req parameter requires associated request", nil)
		}
		req, res = res.Request, nil
	}
	headers := http.Header(nil)
	if req != nil {
		headers = req.Header
	}
	if res != nil {
		headers = res.Header
	}
	switch component.Name {
	case "@method":
		if req != nil {
			return req.Method, nil
		}
	case "@authority":
		if req != nil {
			if authority := httpAuthority(req); authority != "" {
				return authority, nil
			}
			return "", dnsid.NewVerificationError(dnsid.VerificationCodeMalformedToken, false, "dnsid: missing request authority", nil)
		}
		if res == nil {
			return "", nil
		}
	case "@target-uri":
		if req != nil {
			return httpTargetURI(req)
		}
	case "@path":
		if req != nil && req.URL != nil {
			path := req.URL.EscapedPath()
			if path == "" {
				path = "/"
			}
			return path, nil
		}
	case "@query":
		if req != nil && req.URL != nil {
			if req.URL.RawQuery != "" {
				return "?" + req.URL.RawQuery, nil
			}
			return "?", nil
		}
	case "@query-param":
		if req != nil && req.URL != nil {
			name, _ := component.Params["name"].(string)
			if name == "" {
				return "", dnsid.NewVerificationError(dnsid.VerificationCodeMalformedToken, false, "dnsid: @query-param requires name parameter", nil)
			}
			return rawQueryParam(req.URL.RawQuery, name)
		}
	case "@request-target":
		if req != nil && req.URL != nil {
			return req.URL.RequestURI(), nil
		}
	case "@scheme":
		if req != nil {
			return httpScheme(req)
		}
	case "@status":
		if req != nil {
			return "", dnsid.NewVerificationError(dnsid.VerificationCodeMalformedToken, false, "dnsid: @status is invalid for request signatures", nil)
		}
		if res != nil {
			return fmt.Sprintf("%d", res.StatusCode), nil
		}
	case "content-digest":
		value, ok := headerFieldValue(headers, "Content-Digest")
		if !ok {
			return "", dnsid.NewVerificationError(dnsid.VerificationCodeMalformedToken, false, "dnsid: missing HTTP signature field content-digest", nil)
		}
		return value, nil
	default:
		if strings.HasPrefix(component.Name, "@") {
			return "", dnsid.NewVerificationError(dnsid.VerificationCodeMalformedToken, false, "dnsid: unsupported HTTP signature derived component "+component.Name, nil)
		}
		value, ok := headerFieldValue(headers, component.Name)
		if !ok {
			return "", dnsid.NewVerificationError(dnsid.VerificationCodeMalformedToken, false, "dnsid: missing HTTP signature field "+component.Name, nil)
		}
		if key, _ := component.Params["key"].(string); key != "" {
			member, ok := dictionaryMember(value, key)
			if !ok {
				return "", dnsid.NewVerificationError(dnsid.VerificationCodeMalformedToken, false, "dnsid: missing HTTP signature dictionary member "+key, nil)
			}
			return member, nil
		}
		return value, nil
	}
	return "", dnsid.NewVerificationError(dnsid.VerificationCodeMalformedToken, false, "dnsid: unsupported HTTP signature component "+component.Name, nil)
}

func httpTargetURI(req *http.Request) (string, error) {
	if req.URL == nil {
		return "", dnsid.NewVerificationError(dnsid.VerificationCodeMalformedToken, false, "dnsid: missing request URL", nil)
	}
	scheme, err := httpScheme(req)
	if err != nil {
		return "", err
	}
	host := req.Host
	if host == "" {
		host = req.URL.Host
	}
	authority := normalizeHTTPAuthority(host, &url.URL{Scheme: scheme})
	if authority == "" {
		return "", dnsid.NewVerificationError(dnsid.VerificationCodeMalformedToken, false, "dnsid: missing request authority", nil)
	}
	u := *req.URL
	u.Scheme = scheme
	u.Host = authority
	return u.String(), nil
}

func httpScheme(req *http.Request) (string, error) {
	if req != nil && req.URL != nil && req.URL.Scheme != "" {
		return strings.ToLower(req.URL.Scheme), nil
	}
	if req != nil && req.TLS != nil {
		return "https", nil
	}
	return "", dnsid.NewVerificationError(dnsid.VerificationCodeMalformedToken, false, "dnsid: missing request scheme", nil)
}

func httpAuthority(req *http.Request) string {
	if req == nil {
		return ""
	}
	host := req.Host
	if host == "" && req.URL != nil {
		host = req.URL.Host
	}
	return normalizeHTTPAuthority(host, req.URL)
}

func normalizeHTTPAuthority(host string, u *url.URL) string {
	if host == "" {
		return ""
	}
	scheme := ""
	if u != nil {
		scheme = strings.ToLower(u.Scheme)
	}
	parsed := &url.URL{Scheme: scheme, Host: host}
	hostname, port := parsed.Hostname(), parsed.Port()
	if hostname == "" {
		if h, p, err := net.SplitHostPort(host); err == nil {
			hostname, port = h, p
		} else {
			hostname = host
		}
	}
	hostname = strings.ToLower(hostname)
	if strings.Contains(hostname, ":") {
		hostname = "[" + strings.Trim(hostname, "[]") + "]"
	}
	if port == "" || scheme == "https" && port == "443" || scheme == "http" && port == "80" {
		return hostname
	}
	return net.JoinHostPort(strings.Trim(hostname, "[]"), port)
}

type parsedHTTPSignature struct {
	label      string
	components []ComponentIdentifier
	created    int64
	expires    int64
	hasExpires bool
	keyID      string
	httpAlg    string
	alg        dnsid.JoseAlg
	parameters []SignatureParameter
	signature  []byte
}

func parseHTTPSignatureHeaders(req *http.Request) ([]*parsedHTTPSignature, error) {
	total := 0
	for name, values := range req.Header {
		total += len(name)
		for _, value := range values {
			total += len(value)
		}
		if total > 1<<20 {
			return nil, dnsid.NewVerificationError(dnsid.VerificationCodeMalformedToken, false, "dnsid: HTTP headers exceed 1 MiB limit", nil)
		}
	}
	if req.URL != nil && len(req.RequestURI)+len(req.URL.Path)+len(req.URL.RawQuery)+len(req.Host)+len(req.Method) > 64<<10 {
		return nil, dnsid.NewVerificationError(dnsid.VerificationCodeMalformedToken, false, "dnsid: HTTP target exceeds size limit", nil)
	}
	for _, name := range []string{"Signature", "Signature-Input"} {
		size := 0
		for _, value := range req.Header.Values(name) {
			size += len(value) + 2
			if size > 16<<10 {
				return nil, dnsid.NewVerificationError(dnsid.VerificationCodeMalformedToken, false, "dnsid: signature headers exceed size limit", nil)
			}
		}
	}
	inputs, err := ParseSignatureInput(strings.Join(req.Header.Values("Signature-Input"), ", "))
	if err != nil {
		return nil, err
	}
	sigHeader := strings.Join(req.Header.Values("Signature"), ", ")
	if sigHeader == "" {
		return nil, dnsid.NewVerificationError(dnsid.VerificationCodeMalformedToken, false, "dnsid: missing Signature header", nil)
	}
	sigs, err := ParseSignature(sigHeader)
	if err != nil {
		return nil, err
	}
	var candidates []*parsedHTTPSignature
	for label, params := range inputs {
		sig, ok := sigs[label]
		if !ok {
			continue
		}
		if !containsComponent(params.Components, ComponentIdentifier{Name: "@method"}) || !containsComponent(params.Components, ComponentIdentifier{Name: "@authority"}) || !containsComponent(params.Components, ComponentIdentifier{Name: "@target-uri"}) || !hasSignatureParameter(params, "created") || params.KeyID == "" {
			continue
		}
		parsed := &parsedHTTPSignature{label: label, components: params.Components, created: params.Created, expires: params.Expires, hasExpires: hasSignatureParameter(params, "expires"), keyID: params.KeyID, httpAlg: params.Alg, parameters: params.Parameters, signature: sig}
		if parsed.httpAlg != "" {
			parsed.alg = httpSigAlgToJoseAlg(parsed.httpAlg)
			if !parsed.alg.Valid() {
				continue
			}
		}
		if len(candidates) == 2 {
			return nil, dnsid.NewVerificationError(dnsid.VerificationCodeMalformedToken, false, "dnsid: too many acceptable HTTP signatures", nil)
		}
		candidates = append(candidates, parsed)
	}
	if len(candidates) == 0 {
		return nil, dnsid.NewVerificationError(dnsid.VerificationCodeMalformedToken, false, "dnsid: no acceptable HTTP signature input", nil)
	}
	return candidates, nil
}

// ParseSignatureInput parses a Signature-Input dictionary.
func ParseSignatureInput(sigInput string) (map[string]SignatureParams, error) {
	if sigInput == "" {
		return nil, dnsid.NewVerificationError(dnsid.VerificationCodeMalformedToken, false, "dnsid: missing Signature-Input header", nil)
	}
	if err := validateUniqueDictionaryLabels(sigInput, "Signature-Input"); err != nil {
		return nil, err
	}
	dict, err := sfv.NewParser(sigInput, sfv.DefaultLimits()).ParseDictionary()
	if err != nil {
		return nil, dnsid.NewVerificationError(dnsid.VerificationCodeMalformedToken, false, "dnsid: malformed Signature-Input header", err)
	}
	out := map[string]SignatureParams{}
	for _, label := range dict.Keys {
		inner, ok := dict.Values[label].(sfv.InnerList)
		if !ok {
			return nil, dnsid.NewVerificationError(dnsid.VerificationCodeMalformedToken, false, "dnsid: Signature-Input member must be an inner list", nil)
		}
		params := SignatureParams{Label: label, Components: make([]ComponentIdentifier, 0, len(inner.Items)), Parameters: make([]SignatureParameter, 0, len(inner.Parameters))}
		for _, item := range inner.Items {
			name, ok := item.Value.(string)
			if !ok {
				return nil, dnsid.NewVerificationError(dnsid.VerificationCodeMalformedToken, false, "dnsid: malformed HTTP signature component", nil)
			}
			component := ComponentIdentifier{Name: strings.TrimSpace(name)}
			for _, parameter := range item.Parameters {
				if component.Params == nil {
					component.Params = map[string]any{}
				}
				if _, duplicate := component.Params[parameter.Key]; duplicate {
					return nil, dnsid.NewVerificationError(dnsid.VerificationCodeMalformedToken, false, "dnsid: duplicate HTTP signature component parameter", nil)
				}
				component.Params[parameter.Key] = parameter.Value
				component.ParamOrder = append(component.ParamOrder, parameter.Key)
			}
			if err := validateComponentIdentifier(component); err != nil {
				return nil, err
			}
			component.Name = strings.ToLower(component.Name)
			if containsComponent(params.Components, component) {
				return nil, dnsid.NewVerificationError(dnsid.VerificationCodeMalformedToken, false, "dnsid: duplicate HTTP signature component "+component.Name, nil)
			}
			params.Components = append(params.Components, component)
		}
		seenKnown := map[string]bool{}
		for _, parameter := range inner.Parameters {
			name := parameter.Key
			if isKnownSignatureParameter(name) && seenKnown[name] {
				return nil, dnsid.NewVerificationError(dnsid.VerificationCodeMalformedToken, false, "dnsid: duplicate HTTP signature parameter "+name, nil)
			}
			seenKnown[name] = true
			params.Parameters = append(params.Parameters, SignatureParameter{Name: name, Value: parameter.Value})
			if err := assignKnownSignatureParameter(&params, name, parameter.Value); err != nil {
				return nil, err
			}
		}
		out[label] = params
	}
	return out, nil
}

func isKnownSignatureParameter(name string) bool {
	switch name {
	case "keyid", "alg", "created", "expires", "nonce", "tag":
		return true
	default:
		return false
	}
}

func hasSignatureParameter(params SignatureParams, name string) bool {
	if params.Parameters != nil {
		for _, parameter := range params.Parameters {
			if parameter.Name == name {
				return true
			}
		}
		return false
	}
	switch name {
	case "created":
		return params.Created != 0
	case "expires":
		return params.Expires != 0
	case "keyid":
		return params.KeyID != ""
	case "alg":
		return params.Alg != ""
	case "nonce":
		return params.Nonce != ""
	case "tag":
		return params.Tag != ""
	default:
		return false
	}
}

func assignKnownSignatureParameter(params *SignatureParams, name string, value any) error {
	malformed := func() error {
		return dnsid.NewVerificationError(dnsid.VerificationCodeMalformedToken, false, "dnsid: malformed HTTP signature "+name+" parameter", nil)
	}
	switch name {
	case "keyid":
		v, ok := value.(string)
		if !ok {
			return malformed()
		}
		params.KeyID = v
	case "alg":
		v, ok := value.(string)
		if !ok {
			return malformed()
		}
		params.Alg = v
	case "created":
		v, ok := value.(int64)
		if !ok {
			return malformed()
		}
		params.Created = v
	case "expires":
		v, ok := value.(int64)
		if !ok {
			return malformed()
		}
		params.Expires = v
	case "nonce":
		v, ok := value.(string)
		if !ok {
			return malformed()
		}
		params.Nonce = v
	case "tag":
		v, ok := value.(string)
		if !ok {
			return malformed()
		}
		params.Tag = v
	}
	return nil
}

func requireHTTPComponents(req *http.Request, components []ComponentIdentifier) error {
	hasBody := httpRequestHasBody(req)
	if hasBody && !containsComponent(components, ComponentIdentifier{Name: "content-digest"}) {
		return dnsid.NewVerificationError(dnsid.VerificationCodeSignatureInvalid, false, "dnsid: request body is present but content-digest is not covered", nil)
	}
	if containsComponent(components, ComponentIdentifier{Name: "content-digest"}) {
		if req.Body == nil {
			return dnsid.NewVerificationError(dnsid.VerificationCodeSignatureInvalid, false, "dnsid: content-digest covered but request has no body", nil)
		}
		body, err := readBoundedBody(req.Body)
		if err != nil {
			return fmt.Errorf("dnsid: reading request body: %w", err)
		}
		req.Body = io.NopCloser(bytes.NewReader(body))
		if err := digest.VerifyContentDigestBytes(body, req.Header.Get("Content-Digest"), []string{"sha-256"}); err != nil {
			return dnsid.NewVerificationError(dnsid.VerificationCodeSignatureInvalid, false, "dnsid: content-digest mismatch", err)
		}
	}
	return nil
}

func signatureParamsInnerList(params SignatureParams) (sfv.InnerList, error) {
	items := make([]sfv.Item, 0, len(params.Components))
	for _, component := range params.Components {
		item, err := componentItem(component)
		if err != nil {
			return sfv.InnerList{}, err
		}
		items = append(items, item)
	}
	p := make([]sfv.Parameter, 0, len(params.Parameters)+6)
	if params.Parameters != nil {
		seenKnown := map[string]bool{}
		for _, parameter := range params.Parameters {
			if isKnownSignatureParameter(parameter.Name) && seenKnown[parameter.Name] {
				return sfv.InnerList{}, fmt.Errorf("dnsid: duplicate HTTP signature parameter %s", parameter.Name)
			}
			seenKnown[parameter.Name] = true
			if err := assignKnownSignatureParameter(&SignatureParams{}, parameter.Name, parameter.Value); err != nil {
				return sfv.InnerList{}, err
			}
			p = append(p, sfv.Parameter{Key: parameter.Name, Value: parameter.Value})
		}
	} else {
		if params.Created != 0 {
			p = append(p, sfv.Parameter{Key: "created", Value: params.Created})
		}
		if params.Expires != 0 {
			p = append(p, sfv.Parameter{Key: "expires", Value: params.Expires})
		}
		if params.KeyID != "" {
			p = append(p, sfv.Parameter{Key: "keyid", Value: params.KeyID})
		}
		if params.Alg != "" {
			p = append(p, sfv.Parameter{Key: "alg", Value: params.Alg})
		}
		if params.Nonce != "" {
			p = append(p, sfv.Parameter{Key: "nonce", Value: params.Nonce})
		}
		if params.Tag != "" {
			p = append(p, sfv.Parameter{Key: "tag", Value: params.Tag})
		}
	}
	return sfv.InnerList{Items: items, Parameters: p}, nil
}

func validateComponentIdentifier(component ComponentIdentifier) error {
	originalName := strings.TrimSpace(component.Name)
	name := strings.ToLower(originalName)
	malformed := func(message string) error {
		return dnsid.NewVerificationError(dnsid.VerificationCodeMalformedToken, false, "dnsid: "+message, nil)
	}
	if name == "" || !isHTTPSignatureComponentName(name) {
		return malformed("unsupported HTTP signature component " + name)
	}
	if originalName != name {
		return malformed("HTTP signature component names must be lowercase")
	}
	for key, value := range component.Params {
		switch key {
		case "req":
			v, ok := value.(bool)
			if !ok || !v {
				return malformed("malformed HTTP signature req parameter")
			}
		case "key", "name":
			v, ok := value.(string)
			if !ok || v == "" {
				return malformed("malformed HTTP signature component parameter")
			}
		default:
			return malformed("unsupported HTTP signature component parameter")
		}
	}
	_, hasReq := component.Params["req"]
	_, hasKey := component.Params["key"]
	_, hasName := component.Params["name"]
	switch name {
	case "@query-param":
		if !hasName || hasKey {
			return malformed("@query-param requires name parameter")
		}
	case "@status":
		if hasReq || hasKey || hasName {
			return malformed("unsupported HTTP signature component parameter")
		}
	case "@method", "@authority", "@target-uri", "@path", "@query", "@request-target", "@scheme":
		if hasKey || hasName {
			return malformed("unsupported HTTP signature component parameter")
		}
	default:
		if strings.HasPrefix(name, "@") || hasName {
			return malformed("unsupported HTTP signature component parameter")
		}
	}
	return nil
}

func rawQueryParam(rawQuery, name string) (string, error) {
	decodedWant, err := url.QueryUnescape(name)
	if err != nil {
		return "", err
	}
	want := formURLEncode(decodedWant)
	seen := false
	var value string
	for _, part := range strings.Split(rawQuery, "&") {
		rawName, rawValue, _ := strings.Cut(part, "=")
		decodedName, err := url.QueryUnescape(rawName)
		if err != nil || formURLEncode(decodedName) != want {
			continue
		}
		if seen {
			return "", dnsid.NewVerificationError(dnsid.VerificationCodeMalformedToken, false, "dnsid: duplicate @query-param "+name, nil)
		}
		seen = true
		decodedValue, err := url.QueryUnescape(rawValue)
		if err != nil {
			return "", err
		}
		value = formURLEncode(decodedValue)
	}
	if !seen {
		return "", dnsid.NewVerificationError(dnsid.VerificationCodeMalformedToken, false, "dnsid: missing @query-param "+name, nil)
	}
	return value, nil
}

func formURLEncode(s string) string {
	var b strings.Builder
	const hex = "0123456789ABCDEF"
	for _, c := range []byte(s) {
		switch {
		case c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '*' || c == '-' || c == '.' || c == '_':
			b.WriteByte(c)
		case c == ' ':
			b.WriteString("%20")
		default:
			b.WriteByte('%')
			b.WriteByte(hex[c>>4])
			b.WriteByte(hex[c&15])
		}
	}
	return b.String()
}

// ParseSignature parses a Signature dictionary into bytes by label.
func ParseSignature(input string) (map[string][]byte, error) {
	if err := validateUniqueDictionaryLabels(input, "Signature"); err != nil {
		return nil, err
	}
	dict, err := sfv.NewParser(input, sfv.DefaultLimits()).ParseDictionary()
	if err != nil {
		return nil, dnsid.NewVerificationError(dnsid.VerificationCodeMalformedToken, false, "dnsid: malformed Signature header", err)
	}
	out := map[string][]byte{}
	for _, label := range dict.Keys {
		item, ok := dict.Values[label].(sfv.Item)
		if !ok {
			return nil, dnsid.NewVerificationError(dnsid.VerificationCodeMalformedToken, false, "dnsid: malformed Signature header", nil)
		}
		sig, ok := item.Value.([]byte)
		if !ok {
			return nil, dnsid.NewVerificationError(dnsid.VerificationCodeMalformedToken, false, "dnsid: malformed Signature header", nil)
		}
		out[label] = sig
	}
	return out, nil
}

func validateUniqueDictionaryLabels(input, field string) error {
	limits := sfv.DefaultLimits()
	if limits.MaxInputLength > 0 && len(input) > limits.MaxInputLength {
		return dnsid.NewVerificationError(dnsid.VerificationCodeMalformedToken, false, "dnsid: malformed "+field+" header: input exceeds limit", nil)
	}
	members, err := wbahttpsig.ParseDictionaryHeader(input)
	if err != nil {
		return dnsid.NewVerificationError(dnsid.VerificationCodeMalformedToken, false, "dnsid: malformed "+field+" header", err)
	}
	if limits.MaxDictionaryMembers > 0 && len(members) > limits.MaxDictionaryMembers {
		return dnsid.NewVerificationError(dnsid.VerificationCodeMalformedToken, false, "dnsid: malformed "+field+" header: dictionary exceeds member limit", nil)
	}
	seen := make(map[string]struct{}, len(members))
	for _, member := range members {
		if _, duplicate := seen[member.Key]; duplicate {
			return dnsid.NewVerificationError(dnsid.VerificationCodeMalformedToken, false, "dnsid: duplicate "+field+" label "+member.Key, nil)
		}
		seen[member.Key] = struct{}{}
	}
	return nil
}

// JoseAlgToHTTPSigAlg maps SDK JOSE algorithms to RFC 9421 algorithm names.
func JoseAlgToHTTPSigAlg(alg dnsid.JoseAlg) (string, error) {
	switch alg {
	case dnsid.JoseAlgEdDSA:
		return "ed25519", nil
	case dnsid.JoseAlgES256:
		return "ecdsa-p256-sha256", nil
	default:
		return "", dnsid.NewArgumentError(fmt.Sprintf("dnsid: JOSE alg %s has no HTTP Message Signatures mapping", alg), nil)
	}
}

func httpSigAlgToJoseAlg(alg string) dnsid.JoseAlg {
	switch strings.ToLower(alg) {
	case "ed25519":
		return dnsid.JoseAlgEdDSA
	case "ecdsa-p256-sha256":
		return dnsid.JoseAlgES256
	default:
		return dnsid.JoseAlg(alg)
	}
}

func randomHTTPSignatureNonce() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b[:]), nil
}

// AppendComponent validates and appends one component.
func AppendComponent(components *[]ComponentIdentifier, component ComponentIdentifier) error {
	component.Name = strings.ToLower(strings.TrimSpace(component.Name))
	if err := validateComponentIdentifier(component); err != nil {
		return dnsid.NewArgumentError(err.Error(), err)
	}
	if containsComponent(*components, component) {
		return dnsid.NewArgumentError("dnsid: duplicate HTTP signature component "+component.Name, nil)
	}
	*components = append(*components, component)
	return nil
}

func isHTTPSignatureComponentName(component string) bool {
	switch component {
	case "@method", "@authority", "@target-uri", "@path", "@query", "@query-param", "@request-target", "@scheme", "@status", "content-digest":
		return true
	}
	if strings.HasPrefix(component, "@") {
		return false
	}
	for _, r := range component {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' {
			continue
		}
		return false
	}
	return component != ""
}

func containsComponent(values []ComponentIdentifier, want ComponentIdentifier) bool {
	for _, value := range values {
		if componentEqual(value, want) {
			return true
		}
	}
	return false
}

func componentEqual(a, b ComponentIdentifier) bool {
	// SA6005 suggests strings.EqualFold here. Do not apply it: EqualFold does
	// simple case folding, so it treats U+017F (ſ) as equal to "s" and U+0130
	// (İ) as unequal to "i", where the ToLower comparison does the opposite.
	// Component names are ASCII-restricted by validateComponentIdentifier, so
	// the difference is unreachable today — but this is signature-component
	// matching, and the EqualFold direction is the more permissive one. The
	// two allocations are not worth taking that on.
	//nolint:staticcheck // SA6005: see above; EqualFold changes matching semantics.
	if strings.ToLower(strings.TrimSpace(a.Name)) != strings.ToLower(strings.TrimSpace(b.Name)) || len(a.Params) != len(b.Params) {
		return false
	}
	for k, av := range a.Params {
		if bv, ok := b.Params[k]; !ok || av != bv {
			return false
		}
	}
	return true
}

func requestFromMessage(msg any) *http.Request {
	if req, ok := msg.(*http.Request); ok {
		return req
	}
	return nil
}

func responseFromMessage(msg any) *http.Response {
	if res, ok := msg.(*http.Response); ok {
		return res
	}
	return nil
}

func headerFieldValue(header http.Header, name string) (string, bool) {
	values := header.Values(name)
	if len(values) == 0 {
		return "", false
	}
	return strings.Join(values, ", "), true
}

func dictionaryMember(value, key string) (string, bool) {
	dict, err := sfv.NewParser(value, sfv.DefaultLimits()).ParseDictionary()
	if err != nil {
		return "", false
	}
	member, ok := dict.Values[key]
	if !ok {
		return "", false
	}
	var out string
	switch v := member.(type) {
	case sfv.Item:
		out, err = sfv.SerializeItem(v)
	case sfv.InnerList:
		out, err = sfv.SerializeInnerList(v)
	default:
		return "", false
	}
	return out, err == nil
}

func setStructuredDictionaryMember(header http.Header, name, label string, value interface{}) error {
	dict := &sfv.Dictionary{Keys: []string{}, Values: map[string]interface{}{}}
	if existing := strings.Join(header.Values(name), ", "); existing != "" {
		switch http.CanonicalHeaderKey(name) {
		case "Signature-Input":
			if _, err := ParseSignatureInput(existing); err != nil {
				return err
			}
		case "Signature":
			if _, err := ParseSignature(existing); err != nil {
				return err
			}
		}
		parsed, err := sfv.NewParser(existing, sfv.DefaultLimits()).ParseDictionary()
		if err != nil {
			return err
		}
		dict = parsed
	}
	if _, ok := dict.Values[label]; !ok {
		dict.Keys = append(dict.Keys, label)
	}
	dict.Values[label] = value
	out, err := sfv.SerializeDictionary(dict)
	if err != nil {
		return err
	}
	header.Set(name, out)
	return nil
}

type httpRoundTripperFunc func(*http.Request) (*http.Response, error)

func (f httpRoundTripperFunc) RoundTrip(req *http.Request) (*http.Response, error) { return f(req) }

func httpRequestHasBody(req *http.Request) bool {
	return req != nil && req.Body != nil && req.Body != http.NoBody
}

func peerCertificateFromRequest(req *http.Request) *x509.Certificate {
	if req != nil && req.TLS != nil && len(req.TLS.PeerCertificates) > 0 {
		return req.TLS.PeerCertificates[0]
	}
	return nil
}

func verifiedPeerCertificateChainsFromRequest(req *http.Request) [][]*x509.Certificate {
	if req == nil || req.TLS == nil || len(req.TLS.VerifiedChains) == 0 {
		return nil
	}
	return req.TLS.VerifiedChains
}

func (p *Profile) requireLocalIdentity() error {
	if p == nil || p.keys == nil || p.localDomain == "" {
		return dnsid.NewArgumentError("dnsid: local identity and KeyProvider are required", nil)
	}
	return nil
}

func readBoundedBody(r io.Reader) ([]byte, error) {
	const maximum = 8 << 20
	body, err := io.ReadAll(io.LimitReader(r, maximum+1))
	if err == nil && len(body) > maximum {
		err = dnsid.NewVerificationError(dnsid.VerificationCodeMalformedToken, false, "dnsid: HTTP content exceeds 8 MiB limit", nil)
	}
	return body, err
}
