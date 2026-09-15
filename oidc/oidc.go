package oidc

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/dnsid-ai/dnsid-go"
	"github.com/dnsid-ai/dnsid-go/internal/joseutil"
	"github.com/dnsid-ai/dnsid-go/internal/netguard"
	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
)

const (
	grantJWTBearer       = "urn:ietf:params:oauth:grant-type:jwt-bearer"
	maxOIDCResponseBytes = 1 << 20
)

// Config contains OIDC federation profile policy. The zero value applies the
// documented defaults, requires HTTPS issuers, and allows no issuers for
// token verification.
type Config struct {
	// DefaultScope is the scope requested during token exchange when
	// OIDCTokenExchangeOptions.Scope is empty. When both are empty the
	// profile requests "openid".
	DefaultScope string

	// AssertionLifetime is the default validity window of assertions
	// created by CreateOIDCAssertion. Zero means omitted (5 minutes).
	AssertionLifetime time.Duration

	// MaxAssertionLifetime caps the assertion lifetime, including any
	// per-call OIDCAssertionOptions.Expiry override. Zero means omitted
	// (15 minutes). Negative lifetimes are invalid.
	MaxAssertionLifetime time.Duration

	// ClockSkew is the tolerance applied to time claims during token
	// verification. Zero means omitted (30 seconds); WithClockSkew(0)
	// specifies zero tolerance. Negative skew is invalid; expiration is strict.
	ClockSkew               time.Duration
	clockSkewSet            bool
	assertionLifetimeSet    bool
	maxAssertionLifetimeSet bool

	// AllowedIssuers lists the exact issuer URLs VerifyOIDCToken accepts.
	// An empty list rejects every issuer.
	AllowedIssuers []string

	// AllowedTokenAlgorithms is the policy allowlist of JWS algorithms for
	// verified tokens. An empty list means RS256 only. This binding
	// currently verifies RS256 only; other allowed algorithms are rejected
	// as not implemented.
	AllowedTokenAlgorithms []string

	// AllowHTTPLoopbackIssuer permits http:// issuers on localhost and
	// loopback addresses, as a test/local-development escape hatch. All
	// other issuers must use https.
	AllowHTTPLoopbackIssuer bool
}

// WithClockSkew specifies tolerance, including explicit zero.
func (c Config) WithClockSkew(skew time.Duration) Config {
	c.ClockSkew = skew
	c.clockSkewSet = true
	return c
}

// WithAssertionLifetime specifies a positive default assertion lifetime.
func (c Config) WithAssertionLifetime(d time.Duration) Config {
	c.AssertionLifetime = d
	c.assertionLifetimeSet = true
	return c
}

// WithMaxAssertionLifetime specifies a positive maximum assertion lifetime.
func (c Config) WithMaxAssertionLifetime(d time.Duration) Config {
	c.MaxAssertionLifetime = d
	c.maxAssertionLifetimeSet = true
	return c
}
func (p *Profile) validateConfig() error {
	if p == nil || p.cfg.ClockSkew < 0 || p.cfg.AssertionLifetime < 0 || p.cfg.MaxAssertionLifetime < 0 || (p.cfg.assertionLifetimeSet && p.cfg.AssertionLifetime == 0) || (p.cfg.maxAssertionLifetimeSet && p.cfg.MaxAssertionLifetime == 0) {
		return dnsid.NewArgumentError("dnsid: invalid OIDC lifetime or skew", nil)
	}
	return nil
}

// Profile implements OIDC federation helpers on top of DNSid identity verification.
type Profile struct {
	resolver    dnsid.IdentityResolver
	localDomain string
	keys        dnsid.KeyProvider
	client      *http.Client
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

// New constructs an OIDC federation profile. localDomain and kp are required
// for CreateOIDCAssertion and token exchange; resolver is required by
// VerifyOIDCToken when it verifies the token subject as a DNSid domain.
// localDomain is normalized to a canonical FQDN when possible.
func New(resolver dnsid.IdentityResolver, localDomain string, kp dnsid.KeyProvider, cfg Config) *Profile {
	if localDomain != "" {
		if d, err := dnsid.NormalizeFQDN(localDomain); err == nil {
			localDomain = d
		}
	}
	return &Profile{resolver: resolver, localDomain: localDomain, keys: kp, client: noRedirectClient(nil), cfg: cfg}
}

// NewFromIdentityManager constructs an OIDC profile from an
// IdentityManager-like core manager, using the manager as the resolver and
// its Domain as the local domain. kp supplies the signing key.
func NewFromIdentityManager(manager identityManager, kp dnsid.KeyProvider, cfg Config) *Profile {
	localDomain := ""
	if manager != nil {
		localDomain = manager.Domain()
	}
	return New(manager, localDomain, kp, cfg)
}

// NewFromIdentityManagerKeyProvider constructs an OIDC profile from a manager
// that exposes its KeyProvider, such as one loaded with
// dnsid.NewIdentityManagerFromDnsid.
func NewFromIdentityManagerKeyProvider(manager identityManagerWithKeyProvider, cfg Config) *Profile {
	if manager == nil {
		return New(nil, "", nil, cfg)
	}
	return New(manager, manager.Domain(), manager.KeyProvider(), cfg)
}

// SetHTTPClient replaces the profile's HTTP client with a copy of c hardened
// for issuer traffic: the transport is wrapped with SSRF and DNS-rebinding
// protection, and redirects are never followed. Passing nil installs the
// default safe client.
func (p *Profile) SetHTTPClient(c *http.Client) {
	p.client = noRedirectClient(netguard.NewSafeHTTPClientFrom(c))
}

// SetUnsafeHTTPClientForTesting installs a copy of c without SSRF protection;
// redirects are still never followed. It is intended only for tests against
// local servers — production code should use SetHTTPClient.
func (p *Profile) SetUnsafeHTTPClientForTesting(c *http.Client) { p.client = noRedirectClient(c) }

// OIDCAssertionOptions configures CreateOIDCAssertion.
type OIDCAssertionOptions struct {
	// Issuer is the OIDC issuer URL the assertion is addressed to; it
	// becomes the assertion's sole audience. Required.
	Issuer string

	// Expiry overrides Config.AssertionLifetime for this assertion when
	// positive. Zero means omitted; WithExpiry records explicit presence and
	// rejects zero. Negative values and values above the maximum are invalid.
	Expiry    time.Duration
	expirySet bool

	// AdditionalClaims are extra claims to embed in the assertion. They
	// must not override the reserved claims iss, sub, aud, iat, exp, jti,
	// or fqdn.
	AdditionalClaims map[string]any
}

// WithExpiry specifies an explicit positive assertion lifetime.
func (o OIDCAssertionOptions) WithExpiry(d time.Duration) OIDCAssertionOptions {
	o.Expiry = d
	o.expirySet = true
	return o
}

// OIDCTokenExchangeOptions configures ExchangeOIDCToken and GetOIDCToken.
type OIDCTokenExchangeOptions struct {
	// Issuer is the OIDC issuer URL to exchange the assertion with.
	// Required.
	Issuer string

	// Audience is the audience requested for the issued token. Required.
	Audience string

	// Scope is the requested scope. Empty means Config.DefaultScope, or
	// "openid" if that is also empty.
	Scope string

	// Assertion is an optional pre-built JWT-bearer assertion. Its
	// audience must be exactly the issuer. When empty, ExchangeOIDCToken
	// mints a fresh assertion; GetOIDCToken always ignores this field.
	Assertion string
}

// TokenExchangeError is the issuer's refusal of a token exchange: the token
// endpoint answered, with a non-200 status and (usually) an RFC 6749 error
// body. It is distinct from not reaching the endpoint at all, which surfaces
// as a transport error, so callers can tell "the issuer said no" from "the
// exchange did not happen" with errors.As.
type TokenExchangeError struct {
	StatusCode  int    // HTTP status from the token endpoint
	Code        string // RFC 6749 "error", e.g. invalid_grant; empty if the body had none
	Description string // RFC 6749 "error_description", if any
}

func (e *TokenExchangeError) Error() string {
	msg := "dnsid: OIDC token exchange failed: " + e.Code
	if e.Description != "" {
		msg += " " + e.Description
	}
	if e.Code == "" && e.Description == "" {
		msg += fmt.Sprintf("HTTP %d", e.StatusCode)
	}
	return msg
}

// OIDCTokenResponse is a successful response from an OIDC token endpoint.
type OIDCTokenResponse struct {
	AccessToken string `json:"access_token"`
	IDToken     string `json:"id_token,omitempty"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int64  `json:"expires_in,omitempty"`
	Scope       string `json:"scope,omitempty"`

	// Raw is the full decoded JSON response body, including fields not
	// mapped above. It is excluded when the response is re-serialized.
	Raw map[string]any `json:"-"`
}

// VerifyOIDCTokenOptions configures VerifyOIDCToken.
type VerifyOIDCTokenOptions struct {
	// Issuer is the expected issuer URL. Required; it must also appear in
	// Config.AllowedIssuers.
	Issuer string

	// Audience is the expected audience. Required; the token must carry
	// exactly this single audience.
	Audience string

	// VerifyDnsidSubject controls whether the token's sub claim is
	// verified as a DNSid domain through the profile's resolver. Nil or
	// true verifies; false skips subject verification.
	VerifyDnsidSubject *bool
	// Peer supplies trusted current application-peer evidence for DNSid verification.
	Peer dnsid.VerifyDomainOpts
}

// VerifiedOIDCSubject is the result of a successful VerifyOIDCToken call.
type VerifiedOIDCSubject struct {
	Issuer   string
	Subject  string
	Audience string

	// VerifiedDomain is the DNSid verification result for Subject. It is
	// nil when VerifyOIDCTokenOptions.VerifyDnsidSubject disabled subject
	// verification.
	VerifiedDomain *dnsid.VerifiedDomain

	// Claims is the token's full decoded claim set.
	Claims map[string]any
}

// DiscoveryDocument is the subset of OIDC discovery metadata
// (/.well-known/openid-configuration) this profile uses.
type DiscoveryDocument struct {
	Issuer        string `json:"issuer"`
	TokenEndpoint string `json:"token_endpoint"`
	JWKSURI       string `json:"jwks_uri"`
}

// CreateOIDCAssertion signs a JWT-bearer assertion with the profile's active
// operational key. The assertion's iss, sub, and fqdn claims are the profile's
// local domain, its sole audience is the issuer, and it carries iat, exp, and
// a random jti. It returns an error if the profile has no local identity or
// KeyProvider, the issuer is invalid, the requested lifetime exceeds
// Config.MaxAssertionLifetime, or AdditionalClaims override a reserved claim
// or are not JSON-serializable.
func (p *Profile) CreateOIDCAssertion(opts OIDCAssertionOptions) (string, error) {
	if p == nil || p.keys == nil || p.localDomain == "" {
		return "", dnsid.NewArgumentError("dnsid: local identity and KeyProvider are required", nil)
	}
	if err := p.validateConfig(); err != nil {
		return "", err
	}
	issuer, err := validateIssuerRoot(opts.Issuer, p.cfg.AllowHTTPLoopbackIssuer)
	if err != nil {
		return "", err
	}
	lifetime := p.cfg.AssertionLifetime
	if lifetime <= 0 {
		lifetime = 5 * time.Minute
	}
	if opts.Expiry != 0 || opts.expirySet {
		lifetime = opts.Expiry
	}
	max := p.cfg.MaxAssertionLifetime
	if max <= 0 {
		max = 15 * time.Minute
	}
	if lifetime <= 0 || lifetime > max {
		return "", dnsid.NewArgumentError("dnsid: OIDC assertion expiry exceeds maximum lifetime", nil)
	}

	now := time.Now()
	if now.Add(lifetime).Unix() <= now.Unix() {
		return "", dnsid.NewArgumentError("dnsid: expiry is below timestamp resolution", nil)
	}
	jti, err := randomJTI()
	if err != nil {
		return "", err
	}
	claims := map[string]any{"iss": p.localDomain, "sub": p.localDomain, "aud": []string{issuer}, "iat": now.Unix(), "exp": now.Add(lifetime).Unix(), "jti": jti, "fqdn": p.localDomain}
	reserved := map[string]bool{"iss": true, "sub": true, "aud": true, "iat": true, "exp": true, "jti": true, "fqdn": true}
	for k, v := range opts.AdditionalClaims {
		if reserved[k] {
			return "", dnsid.NewArgumentError("dnsid: additionalClaims must not override reserved claim: "+k, nil)
		}
		claims[k] = v
	}
	return signJWT(p.keys, claims)
}

// DiscoverOIDCIssuer fetches the issuer's OIDC discovery document from
// issuer + "/.well-known/openid-configuration". It returns an error unless
// the document's issuer exactly matches the requested issuer and both
// token_endpoint and jwks_uri are same-origin with it. Redirects are
// rejected and responses are capped at 1 MiB.
func (p *Profile) DiscoverOIDCIssuer(ctx context.Context, issuer string) (*DiscoveryDocument, error) {
	issuer, err := validateIssuerRoot(issuer, p != nil && p.cfg.AllowHTTPLoopbackIssuer)
	if err != nil {
		return nil, err
	}
	var doc DiscoveryDocument
	if err := p.getJSON(ctx, issuer+"/.well-known/openid-configuration", &doc); err != nil {
		return nil, err
	}
	if doc.Issuer != issuer {
		return nil, verr(dnsid.VerificationCodeIssuerMismatch, "dnsid: OIDC discovery issuer mismatch", nil)
	}
	if err := validateSameOriginEndpoint(doc.TokenEndpoint, issuer, "token_endpoint"); err != nil {
		return nil, err
	}
	if err := validateSameOriginEndpoint(doc.JWKSURI, issuer, "jwks_uri"); err != nil {
		return nil, err
	}
	return &doc, nil
}

// ExchangeOIDCToken performs an OAuth 2.0 JWT-bearer grant
// (urn:ietf:params:oauth:grant-type:jwt-bearer) against the issuer's token
// endpoint. When opts.Assertion is empty it mints one with
// CreateOIDCAssertion; otherwise the pre-built assertion must be a valid JWT
// whose sole audience is exactly the discovered issuer. The response must
// contain an access_token with token_type Bearer. opts.Audience is required.
func (p *Profile) ExchangeOIDCToken(ctx context.Context, opts OIDCTokenExchangeOptions) (*OIDCTokenResponse, error) {
	if opts.Audience == "" {
		return nil, dnsid.NewArgumentError("dnsid: audience is required", nil)
	}
	doc, err := p.DiscoverOIDCIssuer(ctx, opts.Issuer)
	if err != nil {
		return nil, err
	}
	assertion := opts.Assertion
	if assertion == "" {
		assertion, err = p.CreateOIDCAssertion(OIDCAssertionOptions{Issuer: doc.Issuer})
		if err != nil {
			return nil, err
		}
	} else {
		_, claims, err := parseUnverifiedJWT(assertion)
		if err != nil {
			return nil, dnsid.NewArgumentError("dnsid: OIDC assertion must be a valid JWT", err)
		}
		if aud, ok := audienceList(claims["aud"]); !ok || len(aud) != 1 || aud[0] != doc.Issuer {
			return nil, dnsid.NewArgumentError("dnsid: OIDC assertion audience must exactly match issuer", nil)
		}
	}
	scope := opts.Scope
	if scope == "" {
		scope = p.cfg.DefaultScope
	}
	if scope == "" {
		scope = "openid"
	}
	form := url.Values{"grant_type": {grantJWTBearer}, "assertion": {assertion}, "audience": {opts.Audience}, "scope": {scope}}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, doc.TokenEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := p.httpClientFor(req.URL).Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if isRedirect(resp.StatusCode) {
		return nil, fmt.Errorf("dnsid: OIDC token endpoint redirects are not allowed")
	}
	body, err := readLimited(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		var oe struct {
			Error            string `json:"error"`
			ErrorDescription string `json:"error_description"`
		}
		_ = json.Unmarshal(body, &oe)
		return nil, &TokenExchangeError{StatusCode: resp.StatusCode, Code: oe.Error, Description: oe.ErrorDescription}
	}
	var raw map[string]any
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, err
	}
	tr := &OIDCTokenResponse{AccessToken: asString(raw["access_token"]), IDToken: asString(raw["id_token"]), TokenType: asString(raw["token_type"]), Scope: asString(raw["scope"]), Raw: raw}
	if n, ok := raw["expires_in"].(float64); ok {
		tr.ExpiresIn = int64(n)
	}
	if tr.AccessToken == "" {
		return nil, verr(dnsid.VerificationCodeInvalidClaims, "dnsid: OIDC token response missing access_token", nil)
	}
	if !strings.EqualFold(tr.TokenType, "bearer") {
		return nil, verr(dnsid.VerificationCodeInvalidClaims, "dnsid: OIDC token response token_type must be Bearer", nil)
	}
	return tr, nil
}

// GetOIDCToken mints a DNSid OIDC token: it signs a fresh JWT-bearer
// assertion with the profile's operational key and exchanges it at the
// issuer's token endpoint. It is ExchangeOIDCToken with opts.Assertion
// always ignored.
func (p *Profile) GetOIDCToken(ctx context.Context, opts OIDCTokenExchangeOptions) (*OIDCTokenResponse, error) {
	opts.Assertion = ""
	return p.ExchangeOIDCToken(ctx, opts)
}

// VerifyOIDCToken verifies an OIDC token issued to this relying party. The
// issuer must appear in Config.AllowedIssuers and match the token's iss
// claim, and the token must carry exactly the single audience opts.Audience.
// The signature is verified against the issuer's discovered JWKS: the JWS
// header may contain only alg, kid, and typ, the algorithm must be allowed
// by Config.AllowedTokenAlgorithms (RS256 is the only implemented
// algorithm), and the kid must select exactly one signature-eligible RSA key
// of at least 2048 bits. Time claims are checked within Config.ClockSkew.
// Unless opts.VerifyDnsidSubject is explicitly false, the token's sub claim
// is then verified as a DNSid domain through the profile's resolver, and the
// result is returned in VerifiedOIDCSubject.VerifiedDomain. Errors carry
// dnsid verification codes describing the first failed check.
func (p *Profile) VerifyOIDCToken(ctx context.Context, token string, opts VerifyOIDCTokenOptions) (*VerifiedOIDCSubject, error) {
	ctx, cancel := dnsid.VerificationContext(ctx)
	defer cancel()
	if err := p.validateConfig(); err != nil {
		return nil, err
	}
	issuer, err := validateIssuerRoot(opts.Issuer, p != nil && p.cfg.AllowHTTPLoopbackIssuer)
	if err != nil {
		return nil, err
	}
	if !contains(p.cfg.AllowedIssuers, issuer) {
		return nil, verr(dnsid.VerificationCodeIssuerMismatch, "dnsid: OIDC issuer is not allowed", nil)
	}
	if opts.Audience == "" {
		return nil, dnsid.NewArgumentError("dnsid: audience is required", nil)
	}
	header, claims, err := parseUnverifiedJWT(token)
	if err != nil {
		return nil, err
	}
	if asString(claims["iss"]) != issuer {
		return nil, verr(dnsid.VerificationCodeIssuerMismatch, "dnsid: OIDC issuer mismatch", nil)
	}
	if aud, ok := audienceList(claims["aud"]); !ok || len(aud) != 1 || aud[0] != opts.Audience {
		return nil, verr(dnsid.VerificationCodeAudienceMismatch, "dnsid: OIDC audience mismatch", nil)
	}
	if err := validateProtectedHeader(header); err != nil {
		return nil, err
	}
	if err := validateTimes(claims, p.clockSkew()); err != nil {
		return nil, err
	}
	alg, kid := asString(header["alg"]), asString(header["kid"])
	allowed := p.cfg.AllowedTokenAlgorithms
	if len(allowed) == 0 {
		allowed = []string{"RS256"}
	}
	if !contains(allowed, alg) || alg != "RS256" {
		return nil, verr(dnsid.VerificationCodeSignatureInvalid, "dnsid: OIDC algorithm not allowed or implemented", nil)
	}
	doc, err := p.DiscoverOIDCIssuer(ctx, issuer)
	if err != nil {
		return nil, err
	}
	body, err := p.getBody(ctx, doc.JWKSURI)
	if err != nil {
		return nil, err
	}
	set, err := jwk.Parse(body)
	if err != nil {
		return nil, err
	}
	key, ok := lookupRS256SigningKey(set, kid, alg)
	if !ok || !verifyRS256(token, key) {
		return nil, verr(dnsid.VerificationCodeSignatureInvalid, "dnsid: OIDC token signature invalid", nil)
	}
	if err := validateTimes(claims, p.clockSkew()); err != nil {
		return nil, err
	}
	sub := asString(claims["sub"])
	if sub == "" {
		return nil, verr(dnsid.VerificationCodeInvalidClaims, "dnsid: OIDC token missing sub", nil)
	}
	var vd *dnsid.VerifiedDomain
	if opts.VerifyDnsidSubject == nil || *opts.VerifyDnsidSubject {
		if p == nil || p.resolver == nil {
			return nil, dnsid.NewArgumentError("dnsid: IdentityResolver is required", nil)
		}
		vd, err = dnsid.VerifyIdentity(ctx, p.resolver, sub, opts.Peer)
		if err != nil {
			return nil, err
		}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := validateTimes(claims, p.clockSkew()); err != nil {
		return nil, err
	}
	return &VerifiedOIDCSubject{Issuer: issuer, Subject: sub, Audience: opts.Audience, VerifiedDomain: vd, Claims: claims}, nil
}

func (p *Profile) getJSON(ctx context.Context, rawURL string, out any) error {
	body, err := p.getBody(ctx, rawURL)
	if err != nil {
		return err
	}
	return json.Unmarshal(body, out)
}

func (p *Profile) getBody(ctx context.Context, rawURL string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, err
	}
	resp, err := p.httpClientFor(req.URL).Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if isRedirect(resp.StatusCode) {
		return nil, fmt.Errorf("dnsid: OIDC redirects are not allowed")
	}
	body, err := readLimited(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("dnsid: OIDC fetch failed: status %d", resp.StatusCode)
	}
	return body, nil
}

func (p *Profile) httpClientFor(u *url.URL) *http.Client {
	if p != nil && p.cfg.AllowHTTPLoopbackIssuer && u != nil && u.Scheme == "http" && isLocalhost(u.Hostname()) {
		base := p.client
		if base == nil {
			base = &http.Client{}
		}
		c := *base
		c.Transport = loopbackOnlyTransport()
		c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
		return &c
	}
	if p != nil && p.client != nil {
		return p.client
	}
	return noRedirectClient(nil)
}

func loopbackOnlyTransport() *http.Transport {
	var tr *http.Transport
	if base, ok := http.DefaultTransport.(*http.Transport); ok {
		tr = base.Clone()
	} else {
		tr = &http.Transport{}
	}
	tr.Proxy = nil
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	resolver := &net.Resolver{}
	tr.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, err
		}
		if ip := net.ParseIP(host); ip != nil {
			if !ip.IsLoopback() {
				return nil, fmt.Errorf("dial blocked: %s is not loopback", ip)
			}
			return dialer.DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
		}
		ips, err := resolver.LookupIPAddr(ctx, host)
		if err != nil {
			return nil, err
		}
		for _, ip := range ips {
			if ip.IP == nil || !ip.IP.IsLoopback() {
				return nil, fmt.Errorf("dial blocked: %s resolves outside loopback", host)
			}
		}
		if len(ips) == 0 {
			return nil, fmt.Errorf("dial blocked: %s resolved to no addresses", host)
		}
		var lastErr error
		for _, ip := range ips {
			conn, err := dialer.DialContext(ctx, network, net.JoinHostPort(ip.IP.String(), port))
			if err == nil {
				return conn, nil
			}
			lastErr = err
		}
		return nil, lastErr
	}
	return tr
}

func (p *Profile) clockSkew() time.Duration {
	if p != nil && (p.cfg.ClockSkew != 0 || p.cfg.clockSkewSet) {
		return p.cfg.ClockSkew
	}
	return 30 * time.Second
}

func noRedirectClient(base *http.Client) *http.Client {
	if base == nil {
		base = &http.Client{Transport: dnsid.SafeDialerTransport()}
	}
	c := *base
	c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &c
}

func validateIssuerRoot(raw string, allowHTTPLoopback bool) (string, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme == "" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || strings.HasSuffix(raw, "/") {
		return "", dnsid.NewArgumentError("dnsid: invalid OIDC issuer", err)
	}
	if u.Scheme != "https" && (!allowHTTPLoopback || u.Scheme != "http" || !isLocalhost(u.Hostname())) {
		return "", dnsid.NewArgumentError("dnsid: OIDC issuer must use https", nil)
	}
	return raw, nil
}

func validateSameOriginEndpoint(raw, issuer, name string) error {
	u, err := url.Parse(raw)
	base, _ := url.Parse(issuer)
	if err != nil || u.Scheme == "" || u.Host == "" || u.User != nil || u.Path == "" || u.RawQuery != "" || u.Fragment != "" || u.Scheme != base.Scheme || u.Host != base.Host {
		return verr(dnsid.VerificationCodeInvalidClaims, "dnsid: invalid OIDC "+name, err)
	}
	return nil
}

func isLocalhost(host string) bool {
	ip := net.ParseIP(host)
	return host == "localhost" || ip != nil && ip.IsLoopback()
}

func signJWT(kp dnsid.KeyProvider, claims map[string]any) (string, error) {
	key := kp.JWK()
	if key == nil {
		return "", dnsid.NewArgumentError("dnsid: KeyProvider has no active key", nil)
	}
	kid, _ := key.KeyID()
	alg, _ := key.Algorithm()
	if kid == "" || alg.String() == "" {
		return "", dnsid.NewArgumentError("dnsid: active signing key missing kid or alg", nil)
	}
	header := map[string]any{"alg": alg.String(), "kid": kid, "typ": "JWT"}
	h, err := json.Marshal(header)
	if err != nil {
		return "", err
	}
	p, err := json.Marshal(claims)
	if err != nil {
		return "", dnsid.NewArgumentError("dnsid: OIDC assertion claims are not JSON serializable", err)
	}
	input := b64(h) + "." + b64(p)
	sig, err := kp.Sign([]byte(input))
	if err != nil {
		return "", err
	}
	return input + "." + b64(sig.Signature), nil
}

func randomJTI() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b[:]), nil
}

func parseUnverifiedJWT(token string) (map[string]any, map[string]any, error) {
	_, header, payload, err := joseutil.Compact(token)
	if err != nil {
		return nil, nil, verr(dnsid.VerificationCodeMalformedToken, "dnsid: malformed token", err)
	}
	h, err := joseutil.DecodeObject(header)
	if err != nil {
		return nil, nil, verr(dnsid.VerificationCodeMalformedToken, "dnsid: malformed token", err)
	}
	c, err := joseutil.DecodeObject(payload)
	if err != nil {
		return nil, nil, verr(dnsid.VerificationCodeMalformedToken, "dnsid: malformed token", err)
	}
	return h, c, nil
}

func unverifiedClaims(token string) map[string]any {
	_, c, _ := parseUnverifiedJWT(token)
	return c
}

func validateProtectedHeader(header map[string]any) error {
	if asString(header["alg"]) == "" || asString(header["kid"]) == "" {
		return verr(dnsid.VerificationCodeMalformedToken, "dnsid: alg and kid strings are required", nil)
	}
	if v, exists := header["typ"]; exists {
		if _, ok := v.(string); !ok {
			return verr(dnsid.VerificationCodeMalformedToken, "dnsid: typ must be a string", nil)
		}
	}
	for name := range header {
		switch name {
		case "alg", "kid", "typ":
		default:
			return verr(dnsid.VerificationCodeMalformedToken, "dnsid: unsupported OIDC token header", nil)
		}
	}
	return nil
}

func verifyRS256(token string, key jwk.Key) bool {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return false
	}
	var pub rsa.PublicKey
	if err := jwk.Export(key, &pub); err != nil {
		return false
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return false
	}
	sum := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	return rsa.VerifyPKCS1v15(&pub, crypto.SHA256, sum[:], sig) == nil
}

func lookupRS256SigningKey(set jwk.Set, kid, alg string) (jwk.Key, bool) {
	if set == nil || kid == "" || alg != "RS256" {
		return nil, false
	}
	var match jwk.Key
	for i := 0; i < set.Len(); i++ {
		key, ok := set.Key(i)
		if !ok {
			continue
		}
		keyID, _ := key.KeyID()
		if keyID != kid {
			continue
		}
		if match != nil || !rs256SigningKeyEligible(key) {
			return nil, false
		}
		match = key
	}
	return match, match != nil
}

func rs256SigningKeyEligible(key jwk.Key) bool {
	if key == nil {
		return false
	}
	if v, ok := key.Algorithm(); ok && v != jwa.RS256() {
		return false
	}
	if use, ok := key.KeyUsage(); ok && use != string(jwk.ForSignature) {
		return false
	}
	if k, ok := key.(interface {
		KeyOps() (jwk.KeyOperationList, bool)
	}); ok {
		ops, hasOps := k.KeyOps()
		if hasOps && !onlyKeyOp(ops, jwk.KeyOpVerify) {
			return false
		}
	}
	var pub rsa.PublicKey
	return jwk.Export(key, &pub) == nil && pub.N.BitLen() >= 2048
}

func onlyKeyOp(ops jwk.KeyOperationList, want jwk.KeyOperation) bool {
	if len(ops) == 0 {
		return false
	}
	for _, op := range ops {
		if op != want {
			return false
		}
	}
	return true
}

func validateTimes(claims map[string]any, skew time.Duration) error {
	now := time.Now()
	exp, ok := unixTime(claims["exp"])
	if !ok {
		return verr(dnsid.VerificationCodeInvalidClaims, "dnsid: OIDC token missing or invalid exp", nil)
	}
	if !now.Before(exp) {
		return verr(dnsid.VerificationCodeTokenExpired, "dnsid: token expired", nil)
	}
	if v, exists := claims["nbf"]; exists {
		nbf, ok := unixTime(v)
		if !ok {
			return verr(dnsid.VerificationCodeInvalidClaims, "dnsid: OIDC token invalid nbf", nil)
		}
		if now.Add(skew).Before(nbf) {
			return verr(dnsid.VerificationCodeTokenNotYetValid, "dnsid: token not yet valid", nil)
		}
	}
	iat, ok := unixTime(claims["iat"])
	if !ok {
		return verr(dnsid.VerificationCodeInvalidClaims, "dnsid: OIDC token missing or invalid iat", nil)
	}
	if !exp.After(iat) {
		return verr(dnsid.VerificationCodeInvalidClaims, "dnsid: OIDC token exp must be after iat", nil)
	}
	if now.Add(skew).Before(iat) {
		return verr(dnsid.VerificationCodeTokenNotYetValid, "dnsid: token not yet valid", nil)
	}
	return nil
}

func unixTime(v any) (time.Time, bool) {
	return joseutil.NumericDate(v)
}

func audienceList(v any) ([]string, bool) {
	switch x := v.(type) {
	case string:
		return []string{x}, x != ""
	case []any:
		if len(x) == 0 {
			return nil, false
		}
		out := make([]string, 0, len(x))
		for _, v := range x {
			s, ok := v.(string)
			if !ok || s == "" {
				return nil, false
			}
			out = append(out, s)
		}
		return out, true
	default:
		return nil, false
	}
}

func asString(v any) string { s, _ := v.(string); return s }
func contains(xs []string, x string) bool {
	for _, v := range xs {
		if v == x {
			return true
		}
	}
	return false
}
func isRedirect(code int) bool {
	return code == 301 || code == 302 || code == 303 || code == 307 || code == 308
}
func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }
func readLimited(r io.Reader) ([]byte, error) {
	body, err := io.ReadAll(io.LimitReader(r, maxOIDCResponseBytes+1))
	if err != nil {
		return nil, err
	}
	if len(body) > maxOIDCResponseBytes {
		return nil, fmt.Errorf("dnsid: OIDC response exceeds %d bytes", maxOIDCResponseBytes)
	}
	return body, nil
}
func verr(code dnsid.VerificationCode, msg string, err error) error {
	return dnsid.NewVerificationError(code, false, msg, err)
}
