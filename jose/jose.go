package jose

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/dnsid-ai/dnsid-go"
	"github.com/dnsid-ai/dnsid-go/internal/joseutil"
	"github.com/lestrrat-go/jwx/v3/jwk"
	jwxjwt "github.com/lestrrat-go/jwx/v3/jwt"
)

// Config contains JOSE/JWT/JWS profile policy. The zero value applies the
// profile defaults.
type Config struct {
	// MaxLifetime caps the validity window (exp - iat) of created and
	// verified JWTs. Zero means omitted (15 minutes); negatives are invalid.
	MaxLifetime time.Duration

	// ClockSkew is the tolerance applied to time-based claim checks during
	// verification. Zero means omitted (60 seconds); WithClockSkew(0)
	// specifies zero tolerance. Skew never extends expiration.
	ClockSkew      time.Duration
	clockSkewSet   bool
	maxLifetimeSet bool
}

// WithClockSkew specifies tolerance, including explicit zero.
func (c Config) WithClockSkew(skew time.Duration) Config {
	c.ClockSkew = skew
	c.clockSkewSet = true
	return c
}

// WithMaxLifetime specifies a positive maximum lifetime.
func (c Config) WithMaxLifetime(lifetime time.Duration) Config {
	c.MaxLifetime = lifetime
	c.maxLifetimeSet = true
	return c
}

func (p *Profile) validateConfig() error {
	if p.cfg.ClockSkew < 0 || p.cfg.MaxLifetime < 0 || (p.cfg.maxLifetimeSet && p.cfg.MaxLifetime == 0) {
		return dnsid.NewArgumentError("dnsid: invalid JOSE lifetime or clock skew", nil)
	}
	return nil
}

// Profile implements the DNSid JOSE profile on top of core DNSid identity verification.
type Profile struct {
	resolver            dnsid.IdentityResolver
	localDomain         string
	keys                dnsid.KeyProvider
	cfg                 Config
	signatureRetryMu    sync.Mutex
	signatureRetryAfter map[string]time.Time
}

type identityManager interface {
	dnsid.IdentityResolver
	Domain() string
}

type identityManagerWithKeyProvider interface {
	identityManager
	KeyProvider() dnsid.KeyProvider
}

// New constructs a JOSE profile. localDomain and kp are required for create/sign
// operations. Invalid lifetime/skew configuration is rejected when used.
func New(resolver dnsid.IdentityResolver, localDomain string, kp dnsid.KeyProvider, cfg Config) *Profile {
	if localDomain != "" {
		if d, err := dnsid.NormalizeFQDN(localDomain); err == nil {
			localDomain = d
		}
	}
	return &Profile{resolver: resolver, localDomain: localDomain, keys: kp, cfg: cfg, signatureRetryAfter: make(map[string]time.Time)}
}

// NewFromIdentityManager constructs a JOSE profile from an IdentityManager-like core manager.
func NewFromIdentityManager(manager identityManager, kp dnsid.KeyProvider, cfg Config) *Profile {
	localDomain := ""
	if manager != nil {
		localDomain = manager.Domain()
	}
	return New(manager, localDomain, kp, cfg)
}

// NewFromIdentityManagerKeyProvider constructs a JOSE profile from a manager that exposes its KeyProvider.
func NewFromIdentityManagerKeyProvider(manager identityManagerWithKeyProvider, cfg Config) *Profile {
	if manager == nil {
		return New(nil, "", nil, cfg)
	}
	return New(manager, manager.Domain(), manager.KeyProvider(), cfg)
}

// JWTOptions configures JWT creation.
type JWTOptions struct {
	// Audience is the token's aud claim. It is required and must normalize
	// to a valid FQDN.
	Audience string

	// Expiry is the requested positive lifetime, capped by Config.MaxLifetime.
	// A zero struct field means omitted (15 minutes); WithExpiry records
	// explicit presence and rejects zero. Negative lifetimes are invalid.
	Expiry    time.Duration
	expirySet bool

	// AdditionalClaims holds private claims to embed in the token. The
	// registered claim names iss, sub, aud, exp, iat, nbf, and jti are
	// reserved; CreateJWT fails if any of them appear here.
	AdditionalClaims map[string]any
}

// WithExpiry specifies an explicit positive lifetime; zero is rejected.
func (o JWTOptions) WithExpiry(expiry time.Duration) JWTOptions {
	o.Expiry = expiry
	o.expirySet = true
	return o
}

// VerifyJWTOptions configures JWT verification.
type VerifyJWTOptions struct {
	// ExpectedAudience is the audience that must appear in the token's aud
	// claim. Empty means the profile's local domain; verification fails if
	// both are empty.
	ExpectedAudience string

	// ExpectedIssuer, when non-empty, requires the token's iss claim to
	// match this domain after FQDN normalization.
	ExpectedIssuer string

	// Peer supplies trusted current application-peer evidence, never endpoint certificates.
	Peer dnsid.VerifyDomainOpts
}

// Claims holds the validated claims of a verified DNSid JWT.
type Claims struct {
	// Issuer is the token's iss claim, normalized to a FQDN.
	Issuer string

	// Subject is the token's sub claim, normalized to a FQDN. The DNSid
	// JOSE profile requires it to equal Issuer.
	Subject string

	// Audiences is the token's aud claim with each entry normalized to a
	// FQDN.
	Audiences []string

	// JWTID is the token's jti claim.
	JWTID string

	// IssuedAt is the token's iat claim.
	IssuedAt time.Time

	// Expiry is the token's exp claim.
	Expiry time.Time

	// Extra holds the token's private (non-registered) claims.
	Extra map[string]any
}

type jwtConfig struct {
	Domain               string
	DefaultTokenLifetime time.Duration
	MaxTokenLifetime     time.Duration
	ClockSkew            time.Duration
}

const signatureFailureRefreshBackoff = 30 * time.Second

func (p *Profile) jwtConfig() jwtConfig {
	maxLifetime := p.cfg.MaxLifetime
	if maxLifetime <= 0 {
		maxLifetime = 15 * time.Minute
	}
	clockSkew := p.cfg.ClockSkew
	if clockSkew == 0 && !p.cfg.clockSkewSet {
		clockSkew = 60 * time.Second
	}
	return jwtConfig{Domain: p.localDomain, DefaultTokenLifetime: 15 * time.Minute, MaxTokenLifetime: maxLifetime, ClockSkew: clockSkew}
}

func (p *Profile) requireLocalIdentity() error {
	if p == nil || p.keys == nil || p.localDomain == "" {
		return dnsid.NewArgumentError("dnsid: local identity and KeyProvider are required", nil)
	}
	return nil
}

// CreateJWT produces a DNSid JOSE-profile JWT signed by this profile's active key.
func (p *Profile) CreateJWT(opts JWTOptions) (string, error) {
	if err := p.requireLocalIdentity(); err != nil {
		return "", err
	}
	if err := p.validateConfig(); err != nil {
		return "", err
	}
	return createJWT(p.jwtConfig(), p.keys, opts)
}

// VerifyJWT verifies a DNSid JOSE-profile JWT through core domain verification.
func (p *Profile) VerifyJWT(ctx context.Context, tokenStr string, opts ...VerifyJWTOptions) (*dnsid.VerifiedDomain, *Claims, error) {
	ctx, cancel := dnsid.VerificationContext(ctx)
	defer cancel()
	if p == nil || p.resolver == nil {
		return nil, nil, dnsid.NewArgumentError("dnsid: IdentityResolver is required", nil)
	}
	if err := p.validateConfig(); err != nil {
		return nil, nil, err
	}
	verifyOpts := VerifyJWTOptions{ExpectedAudience: p.localDomain}
	if len(opts) > 0 {
		verifyOpts = opts[0]
		if verifyOpts.ExpectedAudience == "" {
			verifyOpts.ExpectedAudience = p.localDomain
		}
	}
	if verifyOpts.ExpectedAudience == "" {
		return nil, nil, dnsid.NewArgumentError("dnsid: VerifyJWT requires ExpectedAudience when the profile has no local domain", nil)
	}
	header, parts, err := parseJWSProtectedHeader(tokenStr)
	if err != nil {
		return nil, nil, dnsid.NewVerificationError(dnsid.VerificationCodeMalformedToken, false, "dnsid: malformed protected header", err)
	}
	claims, err := validateJWTClaims(parts.payload, p.jwtConfig(), verifyOpts)
	if err != nil {
		return nil, nil, err
	}
	issuer := claims.Issuer
	vd, err := dnsid.VerifyIdentity(ctx, p.resolver, issuer, verifyOpts.Peer)
	if err != nil {
		return nil, nil, err
	}
	if vd.KeySet() == nil || vd.KeySet().Raw() == nil {
		return nil, nil, dnsid.NewVerificationError(dnsid.VerificationCodeJWKSUnavailable, true, fmt.Sprintf("dnsid: no verified JWKS for %s", issuer), nil)
	}
	err = verifyJWTSignature(header, parts, vd.KeySet().Raw())
	if err != nil && p.allowSignatureFailureRefresh(issuer) {
		if evicter, ok := p.resolver.(interface{ EvictDomain(string) }); ok {
			evicter.EvictDomain(issuer)
			if retryVD, retryErr := dnsid.VerifyIdentity(ctx, p.resolver, issuer, verifyOpts.Peer); retryErr == nil && retryVD.KeySet() != nil && retryVD.KeySet().Raw() != nil {
				vd = retryVD
				err = verifyJWTSignature(header, parts, retryVD.KeySet().Raw())
			}
		}
	}
	if err != nil {
		return nil, nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}
	if !time.Now().Before(claims.Expiry) {
		return nil, nil, dnsid.NewVerificationError(dnsid.VerificationCodeTokenExpired, false, "dnsid: token expired during verification", nil)
	}
	return vd, claims, nil
}

func (p *Profile) allowSignatureFailureRefresh(domain string) bool {
	now := time.Now()
	p.signatureRetryMu.Lock()
	defer p.signatureRetryMu.Unlock()
	if p.signatureRetryAfter == nil {
		p.signatureRetryAfter = make(map[string]time.Time)
	}
	if next := p.signatureRetryAfter[domain]; now.Before(next) {
		return false
	}
	for key, expiry := range p.signatureRetryAfter {
		if !now.Before(expiry) {
			delete(p.signatureRetryAfter, key)
		}
	}
	if len(p.signatureRetryAfter) >= 1024 {
		return false
	}
	p.signatureRetryAfter[domain] = now.Add(signatureFailureRefreshBackoff)
	return true
}

func createJWT(cfg jwtConfig, kp dnsid.KeyProvider, opts JWTOptions) (string, error) {
	if opts.Audience == "" {
		return "", dnsid.NewArgumentError("dnsid: audience is required", nil)
	}
	audience, err := dnsid.NormalizeFQDN(opts.Audience)
	if err != nil {
		return "", dnsid.NewArgumentError("dnsid: invalid audience", err)
	}
	lifetime := cfg.DefaultTokenLifetime
	if opts.Expiry != 0 || opts.expirySet {
		lifetime = opts.Expiry
	}
	if lifetime <= 0 || lifetime > cfg.MaxTokenLifetime {
		return "", dnsid.NewArgumentError("dnsid: requested lifetime must be positive and within maximum", nil)
	}
	jti, err := randomJTI()
	if err != nil {
		return "", err
	}
	now := time.Now()
	if now.Add(lifetime).Unix() <= now.Unix() {
		return "", dnsid.NewArgumentError("dnsid: expiry is below timestamp resolution", nil)
	}
	tok, err := jwxjwt.NewBuilder().Issuer(cfg.Domain).Subject(cfg.Domain).Audience([]string{audience}).IssuedAt(now).NotBefore(now).Expiration(now.Add(lifetime)).JwtID(jti).Build()
	if err != nil {
		return "", fmt.Errorf("dnsid: building JWT: %w", err)
	}
	reserved := map[string]bool{"iss": true, "sub": true, "aud": true, "exp": true, "iat": true, "nbf": true, "jti": true}
	for k, v := range opts.AdditionalClaims {
		if reserved[k] {
			return "", dnsid.NewArgumentError(fmt.Sprintf("dnsid: claim %q is reserved and cannot be overridden", k), nil)
		}
		if err := tok.Set(k, v); err != nil {
			return "", fmt.Errorf("dnsid: setting claim %q: %w", k, err)
		}
	}
	kid, alg, err := joseutil.ActiveSigningMetadata(kp)
	if err != nil {
		return "", err
	}
	return signJWTCompact(tok, kp, kid, alg)
}

func randomJTI() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("dnsid: generating JWT ID: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b[:]), nil
}

func verifyJWTSignature(header *jwsProtectedHeader, parts *compactJWSParts, keySet jwk.Set) error {
	candidates, err := jwtVerificationCandidates(header, keySet)
	if err != nil || !verifySignature(header, parts, candidates) {
		return dnsid.NewVerificationError(dnsid.VerificationCodeSignatureInvalid, false, "dnsid: invalid signature: signature verification failed", err)
	}
	return nil
}

func validateJWTClaims(payload []byte, cfg jwtConfig, opts VerifyJWTOptions) (*Claims, error) {
	raw, err := joseutil.DecodeObject(payload)
	if err != nil {
		return nil, dnsid.NewVerificationError(dnsid.VerificationCodeMalformedToken, false, "dnsid: invalid JWT claims JSON", err)
	}
	if err := validateClaimTypes(raw); err != nil {
		return nil, err
	}
	now := time.Now()
	exp, _ := joseutil.NumericDate(raw["exp"])
	iat, _ := joseutil.NumericDate(raw["iat"])
	iss, _ := raw["iss"].(string)
	sub, _ := raw["sub"].(string)
	jti, _ := raw["jti"].(string)
	auds, ok := raw["aud"].([]any)
	if !ok {
		auds = []any{raw["aud"]}
	}
	if !now.Before(exp) {
		return nil, dnsid.NewVerificationError(dnsid.VerificationCodeTokenExpired, false, "dnsid: token expired", nil)
	}
	if iat.After(now.Add(cfg.ClockSkew)) {
		return nil, dnsid.NewVerificationError(dnsid.VerificationCodeTokenNotYetValid, false, "dnsid: token not yet valid", nil)
	}
	if nbf, ok := joseutil.NumericDate(raw["nbf"]); ok && nbf.After(now.Add(cfg.ClockSkew)) {
		return nil, dnsid.NewVerificationError(dnsid.VerificationCodeTokenNotYetValid, false, "dnsid: token not yet valid", nil)
	}
	issuer, err := dnsid.NormalizeFQDN(iss)
	if err != nil {
		return nil, dnsid.NewVerificationError(dnsid.VerificationCodeInvalidClaims, false, fmt.Sprintf("dnsid: invalid claims: issuer %q is not a valid FQDN", iss), err)
	}
	subject, err := dnsid.NormalizeFQDN(sub)
	if err != nil {
		return nil, dnsid.NewVerificationError(dnsid.VerificationCodeInvalidClaims, false, fmt.Sprintf("dnsid: invalid claims: subject %q is not a valid FQDN", sub), err)
	}
	if subject != issuer {
		return nil, dnsid.NewVerificationError(dnsid.VerificationCodeInvalidClaims, false, fmt.Sprintf("dnsid: invalid claims: subject %q must equal issuer %q", sub, iss), nil)
	}
	if !exp.After(iat) {
		return nil, dnsid.NewVerificationError(dnsid.VerificationCodeInvalidClaims, false, "dnsid: exp must be after iat", nil)
	}
	if exp.Sub(iat) > cfg.MaxTokenLifetime {
		return nil, dnsid.NewVerificationError(dnsid.VerificationCodeLifetimeTooLong, false, fmt.Sprintf("dnsid: invalid claims: token lifetime %v exceeds maximum %v", exp.Sub(iat), cfg.MaxTokenLifetime), nil)
	}
	if opts.ExpectedIssuer != "" {
		expected, err := dnsid.NormalizeFQDN(opts.ExpectedIssuer)
		if err != nil {
			return nil, dnsid.NewVerificationError(dnsid.VerificationCodeIssuerMismatch, false, fmt.Sprintf("dnsid: invalid expected issuer %q", opts.ExpectedIssuer), err)
		}
		if issuer != expected {
			return nil, dnsid.NewVerificationError(dnsid.VerificationCodeIssuerMismatch, false, fmt.Sprintf("dnsid: invalid claims: issuer %q does not match expected %q", iss, opts.ExpectedIssuer), nil)
		}
	}
	normalizedAudiences := make([]string, 0, len(auds))
	for _, value := range auds {
		aud, _ := value.(string) // validateClaimTypes checked every audience.
		normalizedAud, err := dnsid.NormalizeFQDN(aud)
		if err != nil {
			return nil, dnsid.NewVerificationError(dnsid.VerificationCodeInvalidClaims, false, fmt.Sprintf("dnsid: invalid claims: audience %q is not a valid FQDN", aud), err)
		}
		normalizedAudiences = append(normalizedAudiences, normalizedAud)
	}
	if opts.ExpectedAudience != "" {
		expected, err := dnsid.NormalizeFQDN(opts.ExpectedAudience)
		if err != nil {
			return nil, dnsid.NewVerificationError(dnsid.VerificationCodeAudienceMismatch, false, fmt.Sprintf("dnsid: invalid expected audience %q", opts.ExpectedAudience), err)
		}
		found := false
		for _, aud := range normalizedAudiences {
			if aud == expected {
				found = true
				break
			}
		}
		if !found {
			return nil, dnsid.NewVerificationError(dnsid.VerificationCodeAudienceMismatch, false, fmt.Sprintf("dnsid: invalid claims: audience does not contain %q", opts.ExpectedAudience), nil)
		}
	}
	claims := &Claims{Issuer: issuer, Subject: subject, Audiences: normalizedAudiences, JWTID: jti, IssuedAt: iat, Expiry: exp, Extra: make(map[string]any)}
	for key, value := range raw {
		if !standardClaims[key] {
			claims.Extra[key] = value
		}
	}
	return claims, nil
}

// CreateJWS creates a compact JWS over payload using this profile's active key.
func (p *Profile) CreateJWS(payload []byte) (string, error) {
	if err := p.requireLocalIdentity(); err != nil {
		return "", err
	}
	kid, alg, err := joseutil.ActiveSigningMetadata(p.keys)
	if err != nil {
		return "", err
	}
	if strings.Contains(kid, "#") {
		return "", dnsid.NewArgumentError("dnsid: active key id must not contain # for JWS", nil)
	}
	headerJSON, err := json.Marshal(struct {
		Alg string `json:"alg"`
		Typ string `json:"typ"`
		Kid string `json:"kid"`
	}{Alg: alg.String(), Typ: "jose", Kid: p.localDomain + "#" + kid})
	if err != nil {
		return "", err
	}
	headerSegment := base64.RawURLEncoding.EncodeToString(headerJSON)
	payloadSegment := base64.RawURLEncoding.EncodeToString(payload)
	signingInput := headerSegment + "." + payloadSegment
	sig, err := p.keys.Sign([]byte(signingInput))
	if err != nil {
		return "", err
	}
	if sig.Kid != kid || sig.Alg != alg {
		return "", fmt.Errorf("active signing key did not match JWS header metadata")
	}
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(sig.Signature), nil
}

// VerifyJWS verifies compact JWS bytes, passing optional trusted current-peer
// evidence through core DNSid verification. Payload bytes remain opaque.
func (p *Profile) VerifyJWS(ctx context.Context, compact string, opts ...dnsid.VerifyDomainOpts) ([]byte, *dnsid.VerifiedDomain, error) {
	ctx, cancel := dnsid.VerificationContext(ctx)
	defer cancel()
	if p == nil || p.resolver == nil {
		return nil, nil, dnsid.NewArgumentError("dnsid: IdentityResolver is required", nil)
	}
	header, parts, err := parseCompactJWSProtectedHeader(compact)
	if err != nil {
		return nil, nil, dnsid.NewVerificationError(dnsid.VerificationCodeMalformedToken, false, fmt.Sprintf("dnsid: malformed JWS: %v", err), nil)
	}
	domain, kid, err := joseutil.SplitDNSIDKid(header.kid)
	if err != nil {
		return nil, nil, dnsid.NewVerificationError(dnsid.VerificationCodeMalformedToken, false, fmt.Sprintf("dnsid: malformed JWS: %v", err), nil)
	}
	var peer dnsid.VerifyDomainOpts
	if len(opts) > 0 {
		peer = opts[0]
	}
	vd, err := dnsid.VerifyIdentity(ctx, p.resolver, domain, peer)
	if err != nil {
		return nil, nil, err
	}
	key, ok := joseutil.LookupJWKByKid(vd.KeySet().Raw(), kid)
	if !ok || !joseutil.SigningKeyEligible(key) || !joseutil.JWKMatchesAlg(key, header.alg) {
		return nil, nil, dnsid.NewVerificationError(dnsid.VerificationCodeKeyNotFound, false, fmt.Sprintf("dnsid: JWS kid %q not found for %s", kid, domain), nil)
	}
	if !verifySignature(header, parts, []jwk.Key{key}) {
		return nil, nil, dnsid.NewVerificationError(dnsid.VerificationCodeSignatureInvalid, false, "dnsid: invalid JWS signature", nil)
	}
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}
	return parts.payload, vd, nil
}

type jwsProtectedHeader struct {
	alg dnsid.JoseAlg
	kid string
}
type compactJWSParts struct {
	payload, signingInput, signatureRaw []byte
}

var errMalformedJWS = errors.New("malformed JWS")

func signJWTCompact(tok jwxjwt.Token, kp dnsid.KeyProvider, kid string, alg dnsid.JoseAlg) (string, error) {
	headerJSON, err := json.Marshal(struct {
		Alg string `json:"alg"`
		Typ string `json:"typ"`
		Kid string `json:"kid"`
	}{Alg: alg.String(), Typ: "JWT", Kid: kid})
	if err != nil {
		return "", err
	}
	payloadJSON, err := marshalJWTClaims(tok)
	if err != nil {
		return "", fmt.Errorf("marshaling claims: %w", err)
	}
	headerSegment := base64.RawURLEncoding.EncodeToString(headerJSON)
	payloadSegment := base64.RawURLEncoding.EncodeToString(payloadJSON)
	signingInput := headerSegment + "." + payloadSegment
	sig, err := kp.Sign([]byte(signingInput))
	if err != nil {
		return "", err
	}
	if sig.Kid != kid || sig.Alg != alg {
		return "", fmt.Errorf("active signing key did not match JWT header metadata")
	}
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(sig.Signature), nil
}

func parseJWSProtectedHeader(tokenStr string) (*jwsProtectedHeader, *compactJWSParts, error) {
	return parseProtectedHeader(tokenStr, true)
}

func parseCompactJWSProtectedHeader(tokenStr string) (*jwsProtectedHeader, *compactJWSParts, error) {
	return parseProtectedHeader(tokenStr, false)
}

func parseProtectedHeader(tokenStr string, jwtTyp bool) (*jwsProtectedHeader, *compactJWSParts, error) {
	segments, headerJSON, payload, err := joseutil.Compact(tokenStr)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %w", errMalformedJWS, err)
	}
	raw, err := joseutil.DecodeObject(headerJSON)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %w", errMalformedJWS, err)
	}
	sig, err := base64.RawURLEncoding.DecodeString(segments[2])
	if err != nil {
		return nil, nil, fmt.Errorf("%w: signature is not base64url", errMalformedJWS)
	}
	for name := range raw {
		switch name {
		case "alg", "typ", "kid", "b64":
		default:
			return nil, nil, fmt.Errorf("%w: disallowed JOSE header %q", errMalformedJWS, name)
		}
	}
	if value, exists := raw["b64"]; exists && value != true {
		return nil, nil, fmt.Errorf("%w: b64 must be true", errMalformedJWS)
	}
	algName, ok := raw["alg"].(string)
	if !ok {
		return nil, nil, fmt.Errorf("%w: token header has no alg", errMalformedJWS)
	}
	alg := dnsid.JoseAlg(algName)
	if !alg.Valid() {
		return nil, nil, fmt.Errorf("%w: alg %q not allowed", errMalformedJWS, algName)
	}
	kid, _ := raw["kid"].(string)
	if kid == "" {
		return nil, nil, fmt.Errorf("%w: JWS header missing kid", errMalformedJWS)
	}
	if typRaw, ok := raw["typ"]; ok {
		typ, ok := typRaw.(string)
		if !ok {
			return nil, nil, fmt.Errorf("%w: typ header must be a string", errMalformedJWS)
		}
		want := "JWT"
		if !jwtTyp {
			want = "jose"
		}
		if typ != want {
			return nil, nil, fmt.Errorf("%w: typ header must be %s", errMalformedJWS, want)
		}
	}
	return &jwsProtectedHeader{alg: alg, kid: kid}, &compactJWSParts{payload: payload, signingInput: []byte(segments[0] + "." + segments[1]), signatureRaw: sig}, nil
}

func marshalJWTClaims(tok jwxjwt.Token) ([]byte, error) {
	payload := make(map[string]any)
	if iss, ok := tok.Issuer(); ok && iss != "" {
		payload["iss"] = iss
	}
	if sub, ok := tok.Subject(); ok && sub != "" {
		payload["sub"] = sub
	}
	if auds, ok := tok.Audience(); ok && len(auds) > 0 {
		payload["aud"] = auds
	}
	if exp, ok := tok.Expiration(); ok && !exp.IsZero() {
		payload["exp"] = exp.Unix()
	}
	if iat, ok := tok.IssuedAt(); ok && !iat.IsZero() {
		payload["iat"] = iat.Unix()
	}
	if nbf, ok := tok.NotBefore(); ok && !nbf.IsZero() {
		payload["nbf"] = nbf.Unix()
	}
	if jti, ok := tok.JwtID(); ok && jti != "" {
		payload["jti"] = jti
	}
	for _, key := range tok.Keys() {
		if _, exists := payload[key]; exists {
			continue
		}
		var val any
		if err := tok.Get(key, &val); err == nil {
			payload[key] = val
		}
	}
	return json.Marshal(payload)
}

func jwtVerificationCandidates(header *jwsProtectedHeader, set jwk.Set) ([]jwk.Key, error) {
	key, ok := joseutil.LookupJWKByKid(set, header.kid)
	if header.kid == "" || !ok || !joseutil.SigningKeyEligible(key) || !joseutil.JWKMatchesAlg(key, header.alg) {
		return nil, fmt.Errorf("JWT kid not found or algorithm mismatch")
	}
	return []jwk.Key{key}, nil
}

func verifySignature(header *jwsProtectedHeader, parts *compactJWSParts, keys []jwk.Key) bool {
	return joseutil.VerifySignature(joseutil.ProtectedHeader{Alg: header.alg, Kid: header.kid}, joseutil.SignatureParts{SigningInput: parts.signingInput, Signature: parts.signatureRaw}, keys)
}

var standardClaims = map[string]bool{"iss": true, "sub": true, "aud": true, "exp": true, "iat": true, "jti": true, "nbf": true}
