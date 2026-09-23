package dnsid

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"slices"
	"strings"
	"sync"
	"time"

	dnsidlog "github.com/dnsid-ai/dnsid-go/log"
	"github.com/lestrrat-go/jwx/v3/jwk"
)

// PolicyFlag is a DNSid TXT-record policy flag.
type PolicyFlag string

// DNSid TXT-record policy flags understood by the verifier.
const (
	PolicyFlagMTLS     PolicyFlag = "mtls"
	PolicyFlagLogCheck PolicyFlag = "logchk"
)

// KeyAge is a DNSid key-age policy value.
type KeyAge string

// DNSSECMode describes the caller's DNSSEC verification policy.
type DNSSECMode string

// DNSSECMode values. DNSSECModeAuto accepts VALID, UNSIGNED, and UNKNOWN
// resolver states; DNSSECModeValidated rejects UNKNOWN; DNSSECModeRequired
// accepts only VALID. Every mode rejects FAILED.
const (
	DNSSECModeAuto      DNSSECMode = "auto"
	DNSSECModeValidated DNSSECMode = "validated"
	DNSSECModeRequired  DNSSECMode = "required"
)

// DNSSECState reports the resolver's DNSSEC validation result.
type DNSSECState string

// DNSSECState values reported by a DNSResolver. VerifyDomain always rejects
// DNSSECStateFailed. DNSSECStateUnknown is accepted by DNSSECModeAuto and
// rejected by DNSSECModeValidated and DNSSECModeRequired; DNSSECStateUnsigned
// is accepted unless the manager's DNSSECMode is DNSSECModeRequired.
const (
	DNSSECStateUnknown  DNSSECState = "UNKNOWN"
	DNSSECStateValid    DNSSECState = "VALID"
	DNSSECStateUnsigned DNSSECState = "UNSIGNED"
	DNSSECStateFailed   DNSSECState = "FAILED"
)

// Config is the single core configuration entry point for an IdentityManager.
// Identity holds the local identity's publication settings and is nil for a
// verification-only manager. Verification and Transport apply identically in
// both modes. Runtime dependencies (key providers, resolvers, fetchers, caches,
// log registries) are supplied through IdentityManagerOption values, not here.
type Config struct {
	Identity     *IdentityConfig
	Verification VerificationConfig
	Transport    TransportConfig
}

// Validate checks every section of the configuration without constructing a
// manager: Identity (when set), Verification, and Transport. It performs no
// network or file I/O.
func (c Config) Validate() error {
	if c.Identity != nil {
		if err := c.Identity.Validate(); err != nil {
			return err
		}
	}
	if err := c.Verification.validate(); err != nil {
		return err
	}
	return c.Transport.validate()
}

// IdentityConfig contains the local identity's DNSid publication settings.
type IdentityConfig struct {
	Domain          string
	GovernanceID    string
	LogRef          string
	StatusURL       string
	PolicyFlags     []PolicyFlag
	MaxKeyAge       KeyAge
	KeyURL          string // Operational-key JWKS URL serialized as ku=.
	EntityKeyURL    string // Accountable-entity JWKS URL serialized as ek=.
	CapabilitiesURL string
	PublishProfile  string
}

// Validate checks required identity configuration.
func (c IdentityConfig) Validate() error {
	if c.Domain == "" {
		return NewArgumentError("dnsid: IdentityConfig.Domain is required", nil)
	}
	if _, err := NormalizeFQDN(c.Domain); err != nil {
		return NewArgumentError("dnsid: invalid IdentityConfig.Domain", err)
	}
	if c.GovernanceID == "" {
		return NewArgumentError("dnsid: IdentityConfig.GovernanceID is required", nil)
	}
	if c.LogRef == "" {
		return NewArgumentError("dnsid: IdentityConfig.LogRef is required", nil)
	}
	if _, _, err := ParseLogRef(c.LogRef); err != nil {
		return NewArgumentError("dnsid: invalid IdentityConfig.LogRef", err)
	}
	if c.StatusURL == "" {
		return NewArgumentError("dnsid: IdentityConfig.StatusURL is required", nil)
	}
	if c.KeyURL != "" {
		if err := validateHTTPSURL(c.KeyURL, "IdentityConfig.KeyURL"); err != nil {
			return NewArgumentError("dnsid: invalid IdentityConfig.KeyURL", err)
		}
	}
	if c.EntityKeyURL != "" {
		if err := validateHTTPSURL(c.EntityKeyURL, "IdentityConfig.EntityKeyURL"); err != nil {
			return NewArgumentError("dnsid: invalid IdentityConfig.EntityKeyURL", err)
		}
	}
	if err := validateHTTPSURL(c.StatusURL, "IdentityConfig.StatusURL"); err != nil {
		return NewArgumentError("dnsid: invalid IdentityConfig.StatusURL", err)
	}
	if c.CapabilitiesURL != "" {
		if err := validateHTTPSURL(c.CapabilitiesURL, "IdentityConfig.CapabilitiesURL"); err != nil {
			return NewArgumentError("dnsid: invalid IdentityConfig.CapabilitiesURL", err)
		}
	}
	if c.MaxKeyAge != "" && !ValidKeyAgeValues[string(c.MaxKeyAge)] {
		return NewArgumentError(fmt.Sprintf("dnsid: invalid IdentityConfig.MaxKeyAge %q", c.MaxKeyAge), nil)
	}
	if c.PublishProfile != "" && c.PublishProfile != DefaultPublishProfile {
		return NewArgumentError(fmt.Sprintf("dnsid: unsupported DNSid publish profile %q", c.PublishProfile), nil)
	}
	return nil
}

// VerificationConfig contains protocol verification policy and counterparty
// acceptance settings. The zero value is spec-strict: status is re-fetched on
// every invocation, DNSSECModeAuto applies, and no acceptance decision is made.
type VerificationConfig struct {
	// StatusCheckInterval is the maximum age of a cached status result before
	// VerifyDomain re-fetches su= on a cache hit. Zero re-fetches every time.
	StatusCheckInterval time.Duration
	DNSSECMode          DNSSECMode
	// TrustedEntities is an optional counterparty allowlist. nil makes no
	// acceptance decision; an empty non-nil slice denies every counterparty.
	TrustedEntities []TrustedEntity
}

// TrustedEntity is one counterparty allowlist entry. GovernanceID must match
// the verified record's gi= exactly after FQDN normalization. When
// EntityKeyThumbprints is non-empty, the verified current record-signing key's
// RFC 7638 SHA-256 thumbprint must also equal one of the pins.
type TrustedEntity struct {
	GovernanceID         string
	EntityKeyThumbprints []string
}

func (c VerificationConfig) validate() error {
	if c.StatusCheckInterval < 0 {
		return NewArgumentError("dnsid: VerificationConfig.StatusCheckInterval must be non-negative", nil)
	}
	switch c.DNSSECMode {
	case "", DNSSECModeAuto, DNSSECModeValidated, DNSSECModeRequired:
	default:
		return NewArgumentError(fmt.Sprintf("dnsid: invalid DNSSEC mode %q", c.DNSSECMode), nil)
	}
	seen := make(map[string]bool, len(c.TrustedEntities))
	for _, e := range c.TrustedEntities {
		gi, err := NormalizeFQDN(e.GovernanceID)
		if err != nil {
			return NewArgumentError(fmt.Sprintf("dnsid: invalid TrustedEntity.GovernanceID %q", e.GovernanceID), err)
		}
		if seen[gi] {
			return NewArgumentError(fmt.Sprintf("dnsid: duplicate TrustedEntity.GovernanceID %q", gi), nil)
		}
		seen[gi] = true
		if e.EntityKeyThumbprints != nil && len(e.EntityKeyThumbprints) == 0 {
			return NewArgumentError(fmt.Sprintf("dnsid: TrustedEntity %q EntityKeyThumbprints must be omitted or non-empty", gi), nil)
		}
		pins := make(map[string]bool, len(e.EntityKeyThumbprints))
		for _, pin := range e.EntityKeyThumbprints {
			raw, err := base64.RawURLEncoding.Strict().DecodeString(pin)
			if err != nil || len(raw) != sha256.Size {
				return NewArgumentError(fmt.Sprintf("dnsid: TrustedEntity %q has an invalid entity key thumbprint", gi), err)
			}
			if pins[pin] {
				return NewArgumentError(fmt.Sprintf("dnsid: TrustedEntity %q has a duplicate entity key thumbprint", gi), nil)
			}
			pins[pin] = true
		}
	}
	return nil
}

// snapshot returns a normalized deep copy so later caller mutation of the
// supplied slices cannot affect the manager.
func (c VerificationConfig) snapshot() VerificationConfig {
	if c.DNSSECMode == "" {
		c.DNSSECMode = DNSSECModeAuto
	}
	if c.TrustedEntities == nil {
		return c
	}
	entities := make([]TrustedEntity, 0, len(c.TrustedEntities))
	for _, e := range c.TrustedEntities {
		gi, _ := NormalizeFQDN(e.GovernanceID) // validated already
		var pins []string
		if e.EntityKeyThumbprints != nil {
			pins = append([]string(nil), e.EntityKeyThumbprints...)
		}
		entities = append(entities, TrustedEntity{GovernanceID: gi, EntityKeyThumbprints: pins})
	}
	c.TrustedEntities = entities
	return c
}

// TransportConfig contains deployment controls for SDK-managed DNS and HTTPS:
// a custom DNS server for TXT lookups and HTTPS name resolution, and an
// additional CA bundle for HTTPS trust. Settings apply only to the default
// implementations; injected resolvers and fetchers are never inspected or
// modified. Setting a DNS server routes lookups through the stdlib resolver,
// which performs no DNSSEC validation.
//
// SDK-managed HTTPS refuses to dial loopback, private, link-local, multicast,
// reserved, and other non-routable addresses. PrivateAddressHosts is the only
// exemption: entries are hostnames ("agent.example.test", exact match) or
// leading-dot suffixes (".test", matching "test" and every name beneath it on
// a DNS-label boundary). A matching destination may resolve to loopback or
// private-use (RFC 1918, RFC 4193) addresses; link-local, multicast, reserved,
// and mixed public+private resolutions are still rejected, IP-literal URLs are
// never exempted, and every redirect hop is matched independently. The list
// is empty by default and there is no built-in exemption for .test or any
// other name; a local `dnsid` stack needs PrivateAddressHosts: []string{".test"}
// (or DNSID_PRIVATE_HOSTS=.test via config.LoadEnvironment). Entries with an IP
// literal, port, scheme, path, or credentials are rejected at construction.
type TransportConfig struct {
	DNSServer           string
	CABundlePath        string
	PrivateAddressHosts []string
}

// IsZero reports whether no transport setting is configured.
func (c TransportConfig) IsZero() bool {
	return c.DNSServer == "" && c.CABundlePath == "" && len(c.PrivateAddressHosts) == 0
}

// validate checks that every PrivateAddressHosts entry is a bare hostname or a
// leading-dot suffix.
func (c TransportConfig) validate() error {
	for _, entry := range c.PrivateAddressHosts {
		name := strings.TrimPrefix(entry, ".")
		if _, err := NormalizeFQDN(name); err != nil || net.ParseIP(strings.TrimSuffix(name, ".")) != nil {
			return NewArgumentError(fmt.Sprintf("dnsid: Config.Transport.PrivateAddressHosts entry %q must be a hostname or leading-dot suffix", entry), err)
		}
	}
	return nil
}

// snapshot returns a copy so later caller mutation of the slice cannot affect
// the manager.
func (c TransportConfig) snapshot() TransportConfig {
	c.PrivateAddressHosts = slices.Clone(c.PrivateAddressHosts)
	return c
}

// IdentityResolver verifies DNSid identity for peer domains.
type IdentityResolver interface {
	VerifyDomain(ctx context.Context, domain string) (*VerifiedDomain, error)
}

// VerifyDomainOpts contains optional inputs for core domain verification.
type VerifyDomainOpts struct {
	// PeerCertificate is the TLS client certificate leaf for records with fl=mtls.
	// Deprecated: set VerifiedPeerCertificateChains from an already-verified
	// TLS connection state instead. A leaf certificate alone is not accepted for
	// fl=mtls because hostname-only checks do not establish mTLS trust.
	PeerCertificate *x509.Certificate

	// VerifiedPeerCertificateChains are the peer certificate chains that the
	// caller's TLS stack has already authenticated for an mTLS connection, such
	// as tls.ConnectionState.VerifiedChains from a request with client cert auth.
	// At least one verified chain with a leaf certificate valid for the DNSid
	// domain is required when the peer record has fl=mtls.
	VerifiedPeerCertificateChains [][]*x509.Certificate
}

// TXTRecordRData is one concatenated TXT RDATA value plus resolver metadata.
type TXTRecordRData struct {
	Value string
	TTL   time.Duration
}

// DNSResolver fetches DNSid TXT records.
//
// DNSSECModeValidated and DNSSECModeRequired require a resolver that reports a
// definitive DNSSEC state. The default netDNSResolver reports
// DNSSECStateUnknown, which DNSSECModeAuto accepts.
type DNSResolver interface {
	FetchTXT(ctx context.Context, name string) ([]TXTRecordRData, DNSSECState, error)
}

// netDNSResolver is the built-in resolver backed by the OS stub resolver via
// net.Resolver. The Go standard library does not expose the AD/CD bits, so this
// resolver performs NO DNSSEC validation and ALWAYS reports DNSSECStateUnknown.
// A real in-transit DNSSEC failure is therefore invisible here. Integrators who
// select DNSSECModeValidated or DNSSECModeRequired MUST supply a DNSSEC-aware
// DNSResolver via WithDNSResolver.
// ponytail: stdlib net.Resolver can't surface AD/CD; a validating resolver
// (miekg/dns against a trusted server, or unbound) is a custom DNSResolver, not
// a change here.
type netDNSResolver struct{ r *net.Resolver }

type customDNSServerResolver struct{ server string }

func (r netDNSResolver) FetchTXT(ctx context.Context, name string) ([]TXTRecordRData, DNSSECState, error) {
	resolver := r.r
	if resolver == nil {
		resolver = net.DefaultResolver
	}
	values, err := resolver.LookupTXT(ctx, name)
	if err != nil {
		return nil, DNSSECStateUnknown, err
	}
	out := make([]TXTRecordRData, 0, len(values))
	for _, v := range values {
		out = append(out, TXTRecordRData{Value: v, TTL: 5 * time.Minute})
	}
	// Always DNSSECStateUnknown: net.Resolver does not expose validation state.
	// See the netDNSResolver type doc — supply a DNSSEC-aware resolver for prod.
	return out, DNSSECStateUnknown, nil
}

func (r customDNSServerResolver) FetchTXT(ctx context.Context, name string) ([]TXTRecordRData, DNSSECState, error) {
	resolver := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return dialDNSServer(ctx, network, r.server)
		},
	}
	return netDNSResolver{r: resolver}.FetchTXT(ctx, name)
}

// dialDNSServer connects to server on the network the Go resolver asked for.
// The resolver starts over UDP and retries over TCP when an answer arrives
// truncated; a DNSid TXT record is large enough that an authoritative server
// adding its authority section can push the answer past the UDP size the
// resolver advertises. Forcing UDP here made that retry dial UDP again and
// return the same truncated answer, so the record read as absent.
func dialDNSServer(ctx context.Context, network, server string) (net.Conn, error) {
	d := net.Dialer{Timeout: 5 * time.Second}
	return d.DialContext(ctx, network, server)
}

// RedirectPolicy controls HTTPS redirect handling for SDK-managed fetches.
type RedirectPolicy string

// RedirectPolicy values. RedirectPolicyNone (the zero-value default) does not
// follow redirects; RedirectPolicySameHost follows HTTPS redirects that stay
// on the allowed host; RedirectPolicyHTTPS follows any HTTPS redirect.
const (
	RedirectPolicyNone     RedirectPolicy = "none"
	RedirectPolicySameHost RedirectPolicy = "sameHost"
	RedirectPolicyHTTPS    RedirectPolicy = "https"
)

// FetchOptions constrains HTTPS JSON fetches.
type FetchOptions struct {
	AllowedHost      string
	DomainBoundary   bool
	MaxResponseBytes int64
	RedirectPolicy   RedirectPolicy
}

// HTTPSFetcher fetches JSON over safe HTTPS. Implementations must be safe for
// concurrent use.
type HTTPSFetcher interface {
	FetchJSON(ctx context.Context, rawURL string, opts FetchOptions) (json.RawMessage, *tls.Certificate, error)
}

type defaultHTTPSFetcher struct{ client *http.Client }

var errTLSPolicy = errors.New("dnsid: TLS policy violation")

type httpStatusError struct {
	statusCode int
}

func (e *httpStatusError) Error() string {
	return fmt.Sprintf("dnsid: HTTPS fetch returned HTTP %d", e.statusCode)
}

func clientWithRedirectPolicy(base *http.Client, originalURL string, opts FetchOptions) *http.Client {
	if base == nil {
		base = newSafeHTTPClientFrom(nil)
	}
	client := *base
	policy := opts.RedirectPolicy
	if policy == "" {
		policy = RedirectPolicyNone
	}
	orig, _ := url.Parse(originalURL)
	originalHost := ""
	if orig != nil {
		originalHost = orig.Hostname()
	}
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if policy == RedirectPolicyNone {
			return http.ErrUseLastResponse
		}
		if len(via) >= 10 {
			return fmt.Errorf("%w: too many HTTPS redirects", errTLSPolicy)
		}
		if req.URL == nil || req.URL.Scheme != "https" {
			return fmt.Errorf("%w: redirect URL must use https", errTLSPolicy)
		}
		if req.URL.User != nil {
			return fmt.Errorf("%w: redirect URL must not include userinfo", errTLSPolicy)
		}
		if req.URL.Fragment != "" || req.URL.RawFragment != "" {
			return fmt.Errorf("%w: redirect URL must not include a fragment", errTLSPolicy)
		}
		switch policy {
		case RedirectPolicySameHost:
			allowed := opts.AllowedHost
			if allowed == "" {
				allowed = originalHost
			}
			if allowed != "" && !fetchHostAllowed(req.URL.Hostname(), allowed, opts.DomainBoundary) {
				return fmt.Errorf("%w: redirect host %q does not match allowed host %q", errTLSPolicy, req.URL.Hostname(), allowed)
			}
			return nil
		case RedirectPolicyHTTPS:
			return nil
		default:
			return fmt.Errorf("%w: unsupported redirect policy %q", errTLSPolicy, policy)
		}
	}
	return &client
}

func certificateFromResponse(resp *http.Response) *tls.Certificate {
	if resp == nil || resp.TLS == nil || len(resp.TLS.PeerCertificates) == 0 || resp.TLS.PeerCertificates[0] == nil {
		return nil
	}
	leaf := resp.TLS.PeerCertificates[0]
	return &tls.Certificate{Certificate: [][]byte{leaf.Raw}, Leaf: leaf}
}

func certificateNotAfter(cert *tls.Certificate) time.Time {
	if cert == nil || cert.Leaf == nil {
		return time.Time{}
	}
	return cert.Leaf.NotAfter
}

func verifiedDomainExpiry(verifiedAt time.Time, dnsTTL time.Duration, keyAge string, keyBoundAt time.Time, runtimeCert, recordSigningCert *tls.Certificate) time.Time {
	var expiry time.Time
	if dnsTTL >= 0 && !verifiedAt.IsZero() {
		expiry = verifiedAt.Add(dnsTTL)
	}
	if keyAge != "" && !keyBoundAt.IsZero() {
		if d, err := parseKeyAgeDuration(keyAge); err == nil {
			keyExpiry := keyBoundAt.Add(d)
			if expiry.IsZero() || keyExpiry.Before(expiry) {
				expiry = keyExpiry
			}
		}
	}
	for _, cert := range []*tls.Certificate{runtimeCert, recordSigningCert} {
		certExpiry := certificateNotAfter(cert)
		if certExpiry.IsZero() {
			continue
		}
		if expiry.IsZero() || certExpiry.Before(expiry) {
			expiry = certExpiry
		}
	}
	return expiry
}

func (f defaultHTTPSFetcher) FetchJSON(ctx context.Context, rawURL string, opts FetchOptions) (json.RawMessage, *tls.Certificate, error) {
	if err := validateManagerFetchURL(rawURL, opts.AllowedHost, opts.DomainBoundary); err != nil {
		return nil, nil, err
	}
	client := f.client
	if client == nil {
		client = newSafeHTTPClientFrom(nil)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, nil, err
	}
	req.Header.Set("Accept", "application/json")
	client = clientWithRedirectPolicy(client, rawURL, opts)
	resp, err := client.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, nil, &httpStatusError{statusCode: resp.StatusCode}
	}
	limit := opts.MaxResponseBytes
	if limit <= 0 {
		limit = 1 << 20
	}
	data, err := readLimited(resp.Body, int(limit))
	if err != nil {
		return nil, nil, err
	}
	return data, certificateFromResponse(resp), nil
}

// IdentityManager is the primary DNSid SDK facade.
type IdentityManager struct {
	identity     IdentityConfig // zero value for verification-only managers
	verification VerificationConfig
	transport    TransportConfig
	keys         KeyProvider
	entityKeys   KeyProvider
	dns          DNSResolver
	https        HTTPSFetcher
	cache        *IdentityCache
	logRegistry  *dnsidlog.LogRegistry
	inFlightMu   sync.Mutex
	verifying    map[string]*inFlightVerification
	refreshing   map[string]*inFlightVerification
	// inFlightHook is a test-only seam called after a caller joins shared work.
	inFlightHook func(string, bool)
	localLogMu   sync.Mutex
	localLog     dnsidlog.Log
	initErr      error
	// dnsInjected/httpsInjected record caller-owned transport so TransportConfig
	// applies only to the SDK-managed defaults.
	dnsInjected   bool
	httpsInjected bool
}

type inFlightVerification struct {
	done    chan struct{}
	cancel  context.CancelFunc
	waiters int
	result  *VerifiedDomain
	err     error
}

// IdentityManagerOption configures IdentityManager.
type IdentityManagerOption func(*IdentityManager)

// WithEntityKeyProvider configures the accountable-entity key used to sign
// identity records and lifecycle events. Verification-only managers do not
// need an entity key provider.
func WithEntityKeyProvider(kp KeyProvider) IdentityManagerOption {
	return func(m *IdentityManager) { m.entityKeys = kp }
}

// WithDNSResolver overrides the built-in resolver. Resolvers used with
// DNSSECModeValidated or DNSSECModeRequired must report definitive DNSSEC
// states rather than DNSSECStateUnknown.
func WithDNSResolver(r DNSResolver) IdentityManagerOption {
	return func(m *IdentityManager) {
		if r == nil {
			m.initErr = NewArgumentError("dnsid: DNSResolver is required", nil)
			return
		}
		m.dns = r
		m.dnsInjected = true
	}
}

// WithHTTPSFetcher replaces the SDK-managed HTTPS JSON fetcher. The supplied
// fetcher becomes responsible for the transport-level protections the default
// provides (HTTPS-only URLs, host allow-listing, SSRF-safe dialing, and
// response size limits) and must be safe for concurrent use.
// Config.Transport does not apply to an injected fetcher.
func WithHTTPSFetcher(f HTTPSFetcher) IdentityManagerOption {
	return func(m *IdentityManager) {
		if f == nil {
			m.initErr = NewArgumentError("dnsid: HTTPSFetcher is required", nil)
			return
		}
		m.https = f
		m.httpsInjected = true
	}
}

// WithIdentityCache shares a bounded storage backend, not verification results.
// Each manager uses a private namespace even when the backend is injected.
// The supplied cache is retained by the manager and must not be nil.
func WithIdentityCache(cache *IdentityCache) IdentityManagerOption {
	return func(m *IdentityManager) {
		if cache == nil {
			m.initErr = NewArgumentError("dnsid: IdentityCache is required", nil)
			return
		}
		m.cache = cache
	}
}

// WithLogRegistry supplies the registry that maps lifecycle-log methods (the
// scheme of a record's lr= reference) to LogReader implementations. Without a
// registry, or for unregistered methods, lifecycle evidence checks fail with
// VerificationCodeLogError.
func WithLogRegistry(r *dnsidlog.LogRegistry) IdentityManagerOption {
	return func(m *IdentityManager) { m.logRegistry = r }
}

// WithHTTPClient bases SDK-managed HTTPS fetches on client, preserving its
// TLS and timeout configuration while wrapping its transport with the SDK's
// SSRF-safe, DNS-rebinding-resistant dialer. The client is caller-owned
// transport: Config.Transport does not apply to it.
func WithHTTPClient(client *http.Client) IdentityManagerOption {
	return func(m *IdentityManager) {
		m.https = defaultHTTPSFetcher{client: newSafeHTTPClientFrom(client)}
		m.httpsInjected = true
	}
}

func (m *IdentityManager) requireLocalIdentity() error {
	if m == nil || m.keys == nil || m.identity.Domain == "" {
		return NewArgumentError("dnsid: local identity and KeyProvider are required", nil)
	}
	return nil
}

// Domain returns this manager's local DNSid identity domain, or an empty
// string when the manager was constructed for verify-only use.
func (m *IdentityManager) Domain() string {
	if m == nil {
		return ""
	}
	return m.identity.Domain
}

// KeyProvider returns this manager's local signing key provider, or nil for verify-only managers.
func (m *IdentityManager) KeyProvider() KeyProvider {
	if m == nil {
		return nil
	}
	return m.keys
}

// OperationalKeyURL returns the HTTPS URL where the operational (ku) JWKS
// should be served. This is the ku= value that CreateTXTRecord would produce.
// Draft 01 defines no default path, so an unset KeyURL returns an empty string.
func (m *IdentityManager) OperationalKeyURL() string {
	if m == nil || m.identity.Domain == "" {
		return ""
	}
	return m.identity.KeyURL
}

// EntityKeyURL returns the HTTPS URL where the draft 01 entity (ek) JWKS should
// be served. It returns an empty string when no entity KeyProvider is
// configured. Draft 01 defines no default path, so an unset EntityKeyURL returns
// an empty string.
func (m *IdentityManager) EntityKeyURL() string {
	if m == nil || m.entityKeys == nil {
		return ""
	}
	return m.identity.EntityKeyURL
}

// NewIdentityManager constructs the DNSid SDK facade. A nil cfg.Identity with
// a nil KeyProvider yields a verification-only manager. A non-nil cfg.Identity
// requires a KeyProvider and enables acting as the configured local identity
// (record creation, JWKS publication, lifecycle events). Configuration is
// validated and snapshotted before any network work; it returns an
// *ArgumentError for invalid configuration, a KeyProvider or entity
// KeyProvider without identity, identity without a KeyProvider, or Config.Transport settings whose only
// SDK-managed consumers were all injected.
func NewIdentityManager(cfg Config, kp KeyProvider, opts ...IdentityManagerOption) (*IdentityManager, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	var identity IdentityConfig
	switch {
	case cfg.Identity != nil && kp == nil:
		return nil, NewArgumentError("dnsid: KeyProvider is required when Config.Identity is set", nil)
	case cfg.Identity == nil && kp != nil:
		return nil, NewArgumentError("dnsid: Config.Identity is required when a KeyProvider is supplied", nil)
	case cfg.Identity != nil:
		identity = *cfg.Identity
		identity.Domain, _ = NormalizeFQDN(identity.Domain) // validated above
		identity.PolicyFlags = append([]PolicyFlag(nil), identity.PolicyFlags...)
	}
	m := &IdentityManager{identity: identity, verification: cfg.Verification.snapshot(), transport: cfg.Transport.snapshot(), keys: kp, cache: NewIdentityCache(5 * time.Minute)}
	for _, opt := range opts {
		opt(m)
	}
	if m.initErr != nil {
		return nil, m.initErr
	}
	if cfg.Identity == nil && m.entityKeys != nil {
		return nil, NewArgumentError("dnsid: Config.Identity is required when an entity KeyProvider is supplied", nil)
	}
	if err := m.applyTransportDefaults(); err != nil {
		return nil, err
	}
	return m, nil
}

// applyTransportDefaults builds the SDK-managed resolver and fetcher for any
// consumer the caller did not inject, applying Config.Transport to them. A
// transport setting with no remaining SDK-managed consumer is rejected.
func (m *IdentityManager) applyTransportDefaults() error {
	cfg := m.transport
	if err := cfg.validate(); err != nil {
		return err
	}
	if cfg.DNSServer != "" && m.dnsInjected && m.httpsInjected {
		return NewArgumentError("dnsid: Config.Transport.DNSServer has no SDK-managed consumer: both DNSResolver and HTTPSFetcher are injected", nil)
	}
	if cfg.CABundlePath != "" && m.httpsInjected {
		return NewArgumentError("dnsid: Config.Transport.CABundlePath has no SDK-managed consumer: HTTPSFetcher is injected", nil)
	}
	if len(cfg.PrivateAddressHosts) > 0 && m.httpsInjected {
		return NewArgumentError("dnsid: Config.Transport.PrivateAddressHosts has no SDK-managed consumer: HTTPSFetcher is injected", nil)
	}
	if !m.dnsInjected {
		if cfg.DNSServer != "" {
			m.dns = customDNSServerResolver{server: cfg.DNSServer}
		} else {
			m.dns = netDNSResolver{}
		}
	}
	if !m.httpsInjected {
		client, err := httpClientWithTransportConfig(cfg)
		if err != nil {
			return err
		}
		m.https = defaultHTTPSFetcher{client: client}
	}
	return nil
}

// NewVerifier constructs an IdentityManager for verification without local
// identity configuration or key material. It is shorthand for
// NewIdentityManager with a zero Config and nil KeyProvider; pass a Config with
// nil Identity to NewIdentityManager to set verification or transport settings.
func NewVerifier(opts ...IdentityManagerOption) (*IdentityManager, error) {
	return NewIdentityManager(Config{}, nil, opts...)
}

// GetKeySet returns the current active operational (ku) public signing key for
// publication. Draft 01 live endpoints expose exactly one current key.
func (m *IdentityManager) GetKeySet() *JWKS {
	set := jwk.NewSet()
	if m == nil || m.keys == nil {
		return NewJWKS(set)
	}
	if key := m.keys.JWK(); publicationJWKValid(key) {
		_ = set.AddKey(key)
	}
	return NewJWKS(set)
}

// GetEntityKeySet returns the current active entity (ek) public signing key for
// publication. Draft 01 live endpoints expose exactly one current key. It returns
// nil when no entity KeyProvider is configured.
func (m *IdentityManager) GetEntityKeySet() *JWKS {
	if m == nil || m.entityKeys == nil {
		return nil
	}
	set := jwk.NewSet()
	if key := m.entityKeys.JWK(); publicationJWKValid(key) {
		_ = set.AddKey(key)
	}
	return NewJWKS(set)
}

func publicationJWKValid(key jwk.Key) bool {
	if key == nil || !isSigningKey(key) {
		return false
	}
	if _, ok := algForJWK(key); !ok {
		return false
	}
	if err := validateJWKAlgConsistency(key); err != nil {
		return false
	}
	if kid, ok := key.KeyID(); !ok || kid == "" {
		return false
	}
	return true
}

// BuildUnsignedTXTRecord builds and validates this identity's unsigned _dnsid
// TXT record. The returned record is ready for its entity-key signature.
func (m *IdentityManager) BuildUnsignedTXTRecord() (*TXTRecord, error) {
	if err := m.requireLocalIdentity(); err != nil {
		return nil, err
	}
	if m.identity.PublishProfile != "" && m.identity.PublishProfile != DefaultPublishProfile {
		return nil, NewArgumentError(fmt.Sprintf("dnsid: unsupported publish profile %q", m.identity.PublishProfile), nil)
	}
	if err := validatePublicationConfig(m.identity, m.keys, m.entityKeys); err != nil {
		return nil, err
	}

	profile := m.identity.PublishProfile
	if profile == "" {
		profile = DefaultPublishProfile
	}
	rec := &TXTRecord{Version: profile, GovernanceID: m.identity.GovernanceID, EntityKeyURI: m.identity.EntityKeyURL, KeyURI: m.identity.KeyURL, LogRef: m.identity.LogRef, StatusURI: m.identity.StatusURL, KeyAge: string(m.identity.MaxKeyAge), Capabilities: m.identity.CapabilitiesURL}
	if len(m.identity.PolicyFlags) > 0 {
		rec.Flags = make([]string, len(m.identity.PolicyFlags))
		for i, f := range m.identity.PolicyFlags {
			rec.Flags[i] = string(f)
		}
	}
	if err := rec.validateUnsigned(m.identity.Domain); err != nil {
		return nil, NewArgumentError("dnsid: generated record fails validation", err)
	}
	return rec, nil
}

// CreateTXTRecord builds and signs this identity's _dnsid TXT record with the
// entity key.
func (m *IdentityManager) CreateTXTRecord() (*TXTRecord, error) {
	rec, err := m.BuildUnsignedTXTRecord()
	if err != nil {
		return nil, err
	}
	if _, err := signRecordWithKeyProvider(rec, m.entityKeys); err != nil {
		return nil, err
	}
	return rec, nil
}

func validatePublicationConfig(cfg IdentityConfig, operationalKeys, entityKeys KeyProvider) error {
	if entityKeys == nil {
		return NewArgumentError("dnsid: draft 01 publishing requires an entity KeyProvider", nil)
	}
	if cfg.KeyURL == "" || cfg.EntityKeyURL == "" {
		return NewArgumentError("dnsid: draft 01 publishing requires KeyURL and EntityKeyURL", nil)
	}
	if !isDomainName(cfg.GovernanceID) {
		return NewArgumentError(fmt.Sprintf("dnsid: draft 01 requires IdentityConfig.GovernanceID to be a domain name, got %q", cfg.GovernanceID), nil)
	}
	giDomain, err := NormalizeFQDN(cfg.GovernanceID)
	if err != nil {
		return NewArgumentError("dnsid: invalid IdentityConfig.GovernanceID", err)
	}
	if cfg.GovernanceID != giDomain {
		return NewArgumentError(fmt.Sprintf("dnsid: IdentityConfig.GovernanceID must be lowercase ASCII in A-label form, got %q", cfg.GovernanceID), nil)
	}
	ekURL, err := url.Parse(cfg.EntityKeyURL)
	if err != nil {
		return NewArgumentError("dnsid: invalid IdentityConfig.EntityKeyURL", err)
	}
	ekHost, err := NormalizeFQDN(ekURL.Hostname())
	if err != nil || !isDomainOrSubdomain(ekHost, giDomain) {
		return NewArgumentError(fmt.Sprintf("dnsid: IdentityConfig.EntityKeyURL host %q must be at or under GovernanceID domain %q", ekURL.Hostname(), giDomain), err)
	}
	if err := validateDraft01PublishingKey(operationalKeys, "operational"); err != nil {
		return err
	}
	if err := validateDraft01PublishingKey(entityKeys, "entity"); err != nil {
		return err
	}
	return ensureDistinctActiveKeys(entityKeys, operationalKeys)
}

func validateDraft01PublishingKey(kp KeyProvider, role string) error {
	if kp == nil || kp.JWK() == nil {
		return NewArgumentError(fmt.Sprintf("dnsid: draft 01 %s KeyProvider has no active key", role), nil)
	}
	key := kp.JWK()
	if kid, ok := key.KeyID(); !ok || kid == "" {
		return NewArgumentError(fmt.Sprintf("dnsid: draft 01 %s key must include kid", role), nil)
	}
	alg, ok := jwkAlg(key)
	if !ok || !alg.Valid() {
		return NewArgumentError(fmt.Sprintf("dnsid: draft 01 %s key must include alg", role), nil)
	}
	if inferred, supported := algForJWK(key); !supported || inferred != alg {
		return NewArgumentError(fmt.Sprintf("dnsid: draft 01 %s key alg is inconsistent with key type", role), nil)
	}
	return nil
}

func ensureDistinctActiveKeys(entity, operational KeyProvider) error {
	if entity == nil || operational == nil {
		return NewArgumentError("dnsid: entity and operational KeyProviders are required", nil)
	}
	entityKey := entity.JWK()
	if entityKey == nil {
		return NewArgumentError("dnsid: entity KeyProvider has no active key", nil)
	}
	operationalKey := operational.JWK()
	if operationalKey == nil {
		return NewArgumentError("dnsid: operational KeyProvider has no active key", nil)
	}
	entityThumbprint, err := (&JWK{key: entityKey}).Thumbprint()
	if err != nil {
		return NewArgumentError("dnsid: entity key thumbprint", err)
	}
	operationalThumbprint, err := (&JWK{key: operationalKey}).Thumbprint()
	if err != nil {
		return NewArgumentError("dnsid: operational key thumbprint", err)
	}
	if entityThumbprint == operationalThumbprint {
		return NewArgumentError(fmt.Sprintf("dnsid: entity key and operational key must be distinct (same thumbprint %q)", entityThumbprint), nil)
	}
	return nil
}

// VerifyDomain performs core DNSid trust establishment for a peer domain: it
// resolves the domain's _dnsid TXT record, verifies the record signature
// against the entity (ek) JWKS, fetches the runtime (ku) JWKS, checks
// lifecycle evidence through the log bound by lr=, and requires the su=
// status endpoint to report ACTIVE. Records with
// fl=logchk expose that policy through VerifiedDomain.RequiresLogCheck; callers
// decide which operations require fresh evidence through VerifyLogEvidence.
// Results are served from the manager's cache until they expire.
//
// The default DNSSECModeAuto accepts the built-in resolver's UNKNOWN DNSSEC
// state; stricter DNSSECModeValidated and DNSSECModeRequired deployments need
// a DNSSEC-aware resolver injected via WithDNSResolver. Failures are reported
// as *VerificationError; check Code and Transient to classify them. It is
// shorthand for VerifyDomainWithOptions with zero options.
func (m *IdentityManager) VerifyDomain(ctx context.Context, domain string) (*VerifiedDomain, error) {
	return m.VerifyDomainWithOptions(ctx, domain, VerifyDomainOpts{})
}

var _ IdentityResolver = (*IdentityManager)(nil)

// VerifyDomainWithOptions performs core DNSid trust establishment with optional
// peer inputs, then enforces any configured VerificationConfig.TrustedEntities
// acceptance policy. Acceptance runs on every successful path, including cache
// hits; verified protocol evidence is cached before acceptance, and denials are
// never cached. A denial is reported as a permanent
// VerificationCodeCounterpartyNotAccepted error.
func (m *IdentityManager) VerifyDomainWithOptions(ctx context.Context, domain string, opts VerifyDomainOpts) (*VerifiedDomain, error) {
	return m.verifyDomain(ctx, domain, opts, true)
}

// verifyDomain is the shared per-invocation verification boundary. Only the
// internal registry publication confirmation path passes acceptance=false;
// there is no public bypass.
func (m *IdentityManager) verifyDomain(ctx context.Context, domain string, opts VerifyDomainOpts, acceptance bool) (result *VerifiedDomain, err error) {
	ctx, cancel := VerificationContext(ctx)
	defer cancel()
	defer func() {
		if err == nil {
			err = ctx.Err()
		}
		if err == nil && acceptance {
			err = m.enforceCounterpartyAcceptance(result)
		}
		if err == nil {
			err = m.requireFreshIdentityEvidence(result, result.cachedState == "fresh")
		}
		if err != nil {
			result = nil
		}
	}()
	if m == nil {
		return nil, NewArgumentError("dnsid: IdentityManager is required", nil)
	}
	normalized, err := NormalizeFQDN(domain)
	if err != nil {
		return nil, NewArgumentError("dnsid: invalid domain", err)
	}
	if vd := m.cachedDomain(normalized); vd != nil {
		return m.verifyCachedDomain(ctx, normalized, opts, vd)
	}
	vd, err := m.coalesceVerification(ctx, normalized, false, func(sharedCtx context.Context) (*VerifiedDomain, error) {
		return m.verifyReusableDomain(sharedCtx, normalized)
	})
	if err != nil {
		return nil, err
	}
	// The cache may have filled between the initial lookup and joining the
	// coordinator. Treat that result as a cache hit, including status refresh.
	if vd.cachedState == "cached" {
		return m.verifyCachedDomain(ctx, normalized, opts, vd)
	}
	if err := m.enforcePerCallPolicy(vd.record, normalized, opts); err != nil {
		return nil, err
	}
	return vd, nil
}

// enforceCounterpartyAcceptance applies the configured allowlist and pins to
// already-verified protocol evidence. A nil allowlist makes no decision. It
// performs no network work and never mutates or caches its result.
func (m *IdentityManager) enforceCounterpartyAcceptance(vd *VerifiedDomain) error {
	if m.verification.TrustedEntities == nil {
		return nil
	}
	if vd == nil || vd.record == nil {
		return NewVerificationError(VerificationCodeCounterpartyNotAccepted, false, "dnsid: counterparty not accepted: no verified record", nil)
	}
	gi, thumbprint := vd.record.GovernanceID, vd.signingKeyThumbprint
	deny := func(reason string) error {
		return NewVerificationError(VerificationCodeCounterpartyNotAccepted, false,
			fmt.Sprintf("dnsid: counterparty not accepted: %s (gi=%q, entity key thumbprint=%q)", reason, gi, thumbprint), nil,
			WithVerifiedIdentity(gi, thumbprint))
	}
	for _, e := range m.verification.TrustedEntities {
		if e.GovernanceID != gi {
			continue
		}
		if e.EntityKeyThumbprints == nil {
			return nil
		}
		for _, pin := range e.EntityKeyThumbprints {
			if pin == thumbprint && thumbprint != "" {
				return nil
			}
		}
		return deny("entity key does not match a configured pin")
	}
	return deny("governance ID is not in the configured allowlist")
}

func (m *IdentityManager) verifyCachedDomain(ctx context.Context, domain string, opts VerifyDomainOpts, vd *VerifiedDomain) (*VerifiedDomain, error) {
	if err := m.enforcePerCallPolicy(vd.record, domain, opts); err != nil {
		return nil, err
	}
	return m.refreshCachedStatusIfNeeded(ctx, vd)
}

func (m *IdentityManager) verifyReusableDomain(ctx context.Context, normalized string) (*VerifiedDomain, error) {
	if vd := m.cachedDomain(normalized); vd != nil {
		return vd, nil
	}
	name := "_dnsid." + normalized
	dnsAcquiredAt := time.Now() // Lookup start is conservative even for injected resolvers.
	rdatas, dnssec, err := m.dns.FetchTXT(ctx, name)
	if err != nil {
		return nil, NewVerificationError(VerificationCodeDNSResolution, true, fmt.Sprintf("dnsid: DNS lookup failed for %s", name), err)
	}
	if err := m.enforceDNSSECPolicy(dnssec); err != nil {
		return nil, err
	}
	if len(rdatas) == 0 {
		return nil, NewVerificationError(VerificationCodeRecordInvalid, false, fmt.Sprintf("dnsid: _dnsid TXT record not found at %s", name), nil)
	}
	if len(rdatas) > 1 {
		return nil, NewVerificationError(VerificationCodeRecordInvalid, false, fmt.Sprintf("dnsid: multiple _dnsid TXT records at %s (expected exactly one)", name), nil)
	}
	if rdatas[0].TTL < 0 || len(rdatas[0].Value) > 65535 {
		return nil, NewVerificationError(VerificationCodeDNSResolution, false, "dnsid: invalid DNS TTL or oversized TXT response", nil)
	}
	rec, err := ParseTXTRecord(rdatas[0].Value)
	if err != nil {
		return nil, NewVerificationError(VerificationCodeRecordInvalid, false,
			fmt.Sprintf("dnsid: invalid _dnsid TXT record at %s", name), err)
	}
	if err := rec.Validate(normalized); err != nil {
		cause := err
		var validationErr *ValidationError
		if !errors.As(err, &validationErr) {
			cause = NewValidationError("dnsid: TXT record validation failed", err)
		}
		return nil, NewVerificationError(VerificationCodeRecordInvalid, false,
			"dnsid: invalid _dnsid TXT record semantics", cause)
	}
	// The entity JWKS verifies the record signature; ku is operational only.
	set, jwksCert, err := m.fetchJWKS(ctx, rec.EntityKeyURI, rec.GovernanceID, true)
	if err != nil {
		return nil, jwksVerificationError(fmt.Sprintf("dnsid: fetching JWKS for %s", normalized), err)
	}
	if _, err := singleDraft01SigningKey(set); err != nil {
		return nil, NewVerificationError(VerificationCodeRecordInvalid, false,
			fmt.Sprintf("dnsid: ek endpoint must serve exactly one current usable key: %v", err), nil)
	}
	signingKey, err := verifiedRecordSigningKey(rec, set)
	if err != nil {
		return nil, err
	}
	signingJWK := &JWK{key: signingKey}
	signingKeyThumbprint, err := signingJWK.Thumbprint()
	if err != nil {
		return nil, NewVerificationError(VerificationCodeRecordInvalid, false, "dnsid: record signing key thumbprint failed", err)
	}
	type identityResult struct {
		vd  *VerifiedDomain
		err error
	}
	type statusResult struct {
		status *AgentStatus
		cert   *tls.Certificate
		err    error
	}
	workCtx := ctx
	if workCtx == nil {
		workCtx = context.Background()
	}
	workCtx, cancel := context.WithCancel(workCtx)
	defer cancel()
	identityResults := make(chan identityResult, 1)
	statusResults := make(chan statusResult, 1)
	go func() {
		kuSet, runtimeCert, err := m.fetchJWKSForDomain(workCtx, rec.KeyURI, normalized)
		if err != nil {
			identityResults <- identityResult{err: jwksVerificationError(fmt.Sprintf("dnsid: fetching ku JWKS for %s", normalized), err)}
			return
		}
		kuOpKey, err := singleDraft01SigningKey(kuSet)
		if err != nil {
			identityResults <- identityResult{err: NewVerificationError(VerificationCodeRecordInvalid, false,
				fmt.Sprintf("dnsid: ku endpoint must serve exactly one current key: %v", err), nil)}
			return
		}
		operationalKeyThumbprint, err := (&JWK{key: kuOpKey}).Thumbprint()
		if err != nil {
			identityResults <- identityResult{err: NewVerificationError(VerificationCodeRecordInvalid, false, "dnsid: ku key thumbprint failed", err)}
			return
		}
		if err := rejectIfEKKUCollide(signingKeyThumbprint, operationalKeyThumbprint); err != nil {
			identityResults <- identityResult{err: err}
			return
		}
		vd := &VerifiedDomain{domain: normalized, record: rec, keySet: NewJWKS(kuSet), recordSigningKeySet: NewJWKS(set), signingKey: signingJWK, signingKeyThumbprint: signingKeyThumbprint, dnssecState: dnssec, dnsTTL: rdatas[0].TTL, jwksTLSCertificate: runtimeCert, ekTLSCertificate: jwksCert, operationalKeyThumbprint: operationalKeyThumbprint, kuKey: kuOpKey}
		if err := m.enforceRecordPolicy(workCtx, rec, normalized, signingKeyThumbprint, operationalKeyThumbprint, vd); err != nil {
			identityResults <- identityResult{err: err}
			return
		}
		identityResults <- identityResult{vd: vd}
	}()
	go func() {
		status, cert, err := m.fetchAgentStatus(workCtx, rec.StatusURI)
		statusResults <- statusResult{status: status, cert: cert, err: err}
	}()

	var identity identityResult
	var statusCheck statusResult
	for identityResults != nil || statusResults != nil {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case identity = <-identityResults:
			identityResults = nil
			if identity.err != nil {
				cancel()
			}
		case statusCheck = <-statusResults:
			statusResults = nil
			if statusCheck.err != nil {
				cancel()
			}
		}
	}
	// Preserve the pre-concurrency identity/policy error precedence without
	// letting a sibling's cancellation mask the failure that caused it.
	if identity.err != nil && !errors.Is(identity.err, context.Canceled) {
		return nil, identity.err
	}
	if statusCheck.err != nil && !errors.Is(statusCheck.err, context.Canceled) {
		return nil, statusCheck.err
	}
	if identity.err != nil {
		return nil, identity.err
	}
	if statusCheck.err != nil {
		return nil, statusCheck.err
	}
	vd := identity.vd
	status, statusCert := statusCheck.status, statusCheck.cert
	now := time.Now()
	vd.status = status
	vd.verifiedAt = now
	vd.lastStatusCheckAt = now
	vd.statusTLSCertificate = statusCert
	vd.dnsExpiresAt = dnsAcquiredAt.Add(rdatas[0].TTL)
	vd.expiry = verifiedDomainExpiry(dnsAcquiredAt, rdatas[0].TTL, rec.KeyAge, vd.keyBoundAt, vd.jwksTLSCertificate, jwksCert)
	vd.cachedState = "fresh"
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := m.requireFreshIdentityEvidence(vd, true); err != nil {
		return nil, err
	}
	m.cache.put(vd, m)
	return vd, nil
}

func (m *IdentityManager) coalesceVerification(ctx context.Context, domain string, refresh bool, work func(context.Context) (*VerifiedDomain, error)) (*VerifiedDomain, error) {
	if ctx == nil {
		return work(ctx)
	}
	m.inFlightMu.Lock()
	calls := m.verifying
	if refresh {
		calls = m.refreshing
	}
	if calls == nil {
		calls = make(map[string]*inFlightVerification)
		if refresh {
			m.refreshing = calls
		} else {
			m.verifying = calls
		}
	}
	call := calls[domain]
	if call == nil {
		sharedCtx, cancel := VerificationContext(context.WithoutCancel(ctx))
		call = &inFlightVerification{done: make(chan struct{}), cancel: cancel}
		calls[domain] = call
		go func() {
			result, err := work(sharedCtx)
			cancel()

			m.inFlightMu.Lock()
			call.result, call.err = result, err
			if calls[domain] == call {
				delete(calls, domain)
			}
			close(call.done)
			m.inFlightMu.Unlock()
		}()
	}
	call.waiters++
	m.inFlightMu.Unlock()
	if m.inFlightHook != nil {
		m.inFlightHook(domain, refresh)
	}

	select {
	case <-call.done:
		return cloneVerifiedDomain(call.result), call.err
	case <-ctx.Done():
		m.inFlightMu.Lock()
		if calls[domain] == call {
			call.waiters--
			if call.waiters == 0 {
				delete(calls, domain)
				call.cancel()
			}
		}
		m.inFlightMu.Unlock()
		return nil, ctx.Err()
	}
}

// rejectIfEKKUCollide enforces the spec's Two-Key Separation rule: a verifier
// MUST reject a record whose ek (record-signing) and ku (operational) keys share
// the same RFC 7638 JWK Thumbprint. This holds unconditionally for every two-key
// profile, even when the DNSid is self-accounted.
func rejectIfEKKUCollide(ekThumbprint, kuThumbprint string) error {
	if ekThumbprint == kuThumbprint {
		return NewVerificationError(VerificationCodeRecordInvalid, false,
			"dnsid: ek and ku keys must be distinct key material (RFC 7638 thumbprints match)", nil)
	}
	return nil
}

func (m *IdentityManager) enforceDNSSECPolicy(state DNSSECState) error {
	if state == "" {
		state = DNSSECStateUnknown
	}
	switch state {
	case DNSSECStateValid, DNSSECStateUnsigned, DNSSECStateUnknown, DNSSECStateFailed:
	default:
		return NewVerificationError(VerificationCodeDNSSECFailed, false,
			fmt.Sprintf("dnsid: resolver reported invalid DNSSEC state %q", state), nil)
	}
	if state == DNSSECStateFailed {
		return NewVerificationError(VerificationCodeDNSSECFailed, false,
			"dnsid: DNSSEC validation failed", nil)
	}
	mode := m.verification.DNSSECMode
	if mode == "" {
		mode = DNSSECModeAuto
	}
	switch mode {
	case DNSSECModeAuto:
		return nil
	case DNSSECModeValidated:
		if state == DNSSECStateUnknown {
			return NewVerificationError(VerificationCodeDNSSECFailed, false,
				"dnsid: DNSSEC validation state is required but resolver reported UNKNOWN", nil)
		}
		return nil
	case DNSSECModeRequired:
		if state != DNSSECStateValid {
			return NewVerificationError(VerificationCodeDNSSECFailed, false,
				fmt.Sprintf("dnsid: DNSSEC required but resolver state is %s", state), nil)
		}
		return nil
	default:
		return NewVerificationError(VerificationCodeDNSSECFailed, false,
			fmt.Sprintf("dnsid: unsupported DNSSEC mode %q", mode), nil)
	}
}

func (m *IdentityManager) enforceRecordPolicy(ctx context.Context, rec *TXTRecord, domain, signingKeyThumbprint, operationalKeyThumbprint string, vd *VerifiedDomain) error {
	reader, err := m.logReaderFor(rec.LogRef)
	if err != nil {
		return err
	}
	if vd != nil {
		vd.logReader = reader
	}
	govID := rec.GovernanceID
	// A delegated governance domain requires an ISSUANCE evidence binding.
	giDomain, _ := NormalizeFQDN(govID)
	if giDomain != "" && !isDomainOrSubdomain(domain, giDomain) {
		verifier, ok := reader.(interface {
			VerifyGovernanceRelationship(context.Context, string, string) error
		})
		if !ok {
			return NewVerificationError(VerificationCodeLogError, false, "dnsid: delegated governance requires log relationship verification", nil)
		}
		if err := verifier.VerifyGovernanceRelationship(ctx, domain, govID); err != nil {
			return logVerificationError(err)
		}
	}
	if rec.KeyAge != "" {
		// ka is tied to the operational (ku) key, not the ek record-signing key.
		kaThumbprint := operationalKeyThumbprint
		if kaThumbprint == "" {
			kaThumbprint = signingKeyThumbprint
		}
		keyBoundAt, err := reader.KeyTimestamp(ctx, domain, kaThumbprint)
		if err != nil {
			return logVerificationError(err)
		}
		if vd != nil {
			vd.keyBoundAt = keyBoundAt
		}
		maxAge, err := parseKeyAgeDuration(rec.KeyAge)
		if err != nil {
			return NewVerificationError(VerificationCodeRecordInvalid, false, "dnsid: invalid ka value", err)
		}
		if time.Since(keyBoundAt) > maxAge {
			return NewVerificationError(VerificationCodeKeyAgeExceeded, false,
				fmt.Sprintf("dnsid: signing key exceeds maximum key age %s", rec.KeyAge), nil)
		}
	}
	if vd == nil || vd.signingKey == nil {
		return NewVerificationError(VerificationCodeLogError, false, "dnsid: verified record key is unavailable for lifecycle binding", nil)
	}
	bindingInput := dnsidlog.BilateralBindingInput{
		Domain:         domain,
		GovernanceID:   govID,
		EntityKey:      vd.signingKey.key,
		OperationalKey: vd.kuKey,
	}
	if verifier, ok := reader.(dnsidlog.LifecycleBindingVerifier); ok {
		if _, err := verifier.VerifyLifecycleBinding(ctx, bindingInput, operationalKeyThumbprint); err != nil {
			return logVerificationError(err)
		}
	} else {
		binding, err := reader.VerifyBilateralBinding(ctx, bindingInput)
		if err != nil {
			return logVerificationError(err)
		}
		if err := reader.VerifyOperationalContinuity(ctx, domain, binding.InitialOperationalThumbprint, operationalKeyThumbprint); err != nil {
			return logVerificationError(err)
		}
	}
	return nil
}

// enforcePerCallPolicy applies connection-specific policy even when core
// identity evidence came from the cache. Operation-level log checking remains
// caller policy through VerifyLogEvidence.
func (m *IdentityManager) enforcePerCallPolicy(rec *TXTRecord, domain string, opts VerifyDomainOpts) error {
	if hasPolicyFlag(rec, PolicyFlagMTLS) {
		return verifyMTLSPeerChains(domain, opts.VerifiedPeerCertificateChains)
	}
	return nil
}

func hasPolicyFlag(rec *TXTRecord, want PolicyFlag) bool {
	if rec == nil {
		return false
	}
	for _, flag := range rec.Flags {
		if strings.TrimSpace(flag) == string(want) {
			return true
		}
	}
	return false
}

func verifyMTLSPeerChains(domain string, chains [][]*x509.Certificate) error {
	if len(chains) == 0 {
		return NewVerificationError(VerificationCodeTLSError, false,
			"dnsid: fl=mtls requires an already-verified peer certificate chain", nil)
	}
	for _, chain := range chains {
		if len(chain) == 0 || chain[0] == nil {
			continue
		}
		if err := chain[0].VerifyHostname(domain); err != nil {
			continue
		}
		return nil
	}
	return NewVerificationError(VerificationCodeTLSError, false,
		fmt.Sprintf("dnsid: verified peer certificate chain is not valid for %s", domain), nil)
}

func (m *IdentityManager) fetchJWKSForDomain(ctx context.Context, keyURL, domain string) (jwk.Set, *tls.Certificate, error) {
	return m.fetchJWKS(ctx, keyURL, domain, false)
}

func (m *IdentityManager) fetchJWKS(ctx context.Context, keyURL, domain string, domainBoundary bool) (jwk.Set, *tls.Certificate, error) {
	msg, cert, err := m.https.FetchJSON(ctx, keyURL, FetchOptions{AllowedHost: domain, DomainBoundary: domainBoundary, MaxResponseBytes: 1 << 20, RedirectPolicy: RedirectPolicySameHost})
	if err != nil {
		return nil, nil, err
	}
	set, err := ParseJWKSet(msg)
	if err != nil {
		return nil, nil, err
	}
	return set, cert, nil
}

func jwksVerificationError(message string, err error) error {
	var parseErr *ParseError
	var validationErr *ValidationError
	if errors.As(err, &parseErr) || errors.As(err, &validationErr) {
		return NewVerificationError(VerificationCodeRecordInvalid, false, message, err)
	}
	if isTLSError(err) {
		return NewVerificationError(VerificationCodeTLSError, false, message, err)
	}
	return NewVerificationError(VerificationCodeJWKSUnavailable, fetchErrorTransient(err), message, err)
}

func fetchErrorTransient(err error) bool {
	var statusErr *httpStatusError
	if errors.As(err, &statusErr) {
		return statusErr.statusCode >= http.StatusInternalServerError && statusErr.statusCode <= 599
	}
	return true
}

func (m *IdentityManager) refreshCachedStatusIfNeeded(ctx context.Context, vd *VerifiedDomain) (*VerifiedDomain, error) {
	if !m.cachedStatusNeedsRefresh(vd) {
		return vd, nil
	}
	domain, err := NormalizeFQDN(vd.domain)
	if err != nil {
		return nil, NewArgumentError("dnsid: invalid cached domain", err)
	}
	return m.coalesceVerification(ctx, domain, true, func(sharedCtx context.Context) (*VerifiedDomain, error) {
		base := vd
		if current := m.cachedDomain(domain); current != nil {
			base = current
			if m.verification.StatusCheckInterval > 0 && !m.cachedStatusNeedsRefresh(current) {
				return current, nil
			}
		}
		status, statusCert, err := m.fetchAgentStatus(sharedCtx, base.record.StatusURI)
		if err != nil {
			var verificationErr *VerificationError
			if errors.As(err, &verificationErr) && verificationErr.Code() == VerificationCodeStatusNotActive {
				m.cache.evict(domain, m)
			}
			return nil, err
		}
		now := time.Now()
		updated := *base
		updated.status = status
		updated.statusTLSCertificate = statusCert
		updated.lastStatusCheckAt = now
		updated.cachedState = "refreshed"
		if err := sharedCtx.Err(); err != nil {
			return nil, err
		}
		if err := m.requireFreshIdentityEvidence(&updated, false); err != nil {
			return nil, err
		}
		m.cache.put(&updated, m)
		return &updated, nil
	})
}

func (m *IdentityManager) cachedStatusNeedsRefresh(vd *VerifiedDomain) bool {
	if vd == nil || vd.record == nil {
		return false
	}
	interval := m.verification.StatusCheckInterval
	return vd.status == nil || interval <= 0 || vd.lastStatusCheckAt.IsZero() || time.Since(vd.lastStatusCheckAt) >= interval
}

func (m *IdentityManager) fetchAgentStatus(ctx context.Context, statusURL string) (*AgentStatus, *tls.Certificate, error) {
	msg, cert, err := m.https.FetchJSON(ctx, statusURL, FetchOptions{AllowedHost: allowedHostFromURL(statusURL), MaxResponseBytes: 64 << 10, RedirectPolicy: RedirectPolicyHTTPS})
	if err != nil {
		if isTLSError(err) {
			return nil, nil, NewVerificationError(VerificationCodeTLSError, false, "dnsid: fetching agent status", err)
		}
		return nil, nil, NewVerificationError(VerificationCodeStatusUnavailable, fetchErrorTransient(err), "dnsid: fetching agent status", err)
	}
	var status AgentStatus
	if err := json.Unmarshal(msg, &status); err != nil {
		return nil, nil, NewVerificationError(VerificationCodeRecordInvalid, false, "dnsid: parsing agent status", NewParseError("dnsid: invalid agent status JSON", err))
	}
	if err := status.Validate(); err != nil {
		return nil, nil, NewVerificationError(VerificationCodeRecordInvalid, false,
			"dnsid: invalid agent status profile", err)
	}
	state := status.State
	if state != AgentStateActive {
		if status.RevocationReason == "" {
			return nil, nil, NewVerificationError(VerificationCodeStatusNotActive, false, fmt.Sprintf("dnsid: agent status is not %s: %s", AgentStateActive, state), nil, WithAgentState(state))
		}
		return nil, nil, NewVerificationError(VerificationCodeStatusNotActive, false, fmt.Sprintf("dnsid: agent status is not %s: %s (%s)", AgentStateActive, state, status.RevocationReason), nil, WithAgentState(state))
	}
	// lastTransitionAt describes when the state changed, not when this response
	// was generated or fetched. It may legitimately be very old for a stable
	// ACTIVE identity, but it cannot describe a transition in the future.
	if status.LastTransitionAt.After(time.Now()) {
		return nil, nil, NewVerificationError(VerificationCodeStatusNotActive, false,
			fmt.Sprintf("dnsid: agent status lastTransitionAt %s is in the future", status.LastTransitionAt.Format(time.RFC3339)), nil)
	}
	return &status, cert, nil
}

// EvictDomain removes a domain's entry from the verified-domain cache so the
// next VerifyDomain call performs a full re-verification. Domains that fail
// normalization are ignored.
func (m *IdentityManager) EvictDomain(domain string) {
	if d, err := NormalizeFQDN(domain); err == nil {
		m.cache.evict(d, m)
	}
}

func validateHTTPSURL(raw, field string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" {
		return NewValidationError(fmt.Sprintf("dnsid: %s must be an HTTPS URL", field), err)
	}
	return nil
}

func validateManagerFetchURL(raw, allowedHost string, domainBoundary bool) error {
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("%w: invalid URL: %w", errTLSPolicy, err)
	}
	if u.Scheme != "https" {
		return fmt.Errorf("%w: URL must use https", errTLSPolicy)
	}
	if u.User != nil {
		return fmt.Errorf("%w: URL must not include userinfo", errTLSPolicy)
	}
	if u.Fragment != "" || u.RawFragment != "" {
		return fmt.Errorf("%w: URL must not include a fragment", errTLSPolicy)
	}
	if allowedHost != "" && !fetchHostAllowed(u.Hostname(), allowedHost, domainBoundary) {
		return fmt.Errorf("%w: URL host %q does not match allowed host %q", errTLSPolicy, u.Hostname(), allowedHost)
	}
	return nil
}

func fetchHostAllowed(host, allowed string, domainBoundary bool) bool {
	host, allowed = strings.ToLower(host), strings.ToLower(allowed)
	return host == allowed || domainBoundary && strings.HasSuffix(host, "."+allowed)
}

func isTLSError(err error) bool {
	if errors.Is(err, errTLSPolicy) {
		return true
	}
	var certificateErr *tls.CertificateVerificationError
	return errors.As(err, &certificateErr)
}

func parseKeyAgeDuration(value string) (time.Duration, error) {
	switch value {
	case "24h":
		return 24 * time.Hour, nil
	case "7d":
		return 7 * 24 * time.Hour, nil
	case "30d":
		return 30 * 24 * time.Hour, nil
	case "90d":
		return 90 * 24 * time.Hour, nil
	default:
		return 0, fmt.Errorf("dnsid: invalid key age %q", value)
	}
}

func isDomainName(value string) bool {
	if value == "" || strings.Contains(value, ":") || strings.Contains(value, "/") {
		return false
	}
	return hostnameRegex.MatchString(value)
}

func allowedHostFromURL(raw string) string {
	u, _ := url.Parse(raw)
	if u == nil {
		return ""
	}
	return u.Hostname()
}

func resolverForDNSServer(server string) ipResolverFunc {
	if server == "" {
		return nil
	}
	resolver := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			d := net.Dialer{Timeout: 5 * time.Second}
			return d.DialContext(ctx, "udp", server)
		},
	}
	return resolver.LookupIPAddr
}

func httpClientWithTransportConfig(cfg TransportConfig) (*http.Client, error) {
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	var base *http.Client
	if cfg.CABundlePath != "" {
		client, err := httpClientWithCABundle(cfg.CABundlePath)
		if err != nil {
			return nil, err
		}
		base = client
	}
	return newSafeHTTPClientFromWithResolver(base, resolverForDNSServer(cfg.DNSServer), slices.Clone(cfg.PrivateAddressHosts)), nil
}

func httpClientWithCABundle(path string) (*http.Client, error) {
	pem, err := os.ReadFile(path)
	if err != nil {
		return nil, NewParseError(fmt.Sprintf("dnsid: reading CA bundle %q", path), err)
	}
	pool, err := x509.SystemCertPool()
	if err != nil || pool == nil {
		pool = x509.NewCertPool()
	}
	if ok := pool.AppendCertsFromPEM(pem); !ok {
		return nil, NewParseError(fmt.Sprintf("dnsid: CA bundle %q contains no certificates", path), nil)
	}
	base := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool}}}
	return newSafeHTTPClientFrom(base), nil
}
