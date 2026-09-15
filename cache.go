package dnsid

import (
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"sync"
	"time"

	dnsidlog "github.com/dnsid-ai/dnsid-go/log"
	"github.com/lestrrat-go/jwx/v3/jwk"
)

// AgentState is the canonical typed lifecycle state, defined in the log
// package (which this package imports). Re-exported here so callers can use
// dnsid.AgentState without importing the log package directly.
type AgentState = dnsidlog.AgentState

// Typed lifecycle constants for callers that want the AgentState type.
const (
	AgentStatePending      = dnsidlog.AgentStatePending
	AgentStateProvisioning = dnsidlog.AgentStateProvisioning
	AgentStateVerifying    = dnsidlog.AgentStateVerifying
	AgentStateActive       = dnsidlog.AgentStateActive
	AgentStateRetired      = dnsidlog.AgentStateRetired
	AgentStateRevoked      = dnsidlog.AgentStateRevoked
)

// ParseAgentState converts a raw string into the typed AgentState, returning
// an error if the value is not one of the six canonical lifecycle states.
// This allows callers that hold string values (e.g. from JSON or databases)
// to safely convert to the typed constant.
func ParseAgentState(s string) (AgentState, error) {
	return dnsidlog.ParseAgentState(s)
}

// AgentStates returns a copy of the six canonical lifecycle states in order.
func AgentStates() []AgentState {
	return dnsidlog.AgentStates()
}

// AgentStatus is the protocol status document fetched from su=.
type AgentStatus struct {
	State            AgentState `json:"state"`
	LastTransitionAt time.Time  `json:"lastTransitionAt"`
	RevocationReason string     `json:"revocationReason,omitempty"`
}

// Validate checks the status document against the DNSid status profile:
// State must exactly match one of the six canonical lifecycle states,
// LastTransitionAt must be set, and a REVOKED status must carry a valid
// revocation reason. It returns a *ValidationError describing the first
// violation, or nil.
func (s *AgentStatus) Validate() error {
	if s == nil {
		return NewValidationError("dnsid: nil agent status", nil)
	}
	switch s.State {
	case AgentStatePending, AgentStateProvisioning, AgentStateVerifying, AgentStateActive, AgentStateRetired, AgentStateRevoked:
	case "":
		return NewValidationError("dnsid: agent status missing state", nil)
	default:
		return NewValidationError(fmt.Sprintf("dnsid: unknown agent status state %q", s.State), nil)
	}
	if s.LastTransitionAt.IsZero() {
		return NewValidationError("dnsid: agent status missing lastTransitionAt", nil)
	}
	if s.State == AgentStateRevoked && !dnsidlog.ValidRevocationReason(s.RevocationReason) {
		return NewValidationError("dnsid: valid revocationReason is required when state is REVOKED", nil)
	}
	return nil
}

// VerifiedDomain is the result of successful DNSid domain verification.
type VerifiedDomain struct {
	domain              string
	record              *TXTRecord
	keySet              *JWKS
	recordSigningKeySet *JWKS
	// kuKey is the current ku operational key, set only for profiles that serve a
	// distinct ku= JWKS.
	kuKey      jwk.Key
	signingKey *JWK
	// signingKeyThumbprint is the RFC 7638 thumbprint of signingKey, computed
	// once at verification so counterparty acceptance never recomputes it.
	signingKeyThumbprint string
	status               *AgentStatus
	dnssecState          DNSSECState
	verifiedAt           time.Time
	lastStatusCheckAt    time.Time
	dnsTTL               time.Duration
	dnsExpiresAt         time.Time
	jwksTLSCertificate   *tls.Certificate
	ekTLSCertificate     *tls.Certificate
	statusTLSCertificate *tls.Certificate
	keyBoundAt           time.Time
	// operationalKeyThumbprint is the ku (operational) key thumbprint. The ka
	// key-age policy is measured against this key's introducing log event, not
	// the ek record-signing key.
	operationalKeyThumbprint string
	logReader                dnsidlog.LogReader
	expiry                   time.Time
	cachedState              string
}

// Domain returns the verified identity domain in normalized FQDN form.
// It returns an empty string on a nil receiver.
func (v *VerifiedDomain) Domain() string {
	if v == nil {
		return ""
	}
	return v.domain
}

// Record returns a deep copy of the verified _dnsid TXT record, or nil on a
// nil receiver. Mutating the returned record does not affect the cached entry.
func (v *VerifiedDomain) Record() *TXTRecord {
	if v == nil {
		return nil
	}
	return cloneTXTRecord(v.record)
}

// KeySet returns a deep copy of the agent runtime (ku) JWKS — the key set the
// agent signs with at runtime — or nil on a nil receiver.
func (v *VerifiedDomain) KeySet() *JWKS {
	if v == nil {
		return nil
	}
	return cloneJWKS(v.keySet)
}

// RecordSigningKeySet returns a deep copy of the accountable-entity (ek)
// JWKS that verified the record signature, or nil on a nil receiver.
func (v *VerifiedDomain) RecordSigningKeySet() *JWKS {
	if v == nil {
		return nil
	}
	return cloneJWKS(v.recordSigningKeySet)
}

// SigningKey returns a deep copy of the entity key that produced the record's
// sg= signature, or nil on a nil receiver.
func (v *VerifiedDomain) SigningKey() *JWK {
	if v == nil {
		return nil
	}
	return cloneJWK(v.signingKey)
}

// Status returns a copy of the agent status document fetched from the su=
// endpoint, or nil on a nil receiver. Verification only succeeds for ACTIVE
// agents, so the returned status always reports State "ACTIVE".
func (v *VerifiedDomain) Status() *AgentStatus {
	if v == nil {
		return nil
	}
	return cloneAgentStatus(v.status)
}

// DNSSECState returns the resolver's DNSSEC validation result for the _dnsid
// lookup. It returns DNSSECStateUnknown on a nil receiver.
func (v *VerifiedDomain) DNSSECState() DNSSECState {
	if v == nil {
		return DNSSECStateUnknown
	}
	return v.dnssecState
}

// VerifiedAt returns when full verification completed. It returns the zero
// time on a nil receiver.
func (v *VerifiedDomain) VerifiedAt() time.Time {
	if v == nil {
		return time.Time{}
	}
	return v.verifiedAt
}

// LastStatusCheckAt returns when the agent status was last fetched, which may
// be later than VerifiedAt for entries refreshed from the cache. It returns
// the zero time on a nil receiver.
func (v *VerifiedDomain) LastStatusCheckAt() time.Time {
	if v == nil {
		return time.Time{}
	}
	return v.lastStatusCheckAt
}

// DNSTTL returns the TTL of the _dnsid TXT record as reported by the
// resolver, or 0 on a nil receiver.
func (v *VerifiedDomain) DNSTTL() time.Duration {
	if v == nil {
		return 0
	}
	return v.dnsTTL
}

// JWKSCertificate returns a copy of the TLS certificate presented by the
// runtime (ku) JWKS endpoint, or nil when unavailable.
func (v *VerifiedDomain) JWKSCertificate() *tls.Certificate {
	if v == nil {
		return nil
	}
	return cloneTLSCertificate(v.jwksTLSCertificate)
}

// JWKSLeafCertificate returns a copy of the leaf certificate presented by the
// runtime (ku) JWKS endpoint, or nil when unavailable.
func (v *VerifiedDomain) JWKSLeafCertificate() *x509.Certificate {
	if v == nil || v.jwksTLSCertificate == nil {
		return nil
	}
	return cloneX509Certificate(v.jwksTLSCertificate.Leaf)
}

// StatusCertificate returns a copy of the TLS certificate presented by the
// status (su) endpoint, or nil when unavailable.
func (v *VerifiedDomain) StatusCertificate() *tls.Certificate {
	if v == nil {
		return nil
	}
	return cloneTLSCertificate(v.statusTLSCertificate)
}

// StatusLeafCertificate returns a copy of the leaf certificate presented by
// the status (su) endpoint, or nil when unavailable.
func (v *VerifiedDomain) StatusLeafCertificate() *x509.Certificate {
	if v == nil || v.statusTLSCertificate == nil {
		return nil
	}
	return cloneX509Certificate(v.statusTLSCertificate.Leaf)
}

// KeyBoundAt returns when the operational key was introduced according to the
// lifecycle log. It is set only when the record carries a ka= key-age policy;
// otherwise, and on a nil receiver, it returns the zero time.
func (v *VerifiedDomain) KeyBoundAt() time.Time {
	if v == nil {
		return time.Time{}
	}
	return v.keyBoundAt
}

// RequiresLogCheck reports whether the verified record carries the logchk
// policy signal. Applications decide which operations require fresh evidence.
func (v *VerifiedDomain) RequiresLogCheck() bool {
	return v != nil && hasPolicyFlag(v.record, PolicyFlagLogCheck)
}

// LogReader returns the lifecycle log reader bound to the record's lr=
// reference during verification, or nil on a nil receiver.
func (v *VerifiedDomain) LogReader() dnsidlog.LogReader {
	if v == nil {
		return nil
	}
	return v.logReader
}

// Expiry returns the earliest instant at which this verification result
// should no longer be trusted: the minimum of the DNS TTL, the ka= key-age
// deadline, and the runtime and record-signing TLS certificate expiries. It
// returns the zero time when no bound applies or on a nil receiver.
func (v *VerifiedDomain) Expiry() time.Time {
	if v == nil {
		return time.Time{}
	}
	return v.expiry
}

// CachedState reports how this result was produced: "fresh" for a full
// verification, "cached" for a cache hit, and "refreshed" for a cache hit
// whose status was re-fetched. It returns an empty string on a nil receiver.
func (v *VerifiedDomain) CachedState() string {
	if v == nil {
		return ""
	}
	return v.cachedState
}

func cloneVerifiedDomain(v *VerifiedDomain) *VerifiedDomain {
	if v == nil {
		return nil
	}
	return &VerifiedDomain{
		domain:                   v.domain,
		record:                   cloneTXTRecord(v.record),
		keySet:                   cloneJWKS(v.keySet),
		recordSigningKeySet:      cloneJWKS(v.recordSigningKeySet),
		kuKey:                    cloneJWKKey(v.kuKey),
		signingKey:               cloneJWK(v.signingKey),
		signingKeyThumbprint:     v.signingKeyThumbprint,
		status:                   cloneAgentStatus(v.status),
		dnssecState:              v.dnssecState,
		verifiedAt:               v.verifiedAt,
		lastStatusCheckAt:        v.lastStatusCheckAt,
		dnsTTL:                   v.dnsTTL,
		dnsExpiresAt:             v.dnsExpiresAt,
		jwksTLSCertificate:       cloneTLSCertificate(v.jwksTLSCertificate),
		ekTLSCertificate:         cloneTLSCertificate(v.ekTLSCertificate),
		statusTLSCertificate:     cloneTLSCertificate(v.statusTLSCertificate),
		keyBoundAt:               v.keyBoundAt,
		operationalKeyThumbprint: v.operationalKeyThumbprint,
		logReader:                v.logReader,
		expiry:                   v.expiry,
		cachedState:              v.cachedState,
	}
}

func cloneTXTRecord(r *TXTRecord) *TXTRecord {
	if r == nil {
		return nil
	}
	copy := *r
	if r.Flags != nil {
		copy.Flags = append([]string(nil), r.Flags...)
	}
	if r.UnknownTags != nil {
		copy.UnknownTags = copyStringMap(r.UnknownTags)
	}
	return &copy
}

func cloneAgentStatus(s *AgentStatus) *AgentStatus {
	if s == nil {
		return nil
	}
	copy := *s
	return &copy
}

func cloneJWKS(j *JWKS) *JWKS {
	if j == nil || j.set == nil {
		return nil
	}
	set := cloneJWKSet(j.set)
	if set == nil {
		return nil
	}
	return &JWKS{set: set}
}

func cloneJWK(k *JWK) *JWK {
	if k == nil {
		return nil
	}
	key := cloneJWKKey(k.key)
	if key == nil {
		return nil
	}
	return &JWK{key: key}
}

func cloneJWKKey(key jwk.Key) jwk.Key {
	if key == nil {
		return nil
	}
	data, err := json.Marshal(key)
	if err != nil {
		return nil
	}
	cloned, err := jwk.ParseKey(data)
	if err != nil {
		return nil
	}
	return cloned
}

func cloneJWKSet(set jwk.Set) jwk.Set {
	if set == nil {
		return nil
	}
	data, err := json.Marshal(set)
	if err != nil {
		return nil
	}
	cloned, err := ParseJWKSet(data)
	if err != nil {
		return nil
	}
	return cloned
}

func cloneX509Certificate(cert *x509.Certificate) *x509.Certificate {
	if cert == nil {
		return nil
	}
	if len(cert.Raw) > 0 {
		if cloned, err := x509.ParseCertificate(append([]byte(nil), cert.Raw...)); err == nil {
			return cloned
		}
	}
	copy := *cert
	copy.Raw = append([]byte(nil), cert.Raw...)
	copy.RawTBSCertificate = append([]byte(nil), cert.RawTBSCertificate...)
	copy.RawSubjectPublicKeyInfo = append([]byte(nil), cert.RawSubjectPublicKeyInfo...)
	copy.RawSubject = append([]byte(nil), cert.RawSubject...)
	copy.RawIssuer = append([]byte(nil), cert.RawIssuer...)
	copy.DNSNames = append([]string(nil), cert.DNSNames...)
	copy.EmailAddresses = append([]string(nil), cert.EmailAddresses...)
	copy.IPAddresses = cloneIPs(cert.IPAddresses)
	copy.URIs = cloneURLs(cert.URIs)
	copy.PermittedDNSDomains = append([]string(nil), cert.PermittedDNSDomains...)
	copy.ExcludedDNSDomains = append([]string(nil), cert.ExcludedDNSDomains...)
	copy.PermittedEmailAddresses = append([]string(nil), cert.PermittedEmailAddresses...)
	copy.ExcludedEmailAddresses = append([]string(nil), cert.ExcludedEmailAddresses...)
	copy.PermittedURIDomains = append([]string(nil), cert.PermittedURIDomains...)
	copy.ExcludedURIDomains = append([]string(nil), cert.ExcludedURIDomains...)
	copy.PermittedIPRanges = cloneIPNets(cert.PermittedIPRanges)
	copy.ExcludedIPRanges = cloneIPNets(cert.ExcludedIPRanges)
	copy.PolicyIdentifiers = cloneObjectIdentifiers(cert.PolicyIdentifiers)
	copy.ExtKeyUsage = append([]x509.ExtKeyUsage(nil), cert.ExtKeyUsage...)
	copy.UnknownExtKeyUsage = cloneObjectIdentifiers(cert.UnknownExtKeyUsage)
	copy.Extensions = cloneExtensions(cert.Extensions)
	copy.ExtraExtensions = cloneExtensions(cert.ExtraExtensions)
	return &copy
}

func cloneIPs(values []net.IP) []net.IP {
	if values == nil {
		return nil
	}
	out := make([]net.IP, len(values))
	for i := range values {
		out[i] = append(net.IP(nil), values[i]...)
	}
	return out
}

func cloneURLs(values []*url.URL) []*url.URL {
	if values == nil {
		return nil
	}
	out := make([]*url.URL, len(values))
	for i := range values {
		if values[i] != nil {
			copy := *values[i]
			out[i] = &copy
		}
	}
	return out
}

func cloneIPNets(values []*net.IPNet) []*net.IPNet {
	if values == nil {
		return nil
	}
	out := make([]*net.IPNet, len(values))
	for i := range values {
		if values[i] != nil {
			out[i] = &net.IPNet{IP: append(net.IP(nil), values[i].IP...), Mask: append(net.IPMask(nil), values[i].Mask...)}
		}
	}
	return out
}

func cloneObjectIdentifiers(values []asn1.ObjectIdentifier) []asn1.ObjectIdentifier {
	if values == nil {
		return nil
	}
	out := make([]asn1.ObjectIdentifier, len(values))
	for i := range values {
		out[i] = append(asn1.ObjectIdentifier(nil), values[i]...)
	}
	return out
}

func cloneExtensions(values []pkix.Extension) []pkix.Extension {
	if values == nil {
		return nil
	}
	out := make([]pkix.Extension, len(values))
	for i := range values {
		out[i] = values[i]
		out[i].Id = append(asn1.ObjectIdentifier(nil), values[i].Id...)
		out[i].Value = append([]byte(nil), values[i].Value...)
	}
	return out
}

func cloneTLSCertificate(cert *tls.Certificate) *tls.Certificate {
	if cert == nil {
		return nil
	}
	copy := *cert
	if cert.Certificate != nil {
		copy.Certificate = make([][]byte, len(cert.Certificate))
		for i := range cert.Certificate {
			copy.Certificate[i] = append([]byte(nil), cert.Certificate[i]...)
		}
	}
	if cert.Leaf != nil {
		copy.Leaf = cloneX509Certificate(cert.Leaf)
	}
	if cert.OCSPStaple != nil {
		copy.OCSPStaple = append([]byte(nil), cert.OCSPStaple...)
	}
	if cert.SignedCertificateTimestamps != nil {
		copy.SignedCertificateTimestamps = make([][]byte, len(cert.SignedCertificateTimestamps))
		for i := range cert.SignedCertificateTimestamps {
			copy.SignedCertificateTimestamps[i] = append([]byte(nil), cert.SignedCertificateTimestamps[i]...)
		}
	}
	if cert.SupportedSignatureAlgorithms != nil {
		copy.SupportedSignatureAlgorithms = append([]tls.SignatureScheme(nil), cert.SupportedSignatureAlgorithms...)
	}
	return &copy
}

type identityCacheKey struct {
	domain  string
	context *IdentityManager
}

// IdentityCache caches domains in manager-private verification namespaces.
// Direct Get/Put/Evict calls use the standalone namespace; managers sharing
// this backend never consume each other's results. Capacity eviction is global.
type IdentityCache struct {
	mu      sync.RWMutex
	entries map[identityCacheKey]*VerifiedDomain

	// gapHook, when set, runs in Get after the read lock is dropped and before
	// the write lock is acquired. Test-only seam for exercising the
	// unlock/relock race deterministically; nil in production.
	gapHook func()
}

// NewIdentityCache constructs a bounded, empty cache. The legacy defaultTTL
// parameter is ignored: only the original absolute evidence expiry is used.
func NewIdentityCache(_ time.Duration) *IdentityCache {
	return &IdentityCache{entries: make(map[identityCacheKey]*VerifiedDomain)}
}

// Get returns a deep copy of the cached entry for domain with CachedState
// "cached", or nil when the domain is absent or the entry has expired.
// Expired entries are evicted on access. Get is safe for concurrent use and
// returns nil on a nil receiver.
func (c *IdentityCache) Get(domain string) *VerifiedDomain {
	return c.get(domain, nil)
}

func (c *IdentityCache) get(domain string, context *IdentityManager) *VerifiedDomain {
	key := identityCacheKey{domain, context}
	if c == nil {
		return nil
	}
	c.mu.RLock()
	vd := c.entries[key]
	if vd == nil {
		c.mu.RUnlock()
		return nil
	}
	if !vd.expiry.IsZero() && !time.Now().Before(vd.expiry) {
		c.mu.RUnlock()
		if c.gapHook != nil {
			c.gapHook()
		}
		// Entry expired: acquire the write lock to evict it, re-checking
		// under the lock in case another goroutine refreshed it meanwhile.
		c.mu.Lock()
		defer c.mu.Unlock()
		existing := c.entries[key]
		if existing != nil && (existing.expiry.IsZero() || time.Now().Before(existing.expiry)) {
			// Another goroutine refreshed it during the unlock gap: it's a
			// valid cache hit now, so return the fresh entry instead of nil.
			copy := cloneVerifiedDomain(existing)
			copy.cachedState = "cached"
			return copy
		}
		delete(c.entries, key)
		return nil
	}
	copy := cloneVerifiedDomain(vd)
	c.mu.RUnlock()
	copy.cachedState = "cached"
	return copy
}

// Put stores a deep copy with its original absolute expiry. Zero-TTL,
// unbounded, expired, and empty-domain results are not stored. At most 1024
// results are retained across namespaces. Put is safe for concurrent use.
func (c *IdentityCache) Put(vd *VerifiedDomain) { c.put(vd, nil) }

func (c *IdentityCache) put(vd *VerifiedDomain, context *IdentityManager) {
	if c == nil || vd == nil || vd.domain == "" || vd.expiry.IsZero() || !time.Now().Before(vd.expiry) || vd.dnsTTL <= 0 {
		return
	}
	copy := cloneVerifiedDomain(vd)
	c.mu.Lock()
	// ponytail: bounded cache; arbitrary eviction, use an LRU only if hit rates require it.
	if len(c.entries) >= 1024 {
		for key := range c.entries {
			delete(c.entries, key)
			break
		}
	}
	c.entries[identityCacheKey{copy.domain, context}] = copy
	c.mu.Unlock()
}

// Evict removes the entry for domain, if present. The domain must already be
// in normalized form (see NormalizeFQDN); IdentityManager.EvictDomain
// normalizes for you. Evict is safe for concurrent use and is a no-op on a
// nil receiver.
func (c *IdentityCache) Evict(domain string) { c.evict(domain, nil) }

func (c *IdentityCache) evict(domain string, context *IdentityManager) {
	if c == nil {
		return
	}
	c.mu.Lock()
	delete(c.entries, identityCacheKey{domain, context})
	c.mu.Unlock()
}
