package dnsid

import (
	"context"
	"crypto/tls"
	"time"
)

// DefaultVerificationTimeout bounds a complete verification when no caller deadline is supplied.
const DefaultVerificationTimeout = 30 * time.Second

// VerificationContext preserves a caller deadline, or supplies the finite SDK default.
// Nested verification operations must pass the returned context to their children.
func VerificationContext(ctx context.Context) (context.Context, context.CancelFunc) {
	if ctx == nil {
		ctx = context.Background()
	}
	if _, ok := ctx.Deadline(); ok {
		return context.WithCancel(ctx)
	}
	return context.WithTimeout(ctx, DefaultVerificationTimeout)
}

// VerifyIdentity resolves an application signer with trusted current-peer evidence.
// Resolvers without the options API cannot authenticate an mtls identity.
func VerifyIdentity(ctx context.Context, resolver IdentityResolver, domain string, opts VerifyDomainOpts) (*VerifiedDomain, error) {
	if resolver == nil {
		return nil, NewArgumentError("dnsid: IdentityResolver is required", nil)
	}
	if r, ok := resolver.(interface {
		VerifyDomainWithOptions(context.Context, string, VerifyDomainOpts) (*VerifiedDomain, error)
	}); ok {
		return r.VerifyDomainWithOptions(ctx, domain, opts)
	}
	vd, err := resolver.VerifyDomain(ctx, domain)
	if err == nil && vd != nil && hasPolicyFlag(vd.record, PolicyFlagMTLS) {
		err = verifyMTLSPeerChains(domain, opts.VerifiedPeerCertificateChains)
	}
	return vd, err
}

func (m *IdentityManager) cachedDomain(domain string) *VerifiedDomain {
	return m.cache.get(domain, m)
}

func (m *IdentityManager) requireFreshIdentityEvidence(vd *VerifiedDomain, freshDNS bool) error {
	if vd == nil {
		return NewVerificationError(VerificationCodeDNSResolution, true, "dnsid: missing identity evidence", nil)
	}
	now := time.Now()
	var err error
	for _, cert := range []*tls.Certificate{vd.jwksTLSCertificate, vd.ekTLSCertificate} {
		if cert != nil && cert.Leaf != nil && (now.Before(cert.Leaf.NotBefore) || !now.Before(cert.Leaf.NotAfter)) {
			err = NewVerificationError(VerificationCodeTLSError, false, "dnsid: identity TLS evidence expired or not yet valid", nil)
		}
	}
	if err == nil && vd.record != nil && vd.record.KeyAge != "" && !vd.keyBoundAt.IsZero() {
		age, parseErr := parseKeyAgeDuration(vd.record.KeyAge)
		if parseErr != nil || !now.Before(vd.keyBoundAt.Add(age)) {
			err = NewVerificationError(VerificationCodeKeyAgeExceeded, false, "dnsid: operational key age exceeded", parseErr)
		}
	}
	if err == nil && ((vd.dnsTTL > 0 && !now.Before(vd.dnsExpiresAt)) || (vd.dnsTTL <= 0 && !freshDNS)) {
		err = NewVerificationError(VerificationCodeDNSResolution, true, "dnsid: DNS identity evidence expired", nil)
	}
	if err != nil {
		m.cache.evict(vd.domain, m)
	}
	return err
}
