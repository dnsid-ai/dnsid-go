package dnsid

import (
	"errors"
	"fmt"
	"net/url"
	"strings"
)

// Canonical returns the canonical string used for TXT-record signature verification.
func (r *TXTRecord) Canonical() string {
	if r == nil {
		return ""
	}
	return string(r.CanonicalContent())
}

// Serialize serializes the record as one _dnsid TXT value.
func (r *TXTRecord) Serialize() string {
	if r == nil {
		return ""
	}
	out, err := r.MarshalTXT()
	if err != nil {
		return ""
	}
	return out
}

// Validate checks record-level semantics with identity-domain context.
func (r *TXTRecord) Validate(identityFQDN string) error {
	return r.validateWithSignatureRequirement(identityFQDN, true)
}

func (r *TXTRecord) validateUnsigned(identityFQDN string) error {
	return r.validateWithSignatureRequirement(identityFQDN, false)
}

func (r *TXTRecord) validateWithSignatureRequirement(identityFQDN string, includeSignature bool) error {
	if r == nil {
		return NewValidationError("dnsid: nil TXTRecord", nil)
	}
	if err := r.validateRequiredTags(includeSignature); err != nil {
		return err
	}
	fqdn, err := NormalizeFQDN(identityFQDN)
	if err != nil {
		return NewValidationError("", err)
	}
	if err := validateRecordHTTPSURL(r.KeyURI, "ku"); err != nil {
		return err
	}
	if err := validateRecordHTTPSURL(r.StatusURI, "su"); err != nil {
		return err
	}
	// Call the package-level ParseLogRef wrapper (which delegates to
	// dnsidlog.ParseLogRef) so that any future allow-listing or
	// normalization logic added to the wrapper is applied here too.
	// We strip the *ParseError wrapping and return a pure ValidationError.
	if _, _, err := ParseLogRef(r.LogRef); err != nil {
		var pe *ParseError
		if errors.As(err, &pe) {
			return NewValidationError(pe.Error(), nil)
		}
		return NewValidationError(err.Error(), nil)
	}
	if r.Capabilities != "" {
		if err := validateRecordHTTPSURL(r.Capabilities, "cu"); err != nil {
			return err
		}
	}

	// The operational key endpoint belongs to the identity domain. The host is
	// compared in NormalizeFQDN form, the name the transport will resolve and
	// present as TLS SNI, rather than through a case fold: strings.EqualFold
	// and strings.ToLower apply Unicode simple case mappings that do not agree
	// with the UTS 46 mapping net/http applies before dialing (U+0130 is the
	// textbook case), so a folded comparison can accept a host that is dialed
	// as a different DNS name. A host that has no canonical form is rejected.
	ku, _ := url.Parse(r.KeyURI)
	kuHost, err := NormalizeFQDN(ku.Hostname())
	if err != nil {
		return NewValidationError(fmt.Sprintf("dnsid: ku host %+q is not a valid DNS name", ku.Hostname()), err)
	}
	if kuHost != fqdn {
		return NewValidationError(fmt.Sprintf("dnsid: ku host %q must equal identity FQDN %q", kuHost, fqdn), nil)
	}

	if err := validateRecordHTTPSURL(r.EntityKeyURI, "ek"); err != nil {
		return err
	}
	gi := strings.TrimSpace(r.GovernanceID)
	if !isDomainName(gi) {
		return NewValidationError(fmt.Sprintf("dnsid: gi %q must be a domain name for version %q", gi, r.Version), nil)
	}
	giDomain, err := NormalizeFQDN(gi)
	if err != nil {
		return NewValidationError("", err)
	}
	if gi != giDomain {
		return NewValidationError(fmt.Sprintf("dnsid: gi %q must be lowercase ASCII in A-label form", gi), nil)
	}
	// The entity key endpoint must sit at or under the governance domain. This
	// boundary is what binds the record-signing key to gi, so, as for ku, the
	// host is compared in NormalizeFQDN form: the exact name that will be
	// dialed. Under a strings.ToLower comparison the host "keys.b\u0130gcorp.com"
	// (reachable from an all-ASCII record as keys.b%C4%B0gcorp.com) folded to a
	// name under bigcorp.com while the JWKS was fetched from
	// keys.xn--bigcorp-....com, a domain anyone can register.
	ekURL, _ := url.Parse(r.EntityKeyURI)
	ekHost, err := NormalizeFQDN(ekURL.Hostname())
	if err != nil {
		return NewValidationError(fmt.Sprintf("dnsid: ek host %+q is not a valid DNS name", ekURL.Hostname()), err)
	}
	if !isDomainOrSubdomain(ekHost, giDomain) {
		return NewValidationError(fmt.Sprintf("dnsid: ek host %q must be at or under gi domain %q", ekHost, giDomain), nil)
	}

	if r.KeyAge != "" && !ValidKeyAgeValues[r.KeyAge] {
		return NewValidationError(fmt.Sprintf("dnsid: invalid ka value: %q", r.KeyAge), nil)
	}
	return nil
}

func validateRecordHTTPSURL(raw, tag string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" {
		return NewValidationError(fmt.Sprintf("dnsid: %s must be an HTTPS URL", tag), nil)
	}
	if u.User != nil {
		return NewValidationError(fmt.Sprintf("dnsid: %s must not include userinfo", tag), nil)
	}
	// TXT values are printable ASCII, so a record URL's host is ASCII as
	// written. url.Parse percent-decodes the host component, which is the only
	// way a non-ASCII byte (or a literal "%", from "%25") can appear in u.Host.
	// Neither belongs in a DNS host name, and RFC 3986 section 3.2.2 directs
	// producers to write internationalized hosts as A-labels rather than
	// percent-encoding them. Rejecting them keeps the host that is compared and
	// dialed identical to the host as published, so a "%" in a record can never
	// act as a formatting character for the host. The path and query keep their
	// percent-encoding untouched.
	for i := 0; i < len(u.Host); i++ {
		if c := u.Host[i]; c >= 0x80 || c == '%' {
			return NewValidationError(fmt.Sprintf("dnsid: %s host must be an ASCII DNS name without percent-escapes", tag), nil)
		}
	}
	return nil
}
