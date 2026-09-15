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

	// The operational key endpoint belongs to the identity domain.
	ku, _ := url.Parse(r.KeyURI)
	if !strings.EqualFold(ku.Hostname(), fqdn) {
		return NewValidationError(fmt.Sprintf("dnsid: ku host %q must equal identity FQDN %q", ku.Hostname(), fqdn), nil)
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
	ekURL, _ := url.Parse(r.EntityKeyURI)
	if ekHost := strings.ToLower(ekURL.Hostname()); !isDomainOrSubdomain(ekHost, giDomain) {
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
	return nil
}
