package dnsid

import "strings"

// OrganizationBinding contains configured or saved account identifiers.
// Empty fields impose no comparison, but discovered identifiers must be valid.
type OrganizationBinding struct {
	OrganizationID string
	GovernanceID   string
}

// ValidateBinding requires verified, gate-authorized governance and entity-key
// delegation. Pending or missing proofs do not make an account ready.
func (r *OrganizationOnboardingResponse) ValidateBinding(expected OrganizationBinding) error {
	if r == nil || strings.TrimSpace(r.OrganizationID) == "" || r.OrganizationID != strings.TrimSpace(r.OrganizationID) {
		return NewValidationError("dnsid: onboarding organization ID is missing or invalid", nil)
	}
	gi, err := NormalizeFQDN(r.GovernanceDomain)
	if err != nil || gi != r.GovernanceDomain {
		return NewValidationError("dnsid: onboarding governance identifier is invalid", err)
	}
	if (expected.OrganizationID != "" && r.OrganizationID != expected.OrganizationID) || (expected.GovernanceID != "" && gi != expected.GovernanceID) {
		return NewValidationError("dnsid: onboarding account binding does not match expected identifiers", nil)
	}
	if r.GI == nil || r.GI.Domain != gi || r.GI.State != "verified" || !r.GI.GateAuthorized || r.EK.Status != "verified" {
		return NewValidationError("dnsid: onboarding governance proof and entity-key delegation are not verified", nil)
	}
	return nil
}
