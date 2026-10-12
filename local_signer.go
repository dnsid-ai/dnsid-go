package dnsid

import "context"

// LogReference returns the configured local lifecycle-log reference.
func (m *IdentityManager) LogReference() string {
	if m == nil {
		return ""
	}
	return m.identity.LogRef
}

// VerifyLocalOperationalKey checks a provider key against current signed local
// publication and lifecycle continuity, without making a counterparty decision.
// An empty kid selects the active key; a nonempty kid permits pending rotation keys.
func (m *IdentityManager) VerifyLocalOperationalKey(ctx context.Context, provider KeyProvider, kid string) (*VerifiedDomain, error) {
	if m == nil || m.identity.Domain == "" || provider == nil {
		return nil, NewArgumentError("dnsid: local identity and key provider are required", nil)
	}
	var selected []string
	if kid != "" {
		selected = []string{kid}
	}
	key := provider.JWK(selected...)
	if key == nil {
		return nil, NewValidationError("dnsid: local signer key is unavailable", nil)
	}
	m.EvictDomain(m.identity.Domain)
	vd, err := m.verifyDomain(ctx, m.identity.Domain, VerifyDomainOpts{}, false)
	if err != nil {
		return nil, err
	}
	if vd.record.GovernanceID != m.identity.GovernanceID || vd.record.LogRef != m.identity.LogRef {
		return nil, NewValidationError("dnsid: local publication does not match configured identity", nil)
	}
	published, err := vd.KeySet().CurrentOperationalSigningKey(vd.record.Version)
	if err != nil {
		return nil, err
	}
	actual := &JWK{key: key}
	thumb, err := actual.Thumbprint()
	if err != nil {
		return nil, err
	}
	publishedThumb, err := published.Thumbprint()
	if err != nil {
		return nil, err
	}
	actualKid, _ := key.KeyID()
	publishedKid, _ := published.Raw().KeyID()
	actualAlg, _ := key.Algorithm()
	publishedAlg, _ := published.Raw().Algorithm()
	if actualKid == "" || actualAlg.String() == "" || actualKid != publishedKid || actualAlg.String() != publishedAlg.String() || thumb != publishedThumb {
		return nil, NewValidationError("dnsid: configured signer does not match verified local publication; explicit rotation is required", nil)
	}
	return vd, m.requireFreshIdentityEvidence(vd, true)
}
