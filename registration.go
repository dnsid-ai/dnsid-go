package dnsid

import (
	"context"
	"encoding/json"
	"strings"
	"unicode/utf8"
)

// RegistrationError retains recovery data after a creation attempt. Failure
// does not prove that no identity exists. Cause preserves registry errors.
type RegistrationError struct {
	Request        json.RawMessage
	IdempotencyKey string
	Creation       *CreateAgentResponse
	Cause          error
}

func (e *RegistrationError) Error() string {
	return "dnsid: registration outcome requires recovery: " + e.Cause.Error()
}
func (e *RegistrationError) Unwrap() error { return e.Cause }

func validateRegistrationCreation(req *CreateAgentRequest, response *CreateAgentResponse) error {
	domain, err := NormalizeFQDN(response.Domain)
	if err != nil {
		return err
	}
	if response.ID == "" || domain != response.Domain || (req.Domain != "" && domain != req.Domain) || (req.RootDomain != "" && (domain == req.RootDomain || !isDomainOrSubdomain(domain, req.RootDomain))) {
		return NewValidationError("dnsid: registry returned mismatched registration identity", nil)
	}
	p := response.PublicationConfig
	if p.PublishProfile != DefaultPublishProfile || p.KeyURL == "" || p.EntityKeyURL == "" {
		return NewValidationError("dnsid: missing or unsupported publication configuration", nil)
	}
	gi, err := NormalizeFQDN(p.GovernanceID)
	if err != nil {
		return err
	}
	if gi != p.GovernanceID || (req.GovernanceDomain != "" && gi != req.GovernanceDomain) {
		return NewValidationError("dnsid: registry returned mismatched governance identifier", nil)
	}
	return (IdentityConfig{Domain: domain, GovernanceID: p.GovernanceID, PublishProfile: p.PublishProfile, KeyURL: p.KeyURL, EntityKeyURL: p.EntityKeyURL, LogRef: p.LogRef, StatusURL: p.StatusURL, CapabilitiesURL: p.CapabilitiesURL, MaxKeyAge: KeyAge(p.MaxKeyAge)}).Validate()
}

// RegisterAgent creates an identity and reads publication authority from
// authenticated management detail. The optional key is transport metadata.
// Creation facts survive a failed detail read in RegistrationError.
func (c *HTTPRegistryClient) RegisterAgent(ctx context.Context, input *AgentRegistrationInput, idempotencyKey string) (*AgentRegistration, error) {
	if input == nil {
		return nil, NewArgumentError("dnsid: registration input is required", nil)
	}
	if c.token == "" {
		return nil, NewArgumentError("dnsid: registration requires an organization credential", nil)
	}
	req := &CreateAgentRequest{Domain: input.Domain, GovernanceDomain: input.GovernanceDomain, RootDomain: input.RootDomain, Name: input.Name, Metadata: input.Metadata, PublicKey: input.PublicKeyJWK, Environment: input.Environment, Managed: input.Managed, ZoneID: input.ZoneID, Tier: input.Tier, CapabilitiesURL: input.CapabilitiesURL}
	creation, err := c.CreateAgentWithIdempotencyKey(ctx, req, idempotencyKey)
	if err != nil {
		return nil, err
	}
	request, _ := json.Marshal(req)
	registration, err := c.GetRegistration(ctx, creation.Domain)
	if err == nil && (registration.ID != creation.ID || registration.Domain != creation.Domain) {
		err = NewValidationError("dnsid: registration detail identifies another agent", nil)
	}
	if err != nil {
		return nil, &RegistrationError{Request: request, IdempotencyKey: idempotencyKey, Creation: creation, Cause: err}
	}
	registration.PublicationConfig = creation.PublicationConfig
	registration.OIDCIssuerURL = creation.OIDCIssuerURL
	return registration, nil
}

// NormalizeAgentRegistrationInput validates selectors and rejects private JWK
// members without requiring an operational key to be selected yet. It returns
// a shallow copy and performs no I/O.
func NormalizeAgentRegistrationInput(input *AgentRegistrationInput) (*AgentRegistrationInput, error) {
	if input == nil {
		return nil, NewArgumentError("dnsid: registration input is required", nil)
	}
	request := &CreateAgentRequest{Domain: input.Domain, GovernanceDomain: input.GovernanceDomain, RootDomain: input.RootDomain, Name: input.Name, Metadata: input.Metadata, PublicKey: input.PublicKeyJWK, Environment: input.Environment, Managed: input.Managed, ZoneID: input.ZoneID, Tier: input.Tier, CapabilitiesURL: input.CapabilitiesURL}
	normalized, err := normalizeRegistrationRequest(request)
	if err != nil {
		return nil, err
	}
	result := *input
	result.Domain = normalized.Domain
	result.GovernanceDomain = normalized.GovernanceDomain
	result.RootDomain = normalized.RootDomain
	result.Name = normalized.Name
	return &result, nil
}

func normalizeRegistrationRequest(req *CreateAgentRequest) (*CreateAgentRequest, error) {
	normalized := *req
	if normalized.Environment != "" && normalized.Environment != "production" && normalized.Environment != "sandbox" {
		return nil, NewArgumentError("dnsid: environment must be \"production\" or \"sandbox\"", nil)
	}
	if normalized.Domain != "" && normalized.ZoneID != "" {
		return nil, NewArgumentError("dnsid: domain and zone_id cannot both be supplied", nil)
	}
	if normalized.Domain != "" && normalized.RootDomain != "" {
		return nil, NewArgumentError("dnsid: domain and root_domain cannot both be supplied", nil)
	}
	if normalized.Tier == "live" {
		return nil, NewArgumentError("dnsid: use CreateLiveAgent for managed Live", nil)
	}
	for _, selector := range []*string{&normalized.Domain, &normalized.RootDomain, &normalized.GovernanceDomain} {
		if *selector != "" {
			value, err := NormalizeFQDN(*selector)
			if err != nil {
				return nil, NewArgumentError("dnsid: invalid registration selector", err)
			}
			*selector = value
		}
	}
	normalized.Name = strings.TrimSpace(normalized.Name)
	if utf8.RuneCountInString(normalized.Name) > 255 {
		return nil, NewArgumentError("dnsid: name exceeds 255 characters", nil)
	}
	if normalized.CapabilitiesURL != "" {
		if err := validateHTTPSURL(normalized.CapabilitiesURL, "capabilities_url"); err != nil {
			return nil, err
		}
	}

	if normalized.PublicKey != nil {
		if err := rejectPrivateJWK(normalized.PublicKey); err != nil {
			return nil, err
		}
	}
	return &normalized, nil
}
