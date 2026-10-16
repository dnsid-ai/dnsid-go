---
title: "Go: dnsid — registry client"
description: "HTTPRegistryClient, publication workflows, and registry request/response types."
---

> Generated from the Go source by scripts/gen-docs.sh — do not edit; run it to regenerate.
> Canonical deep reference: [pkg.go.dev/github.com/dnsid-ai/dnsid-go](https://pkg.go.dev/github.com/dnsid-ai/dnsid-go).
> Guides and account setup: [https://docs.dnsid.ai](https://docs.dnsid.ai).

Part of the root package `github.com/dnsid-ai/dnsid-go` — see [Core: IdentityManager](https://docs.dnsid.ai/reference/go/dnsid) for the package overview.

## type [AgentDetail](<https://github.com/dnsid-ai/dnsid-go/blob/main/registry.go#L245-L270>)

AgentDetail matches the OpenAPI AgentDetail schema.

```go
type AgentDetail struct {
    ID                      string            `json:"id"`
    Domain                  string            `json:"domain"`
    DomainDisplay           string            `json:"domain_display"`
    Name                    string            `json:"name,omitempty"`
    Environment             string            `json:"environment"`
    Status                  string            `json:"status"`
    StatusURL               string            `json:"status_url"`
    Managed                 string            `json:"managed"`
    ProtocolStatus          *AgentStatus      `json:"protocolStatus,omitempty"`
    ServerStatus            string            `json:"serverStatus,omitempty"`
    DNSPublished            bool              `json:"dns_published"`
    DNSPublishedAt          *time.Time        `json:"dns_published_at,omitempty"`
    Challenge               string            `json:"challenge,omitempty"`
    ChallengeExpiresAt      *time.Time        `json:"challenge_expires_at,omitempty"`
    ChainRecordStatus       string            `json:"chain_record_status,omitempty"`
    TransactionID           string            `json:"transaction_id,omitempty"`
    RevocationReason        string            `json:"revocation_reason,omitempty"`
    RevokedAt               *time.Time        `json:"revoked_at,omitempty"`
    IdentityRecordExpiresAt *time.Time        `json:"identity_record_expires_at,omitempty"`
    IdentityRecordExpiring  *bool             `json:"identity_record_expiring,omitempty"`
    Error                   *AgentError       `json:"error,omitempty"`
    PublicationConfig       PublicationConfig `json:"publication_config"`
    CreatedAt               time.Time         `json:"created_at"`
    UpdatedAt               time.Time         `json:"updated_at"`
}
```

<a name="WaitForRegistryStatus"></a>
### func [WaitForRegistryStatus](<https://github.com/dnsid-ai/dnsid-go/blob/main/registry.go#L1310>)

```go
func WaitForRegistryStatus(ctx context.Context, client RegistryStatusReader, fqdn string, targetStatuses []string, opts *WaitForStatusOptions) (*AgentDetail, error)
```

WaitForRegistryStatus polls client until the agent at fqdn reaches one of targetStatuses \(compared case\-insensitively\) and returns that AgentDetail. It returns an error when a terminal registry status is reached first, when polling fails, or when ctx \(bounded by opts.Timeout, if set\) is done. A nil opts polls every second with no timeout beyond ctx's own.

<a name="AgentError"></a>
## type [AgentEvent](<https://github.com/dnsid-ai/dnsid-go/blob/main/registry.go#L391-L398>)

AgentEvent matches the OpenAPI AgentEvent schema.

```go
type AgentEvent struct {
    ID        string         `json:"id"`
    AgentID   string         `json:"agent_id"`
    EventType string         `json:"event_type"`
    CreatedAt time.Time      `json:"created_at"`
    ActorID   *string        `json:"actor_id,omitempty"`
    Details   map[string]any `json:"details,omitempty"`
}
```

<a name="AgentListItem"></a>
## type [AgentListItem](<https://github.com/dnsid-ai/dnsid-go/blob/main/registry.go#L220-L228>)

AgentListItem matches the OpenAPI Agent schema.

```go
type AgentListItem struct {
    ID            string    `json:"id"`
    Domain        string    `json:"domain"`
    DomainDisplay string    `json:"domain_display"`
    Environment   string    `json:"environment"`
    Status        string    `json:"status"`
    CreatedAt     time.Time `json:"created_at"`
    UpdatedAt     time.Time `json:"updated_at"`
}
```

<a name="AgentListResponse"></a>
## type [AgentListResponse](<https://github.com/dnsid-ai/dnsid-go/blob/main/registry.go#L231-L234>)

AgentListResponse matches the OpenAPI AgentListResponse schema.

```go
type AgentListResponse struct {
    Agents     []AgentListItem `json:"agents"`
    NextCursor string          `json:"next_cursor,omitempty"`
}
```

<a name="AgentRegistration"></a>
## type [AgentRegistration](<https://github.com/dnsid-ai/dnsid-go/blob/main/registry.go#L115-L127>)

AgentRegistration is normalized registry workflow state for a local identity.

```go
type AgentRegistration struct {
    ID                   string               `json:"id"`
    PublicationConfig    PublicationConfig    `json:"publication_config"`
    Domain               string               `json:"domain"`
    PublicationAuthority PublicationAuthority `json:"publicationAuthority"`
    RegistryStatus       string               `json:"registryStatus"`
    DNSPublished         bool                 `json:"dnsPublished,omitempty"`
    ProtocolStatus       *AgentStatus         `json:"protocolStatus,omitempty"`
    // OIDCIssuerURL is the exact issuer returned by the registry at creation.
    OIDCIssuerURL string          `json:"oidcIssuerUrl,omitempty"`
    RegistryURL   string          `json:"registryUrl"`
    Raw           json.RawMessage `json:"raw,omitempty"`
}
```

<a name="AgentRegistrationInput"></a>
## type [AgentRegistrationInput](<https://github.com/dnsid-ai/dnsid-go/blob/main/registry.go#L89-L101>)

AgentRegistrationInput is input for registering a local identity with a registry.

```go
type AgentRegistrationInput struct {
    GovernanceDomain string         `json:"governance_domain,omitempty"`
    RootDomain       string         `json:"root_domain,omitempty"`
    Name             string         `json:"name,omitempty"`
    ZoneID           string         `json:"zone_id,omitempty"`
    Tier             string         `json:"tier,omitempty"`
    CapabilitiesURL  string         `json:"capabilities_url,omitempty"`
    Domain           string         `json:"domain,omitempty"`
    Metadata         map[string]any `json:"metadata,omitempty"`
    PublicKeyJWK     any            `json:"public_key,omitempty"`
    Environment      string         `json:"environment,omitempty"`
    Managed          bool           `json:"managed,omitempty"`
}
```

<a name="AgentState"></a>
## type [CanonicalRecordContentResponse](<https://github.com/dnsid-ai/dnsid-go/blob/main/registry.go#L43-L47>)

CanonicalRecordContentResponse is registry\-prepared unsigned canonical TXT content.

```go
type CanonicalRecordContentResponse struct {
    Canonical  string          `json:"canonical"`
    SigningKid string          `json:"signingKid"`
    Raw        json.RawMessage `json:"raw,omitempty"`
}
```

<a name="ChallengeRequest"></a>
## type [ChallengeRequest](<https://github.com/dnsid-ai/dnsid-go/blob/main/registry.go#L310-L313>)

ChallengeRequest matches the OpenAPI ChallengeRequest schema.

```go
type ChallengeRequest struct {
    Nonce     string `json:"nonce"`
    Signature string `json:"signature"`
}
```

<a name="Config"></a>
## type [CreateAgentRequest](<https://github.com/dnsid-ai/dnsid-go/blob/main/registry.go#L143-L156>)

CreateAgentRequest matches the OpenAPI CreateAgentRequest schema.

```go
type CreateAgentRequest struct {
    Domain           string         `json:"domain,omitempty"`
    GovernanceDomain string         `json:"governance_domain,omitempty"`
    RootDomain       string         `json:"root_domain,omitempty"`
    Tier             string         `json:"tier,omitempty"`
    Name             string         `json:"name,omitempty"`
    PublicKey        any            `json:"public_key,omitempty"`
    Metadata         map[string]any `json:"metadata,omitempty"`
    // Optional fields
    Environment     string `json:"environment,omitempty"`
    Managed         bool   `json:"managed,omitempty"`
    ZoneID          string `json:"zone_id,omitempty"`
    CapabilitiesURL string `json:"capabilities_url,omitempty"`
}
```

<a name="CreateAgentResponse"></a>
## type [CreateAgentResponse](<https://github.com/dnsid-ai/dnsid-go/blob/main/registry.go#L159-L168>)

CreateAgentResponse matches the OpenAPI CreateAgentResponse schema.

```go
type CreateAgentResponse struct {
    ID                string            `json:"id"`
    Domain            string            `json:"domain"`
    DomainDisplay     string            `json:"domain_display"`
    Name              string            `json:"name,omitempty"`
    Status            string            `json:"status"`
    StatusURL         string            `json:"status_url"`
    PublicationConfig PublicationConfig `json:"publication_config"`
    OIDCIssuerURL     string            `json:"oidc_issuer_url,omitempty"`
}
```

<a name="DNSRecord"></a>
## type [EventListOptions](<https://github.com/dnsid-ai/dnsid-go/blob/main/registry.go#L450-L453>)

EventListOptions contains optional parameters for GetAgentEvents.

```go
type EventListOptions struct {
    Limit  int
    Cursor string
}
```

<a name="EventListResponse"></a>
## type [EventListResponse](<https://github.com/dnsid-ai/dnsid-go/blob/main/registry.go#L401-L404>)

EventListResponse matches the OpenAPI EventListResponse schema.

```go
type EventListResponse struct {
    Events     []AgentEvent `json:"events"`
    NextCursor *string      `json:"next_cursor,omitempty"`
}
```

<a name="FetchOptions"></a>
## type [HTTPRegistryClient](<https://github.com/dnsid-ai/dnsid-go/blob/main/registry.go#L536-L541>)

HTTPRegistryClient implements RegistryClient against the standard DNSid registry endpoints.

```go
type HTTPRegistryClient struct {
    // contains filtered or unexported fields
}
```

<a name="NewRegistryClient"></a>
### func [NewRegistryClient](<https://github.com/dnsid-ai/dnsid-go/blob/main/registry.go#L597>)

```go
func NewRegistryClient(baseURL string, transportConfig ...TransportConfig) (*HTTPRegistryClient, error)
```

NewRegistryClient creates an HTTP registry client for baseURL. An empty baseURL means DefaultRegistryURL \(the local registry\). HTTPS is required except on loopback hosts.

<a name="NewRegistryClientWithOptions"></a>
### func [NewRegistryClientWithOptions](<https://github.com/dnsid-ai/dnsid-go/blob/main/registry.go#L610>)

```go
func NewRegistryClientWithOptions(baseURL string, opts ...RegistryClientOption) (*HTTPRegistryClient, error)
```

NewRegistryClientWithOptions creates an HTTP registry client with functional options. URL rules follow NewRegistryClient.

<a name="HTTPRegistryClient.CancelAgent"></a>
### func \(\*HTTPRegistryClient\) [CancelAgent](<https://github.com/dnsid-ai/dnsid-go/blob/main/registry.go#L1018>)

```go
func (c *HTTPRegistryClient) CancelAgent(ctx context.Context, fqdn string) (*LifecycleResponse, error)
```

CancelAgent cancels an in\-progress registration workflow for fqdn.

<a name="HTTPRegistryClient.CanonicalRecordContent"></a>
### func \(\*HTTPRegistryClient\) [CanonicalRecordContent](<https://github.com/dnsid-ai/dnsid-go/blob/main/registry.go#L662>)

```go
func (c *HTTPRegistryClient) CanonicalRecordContent(ctx context.Context, domain, signingKid string) (*CanonicalRecordContentResponse, error)
```

CanonicalRecordContent fetches the registry\-prepared unsigned canonical TXT content for domain, targeted at the given record\-signing kid.

<a name="HTTPRegistryClient.ConfirmReady"></a>
### func \(\*HTTPRegistryClient\) [ConfirmReady](<https://github.com/dnsid-ai/dnsid-go/blob/main/registry.go#L1035>)

```go
func (c *HTTPRegistryClient) ConfirmReady(ctx context.Context, fqdn string) (*LifecycleResponse, error)
```

ConfirmReady confirms the agent at fqdn is ready to go live. It is an alias for VerifyAgent.

<a name="HTTPRegistryClient.CreateAgent"></a>
### func \(\*HTTPRegistryClient\) [CreateAgent](<https://github.com/dnsid-ai/dnsid-go/blob/main/registry.go#L703>)

```go
func (c *HTTPRegistryClient) CreateAgent(ctx context.Context, req *CreateAgentRequest) (*CreateAgentResponse, error)
```

CreateAgent performs ordinary registration without retry\-safe replay. The registry resolves hosting; no legacy defaults are injected. Use CreateLiveAgent for managed Live registration.

<a name="HTTPRegistryClient.CreateAgentWithIdempotencyKey"></a>
### func \(\*HTTPRegistryClient\) [CreateAgentWithIdempotencyKey](<https://github.com/dnsid-ai/dnsid-go/blob/main/registry.go#L709>)

```go
func (c *HTTPRegistryClient) CreateAgentWithIdempotencyKey(ctx context.Context, req *CreateAgentRequest, idempotencyKey string) (*CreateAgentResponse, error)
```

CreateAgentWithIdempotencyKey creates an ordinary HTTP 201 registration. Retry only with the same request and non\-empty key. No automatic retry occurs.

<a name="HTTPRegistryClient.CreateLiveAgent"></a>
### func \(\*HTTPRegistryClient\) [CreateLiveAgent](<https://github.com/dnsid-ai/dnsid-go/blob/main/registry.go#L782>)

```go
func (c *HTTPRegistryClient) CreateLiveAgent(ctx context.Context, req *LiveAgentRegistrationInput, idempotencyKey string) (*LiveProvisioningResponse, error)
```

CreateLiveAgent starts the separate managed Live HTTP 202 flow. It sends tier="live", managed=true, and environment="production". The idempotency key is required and must be reused for retries.

<a name="HTTPRegistryClient.GetAgentEvents"></a>
### func \(\*HTTPRegistryClient\) [GetAgentEvents](<https://github.com/dnsid-ai/dnsid-go/blob/main/registry.go#L919>)

```go
func (c *HTTPRegistryClient) GetAgentEvents(ctx context.Context, fqdn string, opts *EventListOptions) (*EventListResponse, error)
```

GetAgentEvents lists registry audit events for the agent at fqdn. A nil opts requests the first page with the server's default limit.

<a name="HTTPRegistryClient.GetAgentStatus"></a>
### func \(\*HTTPRegistryClient\) [GetAgentStatus](<https://github.com/dnsid-ai/dnsid-go/blob/main/registry.go#L851>)

```go
func (c *HTTPRegistryClient) GetAgentStatus(ctx context.Context, fqdn string) (*AgentDetail, error)
```

GetAgentStatus returns the registry's detailed view of the agent at fqdn, including workflow status, DNS publication state, and any workflow error.

<a name="HTTPRegistryClient.GetIdentityRecord"></a>
### func \(\*HTTPRegistryClient\) [GetIdentityRecord](<https://github.com/dnsid-ai/dnsid-go/blob/main/registry.go#L1265>)

```go
func (c *HTTPRegistryClient) GetIdentityRecord(ctx context.Context, fqdn string, req *IdentityRecordRequest) (*IdentityRecordResponse, error)
```

GetIdentityRecord fetches the registry\-prepared canonical identity record content for fqdn, targeted at the signing kid named in req.

<a name="HTTPRegistryClient.GetOrganizationOnboarding"></a>
### func \(\*HTTPRegistryClient\) [GetOrganizationOnboarding](<https://github.com/dnsid-ai/dnsid-go/blob/main/registry.go#L873>)

```go
func (c *HTTPRegistryClient) GetOrganizationOnboarding(ctx context.Context) (*OrganizationOnboardingResponse, error)
```

GetOrganizationOnboarding reads the authenticated organization's onboarding state using the client transport and caller deadline. It never falls back to anonymous access or creates an agent.

<a name="HTTPRegistryClient.GetRegistration"></a>
### func \(\*HTTPRegistryClient\) [GetRegistration](<https://github.com/dnsid-ai/dnsid-go/blob/main/registry.go#L885>)

```go
func (c *HTTPRegistryClient) GetRegistration(ctx context.Context, fqdn string) (*AgentRegistration, error)
```

GetRegistration returns normalized registry workflow state for fqdn, mapping the registry's managed mode \("self" or "dnsid"\) to a PublicationAuthority. It returns a \*ValidationError for unknown managed modes.

<a name="HTTPRegistryClient.ListAgents"></a>
### func \(\*HTTPRegistryClient\) [ListAgents](<https://github.com/dnsid-ai/dnsid-go/blob/main/registry.go#L832>)

```go
func (c *HTTPRegistryClient) ListAgents(ctx context.Context, opts *ListAgentsOptions) (*AgentListResponse, error)
```

ListAgents lists the caller's agents. A nil opts requests the first page with the server's default limit; use the response's NextCursor to page.

<a name="HTTPRegistryClient.ListExpiringAgents"></a>
### func \(\*HTTPRegistryClient\) [ListExpiringAgents](<https://github.com/dnsid-ai/dnsid-go/blob/main/registry.go#L1276>)

```go
func (c *HTTPRegistryClient) ListExpiringAgents(ctx context.Context) (*OperationsAgentListResponse, error)
```

ListExpiringAgents lists agents whose identity records are approaching expiry.

<a name="HTTPRegistryClient.ListFlaggedAgents"></a>
### func \(\*HTTPRegistryClient\) [ListFlaggedAgents](<https://github.com/dnsid-ai/dnsid-go/blob/main/registry.go#L1282>)

```go
func (c *HTTPRegistryClient) ListFlaggedAgents(ctx context.Context) (*OperationsAgentListResponse, error)
```

ListFlaggedAgents lists agents the registry has flagged for operator attention.

<a name="HTTPRegistryClient.ListPendingAgents"></a>
### func \(\*HTTPRegistryClient\) [ListPendingAgents](<https://github.com/dnsid-ai/dnsid-go/blob/main/registry.go#L1288>)

```go
func (c *HTTPRegistryClient) ListPendingAgents(ctx context.Context) (*OperationsAgentListResponse, error)
```

ListPendingAgents lists agents whose registration workflows have not yet completed.

<a name="HTTPRegistryClient.PrepareIssuance"></a>
### func \(\*HTTPRegistryClient\) [PrepareIssuance](<https://github.com/dnsid-ai/dnsid-go/blob/main/registry.go#L1180>)

```go
func (c *HTTPRegistryClient) PrepareIssuance(ctx context.Context, fqdn, idempotencyKey string) (*PreparedRegistryEvent, error)
```

PrepareIssuance asks the registry to prepare a transparency\-log ISSUANCE event for fqdn. The returned entry bytes are untrusted: parse and validate them against the returned log reference before signing. The idempotency key must be 1 to 200 bytes without surrounding whitespace; reuse the same key when retrying.

<a name="HTTPRegistryClient.PrepareKeyRotation"></a>
### func \(\*HTTPRegistryClient\) [PrepareKeyRotation](<https://github.com/dnsid-ai/dnsid-go/blob/main/registry.go#L1200>)

```go
func (c *HTTPRegistryClient) PrepareKeyRotation(ctx context.Context, fqdn string, req *KeyRotationPreparationRequest, idempotencyKey string) (*PreparedRegistryEvent, error)
```

PrepareKeyRotation asks the registry to prepare a transparency\-log KEY\_ROTATION event for fqdn. Authenticate with an organization session or API key; an agent bearer token is not accepted. The request must name the previous key ID and carry the new public key, which is rejected if it contains private JWK members. As with PrepareIssuance, the returned entry bytes are untrusted and must be validated before signing.

<a name="HTTPRegistryClient.PublishSignature"></a>
### func \(\*HTTPRegistryClient\) [PublishSignature](<https://github.com/dnsid-ai/dnsid-go/blob/main/registry.go#L675>)

```go
func (c *HTTPRegistryClient) PublishSignature(ctx context.Context, domain, sig string) (*PublishedRecord, error)
```

PublishSignature submits an encoded record signature for domain and returns the resulting publication state as a PublishedRecord.

<a name="HTTPRegistryClient.RegisterAgent"></a>
### func \(\*HTTPRegistryClient\) [RegisterAgent](<https://github.com/dnsid-ai/dnsid-go/blob/main/registration.go#L47>)

```go
func (c *HTTPRegistryClient) RegisterAgent(ctx context.Context, input *AgentRegistrationInput, idempotencyKey string) (*AgentRegistration, error)
```

RegisterAgent creates an identity and reads publication authority from authenticated management detail. The optional key is transport metadata. Creation facts survive a failed detail read in RegistrationError.

<a name="HTTPRegistryClient.ReissueLiveProof"></a>
### func \(\*HTTPRegistryClient\) [ReissueLiveProof](<https://github.com/dnsid-ai/dnsid-go/blob/main/registry.go#L967>)

```go
func (c *HTTPRegistryClient) ReissueLiveProof(ctx context.Context, fqdn string, req *LiveProofReissueRequest) (*LiveProofReissueResponse, error)
```

ReissueLiveProof requests a replacement challenge for an expired Live proof. RequestID is also sent as the required Idempotency\-Key header.

<a name="HTTPRegistryClient.RejectAgent"></a>
### func \(\*HTTPRegistryClient\) [RejectAgent](<https://github.com/dnsid-ai/dnsid-go/blob/main/registry.go#L1023>)

```go
func (c *HTTPRegistryClient) RejectAgent(ctx context.Context, fqdn string) (*LifecycleResponse, error)
```

RejectAgent marks the registration workflow for fqdn as rejected.

<a name="HTTPRegistryClient.RetireAgent"></a>
### func \(\*HTTPRegistryClient\) [RetireAgent](<https://github.com/dnsid-ai/dnsid-go/blob/main/registry.go#L1010>)

```go
func (c *HTTPRegistryClient) RetireAgent(ctx context.Context, fqdn string, req *RetireAgentRequest) (*LifecycleResponse, error)
```

RetireAgent retires the immutable agent identity without revoking its key.

<a name="HTTPRegistryClient.RevokeAgent"></a>
### func \(\*HTTPRegistryClient\) [RevokeAgent](<https://github.com/dnsid-ai/dnsid-go/blob/main/registry.go#L999>)

```go
func (c *HTTPRegistryClient) RevokeAgent(ctx context.Context, fqdn string, req *RevokeAgentRequest) (*LifecycleResponse, error)
```

RevokeAgent revokes the immutable agent identity at fqdn with the supplied reason. Revocation is a terminal lifecycle transition whose persistence and transparency\-log append are owned by the registry.

<a name="HTTPRegistryClient.SetAuthToken"></a>
### func \(\*HTTPRegistryClient\) [SetAuthToken](<https://github.com/dnsid-ai/dnsid-go/blob/main/registry.go#L583>)

```go
func (c *HTTPRegistryClient) SetAuthToken(token string) error
```

SetAuthToken updates the Bearer token on an existing client \(e.g. after refresh\). It returns an error if the client is configured for plaintext HTTP on a non\-loopback host without WithInsecureHTTP.

<a name="HTTPRegistryClient.SubmitChallenge"></a>
### func \(\*HTTPRegistryClient\) [SubmitChallenge](<https://github.com/dnsid-ai/dnsid-go/blob/main/registry.go#L938>)

```go
func (c *HTTPRegistryClient) SubmitChallenge(ctx context.Context, fqdn string, req *ChallengeRequest) error
```

SubmitChallenge submits a signed domain\-control challenge response for the agent at fqdn. A nil error means the registry accepted the submission.

<a name="HTTPRegistryClient.SubmitLiveProof"></a>
### func \(\*HTTPRegistryClient\) [SubmitLiveProof](<https://github.com/dnsid-ai/dnsid-go/blob/main/registry.go#L945>)

```go
func (c *HTTPRegistryClient) SubmitLiveProof(ctx context.Context, fqdn string, req *LiveProofRequest) (*LiveProofResponse, error)
```

SubmitLiveProof submits proof of possession for a managed Live registration. RequestID is also sent as the required Idempotency\-Key header.

<a name="HTTPRegistryClient.SubmitPreparedEvent"></a>
### func \(\*HTTPRegistryClient\) [SubmitPreparedEvent](<https://github.com/dnsid-ai/dnsid-go/blob/main/registry.go#L1230>)

```go
func (c *HTTPRegistryClient) SubmitPreparedEvent(ctx context.Context, fqdn string, entryBytes []byte, idempotencyKey string) (*SubmissionResult, error)
```

SubmitPreparedEvent submits the exact signed entry bytes of a prepared event \(1 to 65535 bytes\) for transparency\-log inclusion. On an accepted result it verifies that the registry's reported entry hash matches the SHA\-256 of the submitted bytes and returns a \*ValidationError on mismatch. Retry with the same bytes and idempotency key when the registry reports a retryable state \(see RegistryAPIError.RetrySameEntry\).

<a name="HTTPRegistryClient.SubmitSignature"></a>
### func \(\*HTTPRegistryClient\) [SubmitSignature](<https://github.com/dnsid-ai/dnsid-go/blob/main/registry.go#L1270>)

```go
func (c *HTTPRegistryClient) SubmitSignature(ctx context.Context, fqdn string, req *SignatureRequest) (*SignatureResponse, error)
```

SubmitSignature posts a signature through the legacy self\-managed identity\-record endpoint.

<a name="HTTPRegistryClient.UnregisterAgent"></a>
### func \(\*HTTPRegistryClient\) [UnregisterAgent](<https://github.com/dnsid-ai/dnsid-go/blob/main/registry.go#L821>)

```go
func (c *HTTPRegistryClient) UnregisterAgent(ctx context.Context, fqdn string) error
```

UnregisterAgent removes the agent at fqdn. It is best\-effort for registry compatibility: an already\-absent agent or a registry without DELETE support is treated as a successful no\-op.

<a name="HTTPRegistryClient.VerifyAgent"></a>
### func \(\*HTTPRegistryClient\) [VerifyAgent](<https://github.com/dnsid-ai/dnsid-go/blob/main/registry.go#L1029>)

```go
func (c *HTTPRegistryClient) VerifyAgent(ctx context.Context, fqdn string) (*LifecycleResponse, error)
```

VerifyAgent asks the registry to run its verification step for fqdn and advance the registration workflow.

<a name="HTTPRegistryClient.VerifyDomainRemote"></a>
### func \(\*HTTPRegistryClient\) [VerifyDomainRemote](<https://github.com/dnsid-ai/dnsid-go/blob/main/registry.go#L1295>)

```go
func (c *HTTPRegistryClient) VerifyDomainRemote(ctx context.Context, req *VerifyDomainRequest) (*VerifyDomainResponse, error)
```

VerifyDomainRemote asks the registry to check a domain's DNSid state from its vantage point. It complements, but does not replace, local IdentityManager.VerifyDomain verification.

<a name="HTTPRegistryClient.WaitForStatus"></a>
### func \(\*HTTPRegistryClient\) [WaitForStatus](<https://github.com/dnsid-ai/dnsid-go/blob/main/registry.go#L1301>)

```go
func (c *HTTPRegistryClient) WaitForStatus(ctx context.Context, fqdn string, targetStatuses []string, opts *WaitForStatusOptions) (*AgentDetail, error)
```

WaitForStatus polls the registry until the agent at fqdn reaches one of targetStatuses. It is shorthand for WaitForRegistryStatus with this client.

<a name="HTTPSFetcher"></a>
## type [IdentityRecordRequest](<https://github.com/dnsid-ai/dnsid-go/blob/main/registry.go#L273-L275>)

IdentityRecordRequest matches the OpenAPI IdentityRecordRequest schema.

```go
type IdentityRecordRequest struct {
    SigningKid string `json:"signingKid"`
}
```

<a name="IdentityRecordResponse"></a>
## type [IdentityRecordResponse](<https://github.com/dnsid-ai/dnsid-go/blob/main/registry.go#L278-L284>)

IdentityRecordResponse matches the OpenAPI IdentityRecordResponse schema.

```go
type IdentityRecordResponse struct {
    FQDN             string            `json:"fqdn"`
    CanonicalContent string            `json:"canonicalContent"`
    SigningKid       string            `json:"signingKid"`
    ExpiresAt        string            `json:"expiresAt"`
    Tags             map[string]string `json:"tags"`
}
```

<a name="IdentityResolver"></a>
## type [KeyRotationPreparationRequest](<https://github.com/dnsid-ai/dnsid-go/blob/main/registry.go#L50-L53>)

KeyRotationPreparationRequest requests a prepared operational\-key rotation.

```go
type KeyRotationPreparationRequest struct {
    PreviousKeyID string `json:"previous_key_id"`
    PublicKey     any    `json:"public_key"`
}
```

<a name="KeySignature"></a>
## type [LifecycleResponse](<https://github.com/dnsid-ai/dnsid-go/blob/main/registry.go#L384-L388>)

LifecycleResponse matches the OpenAPI LifecycleResponse schema.

```go
type LifecycleResponse struct {
    ID         string `json:"id"`
    Status     string `json:"status"`
    StatusNote string `json:"status_note,omitempty"`
}
```

<a name="ListAgentsOptions"></a>
## type [ListAgentsOptions](<https://github.com/dnsid-ai/dnsid-go/blob/main/registry.go#L444-L447>)

ListAgentsOptions contains optional parameters for ListAgents.

```go
type ListAgentsOptions struct {
    Limit  int
    Cursor string
}
```

<a name="LiveAgentRegistrationInput"></a>
## type [LiveAgentRegistrationInput](<https://github.com/dnsid-ai/dnsid-go/blob/main/registry.go#L173-L179>)

LiveAgentRegistrationInput is the caller\-controlled input for managed Live registration. The client supplies the fixed tier, managed, and environment fields on the wire.

```go
type LiveAgentRegistrationInput struct {
    Name string `json:"name,omitempty"`
    // PublicKey must be one public OKP/Ed25519 signing JWK with alg=EdDSA.
    PublicKey       any    `json:"public_key"`
    Environment     string `json:"environment,omitempty"`
    CapabilitiesURL string `json:"capabilities_url,omitempty"`
}
```

<a name="LiveChallengeTranscript"></a>
## type [LiveChallengeTranscript](<https://github.com/dnsid-ai/dnsid-go/blob/main/registry.go#L183-L191>)

LiveChallengeTranscript is the validated proof\-of\-possession transcript decoded from a Live challenge message.

```go
type LiveChallengeTranscript struct {
    Protocol  string    `json:"protocol"`
    OrgID     string    `json:"org_id"`
    AgentID   string    `json:"agent_id"`
    FQDN      string    `json:"fqdn"`
    KeyID     string    `json:"key_id"`
    Nonce     string    `json:"nonce"`
    ExpiresAt time.Time `json:"expires_at"`
}
```

<a name="LiveProofReissueRequest"></a>
## type [LiveProofReissueRequest](<https://github.com/dnsid-ai/dnsid-go/blob/main/registry.go#L335-L339>)

LiveProofReissueRequest requests a fresh challenge after an expired proof.

```go
type LiveProofReissueRequest struct {
    RequestID string `json:"request_id"`
    // PublicKey is the original Live registration key and is not sent on the wire.
    PublicKey any `json:"-"`
}
```

<a name="LiveProofReissueResponse"></a>
## type [LiveProofReissueResponse](<https://github.com/dnsid-ai/dnsid-go/blob/main/registry.go#L343-L351>)

LiveProofReissueResponse contains the replacement Live proof challenge. Domain and ChallengeTranscript are derived from the validated latest message.

```go
type LiveProofReissueResponse struct {
    RequestID           string                   `json:"request_id"`
    AgentID             string                   `json:"agent_id"`
    Status              string                   `json:"status"`
    Challenge           string                   `json:"challenge"`
    ChallengeMessage    string                   `json:"challenge_message"`
    Domain              string                   `json:"-"`
    ChallengeTranscript *LiveChallengeTranscript `json:"-"`
}
```

<a name="LiveProofRequest"></a>
## type [LiveProofRequest](<https://github.com/dnsid-ai/dnsid-go/blob/main/registry.go#L316-L325>)

LiveProofRequest proves possession of the key supplied for Live registration.

```go
type LiveProofRequest struct {
    RequestID string `json:"request_id"`
    // Challenge must come from the latest registration or reissue response.
    Challenge string `json:"challenge"`
    PublicKey any    `json:"public_key"`
    // Signature is unpadded base64url Ed25519 over the exact bytes obtained by
    // base64url-decoding that response's ChallengeMessage. Do not reserialize
    // ChallengeTranscript before signing.
    Signature string `json:"signature"`
}
```

<a name="LiveProofResponse"></a>
## type [LiveProofResponse](<https://github.com/dnsid-ai/dnsid-go/blob/main/registry.go#L328-L332>)

LiveProofResponse reports the durable Live proof handoff status.

```go
type LiveProofResponse struct {
    RequestID string `json:"request_id"`
    AgentID   string `json:"agent_id"`
    Status    string `json:"status"`
}
```

<a name="LiveProvisioningResponse"></a>
## type [LiveProvisioningResponse](<https://github.com/dnsid-ai/dnsid-go/blob/main/registry.go#L196-L204>)

LiveProvisioningResponse is the HTTP 202 response for a managed Live registration. Domain and ChallengeTranscript are derived and populated while Status is challenge\_pending.

```go
type LiveProvisioningResponse struct {
    RequestID           string                   `json:"request_id"`
    AgentID             string                   `json:"agent_id"`
    Status              string                   `json:"status"`
    Challenge           string                   `json:"challenge"`
    ChallengeMessage    string                   `json:"challenge_message"`
    Domain              string                   `json:"-"`
    ChallengeTranscript *LiveChallengeTranscript `json:"-"`
}
```

<a name="LocalKeyProvider"></a>
## type [OperationsAgent](<https://github.com/dnsid-ai/dnsid-go/blob/main/registry.go#L407-L418>)

OperationsAgent matches the OpenAPI OperationsAgent schema.

```go
type OperationsAgent struct {
    ID                      string      `json:"id"`
    Domain                  string      `json:"domain"`
    DomainDisplay           string      `json:"domain_display"`
    Environment             string      `json:"environment"`
    Status                  string      `json:"status"`
    DaysRemaining           *int        `json:"days_remaining,omitempty"`
    IdentityRecordExpiresAt *string     `json:"identity_record_expires_at,omitempty"`
    Error                   *AgentError `json:"error,omitempty"`
    CreatedAt               time.Time   `json:"created_at"`
    UpdatedAt               time.Time   `json:"updated_at"`
}
```

<a name="OperationsAgentListResponse"></a>
## type [OperationsAgentListResponse](<https://github.com/dnsid-ai/dnsid-go/blob/main/registry.go#L421-L423>)

OperationsAgentListResponse matches the OpenAPI OperationsAgentListResponse schema.

```go
type OperationsAgentListResponse struct {
    Agents []OperationsAgent `json:"agents"`
}
```

<a name="OrganizationOnboardingResponse"></a>
## type [OrganizationOnboardingResponse](<https://github.com/dnsid-ai/dnsid-go/blob/main/registry.go#L857-L868>)

OrganizationOnboardingResponse contains authenticated account bindings and live proof/delegation readiness, not an entity\-key URL or trust root.

```go
type OrganizationOnboardingResponse struct {
    OrganizationID   string `json:"org_id"`
    GovernanceDomain string `json:"governance_domain"`
    GI               *struct {
        Domain         string `json:"domain"`
        State          string `json:"state"`
        GateAuthorized bool   `json:"gate_authorized"`
    }   `json:"gi"`
    EK  struct {
        Status string `json:"status"`
    }   `json:"ek"`
}
```

<a name="ParseError"></a>
## type [PreparedRegistryEvent](<https://github.com/dnsid-ai/dnsid-go/blob/main/registry.go#L58-L61>)

PreparedRegistryEvent contains the untrusted exact bytes and log reference returned by a registry preparation endpoint. Parse and validate EntryBytes against LogReference with the selected log binding before signing.

```go
type PreparedRegistryEvent struct {
    EntryBytes   []byte
    LogReference string
}
```

<a name="PublicationAuthority"></a>
## type [PublicationAuthority](<https://github.com/dnsid-ai/dnsid-go/blob/main/registry.go#L105>)

PublicationAuthority identifies who controls the accountable\-entity key and signs the DNSid record.

```go
type PublicationAuthority string
```

<a name="PublicationAuthorityClient"></a>PublicationAuthority values: the client holds the entity key and signs the record itself, or the registry does so on the client's behalf.

```go
const (
    PublicationAuthorityClient   PublicationAuthority = "client"
    PublicationAuthorityRegistry PublicationAuthority = "registry"
)
```

<a name="PublicationConfig"></a>
## type [PublicationConfig](<https://github.com/dnsid-ai/dnsid-go/blob/main/registry.go#L208-L217>)

PublicationConfig is the authoritative set of profile\-known values the registry uses to construct an agent's unsigned identity record.

```go
type PublicationConfig struct {
    PublishProfile  string `json:"publish_profile"`
    GovernanceID    string `json:"governance_id"`
    KeyURL          string `json:"ku_url"` // Operational-key JWKS URL.
    EntityKeyURL    string `json:"ek_url"` // Accountable-entity JWKS URL.
    LogRef          string `json:"log_ref"`
    StatusURL       string `json:"status_url"`
    CapabilitiesURL string `json:"capabilities_url,omitempty"`
    MaxKeyAge       string `json:"max_key_age,omitempty"`
}
```

<a name="PublishedRecord"></a>
## type [PublishedRecord](<https://github.com/dnsid-ai/dnsid-go/blob/main/registry.go#L130-L138>)

PublishedRecord is the result of a registry TXT publication workflow.

```go
type PublishedRecord struct {
    Domain            string          `json:"domain"`
    OwnerName         string          `json:"ownerName"`
    TXTRecord         string          `json:"txtRecord"`
    TTL               int             `json:"ttl"`
    PublicationStatus string          `json:"publicationStatus"`
    ProtocolStatus    *AgentStatus    `json:"protocolStatus,omitempty"`
    Raw               json.RawMessage `json:"raw,omitempty"`
}
```

<a name="RedirectPolicy"></a>
## type [RegistryClient](<https://github.com/dnsid-ai/dnsid-go/blob/main/registry.go#L483-L516>)

RegistryClient is the full control\-plane client for the DNSid registry API.

```go
type RegistryClient interface {
    RegistryPublisher

    // Agent CRUD
    CreateAgent(ctx context.Context, req *CreateAgentRequest) (*CreateAgentResponse, error)
    CreateLiveAgent(ctx context.Context, req *LiveAgentRegistrationInput, idempotencyKey string) (*LiveProvisioningResponse, error)
    UnregisterAgent(ctx context.Context, fqdn string) error
    ListAgents(ctx context.Context, opts *ListAgentsOptions) (*AgentListResponse, error)
    GetAgentStatus(ctx context.Context, fqdn string) (*AgentDetail, error)
    GetAgentEvents(ctx context.Context, fqdn string, opts *EventListOptions) (*EventListResponse, error)

    // Agent lifecycle
    SubmitChallenge(ctx context.Context, fqdn string, req *ChallengeRequest) error
    SubmitLiveProof(ctx context.Context, fqdn string, req *LiveProofRequest) (*LiveProofResponse, error)
    ReissueLiveProof(ctx context.Context, fqdn string, req *LiveProofReissueRequest) (*LiveProofReissueResponse, error)
    RevokeAgent(ctx context.Context, fqdn string, req *RevokeAgentRequest) (*LifecycleResponse, error)
    RetireAgent(ctx context.Context, fqdn string, req *RetireAgentRequest) (*LifecycleResponse, error)
    CancelAgent(ctx context.Context, fqdn string) (*LifecycleResponse, error)
    RejectAgent(ctx context.Context, fqdn string) (*LifecycleResponse, error)
    VerifyAgent(ctx context.Context, fqdn string) (*LifecycleResponse, error)
    ConfirmReady(ctx context.Context, fqdn string) (*LifecycleResponse, error)

    // Identity record (new API paths)
    GetIdentityRecord(ctx context.Context, fqdn string, req *IdentityRecordRequest) (*IdentityRecordResponse, error)
    SubmitSignature(ctx context.Context, fqdn string, req *SignatureRequest) (*SignatureResponse, error)

    // Operations
    ListExpiringAgents(ctx context.Context) (*OperationsAgentListResponse, error)
    ListFlaggedAgents(ctx context.Context) (*OperationsAgentListResponse, error)
    ListPendingAgents(ctx context.Context) (*OperationsAgentListResponse, error)

    // Verification
    VerifyDomainRemote(ctx context.Context, req *VerifyDomainRequest) (*VerifyDomainResponse, error)
}
```

<a name="RegistryClientControlledPublisher"></a>
## type [RegistryClientControlledPublisher](<https://github.com/dnsid-ai/dnsid-go/blob/main/registry.go#L469-L472>)

RegistryClientControlledPublisher adds the registration state needed to enforce client publication authority before signing.

```go
type RegistryClientControlledPublisher interface {
    RegistryPublisher
    RegistryRegistrationReader
}
```

<a name="RegistryClientOption"></a>
## type [RegistryClientOption](<https://github.com/dnsid-ai/dnsid-go/blob/main/registry.go#L561>)

RegistryClientOption configures an HTTPRegistryClient.

```go
type RegistryClientOption func(*HTTPRegistryClient)
```

<a name="WithAuthToken"></a>
### func [WithAuthToken](<https://github.com/dnsid-ai/dnsid-go/blob/main/registry.go#L564>)

```go
func WithAuthToken(token string) RegistryClientOption
```

WithAuthToken sets a Bearer token for authenticated API calls.

<a name="WithInsecureHTTP"></a>
### func [WithInsecureHTTP](<https://github.com/dnsid-ai/dnsid-go/blob/main/registry.go#L576>)

```go
func WithInsecureHTTP() RegistryClientOption
```

WithInsecureHTTP allows the client to use plaintext HTTP transport. This is intended only for local development and testing; production callers should always use HTTPS.

<a name="WithRegistryHTTPClient"></a>
### func [WithRegistryHTTPClient](<https://github.com/dnsid-ai/dnsid-go/blob/main/registry.go#L569>)

```go
func WithRegistryHTTPClient(client *http.Client) RegistryClientOption
```

WithRegistryHTTPClient sets a custom HTTP client for the registry client.

<a name="RegistryConfig"></a>
## type [RegistryPreparedEventClient](<https://github.com/dnsid-ai/dnsid-go/blob/main/registry.go#L476-L480>)

RegistryPreparedEventClient is the capability required for prepared C2SP transparency\-log preparation and submission transport.

```go
type RegistryPreparedEventClient interface {
    PrepareIssuance(ctx context.Context, fqdn, idempotencyKey string) (*PreparedRegistryEvent, error)
    PrepareKeyRotation(ctx context.Context, fqdn string, req *KeyRotationPreparationRequest, idempotencyKey string) (*PreparedRegistryEvent, error)
    SubmitPreparedEvent(ctx context.Context, fqdn string, entryBytes []byte, idempotencyKey string) (*SubmissionResult, error)
}
```

<a name="RegistryPublisher"></a>
## type [RegistryPublisher](<https://github.com/dnsid-ai/dnsid-go/blob/main/registry.go#L462-L465>)

RegistryPublisher is the canonical\-record and signature\-publication capability shared by registry clients.

```go
type RegistryPublisher interface {
    CanonicalRecordContent(ctx context.Context, domain, signingKid string) (*CanonicalRecordContentResponse, error)
    PublishSignature(ctx context.Context, domain, sig string) (*PublishedRecord, error)
}
```

<a name="RegistryRegistrationReader"></a>
## type [RegistryRegistrationReader](<https://github.com/dnsid-ai/dnsid-go/blob/main/registry.go#L456-L458>)

RegistryRegistrationReader reads normalized registry workflow state.

```go
type RegistryRegistrationReader interface {
    GetRegistration(ctx context.Context, domain string) (*AgentRegistration, error)
}
```

<a name="RegistryRevocationReason"></a>
## type [RegistryRevocationReason](<https://github.com/dnsid-ai/dnsid-go/blob/main/registry.go#L355>)

RegistryRevocationReason is an owner\-authorized registry revocation reason. It is distinct from the protocol REVOCATION reason vocabulary.

```go
type RegistryRevocationReason string
```

<a name="RegistryRevocationReasonOwnerRequest"></a>Owner\-authorized registry revocation reasons.

```go
const (
    RegistryRevocationReasonOwnerRequest  RegistryRevocationReason = "owner_request"
    RegistryRevocationReasonKeyCompromise RegistryRevocationReason = "key_compromise"
)
```

<a name="RegistryRevoker"></a>
## type [RegistryRevoker](<https://github.com/dnsid-ai/dnsid-go/blob/main/log.go#L411-L413>)

RegistryRevoker is the registry capability required for managed revocation.

```go
type RegistryRevoker interface {
    RevokeAgent(ctx context.Context, fqdn string, req *RevokeAgentRequest) (*LifecycleResponse, error)
}
```

<a name="RegistryStatusReader"></a>
## type [RegistryStatusReader](<https://github.com/dnsid-ai/dnsid-go/blob/main/registry.go#L550-L552>)

RegistryStatusReader is the subset needed by WaitForRegistryStatus.

```go
type RegistryStatusReader interface {
    GetAgentStatus(ctx context.Context, fqdn string) (*AgentDetail, error)
}
```

<a name="RegistryWorkflowError"></a>
## type [RetireAgentRequest](<https://github.com/dnsid-ai/dnsid-go/blob/main/registry.go#L379-L381>)

RetireAgentRequest matches the OpenAPI RetireRequest schema.

```go
type RetireAgentRequest struct {
    AgentID string `json:"agent_id"`
}
```

<a name="RevokeAgentRequest"></a>
## type [RevokeAgentRequest](<https://github.com/dnsid-ai/dnsid-go/blob/main/registry.go#L373-L376>)

RevokeAgentRequest matches the OpenAPI RevokeRequest schema.

```go
type RevokeAgentRequest struct {
    AgentID string                   `json:"agent_id"`
    Reason  RegistryRevocationReason `json:"reason"`
}
```

<a name="SDKConformanceMetadata"></a>
## type [SignatureRequest](<https://github.com/dnsid-ai/dnsid-go/blob/main/registry.go#L287-L289>)

SignatureRequest matches the OpenAPI SignatureRequest schema.

```go
type SignatureRequest struct {
    Signature string `json:"signature"`
}
```

<a name="SignatureResponse"></a>
## type [SignatureResponse](<https://github.com/dnsid-ai/dnsid-go/blob/main/registry.go#L301-L307>)

SignatureResponse is the legacy response for POST /agent/\{fqdn\}/signature. Its Status is publication workflow state, not protocol AgentStatus.

```go
type SignatureResponse struct {
    FQDN     string      `json:"fqdn"`
    Status   string      `json:"status"`
    Message  string      `json:"message,omitempty"`
    Records  []DNSRecord `json:"records"`
    ZoneFile string      `json:"zoneFile,omitempty"`
}
```

<a name="SubmissionResult"></a>
## type [SubmissionResult](<https://github.com/dnsid-ai/dnsid-go/blob/main/registry.go#L79-L86>)

SubmissionResult reports registry transparency\-log submission state.

```go
type SubmissionResult struct {
    State     SubmissionState `json:"state"`
    EntryHash string          `json:"entry_hash"`
    Index     *uint64         `json:"index,omitempty"`
    KeyID     string          `json:"key_id,omitempty"`
    LogRef    string          `json:"lr,omitempty"`
    ErrorCode string          `json:"error_code,omitempty"`
}
```

<a name="SubmissionState"></a>
## type [SubmissionState](<https://github.com/dnsid-ai/dnsid-go/blob/main/registry.go#L64>)

SubmissionState is durable registry transparency\-log submission state.

```go
type SubmissionState string
```

<a name="SubmissionStatePending"></a>SubmissionState values. SubmissionStateAccepted and SubmissionStateRejected are terminal; SubmissionStateIndeterminate means the outcome is unknown and the same bytes should be resubmitted with the same idempotency key.

```go
const (
    SubmissionStatePending       SubmissionState = "pending"
    SubmissionStatePrepared      SubmissionState = "prepared"
    SubmissionStateSubmitting    SubmissionState = "submitting"
    SubmissionStateAccepted      SubmissionState = "accepted"
    SubmissionStateRejected      SubmissionState = "rejected"
    SubmissionStateIndeterminate SubmissionState = "indeterminate"
)
```

<a name="TXTRecord"></a>
## type [VerifyDomainRequest](<https://github.com/dnsid-ai/dnsid-go/blob/main/registry.go#L426-L428>)

VerifyDomainRequest matches the OpenAPI VerifyDomainRequest schema.

```go
type VerifyDomainRequest struct {
    Domain string `json:"domain"`
}
```

<a name="VerifyDomainResponse"></a>
## type [VerifyDomainResponse](<https://github.com/dnsid-ai/dnsid-go/blob/main/registry.go#L431-L441>)

VerifyDomainResponse matches the OpenAPI VerifyDomainResponse schema.

```go
type VerifyDomainResponse struct {
    Domain      string  `json:"domain"`
    Registered  bool    `json:"registered"`
    AgentStatus *string `json:"agent_status,omitempty"`
    Reachable   *bool   `json:"reachable,omitempty"`
    KeyMatch    *bool   `json:"key_match,omitempty"`
    VerifiedAt  *string `json:"verified_at,omitempty"`
    ErrorTitle  string  `json:"error_title,omitempty"`
    ErrorDetail string  `json:"error_detail,omitempty"`
    Remediation string  `json:"remediation,omitempty"`
}
```

<a name="WaitForStatusOptions"></a>
## type [WaitForStatusOptions](<https://github.com/dnsid-ai/dnsid-go/blob/main/registry.go#L555-L558>)

WaitForStatusOptions configures registry status polling.

```go
type WaitForStatusOptions struct {
    PollInterval time.Duration
    Timeout      time.Duration
}
```

Generated by [gomarkdoc](<https://github.com/princjef/gomarkdoc>)
