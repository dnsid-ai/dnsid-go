package dnsid

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/lestrrat-go/jwx/v3/jwk"
)

// RegistryConfig contains DNSid registry control-plane settings.
type RegistryConfig struct {
	RegistryURL string
}

// Registry workflow statuses reported by the registry API, alongside the
// AgentState* lifecycle states. READY ends a registration workflow
// successfully; the others are terminal failures.
const (
	RegistryStatusReady     = "READY"
	RegistryStatusCancelled = "CANCELLED"
	RegistryStatusRejected  = "REJECTED"
	RegistryStatusError     = "ERROR"
	RegistryStatusFailed    = "FAILED"
)

// CanonicalRecordContentResponse is registry-prepared unsigned canonical TXT content.
type CanonicalRecordContentResponse struct {
	Canonical  string          `json:"canonical"`
	SigningKid string          `json:"signingKid"`
	Raw        json.RawMessage `json:"raw,omitempty"`
}

// KeyRotationPreparationRequest requests a prepared operational-key rotation.
type KeyRotationPreparationRequest struct {
	PreviousKeyID string `json:"previous_key_id"`
	PublicKey     any    `json:"public_key"`
}

// PreparedRegistryEvent contains the untrusted exact bytes and log reference
// returned by a registry preparation endpoint. Parse and validate EntryBytes
// against LogReference with the selected log binding before signing.
type PreparedRegistryEvent struct {
	EntryBytes   []byte
	LogReference string
}

// SubmissionState is durable registry transparency-log submission state.
type SubmissionState string

// SubmissionState values. SubmissionStateAccepted and SubmissionStateRejected
// are terminal; SubmissionStateIndeterminate means the outcome is unknown and
// the same bytes should be resubmitted with the same idempotency key.
const (
	SubmissionStatePending       SubmissionState = "pending"
	SubmissionStatePrepared      SubmissionState = "prepared"
	SubmissionStateSubmitting    SubmissionState = "submitting"
	SubmissionStateAccepted      SubmissionState = "accepted"
	SubmissionStateRejected      SubmissionState = "rejected"
	SubmissionStateIndeterminate SubmissionState = "indeterminate"
)

// SubmissionResult reports registry transparency-log submission state.
type SubmissionResult struct {
	State     SubmissionState `json:"state"`
	EntryHash string          `json:"entry_hash"`
	Index     *uint64         `json:"index,omitempty"`
	KeyID     string          `json:"key_id,omitempty"`
	LogRef    string          `json:"lr,omitempty"`
	ErrorCode string          `json:"error_code,omitempty"`
}

// AgentRegistrationInput is input for registering a local identity with a registry.
type AgentRegistrationInput struct {
	Domain       string         `json:"domain"`
	Metadata     map[string]any `json:"metadata,omitempty"`
	PublicKeyJWK any            `json:"publicKeyJwk,omitempty"`
	Environment  string         `json:"environment,omitempty"`
	Managed      bool           `json:"managed,omitempty"`
}

// PublicationAuthority identifies who controls the accountable-entity key and
// signs the DNSid record.
type PublicationAuthority string

// PublicationAuthority values: the client holds the entity key and signs the
// record itself, or the registry does so on the client's behalf.
const (
	PublicationAuthorityClient   PublicationAuthority = "client"
	PublicationAuthorityRegistry PublicationAuthority = "registry"
)

// AgentRegistration is normalized registry workflow state for a local identity.
type AgentRegistration struct {
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

// PublishedRecord is the result of a registry TXT publication workflow.
type PublishedRecord struct {
	Domain            string          `json:"domain"`
	OwnerName         string          `json:"ownerName"`
	TXTRecord         string          `json:"txtRecord"`
	TTL               int             `json:"ttl"`
	PublicationStatus string          `json:"publicationStatus"`
	ProtocolStatus    *AgentStatus    `json:"protocolStatus,omitempty"`
	Raw               json.RawMessage `json:"raw,omitempty"`
}

// --- API types matching OpenAPI schemas ---

// CreateAgentRequest matches the OpenAPI CreateAgentRequest schema.
type CreateAgentRequest struct {
	Domain    string `json:"domain,omitempty"`
	Name      string `json:"name,omitempty"`
	PublicKey any    `json:"public_key"`
	// Optional fields
	Environment     string `json:"environment,omitempty"`
	Managed         bool   `json:"managed,omitempty"`
	ZoneID          string `json:"zone_id,omitempty"`
	CapabilitiesURL string `json:"capabilities_url,omitempty"`
}

// CreateAgentResponse matches the OpenAPI CreateAgentResponse schema.
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

// LiveAgentRegistrationInput is the caller-controlled input for managed Live
// registration. The client supplies the fixed tier, managed, and environment
// fields on the wire.
type LiveAgentRegistrationInput struct {
	Name string `json:"name,omitempty"`
	// PublicKey must be one public OKP/Ed25519 signing JWK with alg=EdDSA.
	PublicKey       any    `json:"public_key"`
	Environment     string `json:"environment,omitempty"`
	CapabilitiesURL string `json:"capabilities_url,omitempty"`
}

// LiveChallengeTranscript is the validated proof-of-possession transcript
// decoded from a Live challenge message.
type LiveChallengeTranscript struct {
	Protocol  string    `json:"protocol"`
	OrgID     string    `json:"org_id"`
	AgentID   string    `json:"agent_id"`
	FQDN      string    `json:"fqdn"`
	KeyID     string    `json:"key_id"`
	Nonce     string    `json:"nonce"`
	ExpiresAt time.Time `json:"expires_at"`
}

// LiveProvisioningResponse is the HTTP 202 response for a managed Live
// registration. Domain and ChallengeTranscript are derived and populated while
// Status is challenge_pending.
type LiveProvisioningResponse struct {
	RequestID           string                   `json:"request_id"`
	AgentID             string                   `json:"agent_id"`
	Status              string                   `json:"status"`
	Challenge           string                   `json:"challenge"`
	ChallengeMessage    string                   `json:"challenge_message"`
	Domain              string                   `json:"-"`
	ChallengeTranscript *LiveChallengeTranscript `json:"-"`
}

// PublicationConfig is the authoritative set of profile-known values the
// registry uses to construct an agent's unsigned identity record.
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

// AgentListItem matches the OpenAPI Agent schema.
type AgentListItem struct {
	ID            string    `json:"id"`
	Domain        string    `json:"domain"`
	DomainDisplay string    `json:"domain_display"`
	Environment   string    `json:"environment"`
	Status        string    `json:"status"`
	CreatedAt     time.Time `json:"created_at"`
	UpdatedAt     time.Time `json:"updated_at"`
}

// AgentListResponse matches the OpenAPI AgentListResponse schema.
type AgentListResponse struct {
	Agents     []AgentListItem `json:"agents"`
	NextCursor string          `json:"next_cursor,omitempty"`
}

// AgentError matches the OpenAPI AgentError schema.
type AgentError struct {
	Code        string `json:"code"`
	Title       string `json:"title"`
	Detail      string `json:"detail"`
	Remediation string `json:"remediation"`
}

// AgentDetail matches the OpenAPI AgentDetail schema.
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

// IdentityRecordRequest matches the OpenAPI IdentityRecordRequest schema.
type IdentityRecordRequest struct {
	SigningKid string `json:"signingKid"`
}

// IdentityRecordResponse matches the OpenAPI IdentityRecordResponse schema.
type IdentityRecordResponse struct {
	FQDN             string            `json:"fqdn"`
	CanonicalContent string            `json:"canonicalContent"`
	SigningKid       string            `json:"signingKid"`
	ExpiresAt        string            `json:"expiresAt"`
	Tags             map[string]string `json:"tags"`
}

// SignatureRequest matches the OpenAPI SignatureRequest schema.
type SignatureRequest struct {
	Signature string `json:"signature"`
}

// DNSRecord matches the OpenAPI DNSRecord schema.
type DNSRecord struct {
	Name  string `json:"name"`
	Type  string `json:"type"`
	Value string `json:"value"`
	TTL   int    `json:"ttl"`
}

// SignatureResponse is the legacy response for POST /agent/{fqdn}/signature.
// Its Status is publication workflow state, not protocol AgentStatus.
type SignatureResponse struct {
	FQDN     string      `json:"fqdn"`
	Status   string      `json:"status"`
	Message  string      `json:"message,omitempty"`
	Records  []DNSRecord `json:"records"`
	ZoneFile string      `json:"zoneFile,omitempty"`
}

// ChallengeRequest matches the OpenAPI ChallengeRequest schema.
type ChallengeRequest struct {
	Nonce     string `json:"nonce"`
	Signature string `json:"signature"`
}

// LiveProofRequest proves possession of the key supplied for Live registration.
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

// LiveProofResponse reports the durable Live proof handoff status.
type LiveProofResponse struct {
	RequestID string `json:"request_id"`
	AgentID   string `json:"agent_id"`
	Status    string `json:"status"`
}

// LiveProofReissueRequest requests a fresh challenge after an expired proof.
type LiveProofReissueRequest struct {
	RequestID string `json:"request_id"`
	// PublicKey is the original Live registration key and is not sent on the wire.
	PublicKey any `json:"-"`
}

// LiveProofReissueResponse contains the replacement Live proof challenge.
// Domain and ChallengeTranscript are derived from the validated latest message.
type LiveProofReissueResponse struct {
	RequestID           string                   `json:"request_id"`
	AgentID             string                   `json:"agent_id"`
	Status              string                   `json:"status"`
	Challenge           string                   `json:"challenge"`
	ChallengeMessage    string                   `json:"challenge_message"`
	Domain              string                   `json:"-"`
	ChallengeTranscript *LiveChallengeTranscript `json:"-"`
}

// RegistryRevocationReason is an owner-authorized registry revocation reason.
// It is distinct from the protocol REVOCATION reason vocabulary.
type RegistryRevocationReason string

// Owner-authorized registry revocation reasons.
const (
	RegistryRevocationReasonOwnerRequest  RegistryRevocationReason = "owner_request"
	RegistryRevocationReasonKeyCompromise RegistryRevocationReason = "key_compromise"
)

func validRegistryRevocationReason(reason RegistryRevocationReason) bool {
	switch reason {
	case RegistryRevocationReasonOwnerRequest, RegistryRevocationReasonKeyCompromise:
		return true
	default:
		return false
	}
}

// RevokeAgentRequest matches the OpenAPI RevokeRequest schema.
type RevokeAgentRequest struct {
	AgentID string                   `json:"agent_id"`
	Reason  RegistryRevocationReason `json:"reason"`
}

// RetireAgentRequest matches the OpenAPI RetireRequest schema.
type RetireAgentRequest struct {
	AgentID string `json:"agent_id"`
}

// LifecycleResponse matches the OpenAPI LifecycleResponse schema.
type LifecycleResponse struct {
	ID         string `json:"id"`
	Status     string `json:"status"`
	StatusNote string `json:"status_note,omitempty"`
}

// AgentEvent matches the OpenAPI AgentEvent schema.
type AgentEvent struct {
	ID        string         `json:"id"`
	AgentID   string         `json:"agent_id"`
	EventType string         `json:"event_type"`
	CreatedAt time.Time      `json:"created_at"`
	ActorID   *string        `json:"actor_id,omitempty"`
	Details   map[string]any `json:"details,omitempty"`
}

// EventListResponse matches the OpenAPI EventListResponse schema.
type EventListResponse struct {
	Events     []AgentEvent `json:"events"`
	NextCursor *string      `json:"next_cursor,omitempty"`
}

// OperationsAgent matches the OpenAPI OperationsAgent schema.
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

// OperationsAgentListResponse matches the OpenAPI OperationsAgentListResponse schema.
type OperationsAgentListResponse struct {
	Agents []OperationsAgent `json:"agents"`
}

// VerifyDomainRequest matches the OpenAPI VerifyDomainRequest schema.
type VerifyDomainRequest struct {
	Domain string `json:"domain"`
}

// VerifyDomainResponse matches the OpenAPI VerifyDomainResponse schema.
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

// ListAgentsOptions contains optional parameters for ListAgents.
type ListAgentsOptions struct {
	Limit  int
	Cursor string
}

// EventListOptions contains optional parameters for GetAgentEvents.
type EventListOptions struct {
	Limit  int
	Cursor string
}

// RegistryRegistrationReader reads normalized registry workflow state.
type RegistryRegistrationReader interface {
	GetRegistration(ctx context.Context, domain string) (*AgentRegistration, error)
}

// RegistryPublisher is the canonical-record and signature-publication
// capability shared by registry clients.
type RegistryPublisher interface {
	CanonicalRecordContent(ctx context.Context, domain, signingKid string) (*CanonicalRecordContentResponse, error)
	PublishSignature(ctx context.Context, domain, sig string) (*PublishedRecord, error)
}

// RegistryClientControlledPublisher adds the registration state needed to
// enforce client publication authority before signing.
type RegistryClientControlledPublisher interface {
	RegistryPublisher
	RegistryRegistrationReader
}

// RegistryPreparedEventClient is the capability required for prepared C2SP
// transparency-log preparation and submission transport.
type RegistryPreparedEventClient interface {
	PrepareIssuance(ctx context.Context, fqdn, idempotencyKey string) (*PreparedRegistryEvent, error)
	PrepareKeyRotation(ctx context.Context, fqdn string, req *KeyRotationPreparationRequest, idempotencyKey string) (*PreparedRegistryEvent, error)
	SubmitPreparedEvent(ctx context.Context, fqdn string, entryBytes []byte, idempotencyKey string) (*SubmissionResult, error)
}

// RegistryClient is the full control-plane client for the DNSid registry API.
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

// HTTPRegistryClient implements RegistryClient against the standard DNSid registry endpoints.
type HTTPRegistryClient struct {
	baseURL       string
	client        *http.Client
	token         string
	allowInsecure bool // allow HTTP transport (for testing only)
}

var (
	_ RegistryClient                    = (*HTTPRegistryClient)(nil)
	_ RegistryClientControlledPublisher = (*HTTPRegistryClient)(nil)
	_ RegistryPreparedEventClient       = (*HTTPRegistryClient)(nil)
)

// RegistryStatusReader is the subset needed by WaitForRegistryStatus.
type RegistryStatusReader interface {
	GetAgentStatus(ctx context.Context, fqdn string) (*AgentDetail, error)
}

// WaitForStatusOptions configures registry status polling.
type WaitForStatusOptions struct {
	PollInterval time.Duration
	Timeout      time.Duration
}

// RegistryClientOption configures an HTTPRegistryClient.
type RegistryClientOption func(*HTTPRegistryClient)

// WithAuthToken sets a Bearer token for authenticated API calls.
func WithAuthToken(token string) RegistryClientOption {
	return func(c *HTTPRegistryClient) { c.token = token }
}

// WithRegistryHTTPClient sets a custom HTTP client for the registry client.
func WithRegistryHTTPClient(client *http.Client) RegistryClientOption {
	return func(c *HTTPRegistryClient) { c.client = client }
}

// WithInsecureHTTP allows the client to use plaintext HTTP transport.
// This is intended only for local development and testing; production callers
// should always use HTTPS.
func WithInsecureHTTP() RegistryClientOption {
	return func(c *HTTPRegistryClient) { c.allowInsecure = true }
}

// SetAuthToken updates the Bearer token on an existing client (e.g. after refresh).
// It returns an error if the client is configured for plaintext HTTP without WithInsecureHTTP.
func (c *HTTPRegistryClient) SetAuthToken(token string) error {
	if token != "" && !c.allowInsecure {
		u, err := url.Parse(c.baseURL)
		if err == nil && u.Scheme != "https" {
			return NewArgumentError("dnsid: refusing to send bearer token over plaintext HTTP (use WithInsecureHTTP for local testing)", nil)
		}
	}
	c.token = token
	return nil
}

// NewRegistryClient creates an HTTP registry client for baseURL.
// Only HTTPS URLs are accepted for production use.
func NewRegistryClient(baseURL string, transportConfig ...TransportConfig) (*HTTPRegistryClient, error) {
	u, err := url.Parse(strings.TrimRight(baseURL, "/"))
	if err != nil || u.Scheme != "https" || u.Hostname() == "" {
		return nil, NewArgumentError(fmt.Sprintf("dnsid: registryUrl must be an HTTPS URL (got %q)", baseURL), nil)
	}
	if u.User != nil {
		return nil, NewArgumentError("dnsid: registryUrl must not include userinfo", nil)
	}
	cfg := TransportConfig{}
	if len(transportConfig) > 0 {
		cfg = transportConfig[0]
	}
	client, err := CreateDnsidHTTPClient(cfg)
	if err != nil {
		return nil, err
	}
	return &HTTPRegistryClient{baseURL: u.String(), client: client}, nil
}

// NewRegistryClientWithOptions creates an HTTP registry client with functional options.
// By default only HTTPS URLs are accepted. Use WithInsecureHTTP() for local testing.
func NewRegistryClientWithOptions(baseURL string, opts ...RegistryClientOption) (*HTTPRegistryClient, error) {
	u, err := url.Parse(strings.TrimRight(baseURL, "/"))
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Hostname() == "" {
		return nil, NewArgumentError(fmt.Sprintf("dnsid: registryUrl must be an HTTP or HTTPS URL (got %q)", baseURL), nil)
	}
	if u.User != nil {
		return nil, NewArgumentError("dnsid: registryUrl must not include userinfo", nil)
	}
	client, err := CreateDnsidHTTPClient(TransportConfig{})
	if err != nil {
		return nil, err
	}
	c := &HTTPRegistryClient{baseURL: u.String(), client: client}
	for _, opt := range opts {
		opt(c)
	}
	// Enforce HTTPS when a bearer token is configured, unless explicitly opted into insecure mode.
	if c.token != "" && u.Scheme != "https" && !c.allowInsecure {
		return nil, NewArgumentError("dnsid: refusing to send bearer token over plaintext HTTP (use WithInsecureHTTP for local testing)", nil)
	}
	return c, nil
}

// CreateDnsidHTTPClient creates an SDK-managed HTTP client using DNSid transport settings.
func CreateDnsidHTTPClient(transportConfig TransportConfig) (*http.Client, error) {
	return httpClientWithTransportConfig(transportConfig)
}

// --- Existing methods (backward-compatible) ---

// CanonicalRecordContent fetches the registry-prepared unsigned canonical TXT
// content for domain, targeted at the given record-signing kid.
func (c *HTTPRegistryClient) CanonicalRecordContent(ctx context.Context, domain, signingKid string) (*CanonicalRecordContentResponse, error) {
	resp, err := c.GetIdentityRecord(ctx, domain, &IdentityRecordRequest{SigningKid: signingKid})
	if err != nil {
		return nil, err
	}
	return &CanonicalRecordContentResponse{
		Canonical:  resp.CanonicalContent,
		SigningKid: resp.SigningKid,
	}, nil
}

// PublishSignature submits an encoded record signature for domain and
// returns the resulting publication state as a PublishedRecord.
func (c *HTTPRegistryClient) PublishSignature(ctx context.Context, domain, sig string) (*PublishedRecord, error) {
	resp, err := c.SubmitSignature(ctx, domain, &SignatureRequest{Signature: sig})
	if err != nil {
		return nil, err
	}
	// Map SignatureResponse to the normalized publication result.
	ownerName := "_dnsid." + resp.FQDN
	txtRecord := ""
	ttl := 0
	if len(resp.Records) > 0 {
		ownerName = resp.Records[0].Name
		txtRecord = resp.Records[0].Value
		ttl = resp.Records[0].TTL
	}
	return &PublishedRecord{
		Domain:            resp.FQDN,
		OwnerName:         ownerName,
		TXTRecord:         txtRecord,
		TTL:               ttl,
		PublicationStatus: resp.Status,
	}, nil
}

// --- New RegistryClient methods ---

// CreateAgent registers a non-Live agent through the HTTP 201 flow. It rejects
// a request whose PublicKey contains private JWK members before anything is
// sent to the registry. When Environment is empty it defaults to "production".
// Zone registrations are registry-managed even when Managed is false.
// Self-managed registrations require a domain. Use CreateLiveAgent for
// tier="live".
func (c *HTTPRegistryClient) CreateAgent(ctx context.Context, req *CreateAgentRequest) (*CreateAgentResponse, error) {
	if req == nil {
		return nil, NewArgumentError("dnsid: create agent request is required", nil)
	}
	normalized := *req
	if normalized.Environment == "" {
		normalized.Environment = "production"
	}
	switch normalized.Environment {
	case "sandbox", "production":
	default:
		return nil, NewArgumentError("dnsid: environment must be \"sandbox\" or \"production\"", nil)
	}
	if normalized.Domain != "" && normalized.ZoneID != "" {
		return nil, NewArgumentError("dnsid: domain and zone_id cannot both be supplied", nil)
	}
	managed := normalized.Managed || normalized.Environment == "sandbox" || normalized.ZoneID != ""
	if managed && normalized.Domain != "" {
		return nil, NewArgumentError("dnsid: domain must not be supplied for managed registrations; the registry assigns it", nil)
	}
	if !managed && normalized.Domain == "" {
		return nil, NewArgumentError("dnsid: self-managed registration requires a domain", nil)
	}
	if req.PublicKey != nil {
		if err := rejectPrivateJWK(req.PublicKey); err != nil {
			return nil, err
		}
	}
	return registryJSONStatus[CreateAgentResponse](c, ctx, http.MethodPost, "/api/v1/agent", &normalized, http.StatusCreated)
}

// CreateLiveAgent starts the separate managed Live HTTP 202 flow. It sends
// tier="live", managed=true, and environment="production". The idempotency key
// is required and must be reused for retries.
func (c *HTTPRegistryClient) CreateLiveAgent(ctx context.Context, req *LiveAgentRegistrationInput, idempotencyKey string) (*LiveProvisioningResponse, error) {
	if req == nil || req.PublicKey == nil {
		return nil, NewArgumentError("dnsid: Live create agent request and public key are required", nil)
	}
	if req.Environment != "" && req.Environment != "production" {
		return nil, NewArgumentError("dnsid: Live agents require environment \"production\"", nil)
	}
	if err := validateRegistryIdempotencyKey(idempotencyKey); err != nil {
		return nil, err
	}
	keyID, err := validateLivePublicJWK(req.PublicKey)
	if err != nil {
		return nil, err
	}
	normalized := *req
	normalized.Environment = "production"
	body := struct {
		*LiveAgentRegistrationInput
		Tier    string `json:"tier"`
		Managed bool   `json:"managed"`
	}{LiveAgentRegistrationInput: &normalized, Tier: "live", Managed: true}
	response, err := registryJSONStatus[LiveProvisioningResponse](c, ctx, http.MethodPost, "/api/v1/agent", &body, http.StatusAccepted, map[string]string{"Idempotency-Key": idempotencyKey})
	if err != nil {
		return nil, err
	}
	if err := validateLiveResponse(idempotencyKey, response.RequestID, response.AgentID, response.Status); err != nil {
		return nil, err
	}
	domain, transcript, err := parseLiveChallenge(response.Status, response.AgentID, response.Challenge, response.ChallengeMessage, keyID, "")
	if err != nil {
		return nil, err
	}
	response.Domain, response.ChallengeTranscript = domain, transcript
	return response, nil
}

// UnregisterAgent removes the agent at fqdn. It is best-effort for registry
// compatibility: an already-absent agent or a registry without DELETE support
// is treated as a successful no-op.
func (c *HTTPRegistryClient) UnregisterAgent(ctx context.Context, fqdn string) error {
	err := c.doJSON(ctx, http.MethodDelete, "/api/v1/agent/"+url.PathEscape(fqdn), nil, nil)
	var apiErr *RegistryAPIError
	if errors.As(err, &apiErr) && (apiErr.StatusCode == http.StatusNotFound || apiErr.StatusCode == http.StatusMethodNotAllowed) {
		return nil
	}
	return err
}

// ListAgents lists the caller's agents. A nil opts requests the first page
// with the server's default limit; use the response's NextCursor to page.
func (c *HTTPRegistryClient) ListAgents(ctx context.Context, opts *ListAgentsOptions) (*AgentListResponse, error) {
	path := "/api/v1/agent"
	if opts != nil {
		params := url.Values{}
		if opts.Limit > 0 {
			params.Set("limit", fmt.Sprintf("%d", opts.Limit))
		}
		if opts.Cursor != "" {
			params.Set("cursor", opts.Cursor)
		}
		if encoded := params.Encode(); encoded != "" {
			path += "?" + encoded
		}
	}
	return registryJSON[AgentListResponse](c, ctx, http.MethodGet, path, nil)
}

// GetAgentStatus returns the registry's detailed view of the agent at fqdn,
// including workflow status, DNS publication state, and any workflow error.
func (c *HTTPRegistryClient) GetAgentStatus(ctx context.Context, fqdn string) (*AgentDetail, error) {
	return registryJSON[AgentDetail](c, ctx, http.MethodGet, "/api/v1/agent/"+url.PathEscape(fqdn)+"/status", nil)
}

// GetRegistration returns normalized registry workflow state for fqdn,
// mapping the registry's managed mode ("self" or "dnsid") to a
// PublicationAuthority. It returns a *ValidationError for unknown managed
// modes.
func (c *HTTPRegistryClient) GetRegistration(ctx context.Context, fqdn string) (*AgentRegistration, error) {
	detail, err := c.GetAgentStatus(ctx, fqdn)
	if err != nil {
		return nil, err
	}
	var authority PublicationAuthority
	switch detail.Managed {
	case "self":
		authority = PublicationAuthorityClient
	case "dnsid":
		authority = PublicationAuthorityRegistry
	default:
		return nil, NewValidationError(fmt.Sprintf("dnsid: registry returned unknown managed mode %q", detail.Managed), nil)
	}
	status := detail.ServerStatus
	if status == "" {
		status = detail.Status
	}
	raw, _ := json.Marshal(detail)
	return &AgentRegistration{
		Domain:               detail.Domain,
		PublicationAuthority: authority,
		RegistryStatus:       status,
		DNSPublished:         detail.DNSPublished,
		ProtocolStatus:       detail.ProtocolStatus,
		RegistryURL:          c.baseURL,
		Raw:                  raw,
	}, nil
}

// GetAgentEvents lists registry audit events for the agent at fqdn. A nil
// opts requests the first page with the server's default limit.
func (c *HTTPRegistryClient) GetAgentEvents(ctx context.Context, fqdn string, opts *EventListOptions) (*EventListResponse, error) {
	path := "/api/v1/agent/" + url.PathEscape(fqdn) + "/events"
	if opts != nil {
		params := url.Values{}
		if opts.Limit > 0 {
			params.Set("limit", fmt.Sprintf("%d", opts.Limit))
		}
		if opts.Cursor != "" {
			params.Set("cursor", opts.Cursor)
		}
		if encoded := params.Encode(); encoded != "" {
			path += "?" + encoded
		}
	}
	return registryJSON[EventListResponse](c, ctx, http.MethodGet, path, nil)
}

// SubmitChallenge submits a signed domain-control challenge response for the
// agent at fqdn. A nil error means the registry accepted the submission.
func (c *HTTPRegistryClient) SubmitChallenge(ctx context.Context, fqdn string, req *ChallengeRequest) error {
	// The server returns 202 Accepted with no body on success.
	return c.doJSON(ctx, http.MethodPost, "/api/v1/agent/"+url.PathEscape(fqdn)+"/challenge", req, nil)
}

// SubmitLiveProof submits proof of possession for a managed Live registration.
// RequestID is also sent as the required Idempotency-Key header.
func (c *HTTPRegistryClient) SubmitLiveProof(ctx context.Context, fqdn string, req *LiveProofRequest) (*LiveProofResponse, error) {
	if req == nil || req.Challenge == "" || req.PublicKey == nil || req.Signature == "" {
		return nil, NewArgumentError("dnsid: request ID, challenge, public key, and signature are required", nil)
	}
	if err := validateRegistryIdempotencyKey(req.RequestID); err != nil {
		return nil, err
	}
	if _, err := validateLivePublicJWK(req.PublicKey); err != nil {
		return nil, err
	}
	response, err := registryJSONStatus[LiveProofResponse](c, ctx, http.MethodPost, "/api/v1/agent/"+url.PathEscape(fqdn)+"/proof", req, http.StatusAccepted, map[string]string{"Idempotency-Key": req.RequestID})
	if err != nil {
		return nil, err
	}
	if err := validateLiveResponse(req.RequestID, response.RequestID, response.AgentID, response.Status); err != nil {
		return nil, err
	}
	return response, nil
}

// ReissueLiveProof requests a replacement challenge for an expired Live proof.
// RequestID is also sent as the required Idempotency-Key header.
func (c *HTTPRegistryClient) ReissueLiveProof(ctx context.Context, fqdn string, req *LiveProofReissueRequest) (*LiveProofReissueResponse, error) {
	if req == nil || req.PublicKey == nil {
		return nil, NewArgumentError("dnsid: request ID and original public key are required", nil)
	}
	if err := validateRegistryIdempotencyKey(req.RequestID); err != nil {
		return nil, err
	}
	keyID, err := validateLivePublicJWK(req.PublicKey)
	if err != nil {
		return nil, err
	}
	response, err := registryJSONStatus[LiveProofReissueResponse](c, ctx, http.MethodPost, "/api/v1/agent/"+url.PathEscape(fqdn)+"/proof/reissue", req, http.StatusAccepted, map[string]string{"Idempotency-Key": req.RequestID})
	if err != nil {
		return nil, err
	}
	if err := validateLiveResponse(req.RequestID, response.RequestID, response.AgentID, response.Status); err != nil {
		return nil, err
	}
	if response.Challenge == "" || response.ChallengeMessage == "" {
		return nil, NewValidationError("dnsid: incomplete Live challenge response", nil)
	}
	domain, transcript, err := parseLiveChallenge(response.Status, response.AgentID, response.Challenge, response.ChallengeMessage, keyID, fqdn)
	if err != nil {
		return nil, err
	}
	response.Domain, response.ChallengeTranscript = domain, transcript
	return response, nil
}

// RevokeAgent revokes the immutable agent identity at fqdn with the supplied
// reason. Revocation is a terminal lifecycle transition whose persistence and
// transparency-log append are owned by the registry.
func (c *HTTPRegistryClient) RevokeAgent(ctx context.Context, fqdn string, req *RevokeAgentRequest) (*LifecycleResponse, error) {
	if req == nil || req.AgentID == "" {
		return nil, NewArgumentError("dnsid: agent ID and revocation reason are required", nil)
	}
	if !validRegistryRevocationReason(req.Reason) {
		return nil, NewArgumentError(fmt.Sprintf("dnsid: invalid registry revocation reason %q", req.Reason), nil)
	}
	return registryJSON[LifecycleResponse](c, ctx, http.MethodPost, "/api/v1/agent/"+url.PathEscape(fqdn)+"/revoke", req)
}

// RetireAgent retires the immutable agent identity without revoking its key.
func (c *HTTPRegistryClient) RetireAgent(ctx context.Context, fqdn string, req *RetireAgentRequest) (*LifecycleResponse, error) {
	if req == nil || req.AgentID == "" {
		return nil, NewArgumentError("dnsid: agent ID is required", nil)
	}
	return registryJSON[LifecycleResponse](c, ctx, http.MethodPost, "/api/v1/agent/"+url.PathEscape(fqdn)+"/retire", req)
}

// CancelAgent cancels an in-progress registration workflow for fqdn.
func (c *HTTPRegistryClient) CancelAgent(ctx context.Context, fqdn string) (*LifecycleResponse, error) {
	return registryJSON[LifecycleResponse](c, ctx, http.MethodPost, "/api/v1/agent/"+url.PathEscape(fqdn)+"/cancel", nil)
}

// RejectAgent marks the registration workflow for fqdn as rejected.
func (c *HTTPRegistryClient) RejectAgent(ctx context.Context, fqdn string) (*LifecycleResponse, error) {
	return registryJSON[LifecycleResponse](c, ctx, http.MethodPost, "/api/v1/agent/"+url.PathEscape(fqdn)+"/reject", nil)
}

// VerifyAgent asks the registry to run its verification step for fqdn and
// advance the registration workflow.
func (c *HTTPRegistryClient) VerifyAgent(ctx context.Context, fqdn string) (*LifecycleResponse, error) {
	return registryJSON[LifecycleResponse](c, ctx, http.MethodPost, "/api/v1/agent/"+url.PathEscape(fqdn)+"/verify", nil)
}

// ConfirmReady confirms the agent at fqdn is ready to go live. It is an
// alias for VerifyAgent.
func (c *HTTPRegistryClient) ConfirmReady(ctx context.Context, fqdn string) (*LifecycleResponse, error) {
	return c.VerifyAgent(ctx, fqdn)
}

func rejectPrivateJWK(key any) error {
	data, err := json.Marshal(key)
	if err != nil {
		return NewArgumentError("dnsid: invalid public key JWK", err)
	}
	return rejectPrivateJWKJSON(data)
}

func rejectPrivateJWKJSON(data []byte) error {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		return NewArgumentError("dnsid: invalid public key JWK", err)
	}
	for _, name := range []string{"d", "p", "q", "dp", "dq", "qi", "oth", "k"} {
		if _, ok := fields[name]; ok {
			return NewArgumentError(fmt.Sprintf("dnsid: public key JWK contains private member %q", name), nil)
		}
	}
	keysJSON, ok := fields["keys"]
	if !ok {
		return nil
	}
	var keys []json.RawMessage
	if err := json.Unmarshal(keysJSON, &keys); err != nil {
		return NewArgumentError("dnsid: invalid public key JWKS", err)
	}
	for _, key := range keys {
		if err := rejectPrivateJWKJSON(key); err != nil {
			return err
		}
	}
	return nil
}

func validateLivePublicJWK(value any) (string, error) {
	data, err := json.Marshal(value)
	if err != nil {
		return "", NewArgumentError("dnsid: invalid Live public key JWK", err)
	}
	if err := rejectPrivateJWKJSON(data); err != nil {
		return "", err
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		return "", NewArgumentError("dnsid: invalid Live public key JWK", err)
	}
	if _, ok := fields["keys"]; ok {
		return "", NewArgumentError("dnsid: Live public key must be a bare JWK", nil)
	}
	key, err := jwk.ParseKey(data)
	if err != nil {
		return "", NewArgumentError("dnsid: invalid Live public key JWK", err)
	}
	alg, hasAlg := jwkAlg(key)
	if inferred, ok := algForJWK(key); !ok || inferred != JoseAlgEdDSA || !hasAlg || alg != JoseAlgEdDSA || !signingKeyEligible(key) {
		return "", NewArgumentError("dnsid: Live public key must be an Ed25519 signing JWK with alg=EdDSA", nil)
	}
	var publicKey ed25519.PublicKey
	if err := jwk.Export(key, &publicKey); err != nil || len(publicKey) != ed25519.PublicKeySize {
		return "", NewArgumentError("dnsid: invalid Live Ed25519 public key", err)
	}
	thumbprint, err := (&JWK{key: key}).Thumbprint()
	if err != nil {
		return "", NewArgumentError("dnsid: computing Live public key thumbprint", err)
	}
	if kid, ok := key.KeyID(); ok && kid != "" && kid != thumbprint {
		return "", NewArgumentError("dnsid: Live public key kid does not match its RFC 7638 thumbprint", nil)
	}
	return thumbprint, nil
}

const liveChallengeProtocol = "dnsid-live-provisioning-pop/v1"

func validateLiveResponse(requestID, responseRequestID, agentID, status string) error {
	if responseRequestID == "" || agentID == "" || status == "" {
		return NewValidationError("dnsid: incomplete Live registry response", nil)
	}
	if responseRequestID != requestID {
		return NewValidationError("dnsid: Live registry response request ID does not match the request", nil)
	}
	return nil
}

func parseLiveChallenge(status, agentID, challenge, encoded, expectedKeyID, expectedDomain string) (string, *LiveChallengeTranscript, error) {
	if challenge == "" && encoded == "" && status != "challenge_pending" {
		return "", nil, nil
	}
	if challenge == "" || encoded == "" {
		return "", nil, NewValidationError("dnsid: incomplete Live challenge response", nil)
	}
	message, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil || base64.RawURLEncoding.EncodeToString(message) != encoded || !utf8.Valid(message) {
		return "", nil, NewValidationError("dnsid: invalid Live challenge message encoding", err)
	}
	var transcript LiveChallengeTranscript
	if err := json.Unmarshal(message, &transcript); err != nil {
		return "", nil, NewValidationError("dnsid: invalid Live challenge transcript", err)
	}
	if transcript.Protocol != liveChallengeProtocol || transcript.OrgID == "" || transcript.AgentID == "" || transcript.FQDN == "" || transcript.KeyID == "" || transcript.Nonce == "" || transcript.ExpiresAt.IsZero() {
		return "", nil, NewValidationError("dnsid: incomplete Live challenge transcript", nil)
	}
	if transcript.AgentID != agentID || transcript.Nonce != challenge || (expectedKeyID != "" && transcript.KeyID != expectedKeyID) {
		return "", nil, NewValidationError("dnsid: Live challenge transcript does not match the response or public key", nil)
	}
	domain, err := NormalizeFQDN(transcript.FQDN)
	if err != nil {
		return "", nil, NewValidationError("dnsid: invalid Live challenge transcript domain", err)
	}
	if expectedDomain != "" {
		expected, err := NormalizeFQDN(expectedDomain)
		if err != nil || domain != expected {
			return "", nil, NewValidationError("dnsid: Live challenge transcript domain does not match the proof route", err)
		}
	}
	transcript.FQDN = domain
	return domain, &transcript, nil
}

func validateRegistryIdempotencyKey(key string) error {
	if key == "" || len(key) > 200 || strings.TrimSpace(key) != key {
		return NewArgumentError("dnsid: idempotency key must be 1 to 200 bytes without surrounding whitespace", nil)
	}
	return nil
}

func preparedRegistryEvent(response []byte, headers http.Header) (*PreparedRegistryEvent, error) {
	logReference := headers.Get("DNSID-Log-Reference")
	if logReference == "" {
		return nil, NewValidationError("dnsid: registry prepared event is missing DNSID-Log-Reference", nil)
	}
	return &PreparedRegistryEvent{EntryBytes: response, LogReference: logReference}, nil
}

// PrepareIssuance asks the registry to prepare a transparency-log ISSUANCE
// event for fqdn. The returned entry bytes are untrusted: parse and validate
// them against the returned log reference before signing. The idempotency key
// must be 1 to 200 bytes without surrounding whitespace; reuse the same key
// when retrying.
func (c *HTTPRegistryClient) PrepareIssuance(ctx context.Context, fqdn, idempotencyKey string) (*PreparedRegistryEvent, error) {
	if err := validateRegistryIdempotencyKey(idempotencyKey); err != nil {
		return nil, err
	}
	response, headers, _, err := c.doRequest(ctx, http.MethodPost, "/api/v1/agent/"+url.PathEscape(fqdn)+"/tlog/issuance/prepare", nil, map[string]string{
		"Content-Type":    "application/json",
		"Idempotency-Key": idempotencyKey,
	})
	if err != nil {
		return nil, err
	}
	return preparedRegistryEvent(response, headers)
}

// PrepareKeyRotation asks the registry to prepare a transparency-log
// KEY_ROTATION event for fqdn. Authenticate with an organization session or
// API key; an agent bearer token is not accepted. The request must name the
// previous key ID and carry the new public key, which is rejected if it
// contains private JWK members. As with PrepareIssuance, the returned entry
// bytes are untrusted and must be validated before signing.
func (c *HTTPRegistryClient) PrepareKeyRotation(ctx context.Context, fqdn string, req *KeyRotationPreparationRequest, idempotencyKey string) (*PreparedRegistryEvent, error) {
	if req == nil || req.PreviousKeyID == "" || req.PublicKey == nil {
		return nil, NewArgumentError("dnsid: previous key ID and public key are required", nil)
	}
	if err := validateRegistryIdempotencyKey(idempotencyKey); err != nil {
		return nil, err
	}
	if err := rejectPrivateJWK(req.PublicKey); err != nil {
		return nil, err
	}
	body, err := json.Marshal(req)
	if err != nil {
		return nil, NewArgumentError("dnsid: encoding key rotation preparation request", err)
	}
	response, headers, _, err := c.doRequest(ctx, http.MethodPost, "/api/v1/agent/"+url.PathEscape(fqdn)+"/tlog/key-rotation/prepare", bytes.NewReader(body), map[string]string{
		"Content-Type":    "application/json",
		"Idempotency-Key": idempotencyKey,
	})
	if err != nil {
		return nil, err
	}
	return preparedRegistryEvent(response, headers)
}

// SubmitPreparedEvent submits the exact signed entry bytes of a prepared
// event (1 to 65535 bytes) for transparency-log inclusion. On an accepted
// result it verifies that the registry's reported entry hash matches the
// SHA-256 of the submitted bytes and returns a *ValidationError on mismatch.
// Retry with the same bytes and idempotency key when the registry reports a
// retryable state (see RegistryAPIError.RetrySameEntry).
func (c *HTTPRegistryClient) SubmitPreparedEvent(ctx context.Context, fqdn string, entryBytes []byte, idempotencyKey string) (*SubmissionResult, error) {
	if len(entryBytes) == 0 || len(entryBytes) > 65535 {
		return nil, NewArgumentError("dnsid: prepared event must be between 1 and 65535 bytes", nil)
	}
	if err := validateRegistryIdempotencyKey(idempotencyKey); err != nil {
		return nil, err
	}
	response, _, _, err := c.doRequest(ctx, http.MethodPost, "/api/v1/agent/"+url.PathEscape(fqdn)+"/tlog/events", bytes.NewReader(entryBytes), map[string]string{
		"Content-Type":    "application/json",
		"Idempotency-Key": idempotencyKey,
	})
	if err != nil {
		return nil, err
	}
	var result SubmissionResult
	if err := json.Unmarshal(response, &result); err != nil {
		return nil, NewParseError("dnsid: parsing registry submission response", err)
	}
	switch result.State {
	case SubmissionStatePending, SubmissionStatePrepared, SubmissionStateSubmitting, SubmissionStateAccepted, SubmissionStateRejected, SubmissionStateIndeterminate:
	default:
		return nil, NewValidationError(fmt.Sprintf("dnsid: registry returned unknown submission state %q", result.State), nil)
	}
	if result.State == SubmissionStateAccepted {
		sum := sha256.Sum256(entryBytes)
		expectedHash := hex.EncodeToString(sum[:])
		if result.EntryHash != expectedHash {
			return nil, NewValidationError(fmt.Sprintf("dnsid: registry accepted entry hash %q, want %q for exact submitted bytes", result.EntryHash, expectedHash), nil)
		}
	}
	return &result, nil
}

// GetIdentityRecord fetches the registry-prepared canonical identity record
// content for fqdn, targeted at the signing kid named in req.
func (c *HTTPRegistryClient) GetIdentityRecord(ctx context.Context, fqdn string, req *IdentityRecordRequest) (*IdentityRecordResponse, error) {
	return registryJSON[IdentityRecordResponse](c, ctx, http.MethodPost, "/api/v1/agent/"+url.PathEscape(fqdn)+"/record", req)
}

// SubmitSignature posts a signature through the legacy self-managed identity-record endpoint.
func (c *HTTPRegistryClient) SubmitSignature(ctx context.Context, fqdn string, req *SignatureRequest) (*SignatureResponse, error) {
	return registryJSON[SignatureResponse](c, ctx, http.MethodPost, "/api/v1/agent/"+url.PathEscape(fqdn)+"/signature", req)
}

// ListExpiringAgents lists agents whose identity records are approaching
// expiry.
func (c *HTTPRegistryClient) ListExpiringAgents(ctx context.Context) (*OperationsAgentListResponse, error) {
	return registryJSON[OperationsAgentListResponse](c, ctx, http.MethodGet, "/api/v1/agent/expiring", nil)
}

// ListFlaggedAgents lists agents the registry has flagged for operator
// attention.
func (c *HTTPRegistryClient) ListFlaggedAgents(ctx context.Context) (*OperationsAgentListResponse, error) {
	return registryJSON[OperationsAgentListResponse](c, ctx, http.MethodGet, "/api/v1/agent/flagged", nil)
}

// ListPendingAgents lists agents whose registration workflows have not yet
// completed.
func (c *HTTPRegistryClient) ListPendingAgents(ctx context.Context) (*OperationsAgentListResponse, error) {
	return registryJSON[OperationsAgentListResponse](c, ctx, http.MethodGet, "/api/v1/agent/pending", nil)
}

// VerifyDomainRemote asks the registry to check a domain's DNSid state from
// its vantage point. It complements, but does not replace, local
// IdentityManager.VerifyDomain verification.
func (c *HTTPRegistryClient) VerifyDomainRemote(ctx context.Context, req *VerifyDomainRequest) (*VerifyDomainResponse, error) {
	return registryJSON[VerifyDomainResponse](c, ctx, http.MethodPost, "/api/v1/verify/domain", req)
}

// WaitForStatus polls the registry until the agent at fqdn reaches one of
// targetStatuses. It is shorthand for WaitForRegistryStatus with this client.
func (c *HTTPRegistryClient) WaitForStatus(ctx context.Context, fqdn string, targetStatuses []string, opts *WaitForStatusOptions) (*AgentDetail, error) {
	return WaitForRegistryStatus(ctx, c, fqdn, targetStatuses, opts)
}

// WaitForRegistryStatus polls client until the agent at fqdn reaches one of
// targetStatuses (compared case-insensitively) and returns that AgentDetail.
// It returns an error when a terminal registry status is reached first, when
// polling fails, or when ctx (bounded by opts.Timeout, if set) is done. A nil
// opts polls every second with no timeout beyond ctx's own.
func WaitForRegistryStatus(ctx context.Context, client RegistryStatusReader, fqdn string, targetStatuses []string, opts *WaitForStatusOptions) (*AgentDetail, error) {
	if client == nil {
		return nil, NewArgumentError("dnsid: nil RegistryClient", nil)
	}
	if len(targetStatuses) == 0 {
		return nil, NewArgumentError("dnsid: at least one target status is required", nil)
	}
	interval := time.Second
	if opts != nil && opts.PollInterval > 0 {
		interval = opts.PollInterval
	}
	if opts != nil && opts.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, opts.Timeout)
		defer cancel()
	}
	targets := make(map[string]struct{}, len(targetStatuses))
	for _, status := range targetStatuses {
		if strings.TrimSpace(status) == "" {
			return nil, NewArgumentError("dnsid: target statuses must not be empty", nil)
		}
		targets[strings.ToUpper(status)] = struct{}{}
	}
	for {
		detail, err := client.GetAgentStatus(ctx, fqdn)
		if err != nil {
			return nil, registryWorkflowCallError(ctx, err, nil)
		}
		if detail == nil {
			return nil, NewValidationError("dnsid: registry returned nil agent status", nil)
		}
		if _, ok := targets[strings.ToUpper(detail.Status)]; ok {
			return detail, nil
		}
		if isTerminalRegistryStatus(detail.Status) {
			return nil, &RegistryWorkflowError{Status: detail.Status}
		}
		select {
		case <-ctx.Done():
			return nil, &RegistryWorkflowError{Cause: ctx.Err()}
		case <-time.After(interval):
		}
	}
}

func registryWorkflowCallError(ctx context.Context, err error, registration *AgentRegistration) error {
	if err == nil {
		return nil
	}
	if ctxErr := ctx.Err(); ctxErr != nil {
		return &RegistryWorkflowError{Registration: registration, Cause: ctxErr}
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return &RegistryWorkflowError{Registration: registration, Cause: err}
	}
	return err
}

// isTerminalRegistryStatus reports whether the registry status polling loop
// should stop — i.e. the registration workflow has settled and will not
// progress toward a target status. "Terminal" here means "done polling the
// registry", NOT end-of-lifecycle: ACTIVE is included because it ends the
// registration workflow, even though the agent can still rotate keys while
// active. Only RETIRED/REVOKED are true lifecycle-terminal states.
func isTerminalRegistryStatus(status string) bool {
	switch strings.ToUpper(status) {
	case RegistryStatusReady, string(AgentStateActive), string(AgentStateRetired), string(AgentStateRevoked), RegistryStatusCancelled, RegistryStatusRejected, RegistryStatusError, RegistryStatusFailed:
		return true
	default:
		return false
	}
}

// --- HTTP helpers ---

// RegistryAPIError represents a registry transport failure or non-2xx API
// response. The registry error schema uses fields "error" and "message".
type RegistryAPIError struct {
	StatusCode int
	Code       string `json:"error,omitempty"`
	Message    string `json:"message,omitempty"`
	Cause      error  `json:"-"`
}

// Error implements error, formatting the HTTP status with the registry's
// error code and message when present.
func (e *RegistryAPIError) Error() string {
	if e == nil {
		return "<nil>"
	}
	if e.StatusCode == 0 && e.Cause != nil {
		return "dnsid: registry request failed: " + e.Cause.Error()
	}
	if e.Cause != nil {
		return fmt.Sprintf("dnsid: reading registry HTTP %d response: %v", e.StatusCode, e.Cause)
	}
	if e.Code != "" && e.Message != "" {
		return fmt.Sprintf("dnsid: registry returned HTTP %d [%s]: %s", e.StatusCode, e.Code, e.Message)
	}
	if e.Message != "" {
		return fmt.Sprintf("dnsid: registry returned HTTP %d: %s", e.StatusCode, e.Message)
	}
	return fmt.Sprintf("dnsid: registry returned HTTP %d", e.StatusCode)
}

// Unwrap returns the underlying transport failure, if any.
func (e *RegistryAPIError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Cause
}

// RetrySameEntry reports whether the registry requires retrying the exact
// submitted bytes with the same idempotency key. An unclassified HTTP 5xx is
// indeterminate and therefore also requires an exact-byte retry. Known
// terminal protocol errors override that transport-level fallback.
func (e *RegistryAPIError) RetrySameEntry() bool {
	if e == nil {
		return false
	}
	if e.Cause != nil {
		return true
	}
	switch e.Code {
	case "TLOG_SUBMISSION_BUSY", "TLOG_SUBMISSION_INDETERMINATE":
		return true
	case "IDEMPOTENCY_MISMATCH", "TLOG_IDEMPOTENCY_MISMATCH", "TLOG_PREPARATION_MISMATCH", "TLOG_INVALID_ENTRY":
		return false
	}
	return e.StatusCode == http.StatusRequestTimeout || e.StatusCode == http.StatusTooEarly || e.StatusCode == http.StatusTooManyRequests || e.StatusCode >= 500 && e.StatusCode < 600
}

// SubmissionState maps a prepared-event submission failure to the durable
// lifecycle state shared by managed coordinators.
func (e *RegistryAPIError) SubmissionState() SubmissionState {
	if e == nil {
		return SubmissionStateRejected
	}
	if e.Cause != nil {
		return SubmissionStateIndeterminate
	}
	switch e.Code {
	case "TLOG_SUBMISSION_INDETERMINATE":
		return SubmissionStateIndeterminate
	case "TLOG_SUBMISSION_BUSY":
		return SubmissionStatePending
	case "IDEMPOTENCY_MISMATCH", "TLOG_IDEMPOTENCY_MISMATCH", "TLOG_PREPARATION_MISMATCH", "TLOG_INVALID_ENTRY":
		return SubmissionStateRejected
	}
	if e.RetrySameEntry() {
		return SubmissionStateIndeterminate
	}
	return SubmissionStateRejected
}

// Transient reports whether retrying the registry operation may succeed.
// Prepared-event callers must additionally honor RetrySameEntry so a retry
// never regenerates signed bytes.
func (e *RegistryAPIError) Transient() bool {
	return e != nil && e.RetrySameEntry()
}

func registryJSON[T any](c *HTTPRegistryClient, ctx context.Context, method, path string, in any, headers ...map[string]string) (*T, error) {
	var out T
	if err := c.doJSON(ctx, method, path, in, &out, headers...); err != nil {
		return nil, err
	}
	return &out, nil
}

func registryJSONStatus[T any](c *HTTPRegistryClient, ctx context.Context, method, path string, in any, expectedStatus int, headers ...map[string]string) (*T, error) {
	var out T
	status, err := c.doJSONStatus(ctx, method, path, in, &out, headers...)
	if err != nil {
		return nil, err
	}
	if status != expectedStatus {
		return nil, NewValidationError(fmt.Sprintf("dnsid: registry returned HTTP %d, want HTTP %d", status, expectedStatus), nil)
	}
	return &out, nil
}

// doJSON is the unified HTTP helper supporting GET, POST, PUT, DELETE.
func (c *HTTPRegistryClient) doJSON(ctx context.Context, method, path string, in, out any, extraHeaders ...map[string]string) error {
	_, err := c.doJSONStatus(ctx, method, path, in, out, extraHeaders...)
	return err
}

func (c *HTTPRegistryClient) doJSONStatus(ctx context.Context, method, path string, in, out any, extraHeaders ...map[string]string) (int, error) {
	var body io.Reader
	headers := map[string]string{}
	if in != nil {
		data, err := json.Marshal(in)
		if err != nil {
			return 0, NewArgumentError("dnsid: encoding registry request", err)
		}
		body = bytes.NewReader(data)
		headers["Content-Type"] = "application/json"
	}
	for _, extra := range extraHeaders {
		for name, value := range extra {
			headers[name] = value
		}
	}
	response, _, status, err := c.doRequest(ctx, method, path, body, headers)
	if err != nil {
		return status, err
	}
	if out != nil && len(response) > 0 {
		if err := json.Unmarshal(response, out); err != nil {
			return status, NewParseError("dnsid: parsing registry response", err)
		}
	}
	return status, nil
}

func (c *HTTPRegistryClient) doRequest(ctx context.Context, method, path string, body io.Reader, headers map[string]string) ([]byte, http.Header, int, error) {
	if c == nil || c.client == nil || c.baseURL == "" {
		return nil, nil, 0, NewArgumentError("dnsid: nil RegistryClient", nil)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, body)
	if err != nil {
		return nil, nil, 0, NewArgumentError("dnsid: constructing registry request", err)
	}
	for name, value := range headers {
		req.Header.Set(name, value)
	}
	req.Header.Set("Accept", "application/json")
	if c.token != "" {
		if !c.allowInsecure && req.URL.Scheme != "https" {
			return nil, nil, 0, NewArgumentError("dnsid: refusing to send bearer token over plaintext HTTP (use WithInsecureHTTP for local testing)", nil)
		}
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return nil, nil, 0, &RegistryAPIError{Cause: err}
	}
	defer resp.Body.Close()
	response, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, nil, resp.StatusCode, &RegistryAPIError{StatusCode: resp.StatusCode, Cause: err}
	}
	if resp.StatusCode >= 200 && resp.StatusCode <= 299 {
		return response, resp.Header, resp.StatusCode, nil
	}
	apiErr := &RegistryAPIError{StatusCode: resp.StatusCode}
	var errorResponse struct {
		Error   string `json:"error"`
		Message string `json:"message"`
	}
	if json.Unmarshal(response, &errorResponse) == nil {
		apiErr.Code = errorResponse.Error
		apiErr.Message = errorResponse.Message
	}
	return nil, resp.Header, resp.StatusCode, apiErr
}

// PublishClientControlledRecord signs registry-prepared canonical TXT content
// when the client controls the accountable-entity key.
func (m *IdentityManager) PublishClientControlledRecord(ctx context.Context, client RegistryClientControlledPublisher) (*PublishedRecord, error) {
	if client == nil {
		return nil, NewArgumentError("dnsid: nil RegistryClient", nil)
	}
	if err := m.requireLocalIdentity(); err != nil {
		return nil, err
	}
	registration, err := client.GetRegistration(ctx, m.identity.Domain)
	if err != nil {
		return nil, err
	}
	if registration == nil {
		return nil, NewValidationError("dnsid: registry returned nil registration", nil)
	}
	if registration.Domain != m.identity.Domain {
		return nil, NewValidationError(fmt.Sprintf("dnsid: registry returned registration for %q, want %q", registration.Domain, m.identity.Domain), nil)
	}
	if registration.PublicationAuthority != PublicationAuthorityClient {
		return nil, NewValidationError("dnsid: registry does not grant client publication authority", nil)
	}
	return m.publishClientControlledRecord(ctx, client)
}

func (m *IdentityManager) publishClientControlledRecord(ctx context.Context, client RegistryPublisher) (*PublishedRecord, error) {
	expected, err := m.BuildUnsignedTXTRecord()
	if err != nil {
		return nil, err
	}
	signingKeys := m.entityKeys
	signingKid, err := activeSigningKid(signingKeys)
	if err != nil {
		return nil, err
	}

	canonicalResponse, err := client.CanonicalRecordContent(ctx, m.identity.Domain, signingKid)
	if err != nil {
		return nil, err
	}
	if canonicalResponse == nil {
		return nil, NewValidationError("dnsid: registry returned nil canonical content", nil)
	}
	if canonicalResponse.SigningKid != signingKid {
		return nil, NewValidationError(fmt.Sprintf("dnsid: registry canonical content targets signing kid %q, want %q", canonicalResponse.SigningKid, signingKid), nil)
	}
	registryRecord, err := ParseUnsignedCanonical(canonicalResponse.Canonical)
	if err != nil {
		return nil, err
	}
	if err := registryRecord.validateUnsigned(m.identity.Domain); err != nil {
		return nil, err
	}
	if registryRecord.Version != expected.Version {
		return nil, NewValidationError(fmt.Sprintf("dnsid: registry canonical content uses unexpected DNSid version %q", registryRecord.Version), nil)
	}
	if string(registryRecord.KnownTagsCanonical()) != string(expected.KnownTagsCanonical()) {
		return nil, NewValidationError("dnsid: registry canonical content does not match local unsigned DNSid record", nil)
	}

	sig, err := signingKeys.Sign([]byte(canonicalResponse.Canonical))
	if err != nil {
		return nil, fmt.Errorf("dnsid: registry record signing failed: %w", err)
	}
	if sig == nil {
		return nil, NewArgumentError("dnsid: entity KeyProvider returned no signature", nil)
	}
	if sig.Kid != signingKid {
		return nil, NewValidationError(fmt.Sprintf("dnsid: key provider signed with kid %q, want %q", sig.Kid, signingKid), nil)
	}
	if !sig.Alg.Valid() {
		return nil, NewValidationError(fmt.Sprintf("dnsid: unsupported JOSE alg %q", sig.Alg), nil)
	}
	keyAlg, ok := jwkAlg(signingKeys.JWK(signingKid))
	if !ok || keyAlg != sig.Alg {
		return nil, NewValidationError(fmt.Sprintf("dnsid: draft 01 signature alg %q does not match record-signing key alg %q", sig.Alg, keyAlg), nil)
	}
	encoded, err := encodeRecordSignatureForProfile(expected.Version, sig.Alg, sig.Signature)
	if err != nil {
		return nil, err
	}
	return client.PublishSignature(ctx, m.identity.Domain, encoded)
}

// RegistryWorkflowError reports a terminal or interrupted registry workflow.
type RegistryWorkflowError struct {
	Registration *AgentRegistration
	Status       string
	Cause        error
}

// Error implements error, naming the terminal workflow status when the
// registration is available.
func (e *RegistryWorkflowError) Error() string {
	if e == nil {
		return "dnsid: registry workflow failed"
	}
	if e.Cause != nil {
		return "dnsid: registry workflow interrupted: " + e.Cause.Error()
	}
	status := e.Status
	if status == "" {
		status = registryWorkflowStatus(e.Registration)
	}
	if status != "" {
		return fmt.Sprintf("dnsid: registry workflow reached terminal status %q", status)
	}
	return "dnsid: registry workflow failed"
}

// Unwrap returns the cancellation or timeout that interrupted the workflow.
func (e *RegistryWorkflowError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Cause
}

func registryWorkflowStatus(registration *AgentRegistration) string {
	if registration == nil {
		return ""
	}
	return registration.RegistryStatus
}

// AwaitRegistryManagedPublication waits for registry-managed DNS publication,
// then verifies the record observed through DNS. Required log authorization,
// such as C2SP ISSUANCE consent, must be completed before or concurrently with
// this wait through the bound log package.
func (m *IdentityManager) AwaitRegistryManagedPublication(ctx context.Context, client RegistryRegistrationReader, opts *WaitForStatusOptions) (*PublishedRecord, error) {
	if client == nil {
		return nil, NewArgumentError("dnsid: nil RegistryClient", nil)
	}
	if err := m.requireLocalIdentity(); err != nil {
		return nil, err
	}
	interval := time.Second
	if opts != nil && opts.PollInterval > 0 {
		interval = opts.PollInterval
	}
	if opts != nil && opts.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, opts.Timeout)
		defer cancel()
	}

	var registration *AgentRegistration
	for {
		var err error
		registration, err = client.GetRegistration(ctx, m.identity.Domain)
		if err != nil {
			return nil, registryWorkflowCallError(ctx, err, registration)
		}
		if registration == nil {
			return nil, NewValidationError("dnsid: registry returned nil registration", nil)
		}
		if registration.Domain != m.identity.Domain {
			return nil, NewValidationError(fmt.Sprintf("dnsid: registry returned registration for %q, want %q", registration.Domain, m.identity.Domain), nil)
		}
		if registration.PublicationAuthority != PublicationAuthorityRegistry {
			return nil, NewValidationError("dnsid: registry does not have publication authority", nil)
		}
		status := registryWorkflowStatus(registration)
		switch strings.ToUpper(status) {
		case RegistryStatusRejected, RegistryStatusCancelled, RegistryStatusError, RegistryStatusFailed, string(AgentStateRetired), string(AgentStateRevoked):
			return nil, &RegistryWorkflowError{Registration: registration}
		case RegistryStatusReady:
			if registration.DNSPublished {
				goto published
			}
		}
		select {
		case <-ctx.Done():
			return nil, &RegistryWorkflowError{Registration: registration, Cause: ctx.Err()}
		case <-time.After(interval):
		}
	}

published:
	m.cache.evict(m.identity.Domain, m)
	// Publication confirmation is control-plane: full protocol verification
	// without counterparty acceptance. Public VerifyDomain(localDomain) still
	// enforces the configured policy.
	verified, err := m.verifyDomain(ctx, m.identity.Domain, VerifyDomainOpts{}, false)
	if err != nil {
		return nil, err
	}
	record := verified.Record()
	if record == nil {
		return nil, NewValidationError("dnsid: verified publication has no TXT record", nil)
	}
	expectedProfile := m.identity.PublishProfile
	if expectedProfile == "" {
		expectedProfile = DefaultPublishProfile
	}
	if record.Version != expectedProfile {
		return nil, NewValidationError(fmt.Sprintf("dnsid: registry published unexpected DNSid version %q, want %q", record.Version, expectedProfile), nil)
	}
	return &PublishedRecord{
		Domain:            verified.Domain(),
		OwnerName:         "_dnsid." + verified.Domain(),
		TXTRecord:         record.Serialize(),
		TTL:               int(verified.DNSTTL() / time.Second),
		PublicationStatus: registryWorkflowStatus(registration),
		ProtocolStatus:    verified.Status(),
		Raw:               registration.Raw,
	}, nil
}
