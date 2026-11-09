//go:build dnsid_foundry

// Package foundry implements Known Foundry named caller-key Live creation.
// Importing it requires the dnsid_foundry build tag.
// The package remains gated until the server's named-Live requirements are released.
// Core DNSid, ordinary registration, and configuration loading do not depend on it.
package foundry

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"reflect"
	"strings"
	"sync"
	"time"

	dnsid "github.com/dnsid-ai/dnsid-go"
	"github.com/dnsid-ai/dnsid-go/config"
	dnsidlog "github.com/dnsid-ai/dnsid-go/log"
	"github.com/dnsid-ai/dnsid-go/log/c2sptlog"
	"github.com/lestrrat-go/jwx/v3/jwk"
)

// RegistryClient is the existing low-level registry surface used by Foundry.
type RegistryClient interface {
	CreateLiveAgent(context.Context, *dnsid.LiveAgentRegistrationInput, string) (*dnsid.LiveProvisioningResponse, error)
	GetOrganizationOnboarding(context.Context) (*dnsid.OrganizationOnboardingResponse, error)
	GetAgentStatus(context.Context, string) (*dnsid.AgentDetail, error)
	SubmitLiveProof(context.Context, string, *dnsid.LiveProofRequest) (*dnsid.LiveProofResponse, error)
	ReissueLiveProof(context.Context, string, *dnsid.LiveProofReissueRequest) (*dnsid.LiveProofReissueResponse, error)
	dnsid.RegistryPreparedEventClient
}

// Dependencies supplies explicit runtime dependencies. Injected providers,
// registry clients, and log registries take precedence over loaded selection.
// Credential is used only by the authenticated registry client and is never saved.
type Dependencies struct {
	Credential     string
	KeyProvider    dnsid.KeyProvider
	RegistryClient RegistryClient
	LogRegistry    *dnsidlog.LogRegistry
	Store          FoundryStore
	DNSResolver    dnsid.DNSResolver
	HTTPSFetcher   dnsid.HTTPSFetcher
}

// Client composes the same workflow used by the configured Create facade.
type Client struct {
	loaded config.Loaded
	deps   Dependencies
}

// New validates configuration without discovery, provisioning, or registration.
// LoadDeploymentFile and Merge can supply file and code configuration explicitly.
func New(loaded config.Loaded, deps Dependencies) (*Client, error) {
	if loaded.Dnsid.Identity != nil {
		return nil, dnsid.NewArgumentError("foundry: ordinary identity selectors are not accepted", nil)
	}
	if err := loaded.Dnsid.Validate(); err != nil {
		return nil, err
	}
	if loaded.Foundry.GovernanceID != "" {
		if _, err := dnsid.NormalizeFQDN(loaded.Foundry.GovernanceID); err != nil {
			return nil, err
		}
	}
	loaded.KeySource.EntityKeyPath = "" // Foundry never loads an entity private key.
	if deps.KeyProvider == nil {
		if err := config.ValidateKeySource(loaded.KeySource); err != nil {
			return nil, err
		}
		src := loaded.KeySource
		if (src.Provider == "" || src.Provider == "file") && src.KeyRef == "" && src.KeyStorePath == "" && src.CliDirectory == "" {
			return nil, dnsid.NewArgumentError("foundry: an operational key source or injected provider is required", nil)
		}
	}
	if deps.KeyProvider != nil {
		loaded.KeySource = config.KeySource{}
	}
	if deps.LogRegistry == nil {
		if err := validateTrust(loaded.LogTrust); err != nil {
			return nil, err
		}
	}
	if deps.LogRegistry != nil {
		loaded.LogTrust = config.LogTrust{}
	}
	if deps.Store == nil {
		store, err := NewFileFoundryStore("")
		if err != nil {
			return nil, err
		}
		deps.Store = store
	}
	if loaded.Registry.RegistryURL == "" {
		loaded.Registry.RegistryURL = dnsid.DefaultRegistryURL
	}
	loaded.Registry.RegistryURL = strings.TrimRight(loaded.Registry.RegistryURL, "/")
	if deps.RegistryClient == nil {
		var registry *dnsid.HTTPRegistryClient
		var err error
		if loaded.Dnsid.Transport.IsZero() {
			registry, err = dnsid.NewRegistryClient(loaded.Registry.RegistryURL)
		} else {
			registry, err = dnsid.NewRegistryClient(loaded.Registry.RegistryURL, loaded.Dnsid.Transport)
		}
		if err != nil {
			return nil, err
		}
		if err := registry.SetAuthToken(deps.Credential); err != nil {
			return nil, err
		}
		deps.RegistryClient = registry
	} else {
		if _, err := dnsid.NewRegistryClient(loaded.Registry.RegistryURL); err != nil {
			return nil, err
		}
	}
	if _, err := config.Construct(context.Background(), config.Loaded{Dnsid: loaded.Dnsid}, config.Dependencies{DNSResolver: deps.DNSResolver, HTTPSFetcher: deps.HTTPSFetcher}); err != nil {
		return nil, err
	}
	// Snapshot caller-owned maps and slices before retaining configuration.
	raw, err := json.Marshal(loaded)
	if err != nil {
		return nil, err
	}
	var snapshot config.Loaded
	if err := json.Unmarshal(raw, &snapshot); err != nil {
		return nil, err
	}
	return &Client{loaded: snapshot, deps: deps}, nil
}

func hasTrust(t config.LogTrust) bool {
	return t.Managed || t.Profile != nil || t.PolicyDocument != nil || t.PolicyURL != ""
}

// Create loads environment configuration and the separate DNSID_API_KEY secret.
// Applications with file configuration or injected dependencies use New(...).Create.
func Create(ctx context.Context, name string) (*FoundryIdentity, error) {
	ctx, cancel := operationContext(ctx, createTimeout)
	defer cancel()
	if err := ctx.Err(); err != nil {
		return nil, failure(Deadline, nil, err)
	}
	loaded, err := config.LoadEnvironment(nil)
	if err != nil {
		return nil, err
	}
	client, err := New(loaded, Dependencies{Credential: strings.TrimSpace(os.Getenv("DNSID_API_KEY"))})
	if err != nil {
		return nil, err
	}
	return client.Create(ctx, name)
}

// FoundryIdentity is a durable identity handle. Observation accessors are safe
// during Sign and Active. Domain never changes after Create returns the handle.
type FoundryIdentity struct {
	mu             sync.RWMutex
	client         *Client
	key            OperationKey
	domain         string
	state          dnsid.AgentState
	registryStatus string
	signer         *signingController
	manager        *dnsid.IdentityManager
	logs           *dnsidlog.LogRegistry
	trust          *lazyLogTrust
}

// Domain returns the immutable registry-assigned domain.
func (i *FoundryIdentity) Domain() string { return i.domain }

// State returns the last real public observation, or the empty state.
func (i *FoundryIdentity) State() dnsid.AgentState {
	i.mu.RLock()
	defer i.mu.RUnlock()
	return i.state
}

// RegistryStatus returns the last control-plane observation, not protocol state.
func (i *FoundryIdentity) RegistryStatus() string {
	i.mu.RLock()
	defer i.mu.RUnlock()
	return i.registryStatus
}

// IdentityManager returns the manager sharing this handle's signing controller.
// It returns SigningPaused until the publication configuration is saved.
// All subsequent successful calls return the same instance.
func (i *FoundryIdentity) IdentityManager() (*dnsid.IdentityManager, error) {
	i.mu.RLock()
	defer i.mu.RUnlock()
	if i.manager == nil {
		i.signer.mu.Lock()
		paused := i.signer.pausedError("publication configuration is not saved")
		i.signer.mu.Unlock()
		return nil, paused
	}
	return i.manager, nil
}

// Sign signs raw bytes without adding a JOSE or other application format.
func (i *FoundryIdentity) Sign(data []byte) ([]byte, error) {
	sig, err := i.signer.Sign(data)
	if err != nil {
		return nil, err
	}
	return sig.Signature, nil
}

// Create stops after the identity ID and domain are saved; it does not wait for public ACTIVE.
func (c *Client) Create(ctx context.Context, name string) (identity *FoundryIdentity, err error) {
	ctx, cancel := operationContext(ctx, createTimeout)
	defer cancel()
	var doc *RecoveryDocument
	defer func() {
		err = c.deadlineError(ctx, doc, err)
		if err != nil {
			identity = nil
		}
	}()
	if err := ValidateName(name); err != nil {
		return nil, dnsid.NewArgumentError("foundry: invalid exact name", err)
	}
	if err := ctx.Err(); err != nil {
		return nil, failure(Deadline, nil, err)
	}
	// Validate an already-open key before account discovery, without provisioning.
	if c.deps.KeyProvider != nil {
		if err := validateProviderKey(ctx, c.deps.KeyProvider, false); err != nil && !isKind(err, KeyMissing) {
			return nil, err
		}
	}
	onboarding, err := c.onboarding(ctx, nil)
	if err != nil {
		return nil, err
	}
	key := OperationKey{c.loaded.Registry.RegistryURL, onboarding.OrganizationID, name}
	lease, err := c.deps.Store.Lock(ctx, key)
	if err != nil {
		var structured *Error
		if errors.As(err, &structured) {
			return nil, err
		}
		return nil, c.wrap(nil, err)
	}
	defer func() {
		if closeErr := lease.Close(); closeErr != nil {
			err = errors.Join(err, closeErr)
		}
	}()
	doc, err = lease.Load(ctx)
	if err != nil {
		return nil, failure(Integrity, nil, err)
	}
	if doc != nil {
		if err := c.checkBindings(doc, onboarding); err != nil {
			return nil, err
		}
		if err := registryOutcome(doc); err != nil {
			return nil, err
		}
	}
	provider := c.deps.KeyProvider
	if provider == nil {
		source := c.loaded.KeySource
		if doc != nil {
			source = doc.KeySource
			if doc.CurrentKeySource != nil {
				source = *doc.CurrentKeySource
			}
			if !sameJSON(source, c.loaded.KeySource) && (doc.CurrentKeySource == nil || !sameJSON(doc.KeySource, c.loaded.KeySource)) {
				return nil, failure(KeyMismatch, doc, fmt.Errorf("configured provider reference differs from recovery state"))
			}
		}
		provider, err = config.OperationalKeyProviderFrom(ctx, source, "")
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				return nil, failure(KeyMissing, doc, err)
			}
			return nil, c.wrap(doc, err)
		}
	}
	if err := validateProviderKey(ctx, provider, doc == nil || doc.Phase == "creation-pending"); err != nil {
		var structured *Error
		if errors.As(err, &structured) {
			return nil, withFacts(err, doc)
		}
		return nil, c.wrap(doc, err)
	}
	current, err := providerPublic(ctx, provider)
	if err != nil {
		return nil, c.wrap(doc, err)
	}
	if doc == nil {
		initial, err := json.Marshal(current)
		if err != nil {
			return nil, err
		}
		thumb, err := keyThumb(current)
		if err != nil {
			return nil, err
		}
		requestID, err := RegistrationKey(key.OrganizationID, name, thumb)
		if err != nil {
			return nil, err
		}
		trust, err := trustSnapshot(c.loaded.LogTrust)
		if err != nil {
			return nil, err
		}
		source := c.loaded.KeySource
		source.EntityKeyPath = ""
		doc = &RecoveryDocument{SchemaVersion: 1, Phase: "creation-pending", RegistryURL: key.RegistryURL, OrganizationID: key.OrganizationID, Name: name, GovernanceID: onboarding.GovernanceDomain, LogTrust: trust, KeySource: source, InitialPublicKey: initial, RequestID: requestID, CreationInput: CreationInput{Name: name, PublicKey: initial, Environment: "production", Tier: "live", Managed: true}}
		if err := lease.Save(ctx, doc); err != nil {
			return nil, c.wrap(doc, err)
		}
	} else if err := matchCurrentKey(doc, current); err != nil {
		return nil, err
	}
	if doc.IdentityID == "" || doc.Domain == "" {
		input := &dnsid.LiveAgentRegistrationInput{Name: doc.CreationInput.Name, PublicKey: doc.CreationInput.PublicKey, Environment: doc.CreationInput.Environment, CapabilitiesURL: doc.CreationInput.CapabilitiesURL}
		response, callErr := c.deps.RegistryClient.CreateLiveAgent(ctx, input, doc.RequestID)
		if response != nil {
			if response.RequestID != doc.RequestID || response.AgentID == "" || response.Status == "" {
				return nil, failure(Integrity, doc, fmt.Errorf("invalid Live creation facts"))
			}
			if doc.IdentityID != "" && doc.IdentityID != response.AgentID {
				return nil, failure(Integrity, doc, fmt.Errorf("replay changed identity ID"))
			}
			doc.IdentityID = response.AgentID
			doc.RegistryStatus = response.Status
			if callErr == nil {
				if err := recordChallenge(doc, response); err != nil {
					return nil, err
				}
			}
			if err := lease.Save(ctx, doc); err != nil {
				return nil, c.wrap(doc, errors.Join(callErr, err))
			}
		}
		if callErr != nil {
			return nil, c.wrap(doc, callErr)
		}
		if response == nil {
			return nil, failure(Integrity, doc, fmt.Errorf("empty Live response"))
		}
		if err := registryOutcome(doc); err != nil {
			return nil, err
		}
		if doc.Domain == "" {
			return nil, failure(Unresolved, doc, fmt.Errorf("registry accepted creation without an assigned domain; retry Create"))
		}
	} else if doc.Phase != "complete" {
		if _, err := c.readDetail(ctx, lease, doc); err != nil {
			return nil, err
		}
	}
	signer := newSigningController(provider, doc)
	identity = &FoundryIdentity{client: c, key: key, domain: doc.Domain, registryStatus: doc.RegistryStatus, signer: signer, state: dnsid.AgentState(doc.ProtocolState), logs: c.deps.LogRegistry}
	if err := registryOutcome(doc); err != nil {
		return nil, err
	}
	if identity.logs == nil {
		identity.logs, identity.trust, err = newLazyLogRegistry(c.loaded)
		if err != nil {
			return nil, c.wrap(doc, err)
		}
	}
	if doc.PublicationConfig != nil {
		if err := identity.configureManager(doc); err != nil {
			return nil, err
		}
	}
	if doc.Phase == "complete" && !doc.SigningPaused {
		if err := signer.enable(current); err != nil {
			return nil, err
		}
	}
	return identity, nil
}

func (c *Client) onboarding(ctx context.Context, doc *RecoveryDocument) (*dnsid.OrganizationOnboardingResponse, error) {
	value, err := c.deps.RegistryClient.GetOrganizationOnboarding(ctx)
	if err != nil {
		var api *dnsid.RegistryAPIError
		if errors.As(err, &api) && (api.StatusCode == http.StatusNotFound || api.StatusCode == http.StatusMethodNotAllowed) {
			detail := c.wrap(doc, err)
			detail.Kind, detail.Resumable = UnsupportedContract, false
			return nil, &UnsupportedRegistry{detail}
		}
		return nil, c.wrap(doc, err)
	}
	if value == nil || value.OrganizationID == "" || value.EK.Status == "" || (value.GI != nil && (value.MissingRequiredFields || value.GI.Domain == "" || value.GI.State == "")) {
		return nil, &UnsupportedRegistry{failure(UnsupportedContract, doc, fmt.Errorf("incomplete Identity Digital onboarding contract"))}
	}
	if value.GovernanceDomain == "" || value.GI == nil {
		outcome := failure(WorkflowOutcome, doc, fmt.Errorf("organization governance proof and entity delegation must be verified"))
		outcome.Resumable = true
		return nil, outcome
	}
	gi, err := dnsid.NormalizeFQDN(value.GovernanceDomain)
	if err != nil {
		return nil, failure(Integrity, doc, err)
	}
	proofGI, err := dnsid.NormalizeFQDN(value.GI.Domain)
	if err != nil || proofGI != gi {
		return nil, failure(Integrity, doc, fmt.Errorf("onboarding GI binding mismatch"))
	}
	if value.GI.State != "verified" || !value.GI.GateAuthorized || value.EK.Status != "verified" {
		outcome := failure(WorkflowOutcome, doc, fmt.Errorf("organization governance proof and entity delegation must be verified"))
		outcome.Resumable = true
		return nil, outcome
	}
	if expected := c.loaded.Foundry.OrganizationID; expected != "" && expected != value.OrganizationID {
		return nil, failure(Integrity, doc, fmt.Errorf("unexpected organization ID"))
	}
	if expected := c.loaded.Foundry.GovernanceID; expected != "" {
		normalized, err := dnsid.NormalizeFQDN(expected)
		if err != nil || normalized != gi {
			return nil, failure(Integrity, doc, fmt.Errorf("unexpected governance ID"))
		}
	}
	copy := *value
	copy.GovernanceDomain = gi
	if doc != nil {
		if err := c.checkBindings(doc, &copy); err != nil {
			return nil, err
		}
	}
	return &copy, nil
}

func (c *Client) checkBindings(doc *RecoveryDocument, onboarding *dnsid.OrganizationOnboardingResponse) error {
	if err := doc.validate(); err != nil {
		return failure(Integrity, doc, err)
	}
	if doc.RegistryURL != c.loaded.Registry.RegistryURL || doc.OrganizationID != onboarding.OrganizationID || doc.GovernanceID != onboarding.GovernanceDomain {
		return failure(Integrity, doc, fmt.Errorf("saved registry/account/governance binding mismatch"))
	}
	trust, err := trustSnapshot(c.loaded.LogTrust)
	if err != nil {
		return err
	}
	if c.deps.LogRegistry == nil && !sameJSON(trust, doc.LogTrust) {
		return failure(Integrity, doc, fmt.Errorf("configured log trust differs from recovery state"))
	}
	return nil
}

func sameJSON(a, b any) bool {
	x, err := json.Marshal(a)
	if err != nil {
		return false
	}
	y, err := json.Marshal(b)
	if err != nil {
		return false
	}
	var left, right any
	if json.Unmarshal(x, &left) != nil || json.Unmarshal(y, &right) != nil {
		return false
	}
	return reflect.DeepEqual(left, right)
}

func trustSnapshot(t config.LogTrust) (json.RawMessage, error) {
	if !hasTrust(t) {
		return nil, nil
	}
	return json.Marshal(struct {
		Managed        bool                   `json:"managed,omitempty"`
		Profile        *c2sptlog.TrustProfile `json:"profile,omitempty"`
		PolicyDocument string                 `json:"policyDocument,omitempty"`
		PolicyURL      string                 `json:"policyUrl,omitempty"`
	}{t.Managed, t.Profile, base64.RawURLEncoding.EncodeToString(t.PolicyDocument), t.PolicyURL})
}

func matchCurrentKey(doc *RecoveryDocument, current jwk.Key) error {
	raw := doc.CurrentPublicKey
	if len(raw) == 0 {
		raw = doc.InitialPublicKey
	}
	saved, err := parsePublicKey(raw)
	if err != nil {
		return failure(Integrity, doc, err)
	}
	a, err := keyThumb(saved)
	if err != nil {
		return failure(Integrity, doc, err)
	}
	b, err := keyThumb(current)
	if err != nil {
		return failure(Integrity, doc, err)
	}
	if a != b {
		return failure(KeyMismatch, doc, fmt.Errorf("provider key differs from saved current binding"))
	}
	return nil
}

func withFacts(err error, doc *RecoveryDocument) error {
	var e *Error
	if errors.As(err, &e) {
		next := *e
		if doc != nil {
			next.Phase, next.IdentityID, next.Domain, next.RegistryStatus = doc.Phase, doc.IdentityID, doc.Domain, doc.RegistryStatus
		}
		return &next
	}
	return err
}

func (c *Client) deadlineError(ctx context.Context, doc *RecoveryDocument, err error) error {
	if err == nil || ctx.Err() == nil {
		return err
	}
	var structured *Error
	if errors.As(err, &structured) && structured.Kind != Unresolved && structured.Kind != Deadline && (structured.Kind != Integrity || !errors.Is(err, ctx.Err())) {
		return err
	}
	return c.wrap(doc, errors.Join(err, ctx.Err()))
}

func (c *Client) wrap(doc *RecoveryDocument, err error) *Error {
	kind := Unresolved
	var api *dnsid.RegistryAPIError
	e := failure(kind, doc, err)
	var issuanceErr *c2sptlog.ManagedIssuanceOperationError
	if errors.As(err, &issuanceErr) && doc != nil && doc.Issuance != nil && doc.Issuance.Operation != nil && doc.Issuance.Operation.TerminalFailure {
		e.Code = doc.Issuance.Operation.LastErrorCode
		e.StatusCode = doc.Issuance.StatusCode
	}
	if errors.As(err, &api) {
		e.StatusCode = api.StatusCode
		e.Code = api.Code
		e.Resumable = api.Transient()
		switch api.Code {
		case "KEY_MISSING":
			e.Kind = KeyMissing
		case "KEY_MISMATCH":
			e.Kind = KeyMismatch
		case "KEY_REVOKED":
			e.Kind = KeyRevoked
		}
	}
	var validation *dnsid.ValidationError
	var argument *dnsid.ArgumentError
	var parse *dnsid.ParseError
	if errors.As(err, &validation) || errors.As(err, &argument) || errors.As(err, &parse) {
		e.Kind = Integrity
		e.Resumable = false
	}
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		e.Kind = Deadline
		e.Resumable = true
	}
	return e
}

func registryOutcome(doc *RecoveryDocument) error {
	if doc.ProtocolState == string(dnsid.AgentStateRetired) || doc.ProtocolState == string(dnsid.AgentStateRevoked) {
		return failure(Terminal, doc, fmt.Errorf("same-name replacement is disabled"))
	}
	switch doc.RegistryStatus {
	case "REVOKED", "RETIRED":
		return failure(Terminal, doc, fmt.Errorf("same-name replacement is disabled"))
	case "ERROR", "REJECTED", "CANCELLED":
		outcome := failure(WorkflowOutcome, doc, fmt.Errorf("registry workflow requires an agreed server recovery path"))
		if doc.RegistryError != nil {
			outcome.Code = doc.RegistryError.Code
		}
		return outcome
	}
	return nil
}

func (c *Client) readDetail(ctx context.Context, lease FoundryLease, doc *RecoveryDocument) (*dnsid.AgentDetail, error) {
	detail, err := c.deps.RegistryClient.GetAgentStatus(ctx, doc.Domain)
	if err != nil {
		return nil, c.wrap(doc, err)
	}
	if detail == nil {
		return nil, failure(Integrity, doc, fmt.Errorf("empty registry detail"))
	}
	domain, err := dnsid.NormalizeFQDN(detail.Domain)
	if err != nil || domain != doc.Domain || detail.ID != doc.IdentityID || detail.Name != doc.Name {
		return nil, failure(Integrity, doc, fmt.Errorf("registry detail changed identity bindings"))
	}
	doc.RegistryStatus = detail.Status
	doc.RegistryError = detail.Error
	if err := lease.Save(ctx, doc); err != nil {
		return nil, c.wrap(doc, err)
	}
	if err := registryOutcome(doc); err != nil {
		return nil, err
	}
	return detail, nil
}

func (c *Client) waitForRegistryReady(ctx context.Context, lease FoundryLease, doc *RecoveryDocument) (*dnsid.AgentDetail, error) {
	var backoff pollBackoff
	for {
		detail, err := c.readDetail(ctx, lease, doc)
		if err != nil {
			return nil, err
		}
		if doc.RegistryStatus == "VERIFIED" || doc.RegistryStatus == "READY" {
			return detail, nil
		}
		if err := backoff.wait(ctx); err != nil {
			return nil, c.wrap(doc, err)
		}
	}
}

// Active completes durable setup and makes a new, isolated public observation
// on every call. Cancellation preserves progress and does not cancel the identity.
func (i *FoundryIdentity) Active(ctx context.Context) (identity *FoundryIdentity, err error) {
	ctx, cancel := operationContext(ctx, activeTimeout)
	defer cancel()
	var doc *RecoveryDocument
	defer func() {
		err = i.client.deadlineError(ctx, doc, err)
		if err != nil {
			identity = nil
		}
	}()
	lease, err := i.client.deps.Store.Lock(ctx, i.key)
	if err != nil {
		i.signer.mu.Lock()
		facts := i.signer.facts
		i.signer.mu.Unlock()
		known := &RecoveryDocument{Phase: facts.Phase, IdentityID: facts.IdentityID, Domain: i.domain, RegistryStatus: i.RegistryStatus()}
		var structured *Error
		if errors.As(err, &structured) {
			return nil, withFacts(err, known)
		}
		return nil, i.client.wrap(known, err)
	}
	defer func() {
		if closeErr := lease.Close(); closeErr != nil {
			err = errors.Join(err, closeErr)
		}
	}()
	doc, err = lease.Load(ctx)
	if ctx.Err() != nil {
		return nil, i.client.wrap(doc, ctx.Err())
	}
	if err != nil || doc == nil {
		i.signer.pause("identity recovery state is missing or invalid")
		return nil, failure(Integrity, doc, errors.Join(err, fmt.Errorf("identity recovery state is missing or invalid")))
	}
	defer func() {
		err = i.client.deadlineError(ctx, doc, err)
		i.mu.Lock()
		i.registryStatus = doc.RegistryStatus
		i.state = dnsid.AgentState(doc.ProtocolState)
		i.mu.Unlock()
		i.signer.updateFacts(doc)
		if isKind(err, Terminal) || isKind(err, KeyMismatch) || isKind(err, Integrity) {
			i.signer.pause("terminal observation or binding mismatch")
			doc.SigningPaused = true
			// Keep a confirmed unsafe state paused across restart, even after cancellation.
			pauseCtx, cancelPause := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
			defer cancelPause()
			if saveErr := lease.Save(pauseCtx, doc); saveErr != nil {
				err = errors.Join(err, saveErr)
			}
		}
	}()
	if doc.Domain != i.domain {
		return nil, failure(Integrity, doc, fmt.Errorf("stored domain differs from handle"))
	}
	if _, err := i.client.onboarding(ctx, doc); err != nil {
		return nil, err
	}
	current, err := providerPublic(ctx, i.signer.KeyProvider)
	if err != nil {
		return nil, i.client.wrap(doc, err)
	}
	if err := matchCurrentKey(doc, current); err != nil {
		if doc.Phase != "complete" {
			return nil, err
		}
		// Only fresh signed ku and verified continuity can authorize a successor.
		i.signer.pause("current provider binding needs fresh lifecycle verification")
		doc.SigningPaused = true
		if err := lease.Save(ctx, doc); err != nil {
			return nil, i.client.wrap(doc, err)
		}
	}
	if err := registryOutcome(doc); err != nil {
		return nil, err
	}
	if doc.Proof != nil && doc.Proof.Outcome != "accepted" {
		if err := i.prove(ctx, lease, doc); err != nil {
			return nil, err
		}
	}
	detail, err := i.client.waitForRegistryReady(ctx, lease, doc)
	if err != nil {
		return nil, err
	}
	if err := i.publication(ctx, lease, doc, detail); err != nil {
		return nil, err
	}
	if err := i.configureManager(doc); err != nil {
		return nil, err
	}
	if err := i.issue(ctx, lease, doc); err != nil {
		return nil, err
	}
	if err := i.observe(ctx, lease, doc); err != nil {
		return nil, err
	}
	return i, nil
}

func (i *FoundryIdentity) configureManager(doc *RecoveryDocument) error {
	i.mu.Lock()
	defer i.mu.Unlock()
	if i.manager != nil {
		return nil
	}
	cfg := i.client.loaded.Dnsid
	identity := publicationIdentity(doc.Domain, doc.PublicationConfig)
	cfg.Identity = &identity
	deps := config.Dependencies{KeyProvider: i.signer, DNSResolver: i.client.deps.DNSResolver, HTTPSFetcher: i.client.deps.HTTPSFetcher, LogRegistry: i.logs}
	// Trust factories run in Active with its deadline, not in the constructor.
	loaded := i.client.loaded
	loaded.Dnsid = cfg
	loaded.LogTrust = config.LogTrust{}
	loaded.KeySource = config.KeySource{}
	manager, err := config.Construct(context.Background(), loaded, deps)
	if err != nil {
		return err
	}
	i.manager = manager
	return nil
}
