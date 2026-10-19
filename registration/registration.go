package registration

import (
	"bytes"
	"context"
	"crypto"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"reflect"
	"strings"
	"time"

	dnsid "github.com/dnsid-ai/dnsid-go"
	"github.com/dnsid-ai/dnsid-go/config"
	dnsidlog "github.com/dnsid-ai/dnsid-go/log"
	"github.com/dnsid-ai/dnsid-go/log/c2sptlog"
	"github.com/lestrrat-go/jwx/v3/jwk"
)

// RegistryClient is the existing registry surface used by managed setup.
// Keyed creation must implement permanent organization-scoped idempotency,
// derived-key validation, and atomic name/key ownership. The SDK HTTP client implements this
// interface; consumers do not need a recovery adapter.
type RegistryClient interface {
	dnsid.RegistryPreparedEventClient
	dnsid.RegistryRegistrationReader
	RegisterAgent(context.Context, *dnsid.AgentRegistrationInput, string) (*dnsid.AgentRegistration, error)
	GetOrganizationOnboarding(context.Context) (*dnsid.OrganizationOnboardingResponse, error)
}

// Options supplies optional runtime dependencies. An injected RegistryClient
// owns its credentials and networking. Otherwise setup builds the SDK client
// from the explicit credential and effective transport configuration.
// Injected log trust and providers require stable references on resume.
type Options struct {
	RegistryClient    RegistryClient
	Dependencies      config.Dependencies
	TrustReference    string
	ProviderReference string
	PollInterval      time.Duration
	Timeout           time.Duration
}

// ManagedRegistrationResult is public evidence at observation time. Manager
// retains the application's unchanged counterparty acceptance policy.
type ManagedRegistrationResult struct {
	Registration        *dnsid.AgentRegistration
	Manager             *dnsid.IdentityManager
	PublishedRecord     *dnsid.PublishedRecord
	LoggedStateEvidence dnsidlog.LoggedStateEvidence
}

// Error preserves the failed setup phase, immutable identity when known, and
// underlying structured error without printing credentials or acceptance policy.
type Error struct {
	Phase          string
	Code           string
	Domain         string
	RegistrationID string
	RegistryStatus string
	Resumable      bool
	Cause          error
}

func (e *Error) Error() string {
	return fmt.Sprintf("dnsid: managed registration %s failed (%s), domain=%s id=%s", e.Phase, e.Code, e.Domain, e.RegistrationID)
}
func (e *Error) Unwrap() error { return e.Cause }

// RegisterManagedIdentity creates or resumes one durable managed setup. The
// default total budget is ten minutes. The registry must support permanent
// keyed creation; verify that server contract before enabling automatic recovery.
func RegisterManagedIdentity(ctx context.Context, name string, loaded config.Loaded, credential string, store ManagedRegistrationStore, input *dnsid.AgentRegistrationInput, options ...Options) (result *ManagedRegistrationResult, err error) {
	if len(options) > 1 {
		return nil, dnsid.NewArgumentError("dnsid: at most one registration Options value is allowed", nil)
	}
	var opts Options
	if len(options) == 1 {
		opts = options[0]
	}
	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = 10 * time.Minute
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	phase, code := "validation", "binding"
	var state *State
	defer func() {
		if err == nil && ctx.Err() != nil {
			result = nil
			err = ctx.Err()
		}
		if err == nil {
			return
		}
		e := &Error{Phase: phase, Code: code, Cause: err, Resumable: state != nil}
		if state != nil {
			if state.Creation != nil {
				e.Domain = state.Creation.Domain
				e.RegistrationID = state.Creation.ID
			}
			if state.Registration != nil {
				e.Domain = state.Registration.Domain
				e.RegistrationID = state.Registration.ID
				e.RegistryStatus = state.ObservedRegistryStatus
				if e.RegistryStatus == "" {
					e.RegistryStatus = state.Registration.RegistryStatus
				}
			}
		}
		var verification *dnsid.VerificationError
		if errors.As(err, &verification) && (verification.Code() == dnsid.VerificationCodeTerminalState || verification.AgentState() == dnsid.AgentStateRetired || verification.AgentState() == dnsid.AgentStateRevoked) {
			e.Code = "terminal"
			e.Resumable = false
		}
		var workflow *dnsid.RegistryWorkflowError
		if errors.As(err, &workflow) && workflow.Registration != nil {
			e.RegistryStatus = workflow.Registration.RegistryStatus
			if workflow.Cause == nil {
				e.Code = "terminal"
				e.Resumable = false
			}
		}
		if e.Code == "corrupt_state" {
			e.Resumable = false
		}
		err = e
	}()
	if store == nil {
		return nil, dnsid.NewArgumentError("dnsid: registration store is required", nil)
	}
	if err = loaded.Dnsid.Validate(); err != nil {
		return nil, err
	}
	name, err = normalizeName(name)
	if err != nil {
		return nil, err
	}
	gi := loaded.Registration.GovernanceID
	if gi != "" {
		gi, err = dnsid.NormalizeFQDN(gi)
		if err != nil {
			return nil, dnsid.NewArgumentError("dnsid: invalid expected governance ID", err)
		}
	}
	loaded.Registration.GovernanceID = gi
	loaded.Registration.OrganizationID = strings.TrimSpace(loaded.Registration.OrganizationID)
	if err = validateHTTPS(loaded.Registration.EntityKeyURL); err != nil {
		return nil, err
	}
	input, err = normalizeInput(input, gi)
	if err != nil {
		return nil, err
	}
	if input != nil && input.Name != "" && input.Name != name {
		return nil, dnsid.NewArgumentError("dnsid: input.name differs from the operation name", nil)
	}
	if opts.Dependencies.LogRegistry == nil && reflect.ValueOf(loaded.LogTrust).IsZero() {
		return nil, dnsid.NewArgumentError("dnsid: explicit log trust is required", nil)
	}
	if opts.Dependencies.LogRegistry != nil && opts.TrustReference == "" {
		return nil, dnsid.NewArgumentError("dnsid: injected log trust requires a stable TrustReference", nil)
	}
	// Managed setup only retrieves the entity's public bootstrap key.
	loaded.KeySource.EntityKeyPath = ""
	if opts.Dependencies.KeyProvider != nil {
		if opts.ProviderReference == "" {
			return nil, dnsid.NewArgumentError("dnsid: injected provider requires a stable ProviderReference", nil)
		}
		// Injection displaces source resolution, including unavailable packages.
		loaded.KeySource = config.KeySource{}
	} else if err = config.ValidateKeySource(loaded.KeySource); err != nil {
		return nil, err
	}
	if opts.Dependencies.EntityKeyProvider != nil {
		return nil, dnsid.NewArgumentError("dnsid: managed setup never uses an entity private key", nil)
	}
	if opts.Dependencies.HTTPClient != nil && opts.Dependencies.HTTPSFetcher != nil {
		return nil, dnsid.NewArgumentError("dnsid: HTTPClient and HTTPSFetcher cannot both be supplied", nil)
	}
	loaded, err = clone(loaded)
	if err != nil {
		return nil, err
	}
	registryURL := strings.TrimRight(loaded.Registry.RegistryURL, "/")
	if registryURL == "" {
		registryURL = dnsid.DefaultRegistryURL
	}
	loaded.Registry.RegistryURL = registryURL
	registry := opts.RegistryClient
	if registry != nil {
		if _, err = dnsid.NewRegistryClientWithOptions(registryURL); err != nil {
			return nil, err
		}
	}
	if registry == nil {
		if credential == "" {
			return nil, dnsid.NewArgumentError("dnsid: registration requires an organization credential", nil)
		}
		httpClient := opts.Dependencies.HTTPClient
		if httpClient == nil {
			httpClient, err = dnsid.CreateDnsidHTTPClient(loaded.Dnsid.Transport)
			if err != nil {
				return nil, err
			}
		}
		client, clientErr := dnsid.NewRegistryClientWithOptions(registryURL, dnsid.WithRegistryHTTPClient(httpClient), dnsid.WithAuthToken(credential))
		if clientErr != nil {
			return nil, clientErr
		}
		registry = client
	}
	phase = "account"
	if loaded.Registration.OrganizationID == "" {
		if err = discoverAccount(ctx, registry, &loaded.Registration, opts.PollInterval); err != nil {
			return nil, err
		}
	}
	scope := Scope{RegistryURL: registryURL, OrganizationID: loaded.Registration.OrganizationID, Name: name}
	phase = "recovery"
	session, lockErr := store.Acquire(ctx, scope)
	if lockErr != nil {
		code = "store"
		return nil, lockErr
	}
	defer func() {
		if closeErr := session.Close(); closeErr != nil {
			result = nil
			err = errors.Join(err, closeErr)
		}
	}()
	state, err = session.Load(ctx)
	if err != nil {
		code = "store"
		return nil, err
	}
	if state != nil {
		if state.Scope != scope {
			return nil, fmt.Errorf("saved registry/account/name binding conflicts")
		}
		if err = validateState(state); err != nil {
			code = "corrupt_state"
			return nil, err
		}
		if loaded.Registration.GovernanceID == "" {
			loaded.Registration.GovernanceID = state.Loaded.Registration.GovernanceID
		}
	}
	if loaded.Registration.GovernanceID == "" {
		if err = discoverAccount(ctx, registry, &loaded.Registration, opts.PollInterval); err != nil {
			return nil, err
		}
	}
	gi = loaded.Registration.GovernanceID
	if input != nil && input.GovernanceDomain != "" && input.GovernanceDomain != gi {
		return nil, dnsid.NewArgumentError("dnsid: requested governance domain differs from resolved expectation", nil)
	}
	providerRef := opts.ProviderReference
	if providerRef == "" {
		providerRef = loaded.KeySource.KeyRef
		if providerRef == "" {
			providerRef = "file:store:operational-key"
		}
	}
	if state != nil {
		if !equal(state.Loaded.Registration, loaded.Registration) || !equal(state.Loaded.LogTrust, loaded.LogTrust) || state.LogTrustReference != opts.TrustReference || (!state.Complete && (!equal(state.Loaded.KeySource, loaded.KeySource) || state.ProviderReference != providerRef)) {
			return nil, fmt.Errorf("deployment or provider binding conflicts with saved setup")
		}
		if input != nil && !state.matchesInput(input) {
			return nil, fmt.Errorf("input conflicts with original registration request")
		}
	}
	logRegistry := opts.Dependencies.LogRegistry
	if logRegistry == nil {
		logRegistry, err = config.LogRegistryFromTrust(ctx, loaded.LogTrust, loaded.Dnsid.Transport)
		if err != nil {
			return nil, err
		}
	}
	if state == nil {
		extra := &dnsid.AgentRegistrationInput{}
		var expectedKey json.RawMessage
		if input != nil {
			*extra = *input
			if input.PublicKeyJWK != nil {
				key, keyErr := parsePublic(input.PublicKeyJWK)
				if keyErr != nil {
					return nil, keyErr
				}
				expectedKey, err = publicJSON(key)
				if err != nil {
					return nil, err
				}
			}
		}
		extra.Name, extra.PublicKeyJWK = "", nil
		locator := "operational-key.json"
		if generation := loaded.KeySource.Generation; generation != nil {
			key, locatorErr := digestStrings(generation.Locator)
			if locatorErr != nil {
				return nil, locatorErr
			}
			locator = "key-" + key + ".json"
		}
		state = &State{Version: 3, Scope: scope, Loaded: loaded, Input: extra, OperationalKey: expectedKey, KeyLocator: locator, ProviderReference: providerRef, Phase: "intent", LogTrustReference: opts.TrustReference}
		if err = session.Save(ctx, state); err != nil {
			return nil, err
		}
	}
	phase = "key"
	code = "missing_key"
	provider := opts.Dependencies.KeyProvider
	if provider == nil && (loaded.KeySource.KeyRef != "" || loaded.KeySource.CliDirectory != "" || loaded.KeySource.KeyStorePath != "" || (loaded.KeySource.Provider != "" && loaded.KeySource.Provider != "file")) {
		domain := ""
		if state.Registration != nil {
			domain = state.Registration.Domain
		} else if loaded.Dnsid.Identity != nil {
			domain = loaded.Dnsid.Identity.Domain
		}
		provider, err = config.OperationalKeyProviderFrom(ctx, loaded.KeySource, domain)
		if err != nil {
			return nil, err
		}
	}
	if provider == nil {
		create := !state.KeyStarted && state.Phase == "intent"
		if create {
			state.KeyStarted = true
			if err = session.Save(ctx, state); err != nil {
				return nil, err
			}
		}
		provider, err = session.RecoverKey(ctx, create)
		if err != nil {
			return nil, err
		}
	}
	if provider.JWK() == nil {
		return nil, fmt.Errorf("provider has no current signing key")
	}
	currentPin, pinErr := thumbprint(provider.JWK())
	if pinErr != nil {
		return nil, pinErr
	}
	if state.Complete && (!equal(state.Loaded.KeySource, loaded.KeySource) || state.ProviderReference != providerRef) && currentPin == state.CurrentOperationalThumbprint {
		return nil, fmt.Errorf("changing key-source configuration alone is not an authorized rotation")
	}
	publicKey, keyErr := publicJSON(provider.JWK())
	if keyErr != nil {
		return nil, keyErr
	}
	if len(state.OperationalKey) == 0 {
		state.OperationalKey = publicKey
	}
	if state.Phase == "intent" {
		original, keyErr := parsePublic(state.OperationalKey)
		if keyErr != nil || !sameKey(original, provider.JWK()) {
			return nil, fmt.Errorf("requested registration key differs from provider: %w", keyErr)
		}
		state.Phase = "request"
		if err = session.Save(ctx, state); err != nil {
			return nil, err
		}
	}
	_, issuanceKey, keyErr := state.replayKeys()
	if keyErr != nil {
		return nil, keyErr
	}
	original, keyErr := jwk.ParseKey(state.OperationalKey)
	if keyErr != nil {
		return nil, keyErr
	}
	if !state.Complete && !sameKey(original, provider.JWK()) {
		code = "key_binding"
		return nil, fmt.Errorf("unfinished setup requires original operational key")
	}
	phase = "registration"
	code = "creation"
	if state.Registration == nil {
		if err = register(ctx, session, state, registry, opts.PollInterval); err != nil {
			return nil, err
		}
	}
	r := state.Registration
	if state.Complete {
		if err = retry(ctx, opts.PollInterval, func() error {
			current, readErr := registry.GetRegistration(ctx, r.Domain)
			if readErr != nil {
				return readErr
			}
			if readErr = checkSnapshot(current, state); readErr != nil {
				return readErr
			}
			if current.OIDCIssuerURL != "" && current.OIDCIssuerURL != state.Registration.OIDCIssuerURL {
				return fmt.Errorf("authenticated read changed retained OIDC issuer")
			}
			current.OIDCIssuerURL = state.Registration.OIDCIssuerURL
			r = current
			return nil
		}); err != nil {
			return nil, err
		}
	}
	phase = "bindings"
	code = "binding"
	if err = checkRegistration(r, state); err != nil {
		return nil, err
	}
	identity := identityFrom(r)
	if loaded.Dnsid.Identity != nil && !equal(config.Merge(config.Loaded{Dnsid: dnsid.Config{Identity: &identity}}, config.Loaded{Dnsid: dnsid.Config{Identity: loaded.Dnsid.Identity}}).Dnsid.Identity, &identity) {
		return nil, fmt.Errorf("local identity conflicts with retained publication snapshot")
	}
	// Resolve the assigned instance against independently selected log trust.
	boundReader, readerErr := logRegistry.NewReader(r.PublicationConfig.LogRef)
	if readerErr != nil {
		return nil, readerErr
	}
	client, clientErr := c2sptlog.New(r.PublicationConfig.LogRef)
	if clientErr != nil {
		return nil, clientErr
	}
	phase = "prerequisite"
	if !state.Complete {
		if err = awaitPrerequisite(ctx, registry, state, opts.PollInterval); err != nil {
			return nil, err
		}
	}
	phase = "entity_key"
	var entity jwk.Key
	if len(state.EntityKey) == 0 {
		err = retry(ctx, opts.PollInterval, func() error {
			var callErr error
			entity, callErr = fetchEntity(ctx, loaded, opts.Dependencies, r.PublicationConfig.PublishProfile)
			return callErr
		})
		if err != nil {
			return nil, err
		}
		state.EntityKey, err = publicJSON(entity)
		if err != nil {
			return nil, err
		}
		state.EntityThumbprint, err = thumbprint(entity)
		if err != nil {
			return nil, err
		}
		if err = session.Save(ctx, state); err != nil {
			return nil, err
		}
	} else {
		entity, err = jwk.ParseKey(state.EntityKey)
		if err != nil {
			return nil, err
		}
	}
	// Factories can return fail-closed readers for untrusted selectors. Exercise
	// their local canonicalization path before granting operational consent.
	if _, err = boundReader.Canonical(dnsidlog.LogEvent{Type: dnsidlog.LogEventIssuance, Domain: r.Domain, GovernanceID: gi, Timestamp: time.Now(), InitialEntityPublicKey: entity, InitialOperationalPublicKey: original}); err != nil {
		code = "log_binding"
		return nil, err
	}
	if state.Issuance == nil {
		if err = retry(ctx, opts.PollInterval, func() error {
			return openIssuance(ctx, boundReader, client, state, entity, provider, issuanceKey)
		}); err != nil {
			return nil, err
		}
		if state.Issuance != nil {
			if err = saveRecovery(ctx, session, state); err != nil {
				return nil, err
			}
		}
	}
	if state.Issuance != nil {
		var historical *c2sptlog.ManagedIssuanceState
		if err = retry(ctx, opts.PollInterval, func() error {
			var recoveryErr error
			historical, recoveryErr = recoverIssuance(ctx, boundReader, state)
			return recoveryErr
		}); err != nil {
			return nil, err
		}
		if err = c2sptlog.ValidateManagedIssuanceState(ctx, client, historical, entity, provider); err != nil {
			code = "corrupt_state"
			return nil, err
		}
	}
	// The application manager never receives the setup-specific allowlist/pin.
	local := loaded
	local.Dnsid.Identity = &identity
	deps := opts.Dependencies
	deps.KeyProvider = provider
	deps.LogRegistry = logRegistry
	manager, managerErr := config.Construct(ctx, local, deps)
	if managerErr != nil {
		return nil, managerErr
	}
	phase = "issuance"
	code = "issuance"
	issuanceStore := &issuanceSession{session: session, state: state}
	activation := c2sptlog.ManagedIssuanceActivationControllerFunc(func(context.Context, bool) error { return nil })
	if !state.Complete {
		err = retry(ctx, opts.PollInterval, func() error {
			if state.Issuance == nil {
				_, callErr := c2sptlog.BeginManagedIssuance(ctx, c2sptlog.ManagedIssuanceOptions{Domain: r.Domain, GovernanceID: gi, Client: client, IdempotencyKey: issuanceKey, EntityPublicKey: entity, KeyProvider: provider, RegistryClient: registry, Store: issuanceStore, ActivationControl: activation})
				return callErr
			}
			_, callErr := c2sptlog.ResumeManagedIssuance(ctx, c2sptlog.ResumeManagedIssuanceOptions{Domain: r.Domain, Client: client, EntityPublicKey: entity, KeyProvider: provider, RegistryClient: registry, Store: issuanceStore, ActivationControl: activation})
			return callErr
		})
		if err != nil {
			return nil, err
		}
	}
	if state.Issuance.Submission == nil || state.Issuance.Submission.State != dnsid.SubmissionStateAccepted {
		return nil, fmt.Errorf("managed issuance is not accepted")
	}
	phase = "publication"
	code = "propagation"
	reader := &snapshotReader{RegistryClient: registry, state: state}
	var published *dnsid.PublishedRecord
	err = retry(ctx, opts.PollInterval, func() error {
		var callErr error
		published, callErr = manager.AwaitRegistryManagedPublication(ctx, reader, &dnsid.WaitForStatusOptions{PollInterval: interval(opts.PollInterval)})
		return callErr
	})
	if err != nil {
		return nil, err
	}
	phase = "verification"
	code = "public_binding"
	verifierConfig := loaded
	verifierConfig.Dnsid.Identity = nil
	verifierConfig.Dnsid.Verification.TrustedEntities = []dnsid.TrustedEntity{{GovernanceID: gi, EntityKeyThumbprints: []string{state.EntityThumbprint}}}
	verifierDeps := config.Dependencies{LogRegistry: logRegistry, DNSResolver: deps.DNSResolver, HTTPSFetcher: deps.HTTPSFetcher, HTTPClient: deps.HTTPClient}
	var evidence dnsidlog.LoggedStateEvidence
	err = retry(ctx, opts.PollInterval, func() error {
		// Fresh credential-free verifier/cache on every observation attempt.
		verifier, callErr := config.Construct(ctx, verifierConfig, verifierDeps)
		if callErr != nil {
			return callErr
		}
		verified, callErr := verifier.VerifyDomain(ctx, r.Domain)
		if callErr != nil {
			return callErr
		}
		record := verified.Record()
		if !recordMatches(record, r.PublicationConfig) || verified.Status().State != dnsid.AgentStateActive {
			return fmt.Errorf("public identity differs from retained active publication")
		}
		current, callErr := verified.KeySet().CurrentOperationalSigningKey(r.PublicationConfig.PublishProfile)
		if callErr != nil {
			return callErr
		}
		if !sameKey(current.Raw(), provider.JWK()) {
			return fmt.Errorf("provider differs from publicly verified current operational key; recover pending rotation separately")
		}
		evidence, callErr = verified.VerifyLogEvidence(ctx, time.Now())
		if callErr != nil {
			return callErr
		}
		if string(evidence.LogReference) != r.PublicationConfig.LogRef || evidence.LoggedState != dnsidlog.AgentStateActive || evidence.HistoryStart == "" || evidence.HistoryEnd == "" || evidence.CompleteThrough == "" || evidence.FreshnessTime.IsZero() {
			return fmt.Errorf("public lifecycle evidence is incomplete or does not identify the active assigned instance")
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	phase = "completion"
	code = "store"
	if !state.Complete {
		if _, err = c2sptlog.CompleteManagedIssuance(ctx, r.Domain, issuanceStore, activation); err != nil {
			return nil, err
		}
		state.Complete = true
	}
	state.Phase = "complete"
	state.Loaded, state.ProviderReference = loaded, providerRef
	state.CurrentOperationalThumbprint = currentPin
	if !state.IssuanceCompacted {
		if err = retry(ctx, opts.PollInterval, func() error { return compactIssuance(ctx, boundReader, state) }); err != nil {
			return nil, err
		}
	}
	if err = session.Save(ctx, state); err != nil {
		return nil, err
	}
	return &ManagedRegistrationResult{Registration: r, Manager: manager, PublishedRecord: published, LoggedStateEvidence: evidence}, nil
}

func register(ctx context.Context, session Session, s *State, a RegistryClient, poll time.Duration) error {
	return retry(ctx, poll, func() error {
		var r *dnsid.AgentRegistration
		var err error
		if s.Creation != nil && s.Creation.ID != "" && s.Creation.Domain != "" {
			r, err = a.GetRegistration(ctx, s.Creation.Domain)
			if err != nil {
				return err
			}
			if r == nil || r.ID != s.Creation.ID || r.Domain != s.Creation.Domain || !equal(r.PublicationConfig, s.Creation.PublicationConfig) {
				return fmt.Errorf("detail conflicts with retained creation")
			}
			r.OIDCIssuerURL = s.Creation.OIDCIssuerURL
		} else {
			key, _, keyErr := s.replayKeys()
			if keyErr != nil {
				return keyErr
			}
			r, err = a.RegisterAgent(ctx, s.creationInput(), key)
			var recovery *dnsid.RegistrationError
			if errors.As(err, &recovery) && recovery.Creation != nil && recovery.Creation.ID != "" {
				s.Creation = recovery.Creation
			}
		}
		if r != nil {
			if s.Registration != nil && !equal(s.Registration, r) {
				return fmt.Errorf("creation replay changed retained identity")
			}
			s.Registration = r
		}
		if err == nil {
			if err = checkRegistration(s.Registration, s); err == nil {
				s.CreationFingerprint = inputFingerprint(s.creationInput())
				s.Input, s.Creation = nil, nil
				s.Phase = "registered"
			}
		}
		return errors.Join(err, saveRecovery(ctx, session, s))
	})
}

// A cancelled mutation still needs a bounded opportunity to retain its facts.
func saveRecovery(ctx context.Context, session Session, state *State) error {
	cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	return session.Save(cleanup, state)
}

func normalizeInput(input *dnsid.AgentRegistrationInput, gi string) (*dnsid.AgentRegistrationInput, error) {
	if input == nil {
		return nil, nil
	}
	if input.Name != "" {
		if _, err := normalizeName(input.Name); err != nil {
			return nil, err
		}
	}
	i, err := clone(*input)
	if err != nil {
		return nil, dnsid.NewArgumentError("dnsid: invalid registration input", err)
	}
	normalized, err := dnsid.NormalizeAgentRegistrationInput(&i)
	if err != nil {
		return nil, err
	}
	i = *normalized
	if i.Name != "" {
		i.Name, err = normalizeName(i.Name)
		if err != nil {
			return nil, err
		}
	}
	if gi != "" && i.GovernanceDomain != "" && i.GovernanceDomain != gi {
		return nil, dnsid.NewArgumentError("dnsid: requested governance domain differs from setup expectation", nil)
	}
	if i.PublicKeyJWK != nil {
		if _, err := parsePublic(i.PublicKeyJWK); err != nil {
			return nil, err
		}
	}
	return &i, nil
}

func validateHTTPS(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.Fragment != "" {
		return dnsid.NewArgumentError("dnsid: setup endpoint must be HTTPS without userinfo or fragment", err)
	}
	return nil
}
func clone[T any](value T) (T, error) {
	var result T
	data, err := json.Marshal(value)
	if err != nil {
		return result, err
	}
	err = json.Unmarshal(data, &result)
	return result, err
}
func equal(a, b any) bool {
	left, err := json.Marshal(a)
	if err != nil {
		return false
	}
	right, err := json.Marshal(b)
	return err == nil && bytes.Equal(left, right)
}
func inputFingerprint(input *dnsid.AgentRegistrationInput) string {
	copy := *input
	copy.Name, copy.PublicKeyJWK = "", nil
	data, _ := json.Marshal(copy)
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}
func (s *State) matchesInput(input *dnsid.AgentRegistrationInput) bool {
	if input.PublicKeyJWK != nil {
		requested, err := parsePublic(input.PublicKeyJWK)
		original, originalErr := parsePublic(s.OperationalKey)
		if err != nil || originalErr != nil || !sameKey(requested, original) {
			return false
		}
	}
	if s.Input != nil {
		return inputFingerprint(input) == inputFingerprint(s.Input)
	}
	return inputFingerprint(input) == s.CreationFingerprint
}
func publicJSON(key jwk.Key) (json.RawMessage, error) {
	public, err := key.PublicKey()
	if err != nil {
		return nil, err
	}
	return json.Marshal(public)
}
func parsePublic(value any) (jwk.Key, error) {
	if _, err := dnsid.NormalizeAgentRegistrationInput(&dnsid.AgentRegistrationInput{PublicKeyJWK: value}); err != nil {
		return nil, err
	}
	data, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	key, err := jwk.ParseKey(data)
	if err != nil {
		return nil, err
	}
	private, err := jwk.IsPrivateKey(key)
	if err != nil || private {
		return nil, dnsid.NewArgumentError("dnsid: registration recovery must contain public keys only", err)
	}
	return key, nil
}
func thumbprint(key jwk.Key) (string, error) {
	if key == nil {
		return "", fmt.Errorf("missing public key")
	}
	b, err := key.Thumbprint(crypto.SHA256)
	return base64.RawURLEncoding.EncodeToString(b), err
}
func sameKey(a, b jwk.Key) bool {
	x, err := thumbprint(a)
	if err != nil {
		return false
	}
	y, err := thumbprint(b)
	return err == nil && x == y
}
func interval(value time.Duration) time.Duration {
	if value <= 0 {
		return time.Second
	}
	return value
}
func retry(ctx context.Context, poll time.Duration, call func() error) error {
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		err := call()
		if err == nil {
			return nil
		}
		if !transient(err) {
			return err
		}
		timer := time.NewTimer(interval(poll))
		select {
		case <-ctx.Done():
			timer.Stop()
			return errors.Join(ctx.Err(), err)
		case <-timer.C:
		}
	}
}
func transient(err error) bool {
	var issuance *c2sptlog.ManagedIssuanceOperationError
	if errors.As(err, &issuance) {
		return issuance.Transient() || issuance.ShouldRetrySameBytes()
	}
	var api *dnsid.RegistryAPIError
	if errors.As(err, &api) {
		return api.Transient()
	}
	var verification *dnsid.VerificationError
	if errors.As(err, &verification) {
		// DNS absence is retryable; malformed data, signatures, and policy are not.
		if errors.Is(err, dnsid.ErrIdentityRecordNotFound) {
			return true
		}
		if verification.Code() == dnsid.VerificationCodeDNSResolution {
			var dnsErr *net.DNSError
			return errors.As(err, &dnsErr) && (dnsErr.IsNotFound || dnsErr.IsTemporary || dnsErr.IsTimeout)
		}
		switch verification.Code() {
		case dnsid.VerificationCodeStatusUnavailable, dnsid.VerificationCodeJWKSUnavailable, dnsid.VerificationCodeTLSError:
			return verification.Transient()
		}
		return false
	}
	var network net.Error
	return errors.As(err, &network) && network.Timeout()
}

func identityFrom(r *dnsid.AgentRegistration) dnsid.IdentityConfig {
	p := r.PublicationConfig
	return dnsid.IdentityConfig{Domain: r.Domain, GovernanceID: p.GovernanceID, LogRef: p.LogRef, StatusURL: p.StatusURL, EntityKeyURL: p.EntityKeyURL, KeyURL: p.KeyURL, PublishProfile: p.PublishProfile, CapabilitiesURL: p.CapabilitiesURL, MaxKeyAge: dnsid.KeyAge(p.MaxKeyAge)}
}
func checkRegistration(r *dnsid.AgentRegistration, s *State) error {
	if r == nil || r.ID == "" || r.Domain == "" {
		return fmt.Errorf("registration lacks immutable identity")
	}
	domain, err := dnsid.NormalizeFQDN(r.Domain)
	if err != nil || domain != r.Domain {
		return fmt.Errorf("registration domain is not normalized")
	}
	if r.PublicationAuthority != dnsid.PublicationAuthorityRegistry || r.PublicationConfig.PublishProfile != dnsid.DefaultPublishProfile {
		return fmt.Errorf("unsupported publication authority or profile")
	}
	if r.PublicationConfig.GovernanceID != s.Loaded.Registration.GovernanceID || r.PublicationConfig.EntityKeyURL != s.Loaded.Registration.EntityKeyURL {
		return fmt.Errorf("registration differs from independent deployment bindings")
	}
	if s.Input != nil && s.Input.CapabilitiesURL != "" && s.Input.CapabilitiesURL != r.PublicationConfig.CapabilitiesURL {
		return fmt.Errorf("publication capabilities URL differs from request")
	}
	if r.RegistryURL != "" && strings.TrimRight(r.RegistryURL, "/") != s.RegistryURL {
		return fmt.Errorf("registration belongs to another registry")
	}
	if s.Input != nil && s.Input.Domain != "" && s.Input.Domain != r.Domain {
		return fmt.Errorf("assigned domain differs from request")
	}
	if s.Input != nil && s.Input.RootDomain != "" && !strings.HasSuffix(r.Domain, "."+s.Input.RootDomain) {
		return fmt.Errorf("assigned domain differs from requested root")
	}
	if s.Creation != nil && s.Creation.ID != "" && (r.ID != s.Creation.ID || r.Domain != s.Creation.Domain || (!s.Complete && !equal(r.PublicationConfig, s.Creation.PublicationConfig))) {
		return fmt.Errorf("registration conflicts with creation facts")
	}
	return identityFrom(r).Validate()
}
func recordMatches(r *dnsid.TXTRecord, p dnsid.PublicationConfig) bool {
	return r != nil && r.Version == p.PublishProfile && r.GovernanceID == p.GovernanceID && r.LogRef == p.LogRef && r.EntityKeyURI == p.EntityKeyURL && r.KeyURI == p.KeyURL && r.StatusURI == p.StatusURL && r.Capabilities == p.CapabilitiesURL && r.KeyAge == p.MaxKeyAge
}
func awaitPrerequisite(ctx context.Context, a RegistryClient, s *State, poll time.Duration) error {
	return retry(ctx, poll, func() error {
		r, err := a.GetRegistration(ctx, s.Registration.Domain)
		if err != nil {
			return err
		}
		if err := checkSnapshot(r, s); err != nil {
			return err
		}
		switch strings.ToUpper(r.RegistryStatus) {
		case "VERIFIED", dnsid.RegistryStatusReady:
			return nil
		case dnsid.RegistryStatusRejected, dnsid.RegistryStatusCancelled, dnsid.RegistryStatusError, dnsid.RegistryStatusFailed, "REVOKED", "RETIRED":
			return &dnsid.RegistryWorkflowError{Registration: r}
		default:
			return dnsid.NewVerificationError(dnsid.VerificationCodeStatusUnavailable, true, "registration prerequisite is pending", nil)
		}
	})
}
func checkSnapshot(r *dnsid.AgentRegistration, s *State) error {
	if err := checkRegistration(r, s); err != nil {
		return err
	}
	expected := s.Registration.PublicationConfig
	if s.Complete {
		expected.KeyURL = r.PublicationConfig.KeyURL
	}
	if r.ID != s.Registration.ID || r.Domain != s.Registration.Domain || !equal(r.PublicationConfig, expected) {
		return fmt.Errorf("authenticated detail changed retained publication snapshot")
	}
	s.ObservedRegistryStatus = r.RegistryStatus
	return nil
}

type snapshotReader struct {
	RegistryClient
	state *State
}

func (r *snapshotReader) GetRegistration(ctx context.Context, domain string) (*dnsid.AgentRegistration, error) {
	value, err := r.RegistryClient.GetRegistration(ctx, domain)
	if err != nil {
		return nil, err
	}
	if err := checkSnapshot(value, r.state); err != nil {
		return nil, err
	}
	return value, nil
}

func fetchEntity(ctx context.Context, l config.Loaded, deps config.Dependencies, profile string) (jwk.Key, error) {
	var data []byte
	if deps.HTTPSFetcher != nil {
		raw, _, err := deps.HTTPSFetcher.FetchJSON(ctx, l.Registration.EntityKeyURL, dnsid.FetchOptions{RedirectPolicy: dnsid.RedirectPolicyNone, MaxResponseBytes: 65536})
		if err != nil {
			return nil, err
		}
		data = raw
	} else {
		client := deps.HTTPClient
		if client == nil {
			var err error
			client, err = dnsid.CreateDnsidHTTPClient(l.Dnsid.Transport)
			if err != nil {
				return nil, err
			}
		}
		copy := *client
		copy.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, l.Registration.EntityKeyURL, nil)
		if err != nil {
			return nil, err
		}
		response, err := copy.Do(req)
		if err != nil {
			return nil, err
		}
		defer response.Body.Close()
		if response.StatusCode != http.StatusOK {
			return nil, dnsid.NewVerificationError(dnsid.VerificationCodeJWKSUnavailable, response.StatusCode == http.StatusTooManyRequests || response.StatusCode >= http.StatusInternalServerError, fmt.Sprintf("entity bootstrap HTTP %d", response.StatusCode), nil)
		}
		data, err = io.ReadAll(io.LimitReader(response.Body, 65537))
		if err != nil {
			return nil, err
		}
	}
	if len(data) > 65536 {
		return nil, fmt.Errorf("entity JWKS exceeds 64 KiB")
	}
	keys, err := dnsid.ParseJWKS(data)
	if err != nil {
		return nil, err
	}
	key, err := keys.CurrentRecordSigningKey(profile)
	if err != nil {
		return nil, err
	}
	return key.Raw(), nil
}

// issuanceSession delegates every lifecycle transition to the existing binding.
// The registry owns activation; the internal control callback does not publish.
type issuanceSession struct {
	session Session
	state   *State
}

func (s *issuanceSession) CreateManagedIssuance(ctx context.Context, value *c2sptlog.ManagedIssuanceState) (*c2sptlog.ManagedIssuanceState, error) {
	if s.state.Issuance != nil {
		return clone(s.state.Issuance)
	}
	return nil, s.PersistManagedIssuance(ctx, value)
}
func (s *issuanceSession) LoadManagedIssuance(_ context.Context, domain string) (*c2sptlog.ManagedIssuanceState, error) {
	if s.state.Issuance != nil && s.state.Issuance.Domain != domain {
		return nil, fmt.Errorf("issuance domain conflicts with setup")
	}
	return clone(s.state.Issuance)
}
func (s *issuanceSession) PersistManagedIssuance(ctx context.Context, value *c2sptlog.ManagedIssuanceState) error {
	copy, err := clone(value)
	if err != nil {
		return err
	}
	next := *s.state
	next.Issuance = copy
	next.Phase = "issuance"
	if err := saveRecovery(ctx, s.session, &next); err != nil {
		return err
	}
	*s.state = next
	return nil
}

func validateState(s *State) error {
	if s.Version != 3 || s.RegistryURL == "" || s.OrganizationID == "" || s.Name == "" || s.ProviderReference == "" || s.KeyLocator == "" || (s.Input == nil && s.Registration == nil) {
		return fmt.Errorf("incomplete registration intent")
	}
	if name, err := normalizeName(s.Name); err != nil || name != s.Name || s.OrganizationID != s.Loaded.Registration.OrganizationID || s.RegistryURL != s.Loaded.Registry.RegistryURL {
		return fmt.Errorf("invalid saved scope/account bindings")
	}
	if s.Input != nil {
		if _, err := normalizeInput(s.Input, s.Loaded.Registration.GovernanceID); err != nil {
			return err
		}
		if s.Input.Name != "" || s.Input.PublicKeyJWK != nil {
			return fmt.Errorf("creation extras duplicate name or public key")
		}
	}
	if len(s.OperationalKey) == 0 {
		if s.Creation != nil || s.Registration != nil || s.Issuance != nil || s.Complete {
			return fmt.Errorf("creation artifacts without original key")
		}
		return nil
	}
	key, err := parsePublic(s.OperationalKey)
	if err != nil {
		return err
	}
	if s.Registration != nil && s.Input == nil && s.CreationFingerprint == "" {
		return fmt.Errorf("compacted creation lacks input fingerprint")
	}
	_, issuanceKey, err := s.replayKeys()
	if err != nil {
		return err
	}
	if s.Registration != nil {
		if err := checkRegistration(s.Registration, s); err != nil {
			return err
		}
	}
	if len(s.EntityKey) != 0 {
		entity, err := parsePublic(s.EntityKey)
		if err != nil {
			return err
		}
		pin, err := thumbprint(entity)
		if err != nil || pin != s.EntityThumbprint {
			return fmt.Errorf("entity recovery pin differs from public key")
		}
	}
	if s.Issuance != nil {
		i := s.Issuance
		if len(i.EntryBytes) != 0 && i.Prepared == nil {
			return fmt.Errorf("completed issuance bytes lack original preparation")
		}
		if s.Registration == nil || len(s.EntityKey) == 0 || (!s.IssuanceCompacted && i.IdempotencyKey != issuanceKey) || (s.IssuanceCompacted && i.IdempotencyKey != "") || i.Domain != s.Registration.Domain || i.LogReference != s.Registration.PublicationConfig.LogRef || i.GovernanceID != s.Loaded.Registration.GovernanceID || i.EntityThumbprint != s.EntityThumbprint {
			return fmt.Errorf("issuance conflicts with setup bindings")
		}
		kid, _ := key.KeyID()
		if kid != i.OperationalKid {
			return fmt.Errorf("issuance kid differs from original public key")
		}
		pin, err := thumbprint(key)
		if err != nil || pin != i.OperationalThumbprint {
			return fmt.Errorf("issuance conflicts with original operational key")
		}
	}
	if s.IssuanceCompacted && (!s.Complete || s.Issuance == nil || s.Issuance.Prepared != nil || len(s.Issuance.EntryBytes) != 0 || s.Issuance.EntryHash == "") {
		return fmt.Errorf("invalid compacted issuance state")
	}
	if s.Complete && (s.Issuance == nil || !s.Issuance.Complete || s.CurrentOperationalThumbprint == "") {
		return fmt.Errorf("completed setup lacks completed issuance")
	}
	return nil
}
