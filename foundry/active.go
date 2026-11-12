//go:build dnsid_foundry

package foundry

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	dnsid "github.com/dnsid-ai/dnsid-go"
	"github.com/dnsid-ai/dnsid-go/config"
	dnsidlog "github.com/dnsid-ai/dnsid-go/log"
	"github.com/dnsid-ai/dnsid-go/log/c2sptlog"
)

func validateTrust(trust config.LogTrust) error {
	variants := 0
	for _, present := range []bool{trust.Managed, trust.Profile != nil, trust.PolicyDocument != nil, trust.PolicyURL != ""} {
		if present {
			variants++
		}
	}
	if variants != 1 {
		return dnsid.NewArgumentError("foundry: logTrust must select exactly one variant, or inject a LogRegistry", nil)
	}
	if trust.Profile != nil {
		data, err := json.Marshal(trust.Profile)
		if err != nil {
			return err
		}
		if _, err := c2sptlog.ParseTrustProfile(data); err != nil {
			return err
		}
	}
	if trust.PolicyDocument != nil {
		if _, err := c2sptlog.ParsePolicy(trust.PolicyDocument); err != nil {
			return err
		}
	}
	if trust.PolicyURL != "" {
		u, err := url.Parse(trust.PolicyURL)
		if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.Fragment != "" {
			return dnsid.NewArgumentError("foundry: log policy URL must be HTTPS without userinfo or fragment", err)
		}
	}
	return nil
}

func (i *FoundryIdentity) ensureLogs(ctx context.Context) error {
	if i.client.deps.LogRegistry != nil {
		return nil
	}
	_, err := i.trust.get(ctx)
	return err
}

func (i *FoundryIdentity) publication(ctx context.Context, lease FoundryLease, doc *RecoveryDocument, detail *dnsid.AgentDetail) error {
	if detail.Managed != "dnsid" {
		return failure(UnsupportedContract, doc, fmt.Errorf("foundry requires registry publication authority"))
	}
	p := detail.PublicationConfig
	gi, err := dnsid.NormalizeFQDN(p.GovernanceID)
	if err != nil || gi != doc.GovernanceID {
		return failure(Integrity, doc, fmt.Errorf("publication governance binding mismatch"))
	}
	p.GovernanceID = gi
	cfg := publicationIdentity(doc.Domain, &p)
	if err := cfg.Validate(); err != nil {
		return failure(Integrity, doc, err)
	}
	if p.PublishProfile != dnsid.DefaultPublishProfile || p.KeyURL == "" || p.EntityKeyURL == "" {
		return failure(UnsupportedContract, doc, fmt.Errorf("incomplete or unsupported publication configuration"))
	}
	if doc.PublicationConfig != nil && !sameJSON(*doc.PublicationConfig, p) {
		return failure(Integrity, doc, fmt.Errorf("registry changed saved publication configuration"))
	}
	raw, err := i.fetchEntity(ctx, p.EntityKeyURL)
	if err != nil {
		return i.client.wrap(doc, err)
	}
	set, err := dnsid.ParseJWKS(raw)
	if err != nil {
		return failure(Integrity, doc, err)
	}
	key, err := set.CurrentRecordSigningKey(p.PublishProfile)
	if err != nil {
		return failure(Integrity, doc, err)
	}
	entity, err := json.Marshal(key.Raw())
	if err != nil {
		return err
	}
	if len(doc.EntityPublicKey) > 0 {
		old, err := parsePublicKey(doc.EntityPublicKey)
		if err != nil {
			return err
		}
		oldThumb, err := keyThumb(old)
		if err != nil {
			return err
		}
		newThumb, err := key.Thumbprint()
		if err != nil || oldThumb != newThumb {
			return failure(Integrity, doc, fmt.Errorf("entity public key changed"))
		}
	}
	if doc.OIDCIssuerURL != "" && detail.OIDCIssuerURL != "" && doc.OIDCIssuerURL != detail.OIDCIssuerURL {
		return failure(Integrity, doc, fmt.Errorf("registry changed saved OIDC issuer"))
	}
	if detail.OIDCIssuerURL != "" {
		doc.OIDCIssuerURL = detail.OIDCIssuerURL
	}
	doc.PublicationConfig = &p
	doc.EntityPublicKey = entity
	if err := lease.Save(ctx, doc); err != nil {
		return i.client.wrap(doc, err)
	}
	if err := i.configureManager(doc); err != nil {
		return err
	}
	return i.ensureLogs(ctx)
}

func (i *FoundryIdentity) fetchEntity(ctx context.Context, rawURL string) (json.RawMessage, error) {
	u, err := url.Parse(rawURL)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.Fragment != "" {
		return nil, fmt.Errorf("foundry: entity key URL must be HTTPS without userinfo or fragment")
	}
	if fetcher := i.client.deps.HTTPSFetcher; fetcher != nil {
		data, _, err := fetcher.FetchJSON(ctx, rawURL, dnsid.FetchOptions{AllowedHost: u.Hostname(), MaxResponseBytes: 1 << 20, RedirectPolicy: dnsid.RedirectPolicyNone, Revalidate: true})
		return data, err
	}
	client, err := dnsid.CreateDnsidHTTPClient(i.client.loaded.Dnsid.Transport)
	if err != nil {
		return nil, err
	}
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, err
	}
	response, err := client.Do(request)
	if err != nil {
		return nil, err
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode != http.StatusOK {
		return nil, &dnsid.RegistryAPIError{StatusCode: response.StatusCode, Message: "public entity JWKS fetch failed"}
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, (1<<20)+1))
	if err != nil {
		return nil, err
	}
	if len(data) > 1<<20 {
		return nil, fmt.Errorf("foundry: entity JWKS exceeds size limit")
	}
	return json.RawMessage(data), nil
}

func (i *FoundryIdentity) issue(ctx context.Context, lease FoundryLease, doc *RecoveryDocument) error {
	client, err := c2sptlog.New(doc.PublicationConfig.LogRef)
	if err != nil {
		return failure(UnsupportedContract, doc, err)
	}
	entity, err := parsePublicKey(doc.EntityPublicKey)
	if err != nil {
		return failure(Integrity, doc, err)
	}
	store := &issuanceStore{lease: lease, doc: doc}
	var backoff pollBackoff
	trustedRegistry := i.logs
	if i.trust != nil {
		trustedRegistry, err = i.trust.get(ctx)
		if err != nil {
			return i.client.wrap(doc, err)
		}
	}
	trustedReader, err := trustedRegistry.NewReader(doc.PublicationConfig.LogRef)
	if err != nil {
		return failure(Integrity, doc, err)
	}
	registry := &issuanceRegistry{RegistryPreparedEventClient: i.client.deps.RegistryClient, store: store, trusted: trustedReader}
	activation := c2sptlog.ManagedIssuanceActivationControllerFunc(func(ctx context.Context, blocked bool) error {
		if blocked {
			i.signer.pause("issuance or public readiness is pending")
		}
		return ctx.Err()
	})
	if doc.Issuance != nil && doc.Issuance.Recovered {
		return i.verifySavedAcceptance(ctx, doc)
	}
	for {
		detail, err := i.client.readDetail(ctx, lease, doc)
		if err != nil {
			if !retryable(ctx, err) {
				return err
			}
			if err := backoff.wait(ctx); err != nil {
				return i.client.wrap(doc, err)
			}
			continue
		}
		if (doc.RegistryStatus != "PROVISIONING" && doc.RegistryStatus != "READY") || !detail.DNSPublished {
			if err := backoff.wait(ctx); err != nil {
				return i.client.wrap(doc, err)
			}
			continue
		}
		if doc.RegistryStatus == "READY" && doc.Issuance == nil {
			recovered, err := i.recoverIssuance(ctx, lease, doc)
			if err != nil {
				var workflow *Error
				if errors.As(err, &workflow) {
					return withFacts(err, doc)
				}
				if !retryable(ctx, err) {
					return failure(Integrity, doc, err)
				}
				return i.client.wrap(doc, err)
			}
			if !recovered {
				return failure(Unresolved, doc, fmt.Errorf("READY identity has no ISSUANCE in verified history yet"))
			}
			return nil
		}
		var state *c2sptlog.ManagedIssuanceState
		if doc.Issuance != nil {
			state = doc.Issuance.Operation
		}
		provider := deadlineProvider{KeyProvider: i.signer.KeyProvider, ctx: ctx}
		if state == nil {
			_, err = c2sptlog.BeginManagedIssuance(ctx, c2sptlog.ManagedIssuanceOptions{Domain: doc.Domain, GovernanceID: doc.GovernanceID, Client: client, EntityPublicKey: entity, KeyProvider: provider, RegistryClient: registry, IdempotencyKey: doc.IssuanceKey, Store: store, ActivationControl: activation})
		} else {
			_, err = c2sptlog.ResumeManagedIssuance(ctx, c2sptlog.ResumeManagedIssuanceOptions{Domain: doc.Domain, Client: client, EntityPublicKey: entity, KeyProvider: provider, RegistryClient: registry, Store: store, ActivationControl: activation})
		}
		if err != nil {
			if serverRejectedIssuance(err, doc) {
				recovered, recoveryErr := i.recoverIssuance(ctx, lease, doc)
				if recovered {
					return nil
				}
				outcome := i.client.wrap(doc, errors.Join(err, recoveryErr))
				outcome.Kind, outcome.Resumable = Unresolved, true
				if recoveryErr != nil && !retryable(ctx, recoveryErr) {
					outcome.Kind, outcome.Resumable = Integrity, false
				}
				return outcome
			}
			if !retryable(ctx, err) {
				return i.client.wrap(doc, err)
			}
		}
		if doc.Issuance != nil && doc.Issuance.Operation != nil && doc.Issuance.Operation.Submission != nil && doc.Issuance.Operation.Submission.State == dnsid.SubmissionStateAccepted {
			if doc.Phase != "complete" {
				doc.Phase = "issuance-accepted"
			}
			if err := lease.Save(ctx, doc); err != nil {
				return i.client.wrap(doc, err)
			}
			return nil
		}
		if err := backoff.wait(ctx); err != nil {
			return i.client.wrap(doc, err)
		}
	}
}

func serverRejectedIssuance(err error, doc *RecoveryDocument) bool {
	var operation *c2sptlog.ManagedIssuanceOperationError
	if !errors.As(err, &operation) || operation.State != dnsid.SubmissionStateRejected {
		return false
	}
	var api *dnsid.RegistryAPIError
	if errors.As(err, &api) {
		return issuanceRejection(api.StatusCode, api.Code)
	}
	// Resume retains the rejection in durable coordinator state, not its original error.
	return doc.Issuance != nil && doc.Issuance.Operation != nil && doc.Issuance.Operation.TerminalFailure && issuanceRejection(doc.Issuance.StatusCode, doc.Issuance.Operation.LastErrorCode)
}

func issuanceRejection(status int, code string) bool {
	if status == http.StatusUnauthorized || status == http.StatusForbidden || status == http.StatusNotFound {
		return false
	}
	switch code {
	case "IDEMPOTENCY_MISMATCH", "TLOG_IDEMPOTENCY_MISMATCH", "TLOG_PREPARATION_MISMATCH", "TLOG_INVALID_ENTRY":
		return true
	default:
		return false
	}
}

func (i *FoundryIdentity) verifySavedAcceptance(ctx context.Context, doc *RecoveryDocument) error {
	if err := doc.validate(); err != nil {
		return failure(Integrity, doc, err)
	}
	reader, err := i.logs.NewReader(doc.Issuance.AcceptedReference)
	if err != nil {
		return failure(Integrity, doc, err)
	}
	initial, err := parsePublicKey(doc.InitialPublicKey)
	if err != nil {
		return failure(Integrity, doc, err)
	}
	entity, err := parsePublicKey(doc.EntityPublicKey)
	if err != nil {
		return failure(Integrity, doc, err)
	}
	_, err = reader.VerifyBilateralBinding(ctx, dnsidlog.BilateralBindingInput{Domain: doc.Domain, GovernanceID: doc.GovernanceID, EntityKey: entity, OperationalKey: initial})
	if ctx.Err() != nil {
		return i.client.wrap(doc, ctx.Err())
	}
	if err != nil {
		if retryable(ctx, err) {
			return i.client.wrap(doc, err)
		}
		return failure(Integrity, doc, err)
	}
	return nil
}

func (i *FoundryIdentity) recoverIssuance(ctx context.Context, lease FoundryLease, doc *RecoveryDocument) (bool, error) {
	reader, err := i.logs.NewReader(doc.PublicationConfig.LogRef)
	if err != nil {
		return false, err
	}
	events, err := reader.RebuildHistory(ctx, doc.Domain)
	if err != nil {
		return false, err
	}
	if len(events) == 0 {
		return false, nil
	}
	var genesis dnsidlog.LogEvent
	for _, event := range events {
		if event.Type == dnsidlog.LogEventIssuance {
			genesis = event
			break
		}
	}
	if genesis.Type == "" {
		return false, nil
	}
	initial, err := parsePublicKey(doc.InitialPublicKey)
	if err != nil {
		return false, err
	}
	initialThumb, err := keyThumb(initial)
	if err != nil {
		return false, err
	}
	entity, err := parsePublicKey(doc.EntityPublicKey)
	if err != nil {
		return false, err
	}
	entityThumb, err := keyThumb(entity)
	if err != nil {
		return false, err
	}
	if genesis.Domain != doc.Domain || genesis.GovernanceID != doc.GovernanceID || genesis.InitialEntityThumbprint != entityThumb {
		return false, failure(Integrity, doc, fmt.Errorf("accepted ISSUANCE has different identity or key bindings"))
	}
	creation, err := parsePublicKey(doc.CreationInput.PublicKey)
	if err != nil {
		return false, err
	}
	creationThumb, err := keyThumb(creation)
	if err != nil {
		return false, err
	}
	if genesis.InitialOperationalThumbprint != initialThumb {
		// Only a replica without accepted state can recover an earlier issuance key.
		if initialThumb != creationThumb || (doc.Issuance != nil && doc.Issuance.Recovered) {
			return false, failure(Integrity, doc, fmt.Errorf("accepted ISSUANCE changed its initial key"))
		}
		initial = genesis.InitialOperationalPublicKey
		initialThumb, err = keyThumb(initial)
		if err != nil || initialThumb != genesis.InitialOperationalThumbprint {
			return false, failure(Integrity, doc, fmt.Errorf("invalid ISSUANCE operational key"))
		}
	}
	if _, err := reader.VerifyBilateralBinding(ctx, dnsidlog.BilateralBindingInput{Domain: doc.Domain, GovernanceID: doc.GovernanceID, EntityKey: entity, OperationalKey: initial}); err != nil {
		return false, err
	}
	if initialThumb != creationThumb {
		if err := reader.VerifyOperationalContinuity(ctx, doc.Domain, initialThumb, creationThumb); err != nil {
			return false, err
		}
		manager, err := i.IdentityManager()
		if err != nil {
			return false, err
		}
		vd, err := manager.VerifyLocalPublication(ctx)
		if err != nil {
			return false, err
		}
		key, err := vd.KeySet().CurrentOperationalSigningKey(doc.PublicationConfig.PublishProfile)
		if err != nil {
			return false, err
		}
		observedThumb, err := key.Thumbprint()
		if err != nil || observedThumb != creationThumb {
			return false, failure(KeyMismatch, doc, fmt.Errorf("creation key does not match signed current ku"))
		}
	}
	initialJSON, err := json.Marshal(initial)
	if err != nil {
		return false, err
	}
	doc.InitialPublicKey = initialJSON
	if initialThumb != creationThumb {
		doc.CurrentPublicKey = append(json.RawMessage(nil), doc.CreationInput.PublicKey...)
	}
	if doc.Issuance == nil {
		doc.Issuance = &IssuanceState{}
	}
	// No receipt from the winner is attached to the local coordinator's bytes.
	if operation := doc.Issuance.Operation; operation == nil || operation.Submission == nil || operation.Submission.State != dnsid.SubmissionStateAccepted {
		doc.Issuance.Recovered = true
	}
	doc.Issuance.AcceptedReference = doc.PublicationConfig.LogRef
	if doc.Phase != "complete" {
		doc.Phase = "issuance-accepted"
	}
	if err := lease.Save(ctx, doc); err != nil {
		return false, err
	}
	return true, nil
}

type issuanceRegistry struct {
	dnsid.RegistryPreparedEventClient
	store   *issuanceStore
	trusted dnsidlog.LogReader
}

func (r *issuanceRegistry) PrepareIssuance(ctx context.Context, domain, key string) (*dnsid.PreparedRegistryEvent, error) {
	if encoded := r.store.doc.Issuance.PreparedBytes; encoded != "" {
		data, err := base64.RawURLEncoding.Strict().DecodeString(encoded)
		if err != nil {
			return nil, err
		}
		return r.validateTrust(&dnsid.PreparedRegistryEvent{EntryBytes: data})
	}
	r.store.transportStatus = 0
	prepared, err := r.RegistryPreparedEventClient.PrepareIssuance(ctx, domain, key)
	if err != nil || prepared == nil {
		return prepared, errors.Join(err, r.captureHTTP(ctx, err))
	}
	if _, err := r.validateTrust(prepared); err != nil {
		return nil, err
	}
	next := *r.store.doc
	issuance := *next.Issuance
	issuance.PreparedBytes = base64.RawURLEncoding.EncodeToString(prepared.EntryBytes)
	issuance.StatusCode = 0
	next.Issuance = &issuance
	if err := r.store.lease.Save(ctx, &next); err != nil {
		return nil, err
	}
	*r.store.doc = next
	return prepared, nil
}

func (r *issuanceRegistry) validateTrust(raw *dnsid.PreparedRegistryEvent) (*dnsid.PreparedRegistryEvent, error) {
	_, prepared, err := c2sptlog.ParsePreparedIssuance(raw.EntryBytes)
	if err != nil {
		return nil, err
	}
	event, err := prepared.Event()
	if err != nil {
		return nil, err
	}
	if _, err := r.trusted.Canonical(event); err != nil {
		return nil, dnsid.NewValidationError("foundry: ISSUANCE is outside configured log trust", err)
	}
	return raw, nil
}

func (r *issuanceRegistry) SubmitPreparedEvent(ctx context.Context, domain string, entry []byte, key string) (*dnsid.SubmissionResult, error) {
	r.store.transportStatus = 0
	result, err := r.RegistryPreparedEventClient.SubmitPreparedEvent(ctx, domain, entry, key)
	if err != nil {
		return result, errors.Join(err, r.captureHTTP(ctx, err))
	}
	return result, nil
}

func (r *issuanceRegistry) captureHTTP(ctx context.Context, cause error) error {
	var api *dnsid.RegistryAPIError
	if !errors.As(cause, &api) || api.StatusCode == 0 {
		return nil
	}
	next := *r.store.doc
	issuance := *next.Issuance
	issuance.StatusCode = api.StatusCode
	r.store.transportStatus = api.StatusCode
	next.Issuance = &issuance
	if err := r.store.lease.Save(ctx, &next); err != nil {
		return err
	}
	*r.store.doc = next
	return nil
}

type issuanceStore struct {
	lease           FoundryLease
	doc             *RecoveryDocument
	transportStatus int
}

func (s *issuanceStore) CreateManagedIssuance(ctx context.Context, state *c2sptlog.ManagedIssuanceState) (*c2sptlog.ManagedIssuanceState, error) {
	if s.doc.Issuance != nil && s.doc.Issuance.Operation != nil {
		return s.doc.Issuance.Operation, nil
	}
	next := *s.doc
	next.Issuance = &IssuanceState{Operation: state}
	if err := s.lease.Save(ctx, &next); err != nil {
		return nil, err
	}
	*s.doc = next
	return nil, nil
}
func (s *issuanceStore) LoadManagedIssuance(ctx context.Context, domain string) (*c2sptlog.ManagedIssuanceState, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if domain != s.doc.Domain {
		return nil, fmt.Errorf("foundry: issuance store domain mismatch")
	}
	if s.doc.Issuance == nil {
		return nil, nil
	}
	if s.doc.Issuance.Operation == nil {
		return nil, nil
	}
	state := *s.doc.Issuance.Operation
	state.EntryBytes = append([]byte(nil), state.EntryBytes...)
	if state.Submission != nil {
		submission := *state.Submission
		state.Submission = &submission
	}
	return &state, nil
}
func (s *issuanceStore) PersistManagedIssuance(ctx context.Context, state *c2sptlog.ManagedIssuanceState) error {
	next := *s.doc
	issuance := *next.Issuance
	retained := *state
	// Admission failures do not reject issuance bytes or poison credential recovery.
	if retained.TerminalFailure && !issuanceRejection(s.transportStatus, retained.LastErrorCode) {
		retained.TerminalFailure = false
		if retained.Submission != nil && retained.Submission.State == dnsid.SubmissionStateRejected {
			submission := *retained.Submission
			submission.State = dnsid.SubmissionStatePrepared
			retained.Submission = &submission
		}
	}
	issuance.Operation = &retained
	issuance.StatusCode = s.transportStatus
	next.Issuance = &issuance
	if state.Submission != nil && state.Submission.State == dnsid.SubmissionStateAccepted && next.Phase != "complete" {
		next.Phase = "issuance-accepted"
	}
	if err := s.lease.Save(ctx, &next); err != nil {
		return err
	}
	*s.doc = next
	return nil
}

func (i *FoundryIdentity) observe(ctx context.Context, lease FoundryLease, doc *RecoveryDocument) error {
	// The manager's local-publication path bypasses caches and counterparty policy.
	i.mu.RLock()
	manager := i.manager
	i.mu.RUnlock()
	var backoff pollBackoff
	for {
		if _, err := i.client.readDetail(ctx, lease, doc); err != nil {
			if !retryable(ctx, err) {
				return err
			}
			if err := backoff.wait(ctx); err != nil {
				return i.client.wrap(doc, err)
			}
			continue
		}
		if doc.RegistryStatus != "READY" {
			if err := backoff.wait(ctx); err != nil {
				return i.client.wrap(doc, err)
			}
			continue
		}
		vd, err := manager.VerifyLocalPublication(ctx)
		if ctx.Err() != nil {
			return i.client.wrap(doc, ctx.Err())
		}
		if err != nil {
			var verification *dnsid.VerificationError
			if errors.As(err, &verification) && verification.AgentState() != "" {
				doc.ProtocolState = string(verification.AgentState())
				if verification.AgentState() == dnsid.AgentStateRevoked || verification.AgentState() == dnsid.AgentStateRetired {
					if saveErr := lease.Save(ctx, doc); saveErr != nil {
						return i.client.wrap(doc, saveErr)
					}
					return failure(Terminal, doc, err)
				}
			}
			if !retryable(ctx, err) {
				return failure(Integrity, doc, err)
			}
			if err := backoff.wait(ctx); err != nil {
				return i.client.wrap(doc, err)
			}
			continue
		}
		record := vd.Record()
		gi, err := dnsid.NormalizeFQDN(record.GovernanceID)
		if err != nil || vd.Domain() != doc.Domain || record.Version != doc.PublicationConfig.PublishProfile || gi != doc.GovernanceID || record.LogRef != doc.PublicationConfig.LogRef {
			return failure(Integrity, doc, fmt.Errorf("public identity bindings differ from saved publication"))
		}
		expectedEntity, err := parsePublicKey(doc.EntityPublicKey)
		if err != nil {
			return err
		}
		expectedThumb, err := keyThumb(expectedEntity)
		if err != nil {
			return err
		}
		observedThumb, err := vd.SigningKey().Thumbprint()
		if err != nil || observedThumb != expectedThumb {
			return failure(Integrity, doc, fmt.Errorf("public entity key mismatch"))
		}
		key, err := vd.KeySet().CurrentOperationalSigningKey(record.Version)
		if err != nil {
			return failure(Integrity, doc, err)
		}
		current, err := providerPublic(ctx, i.signer.KeyProvider)
		if err != nil {
			return i.client.wrap(doc, err)
		}
		currentThumb, err := keyThumb(current)
		if err != nil {
			return err
		}
		observedKey, err := key.Thumbprint()
		if err != nil || observedKey != currentThumb {
			return failure(KeyMismatch, doc, fmt.Errorf("signed current ku does not serve the provider key"))
		}
		evidence, err := manager.VerifyLogEvidence(ctx, vd, time.Now())
		if ctx.Err() != nil {
			return i.client.wrap(doc, ctx.Err())
		}
		if err != nil {
			if !retryable(ctx, err) {
				return failure(Integrity, doc, err)
			}
			if err := backoff.wait(ctx); err != nil {
				return i.client.wrap(doc, err)
			}
			continue
		}
		if vd.Status() == nil || vd.Status().State != dnsid.AgentStateActive || evidence.LoggedState != dnsidlog.AgentStateActive {
			return failure(Integrity, doc, fmt.Errorf("public identity is not ACTIVE"))
		}
		doc.ProtocolState = string(vd.Status().State)
		if doc.Issuance != nil && doc.Issuance.Operation != nil && !doc.Issuance.Recovered {
			activation := c2sptlog.ManagedIssuanceActivationControllerFunc(func(ctx context.Context, blocked bool) error { return ctx.Err() })
			if _, err := c2sptlog.CompleteManagedIssuance(ctx, doc.Domain, &issuanceStore{lease: lease, doc: doc}, activation); err != nil {
				return i.client.wrap(doc, err)
			}
		}
		initial, err := parsePublicKey(doc.InitialPublicKey)
		if err != nil {
			return failure(Integrity, doc, err)
		}
		initialThumb, err := keyThumb(initial)
		if err != nil {
			return failure(Integrity, doc, err)
		}
		if currentThumb != initialThumb {
			doc.CurrentPublicKey, err = json.Marshal(current)
			if err != nil {
				return failure(Integrity, doc, err)
			}
		}
		doc.Phase = "complete"
		doc.SigningPaused = false
		if err := lease.Save(ctx, doc); err != nil {
			return i.client.wrap(doc, err)
		}
		return i.signer.enable(current)
	}
}

func retryable(ctx context.Context, err error) bool {
	var malformed *dnsid.ParseError
	var invalid *dnsid.ValidationError
	var argumentError *dnsid.ArgumentError
	if errors.As(err, &malformed) || errors.As(err, &invalid) || errors.As(err, &argumentError) {
		return false
	}
	var workflow *Error
	if errors.As(err, &workflow) {
		return workflow.Resumable
	}
	if ctx.Err() != nil && (errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled)) {
		return false
	}
	var verification *dnsid.VerificationError
	if errors.As(err, &verification) {
		return verification.Transient() || verification.Code() == dnsid.VerificationCodeRecordNotFound || verification.Code() == dnsid.VerificationCodeStatusNotActive
	}
	var logErr *dnsidlog.VerificationError
	if errors.As(err, &logErr) {
		return logErr.Transient()
	}
	var transient interface{ Transient() bool }
	if errors.As(err, &transient) {
		return transient.Transient()
	}
	var validation *dnsid.ValidationError
	var argument *dnsid.ArgumentError
	return !errors.As(err, &validation) && !errors.As(err, &argument)
}
