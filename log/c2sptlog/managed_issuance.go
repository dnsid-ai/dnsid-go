package c2sptlog

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"

	dnsid "github.com/dnsid-ai/dnsid-go"
	dnsidlog "github.com/dnsid-ai/dnsid-go/log"
	"github.com/lestrrat-go/jwx/v3/jwk"
)

// ManagedIssuanceState is the durable recovery record for one registry-managed
// ISSUANCE. Once EntryBytes is set it is immutable and every retry reuses it
// with IdempotencyKey.
type ManagedIssuanceState struct {
	Domain                string                  `json:"domain"`
	GovernanceID          string                  `json:"governance_id"`
	LogReference          string                  `json:"log_reference"`
	EntityThumbprint      string                  `json:"entity_thumbprint"`
	OperationalKid        string                  `json:"operational_kid"`
	OperationalThumbprint string                  `json:"operational_thumbprint"`
	EntryBytes            []byte                  `json:"entry_bytes,omitempty"`
	EntryHash             string                  `json:"entry_hash,omitempty"`
	IdempotencyKey        string                  `json:"idempotency_key"`
	Submission            *dnsid.SubmissionResult `json:"submission,omitempty"`
	LastErrorCode         string                  `json:"last_error_code,omitempty"`
	TerminalFailure       bool                    `json:"terminal_failure"`
	Complete              bool                    `json:"complete"`
	ActivationBlocked     bool                    `json:"activation_blocked"`
}

// ManagedIssuanceStore provides exclusive durable state for one identity
// instance. CreateManagedIssuance atomically persists initial when no operation
// exists and returns the existing operation otherwise.
type ManagedIssuanceStore interface {
	CreateManagedIssuance(context.Context, *ManagedIssuanceState) (*ManagedIssuanceState, error)
	LoadManagedIssuance(context.Context, string) (*ManagedIssuanceState, error)
	PersistManagedIssuance(context.Context, *ManagedIssuanceState) error
}

// ManagedIssuanceActivationController prevents ACTIVE publication while the
// bilateral ISSUANCE outcome is unresolved.
type ManagedIssuanceActivationController interface {
	SetManagedIssuanceActivationBlocked(context.Context, bool) error
}

// ManagedIssuanceActivationControllerFunc adapts a function to the activation
// controller interface.
type ManagedIssuanceActivationControllerFunc func(context.Context, bool) error

// SetManagedIssuanceActivationBlocked calls f.
func (f ManagedIssuanceActivationControllerFunc) SetManagedIssuanceActivationBlocked(ctx context.Context, blocked bool) error {
	if f == nil {
		return dnsid.NewArgumentError("dnsid: managed issuance activation control function is required", nil)
	}
	return f(ctx, blocked)
}

// ManagedIssuanceOptions configures a new registry-managed split ISSUANCE.
type ManagedIssuanceOptions struct {
	Domain            string
	GovernanceID      string
	Client            *Client
	EntityPublicKey   jwk.Key
	KeyProvider       dnsid.KeyProvider
	RegistryClient    dnsid.RegistryPreparedEventClient
	IdempotencyKey    string
	Store             ManagedIssuanceStore
	ActivationControl ManagedIssuanceActivationController
}

// ResumeManagedIssuanceOptions identifies the authoritative persisted
// operation by Domain. Resume never trusts caller-supplied recovery state,
// prepares a different event, or changes the idempotency key.
type ResumeManagedIssuanceOptions struct {
	Domain            string
	Client            *Client
	EntityPublicKey   jwk.Key
	KeyProvider       dnsid.KeyProvider
	RegistryClient    dnsid.RegistryPreparedEventClient
	Store             ManagedIssuanceStore
	ActivationControl ManagedIssuanceActivationController
}

// ManagedIssuanceInProgressError reports that durable state already owns the
// identity instance, so a fresh ISSUANCE must not be generated.
type ManagedIssuanceInProgressError struct {
	Issuance *ManagedIssuanceState
}

func (e *ManagedIssuanceInProgressError) Error() string {
	return "dnsid: managed issuance already exists; resume the durable operation"
}

// ManagedIssuanceOperationError reports a preparation or submission failure.
// State and retry flags are stable management semantics; RetrySameBytes is true
// only after completed bytes have been fixed and must be replayed unchanged.
type ManagedIssuanceOperationError struct {
	Issuance         *ManagedIssuanceState
	State            dnsid.SubmissionState
	TransientFailure bool
	RetrySameBytes   bool
	Err              error
}

func (e *ManagedIssuanceOperationError) Error() string {
	if e == nil || e.Err == nil {
		return "dnsid: managed issuance operation failed"
	}
	return "dnsid: managed issuance operation failed: " + e.Err.Error()
}

func (e *ManagedIssuanceOperationError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Err
}

// Transient reports whether retrying the operation may succeed.
func (e *ManagedIssuanceOperationError) Transient() bool { return e != nil && e.TransientFailure }

// ShouldRetrySameBytes reports whether recovery must resubmit the exact
// persisted bytes with the same idempotency key.
func (e *ManagedIssuanceOperationError) ShouldRetrySameBytes() bool {
	return e != nil && e.RetrySameBytes
}

// BeginManagedIssuance starts one durable split ISSUANCE. Any existing state
// for the domain blocks preparation, including a completed issuance.
func BeginManagedIssuance(ctx context.Context, opts ManagedIssuanceOptions) (*ManagedIssuanceState, error) {
	if err := validateManagedIssuanceDependencies(opts.Client, opts.EntityPublicKey, opts.KeyProvider, opts.RegistryClient, opts.Store, opts.ActivationControl); err != nil {
		return nil, err
	}
	domain, err := dnsid.NormalizeFQDN(opts.Domain)
	if err != nil {
		return nil, err
	}
	governanceID, err := dnsid.NormalizeFQDN(opts.GovernanceID)
	if err != nil {
		return nil, dnsid.NewArgumentError("dnsid: managed issuance governance ID is invalid", err)
	}
	if err := validateManagedIdempotencyKey(opts.IdempotencyKey); err != nil {
		return nil, err
	}
	entityThumb, err := thumbprint(opts.EntityPublicKey)
	if err != nil {
		return nil, dnsid.NewArgumentError("dnsid: managed issuance entity key", err)
	}
	operationalKid, operationalThumb, _, err := managedRotationKey(opts.KeyProvider.JWK())
	if err != nil {
		return nil, err
	}
	if entityThumb == operationalThumb {
		return nil, dnsid.NewValidationError("dnsid: managed issuance requires distinct entity and operational keys", nil)
	}
	issuance := &ManagedIssuanceState{
		Domain: domain, GovernanceID: governanceID, LogReference: opts.Client.ref.String(),
		EntityThumbprint: entityThumb, OperationalKid: operationalKid, OperationalThumbprint: operationalThumb,
		IdempotencyKey: opts.IdempotencyKey, ActivationBlocked: true,
	}
	existing, err := opts.Store.CreateManagedIssuance(ctx, cloneManagedIssuance(issuance))
	if err != nil {
		return issuance, fmt.Errorf("dnsid: creating managed issuance: %w", err)
	}
	if existing != nil {
		return cloneManagedIssuance(existing), &ManagedIssuanceInProgressError{Issuance: cloneManagedIssuance(existing)}
	}
	if err := opts.ActivationControl.SetManagedIssuanceActivationBlocked(ctx, true); err != nil {
		return issuance, err
	}
	return prepareAndSubmitManagedIssuance(ctx, opts.Client, opts.EntityPublicKey, opts.KeyProvider, opts.RegistryClient, issuance, opts.Store)
}

// ResumeManagedIssuance resumes preparation with the same idempotency key when
// no completed bytes exist, or resubmits the exact persisted bytes otherwise.
func ResumeManagedIssuance(ctx context.Context, opts ResumeManagedIssuanceOptions) (*ManagedIssuanceState, error) {
	if err := validateManagedIssuanceDependencies(opts.Client, opts.EntityPublicKey, opts.KeyProvider, opts.RegistryClient, opts.Store, opts.ActivationControl); err != nil {
		return nil, err
	}
	domain, err := dnsid.NormalizeFQDN(opts.Domain)
	if err != nil {
		return nil, err
	}
	issuance, err := opts.Store.LoadManagedIssuance(ctx, domain)
	if err != nil {
		return nil, fmt.Errorf("dnsid: loading managed issuance: %w", err)
	}
	if issuance == nil {
		return nil, dnsid.NewValidationError("dnsid: no durable managed issuance exists for domain", nil)
	}
	if err := validatePersistedManagedIssuance(ctx, opts.Client, issuance, opts.EntityPublicKey, opts.KeyProvider); err != nil {
		return issuance, dnsid.NewValidationError("dnsid: persisted managed issuance state failed integrity validation", err)
	}
	if issuance.Complete {
		if issuance.ActivationBlocked {
			return CompleteManagedIssuance(ctx, domain, opts.Store, opts.ActivationControl)
		}
		return issuance, nil
	}
	if err := opts.ActivationControl.SetManagedIssuanceActivationBlocked(ctx, true); err != nil {
		return issuance, err
	}
	if issuance.Submission != nil && issuance.Submission.State == dnsid.SubmissionStateAccepted {
		return issuance, nil
	}
	if issuance.Submission != nil && issuance.Submission.State == dnsid.SubmissionStateRejected {
		return issuance, &ManagedIssuanceOperationError{Issuance: cloneManagedIssuance(issuance), State: dnsid.SubmissionStateRejected, Err: fmt.Errorf("registry rejected the prepared ISSUANCE: %s", issuance.Submission.ErrorCode)}
	}
	if issuance.TerminalFailure {
		return issuance, &ManagedIssuanceOperationError{Issuance: cloneManagedIssuance(issuance), State: dnsid.SubmissionStateRejected, Err: fmt.Errorf("managed ISSUANCE preparation failed terminally: %s", issuance.LastErrorCode)}
	}
	if len(issuance.EntryBytes) == 0 {
		return prepareAndSubmitManagedIssuance(ctx, opts.Client, opts.EntityPublicKey, opts.KeyProvider, opts.RegistryClient, issuance, opts.Store)
	}
	return submitManagedIssuance(ctx, opts.RegistryClient, issuance, opts.Store)
}

// CompleteManagedIssuance marks publication/setup convergence complete and
// releases the activation block. It requires an accepted exact-byte result.
// Callers invoke it only after externally verifying required DNS, JWKS, and
// status resources; this log coordinator does not publish those resources.
func CompleteManagedIssuance(ctx context.Context, domain string, store ManagedIssuanceStore, activation ManagedIssuanceActivationController) (*ManagedIssuanceState, error) {
	if store == nil || activation == nil {
		return nil, dnsid.NewArgumentError("dnsid: managed issuance completion requires store and activation control", nil)
	}
	normalized, err := dnsid.NormalizeFQDN(domain)
	if err != nil {
		return nil, err
	}
	next, err := store.LoadManagedIssuance(ctx, normalized)
	if err != nil {
		return nil, fmt.Errorf("dnsid: loading managed issuance: %w", err)
	}
	if next == nil || next.Submission == nil || next.Submission.State != dnsid.SubmissionStateAccepted {
		return next, dnsid.NewValidationError("dnsid: managed issuance cannot complete before accepted log submission", nil)
	}
	if next.Domain != normalized {
		return next, dnsid.NewValidationError("dnsid: loaded managed issuance belongs to a different domain", nil)
	}
	if err := validateManagedIssuanceCompletionState(next); err != nil {
		return next, dnsid.NewValidationError("dnsid: accepted managed issuance state failed integrity validation", err)
	}
	next.Complete = true
	next.ActivationBlocked = true
	if err := persistManagedIssuance(ctx, store, next); err != nil {
		return next, err
	}
	if err := activation.SetManagedIssuanceActivationBlocked(ctx, false); err != nil {
		return next, err
	}
	next.ActivationBlocked = false
	if err := persistManagedIssuance(ctx, store, next); err != nil {
		return next, err
	}
	return next, nil
}

func prepareAndSubmitManagedIssuance(ctx context.Context, client *Client, entityKey jwk.Key, provider dnsid.KeyProvider, registry dnsid.RegistryPreparedEventClient, issuance *ManagedIssuanceState, store ManagedIssuanceStore) (*ManagedIssuanceState, error) {
	raw, err := registry.PrepareIssuance(ctx, issuance.Domain, issuance.IdempotencyKey)
	if err != nil {
		operationErr := normalizeManagedPreparationError("issuance", issuance, err)
		next := cloneManagedIssuance(issuance)
		next.LastErrorCode = managedPreparationErrorCode(err)
		next.TerminalFailure = !operationErr.Transient()
		if persistErr := persistManagedIssuance(ctx, store, next); persistErr != nil {
			operationErr.Err = errors.Join(operationErr.Err, persistErr)
			return issuance, operationErr
		}
		operationErr.Issuance = cloneManagedIssuance(next)
		return next, operationErr
	}
	if raw == nil || raw.LogReference != issuance.LogReference {
		return issuance, dnsid.NewValidationError("dnsid: registry preparation returned an unexpected c2sp-tlog reference", nil)
	}
	prepared, err := client.ParsePreparedEvent(raw.EntryBytes)
	if err != nil {
		return issuance, err
	}
	if err := validateManagedPreparedIssuance(prepared, issuance, entityKey, provider.JWK()); err != nil {
		return issuance, err
	}
	prepared, err = client.SignPreparedEvent(ctx, prepared, SignerOperationalCountersignature, provider)
	if err != nil {
		return issuance, err
	}
	entryBytes, err := client.PreparedEntryBytes(ctx, prepared)
	if err != nil {
		return issuance, err
	}
	next := cloneManagedIssuance(issuance)
	next.EntryBytes = append([]byte(nil), entryBytes...)
	sum := sha256.Sum256(entryBytes)
	next.EntryHash = hex.EncodeToString(sum[:])
	next.LastErrorCode = ""
	next.TerminalFailure = false
	if err := persistManagedIssuance(ctx, store, next); err != nil {
		return issuance, err
	}
	return submitManagedIssuance(ctx, registry, next, store)
}

func submitManagedIssuance(ctx context.Context, registry dnsid.RegistryPreparedEventClient, issuance *ManagedIssuanceState, store ManagedIssuanceStore) (*ManagedIssuanceState, error) {
	result, err := registry.SubmitPreparedEvent(ctx, issuance.Domain, append([]byte(nil), issuance.EntryBytes...), issuance.IdempotencyKey)
	if err != nil {
		state, transient, retry := managedSubmissionFailure(err)
		next := cloneManagedIssuance(issuance)
		next.Submission = &dnsid.SubmissionResult{State: state, EntryHash: issuance.EntryHash, ErrorCode: managedSubmissionErrorCode(err)}
		next.LastErrorCode = next.Submission.ErrorCode
		next.TerminalFailure = state == dnsid.SubmissionStateRejected
		if persistErr := persistManagedIssuance(ctx, store, next); persistErr != nil {
			return issuance, &ManagedIssuanceOperationError{Issuance: cloneManagedIssuance(issuance), State: state, TransientFailure: transient, RetrySameBytes: retry, Err: errors.Join(err, persistErr)}
		}
		return next, &ManagedIssuanceOperationError{Issuance: cloneManagedIssuance(next), State: state, TransientFailure: transient, RetrySameBytes: retry, Err: err}
	}
	if err := validateManagedIssuanceSubmission(issuance, result); err != nil {
		return issuance, &ManagedIssuanceOperationError{Issuance: cloneManagedIssuance(issuance), State: dnsid.SubmissionStateRejected, Err: err}
	}
	next := cloneManagedIssuance(issuance)
	next.Submission = cloneSubmission(result)
	next.LastErrorCode = result.ErrorCode
	next.TerminalFailure = result.State == dnsid.SubmissionStateRejected
	if err := persistManagedIssuance(ctx, store, next); err != nil {
		return issuance, &ManagedIssuanceOperationError{Issuance: cloneManagedIssuance(issuance), State: result.State, TransientFailure: true, RetrySameBytes: true, Err: err}
	}
	if result.State == dnsid.SubmissionStateRejected {
		return next, &ManagedIssuanceOperationError{Issuance: cloneManagedIssuance(next), State: result.State, Err: fmt.Errorf("registry rejected the prepared ISSUANCE: %s", result.ErrorCode)}
	}
	return next, nil
}

func validateManagedIssuanceDependencies(client *Client, entityKey jwk.Key, provider dnsid.KeyProvider, registry dnsid.RegistryPreparedEventClient, store ManagedIssuanceStore, activation ManagedIssuanceActivationController) error {
	switch {
	case client == nil:
		return dnsid.NewArgumentError("dnsid: c2sp-tlog client is required", nil)
	case entityKey == nil:
		return dnsid.NewArgumentError("dnsid: managed issuance entity public key is required", nil)
	case provider == nil:
		return dnsid.NewArgumentError("dnsid: managed issuance KeyProvider is required", nil)
	case registry == nil:
		return dnsid.NewArgumentError("dnsid: managed issuance RegistryPreparedEventClient is required", nil)
	case store == nil:
		return dnsid.NewArgumentError("dnsid: managed issuance store is required", nil)
	case activation == nil:
		return dnsid.NewArgumentError("dnsid: managed issuance activation control is required", nil)
	default:
		return nil
	}
}

func validateManagedPreparedIssuance(prepared *PreparedEvent, issuance *ManagedIssuanceState, entityKey, operationalKey jwk.Key) error {
	event, err := prepared.Event()
	if err != nil {
		return err
	}
	if event.Type != dnsidlog.LogEventIssuance || event.Domain != issuance.Domain || event.GovernanceID != issuance.GovernanceID {
		return dnsid.NewValidationError("dnsid: registry preparation is not the expected ISSUANCE", nil)
	}
	entityThumb, err := thumbprint(event.InitialEntityPublicKey)
	if err != nil || entityThumb != issuance.EntityThumbprint {
		return dnsid.NewValidationError("dnsid: registry ISSUANCE entity key does not match expected key", err)
	}
	expectedEntityThumb, err := thumbprint(entityKey)
	if err != nil || expectedEntityThumb != entityThumb {
		return dnsid.NewValidationError("dnsid: managed ISSUANCE expected entity key mismatch", err)
	}
	operationalThumb, err := thumbprint(event.InitialOperationalPublicKey)
	if err != nil || operationalThumb != issuance.OperationalThumbprint {
		return dnsid.NewValidationError("dnsid: registry ISSUANCE operational key does not match active key", err)
	}
	expectedOperationalThumb, err := thumbprint(operationalKey)
	if err != nil || expectedOperationalThumb != operationalThumb {
		return dnsid.NewValidationError("dnsid: managed ISSUANCE active operational key mismatch", err)
	}
	return nil
}

func validatePersistedManagedIssuance(ctx context.Context, client *Client, issuance *ManagedIssuanceState, entityKey jwk.Key, provider dnsid.KeyProvider) error {
	if issuance == nil || issuance.Domain == "" || issuance.GovernanceID == "" || issuance.LogReference == "" || issuance.IdempotencyKey == "" || issuance.EntityThumbprint == "" || issuance.OperationalKid == "" || issuance.OperationalThumbprint == "" {
		return fmt.Errorf("complete persisted managed issuance state is required")
	}
	if validateManagedIdempotencyKey(issuance.IdempotencyKey) != nil {
		return fmt.Errorf("invalid persisted idempotency key")
	}
	domain, err := dnsid.NormalizeFQDN(issuance.Domain)
	if err != nil || domain != issuance.Domain {
		return managedIssuanceIntegrityError("persisted domain is not normalized", err)
	}
	ref, err := ParseReference(issuance.LogReference)
	if err != nil || ref.String() != client.ref.String() {
		return managedIssuanceIntegrityError("persisted log reference does not match client", err)
	}
	if issuance.Complete && (issuance.Submission == nil || issuance.Submission.State != dnsid.SubmissionStateAccepted) {
		return fmt.Errorf("completed issuance does not have accepted submission")
	}
	if !issuance.ActivationBlocked && !issuance.Complete {
		return fmt.Errorf("incomplete issuance must remain activation-blocked")
	}
	if entityThumb, err := thumbprint(entityKey); err != nil || entityThumb != issuance.EntityThumbprint {
		return managedIssuanceIntegrityError("persisted entity key does not match expected key", err)
	}
	if len(issuance.EntryBytes) == 0 {
		if issuance.EntryHash != "" || issuance.Submission != nil {
			return fmt.Errorf("persisted issuance has submission state without completed bytes")
		}
		operational := provider.JWK(issuance.OperationalKid)
		if operational == nil {
			operational = provider.JWK()
		}
		if operationalThumb, err := thumbprint(operational); err != nil || operationalThumb != issuance.OperationalThumbprint {
			return managedIssuanceIntegrityError("persisted operational key does not match provider", err)
		}
		return nil
	}
	sum := sha256.Sum256(issuance.EntryBytes)
	if issuance.EntryHash != hex.EncodeToString(sum[:]) {
		return fmt.Errorf("persisted entry hash does not match entry bytes")
	}
	prepared, err := client.ParsePreparedEvent(issuance.EntryBytes)
	if err != nil {
		return err
	}
	verifiedBytes, err := client.PreparedEntryBytes(ctx, prepared)
	if err != nil || !bytes.Equal(verifiedBytes, issuance.EntryBytes) {
		return managedIssuanceIntegrityError("persisted issuance signatures or bytes are invalid", err)
	}
	event, err := prepared.Event()
	if err != nil {
		return err
	}
	if event.Type != dnsidlog.LogEventIssuance || event.Domain != issuance.Domain || event.GovernanceID != issuance.GovernanceID {
		return fmt.Errorf("persisted issuance metadata does not match entry bytes")
	}
	entityEventThumb, err := thumbprint(event.InitialEntityPublicKey)
	if err != nil || entityEventThumb != issuance.EntityThumbprint {
		return managedIssuanceIntegrityError("persisted issuance entity key does not match metadata", err)
	}
	operationalEventThumb, err := thumbprint(event.InitialOperationalPublicKey)
	if err != nil || operationalEventThumb != issuance.OperationalThumbprint {
		return managedIssuanceIntegrityError("persisted issuance operational key does not match metadata", err)
	}
	return nil
}

func validateManagedIssuanceSubmission(issuance *ManagedIssuanceState, result *dnsid.SubmissionResult) error {
	if result == nil {
		return dnsid.NewValidationError("dnsid: registry returned no managed issuance submission result", nil)
	}
	if issuance.Submission != nil && issuance.Submission.EntryHash != "" && result.EntryHash != "" && issuance.Submission.EntryHash != result.EntryHash {
		return dnsid.NewValidationError("dnsid: registry reconciled a different entry hash for this managed issuance", nil)
	}
	switch result.State {
	case dnsid.SubmissionStatePrepared, dnsid.SubmissionStateSubmitting, dnsid.SubmissionStatePending, dnsid.SubmissionStateIndeterminate, dnsid.SubmissionStateRejected:
		return nil
	case dnsid.SubmissionStateAccepted:
	default:
		return dnsid.NewValidationError(fmt.Sprintf("dnsid: unknown managed issuance submission state %q", result.State), nil)
	}
	if result.EntryHash != issuance.EntryHash {
		return dnsid.NewValidationError("dnsid: accepted submission entry hash does not match exact managed issuance bytes", nil)
	}
	if result.KeyID != "" && result.KeyID != issuance.OperationalKid {
		return dnsid.NewValidationError("dnsid: accepted submission key_id does not match operational key", nil)
	}
	if result.Index == nil || result.LogRef == "" {
		return dnsid.NewValidationError("dnsid: accepted submission is missing final c2sp-tlog reference", nil)
	}
	ref, index, err := ParseFinalEventRef(dnsidlog.LogRef(result.LogRef))
	if err != nil || ref.String() != issuance.LogReference || index != *result.Index {
		return dnsid.NewValidationError("dnsid: accepted submission final reference does not match managed issuance stream and index", err)
	}
	return nil
}

func validateManagedIssuanceCompletionState(issuance *ManagedIssuanceState) error {
	if len(issuance.EntryBytes) == 0 || issuance.EntryHash == "" {
		return errors.New("accepted issuance is missing exact entry bytes or hash")
	}
	sum := sha256.Sum256(issuance.EntryBytes)
	if issuance.EntryHash != hex.EncodeToString(sum[:]) || issuance.Submission.EntryHash != issuance.EntryHash {
		return errors.New("accepted issuance hash does not match exact entry bytes")
	}
	if issuance.Submission.Index == nil || issuance.Submission.LogRef == "" {
		return errors.New("accepted issuance is missing final reference")
	}
	ref, index, err := ParseFinalEventRef(dnsidlog.LogRef(issuance.Submission.LogRef))
	if err != nil || ref.String() != issuance.LogReference || index != *issuance.Submission.Index {
		return managedIssuanceIntegrityError("accepted issuance final reference does not match durable state", err)
	}
	return nil
}

func normalizeManagedPreparationError(operation string, issuance *ManagedIssuanceState, err error) *ManagedIssuanceOperationError {
	var apiErr *dnsid.RegistryAPIError
	if errors.As(err, &apiErr) {
		state := dnsid.SubmissionStateRejected
		if apiErr.Transient() {
			state = dnsid.SubmissionStatePrepared
		}
		return &ManagedIssuanceOperationError{Issuance: cloneManagedIssuance(issuance), State: state, TransientFailure: apiErr.Transient(), Err: err}
	}
	return &ManagedIssuanceOperationError{Issuance: cloneManagedIssuance(issuance), State: dnsid.SubmissionStatePrepared, TransientFailure: true, Err: fmt.Errorf("dnsid: managed %s preparation failed: %w", operation, err)}
}

func managedPreparationErrorCode(err error) string {
	var apiErr *dnsid.RegistryAPIError
	if errors.As(err, &apiErr) && apiErr.Code != "" {
		return apiErr.Code
	}
	return "TLOG_PREPARATION_UNAVAILABLE"
}

func persistManagedIssuance(ctx context.Context, store ManagedIssuanceStore, issuance *ManagedIssuanceState) error {
	if err := store.PersistManagedIssuance(ctx, cloneManagedIssuance(issuance)); err != nil {
		return fmt.Errorf("dnsid: persisting managed issuance: %w", err)
	}
	return nil
}

func managedIssuanceIntegrityError(message string, cause error) error {
	if cause != nil {
		return fmt.Errorf("%s: %w", message, cause)
	}
	return errors.New(message)
}

func cloneManagedIssuance(issuance *ManagedIssuanceState) *ManagedIssuanceState {
	if issuance == nil {
		return nil
	}
	copy := *issuance
	copy.EntryBytes = append([]byte(nil), issuance.EntryBytes...)
	copy.Submission = cloneSubmission(issuance.Submission)
	return &copy
}
