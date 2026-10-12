package c2sptlog

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"strings"

	dnsid "github.com/dnsid-ai/dnsid-go"
	dnsidlog "github.com/dnsid-ai/dnsid-go/log"
	"github.com/lestrrat-go/jwx/v3/jwk"
)

// ManagedKeyRotationState is the durable recovery record for one
// registry-managed operational-key rotation. EntryBytes and IdempotencyKey
// are immutable once first persisted and are reused verbatim on every retry.
type ManagedKeyRotationState struct {
	Domain                   string                  `json:"domain"`
	LogReference             string                  `json:"log_reference"`
	PreviousProviderRef      string                  `json:"previous_provider_ref"`
	NewProviderRef           string                  `json:"new_provider_ref"`
	PreviousAlgorithm        dnsid.JoseAlg           `json:"previous_algorithm"`
	NewAlgorithm             dnsid.JoseAlg           `json:"new_algorithm"`
	PreviousKid              string                  `json:"previous_kid"`
	PreviousThumbprint       string                  `json:"previous_thumbprint"`
	NewKid                   string                  `json:"new_kid"`
	NewThumbprint            string                  `json:"new_thumbprint"`
	EntryBytes               []byte                  `json:"entry_bytes"`
	EntryHash                string                  `json:"entry_hash"`
	IdempotencyKey           string                  `json:"idempotency_key"`
	Submission               *dnsid.SubmissionResult `json:"submission,omitempty"`
	Activated                bool                    `json:"activated"`
	ApplicationSigningPaused bool                    `json:"application_signing_paused"`
}

// ManagedKeyRotationStore durably saves each recoverable rotation state.
type ManagedKeyRotationStore interface {
	PersistManagedKeyRotation(context.Context, *ManagedKeyRotationState) error
}

// ManagedKeyRotationStoreFunc adapts a function to ManagedKeyRotationStore.
type ManagedKeyRotationStoreFunc func(context.Context, *ManagedKeyRotationState) error

// PersistManagedKeyRotation calls f to persist state.
func (f ManagedKeyRotationStoreFunc) PersistManagedKeyRotation(ctx context.Context, state *ManagedKeyRotationState) error {
	if f == nil {
		return dnsid.NewArgumentError("dnsid: managed key rotation persistence function is required", nil)
	}
	return f(ctx, state)
}

// ApplicationSigningController pauses or resumes new application signatures.
type ApplicationSigningController interface {
	SetApplicationSigningPaused(context.Context, bool) error
}

// ApplicationSigningControllerFunc adapts a function to ApplicationSigningController.
type ApplicationSigningControllerFunc func(context.Context, bool) error

// SetApplicationSigningPaused calls f to update application-signing state.
func (f ApplicationSigningControllerFunc) SetApplicationSigningPaused(ctx context.Context, paused bool) error {
	if f == nil {
		return dnsid.NewArgumentError("dnsid: application-signing control function is required", nil)
	}
	return f(ctx, paused)
}

// ManagedKeyRotationOptions configures a new managed operational-key rotation.
// Store, ApplicationSigning, PublicationVerifier and WireSigner are mandatory.
// Provider references identify durable provider state, never credentials.
type ManagedKeyRotationOptions struct {
	Domain         string
	Client         *Client
	KeyProvider    dnsid.KeyProvider
	TargetProvider dnsid.KeyProvider
	// TargetAlgorithm defaults to the previous operational key's algorithm.
	TargetAlgorithm     dnsid.JoseAlg
	PreviousProviderRef string
	NewProviderRef      string
	PublicationVerifier LocalPublicationVerifier
	WireSigner          func(context.Context, dnsid.KeyProvider) error
	RegistryClient      dnsid.RegistryPreparedEventClient
	IdempotencyKey      string
	Store               ManagedKeyRotationStore
	ApplicationSigning  ApplicationSigningController
}

// ResumeManagedKeyRotationOptions resumes a previously persisted rotation.
// ResolveProvider must open saved provider state rather than deployment selections.
// WireSigner installs the resolved active provider at the application boundary.
type ResumeManagedKeyRotationOptions struct {
	ResolveProvider     func(context.Context, string) (dnsid.KeyProvider, error)
	Client              *Client
	PublicationVerifier LocalPublicationVerifier
	WireSigner          func(context.Context, dnsid.KeyProvider) error
	RegistryClient      dnsid.RegistryPreparedEventClient
	Rotation            *ManagedKeyRotationState
	Store               ManagedKeyRotationStore
	ApplicationSigning  ApplicationSigningController
}

// LocalPublicationVerifier verifies signed local publication and key continuity.
// IdentityManager implements this interface.
type LocalPublicationVerifier interface {
	Domain() string
	LogReference() string
	VerifyLocalOperationalKey(context.Context, dnsid.KeyProvider, string) (*dnsid.VerifiedDomain, error)
}

// ManagedKeyRotationSubmissionError reports a submission or persistence
// failure after exact completed entry bytes have been fixed.
type ManagedKeyRotationSubmissionError struct {
	Rotation         *ManagedKeyRotationState
	State            dnsid.SubmissionState
	TransientFailure bool
	RetrySameBytes   bool
	Err              error
}

func (e *ManagedKeyRotationSubmissionError) Error() string {
	if e == nil || e.Err == nil {
		return "dnsid: managed key rotation submission failed"
	}
	return "dnsid: managed key rotation submission failed: " + e.Err.Error()
}

func (e *ManagedKeyRotationSubmissionError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Err
}

// Transient reports whether retrying the operation may succeed.
func (e *ManagedKeyRotationSubmissionError) Transient() bool { return e != nil && e.TransientFailure }

// ShouldRetrySameBytes reports whether recovery must resubmit the exact
// persisted bytes with the same idempotency key.
func (e *ManagedKeyRotationSubmissionError) ShouldRetrySameBytes() bool {
	return e != nil && e.RetrySameBytes
}

// ManagedKeyRotationActivationError reports accepted registry submission with
// incomplete local activation, supersession, pause release, or persistence.
type ManagedKeyRotationActivationError struct {
	Rotation *ManagedKeyRotationState
	Err      error
}

func (e *ManagedKeyRotationActivationError) Error() string {
	if e == nil || e.Err == nil {
		return "dnsid: managed key rotation activation is incomplete"
	}
	return "dnsid: managed key rotation activation is incomplete: " + e.Err.Error()
}

func (e *ManagedKeyRotationActivationError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Err
}

// RotateManagedOperationalKey prepares and submits one registry-managed C2SP
// KEY_ROTATION. The registry exclusively owns publication and append recovery;
// this function activates locally only after an accepted result is bound to the
// exact persisted bytes and final event reference.
func RotateManagedOperationalKey(ctx context.Context, opts ManagedKeyRotationOptions) (*ManagedKeyRotationState, error) {
	if err := validateManagedRotationDependencies(opts.KeyProvider, opts.RegistryClient, opts.Store, opts.ApplicationSigning); err != nil {
		return nil, err
	}
	if opts.Client == nil || opts.PublicationVerifier == nil || opts.WireSigner == nil || strings.TrimSpace(opts.PreviousProviderRef) == "" {
		return nil, dnsid.NewArgumentError("dnsid: rotation client, publication verifier, signer wiring and saved provider references are required", nil)
	}
	target := opts.TargetProvider
	if target == nil {
		target = opts.KeyProvider
		if opts.NewProviderRef == "" {
			opts.NewProviderRef = opts.PreviousProviderRef
		} else if opts.NewProviderRef != opts.PreviousProviderRef {
			return nil, dnsid.NewArgumentError("dnsid: a different provider reference requires an explicit target provider", nil)
		}
	}
	if strings.TrimSpace(opts.NewProviderRef) == "" {
		return nil, dnsid.NewArgumentError("dnsid: target provider reference is required", nil)
	}
	domain, err := dnsid.NormalizeFQDN(opts.Domain)
	if err != nil {
		return nil, err
	}
	if opts.PublicationVerifier.Domain() != domain || opts.PublicationVerifier.LogReference() != opts.Client.ref.String() {
		return nil, dnsid.NewArgumentError("dnsid: publication verifier belongs to another identity", nil)
	}
	if opts.TargetProvider != nil && opts.PreviousProviderRef == opts.NewProviderRef {
		return nil, dnsid.NewArgumentError("dnsid: explicit target requires a distinct stable provider reference", nil)
	}
	if err := validateManagedIdempotencyKey(opts.IdempotencyKey); err != nil {
		return nil, err
	}
	if opts.TargetAlgorithm != "" && !opts.TargetAlgorithm.Valid() {
		return nil, dnsid.NewArgumentError("dnsid: unsupported target signing algorithm", nil)
	}
	previousKey := opts.KeyProvider.JWK()
	previousKid, previousThumb, algorithm, err := managedRotationKey(previousKey)
	if err != nil {
		return nil, err
	}
	if _, err := opts.PublicationVerifier.VerifyLocalOperationalKey(ctx, opts.KeyProvider, previousKid); err != nil {
		return nil, err
	}
	targetAlgorithm := opts.TargetAlgorithm
	if targetAlgorithm == "" {
		targetAlgorithm = algorithm
	}
	newKid, err := target.GenerateKey(targetAlgorithm)
	if err != nil {
		return nil, err
	}
	newKey := target.JWK(newKid)
	providerNewKid, newThumb, newAlgorithm, err := managedRotationKey(newKey)
	if err != nil {
		return nil, err
	}
	if providerNewKid != newKid || newAlgorithm != targetAlgorithm {
		return nil, dnsid.NewValidationError("dnsid: generated pending key does not match the requested kid and algorithm", nil)
	}
	if newThumb == previousThumb {
		return nil, dnsid.NewValidationError("dnsid: managed KEY_ROTATION requires a distinct pending operational key", nil)
	}

	raw, err := opts.RegistryClient.PrepareKeyRotation(ctx, domain, &dnsid.KeyRotationPreparationRequest{PreviousKeyID: previousThumb, PublicKey: newKey}, opts.IdempotencyKey)
	if err != nil {
		return nil, err
	}
	if raw == nil || raw.LogReference != opts.Client.ref.String() {
		return nil, dnsid.NewValidationError("dnsid: registry preparation returned an unexpected c2sp-tlog reference", nil)
	}
	prepared, err := opts.Client.ParsePreparedEvent(raw.EntryBytes)
	if err != nil {
		return nil, err
	}
	if err := validateManagedPreparedRotation(prepared, domain, previousThumb, newKid, newThumb, newKey); err != nil {
		return nil, err
	}
	prepared, err = opts.Client.SignPreparedEvent(ctx, prepared, SignerPreviousOperational, opts.KeyProvider)
	if err != nil {
		return nil, err
	}
	prepared, err = opts.Client.SignPreparedEventWithKey(ctx, prepared, SignerNewOperational, target, newKid)
	if err != nil {
		return nil, err
	}
	entryBytes, err := opts.Client.PreparedEntryBytes(ctx, prepared)
	if err != nil {
		return nil, err
	}
	entryHash := sha256.Sum256(entryBytes)
	rotation := &ManagedKeyRotationState{
		Domain:                   domain,
		LogReference:             opts.Client.ref.String(),
		PreviousProviderRef:      opts.PreviousProviderRef,
		NewProviderRef:           opts.NewProviderRef,
		PreviousAlgorithm:        algorithm,
		NewAlgorithm:             newAlgorithm,
		PreviousKid:              previousKid,
		PreviousThumbprint:       previousThumb,
		NewKid:                   newKid,
		NewThumbprint:            newThumb,
		EntryBytes:               append([]byte(nil), entryBytes...),
		EntryHash:                hex.EncodeToString(entryHash[:]),
		IdempotencyKey:           opts.IdempotencyKey,
		ApplicationSigningPaused: true,
	}
	if err := persistManagedRotation(ctx, opts.Store, rotation); err != nil {
		return rotation, &ManagedKeyRotationSubmissionError{Rotation: cloneManagedRotation(rotation), State: dnsid.SubmissionStatePrepared, TransientFailure: true, RetrySameBytes: true, Err: err}
	}
	if err := opts.ApplicationSigning.SetApplicationSigningPaused(ctx, true); err != nil {
		return rotation, &ManagedKeyRotationSubmissionError{Rotation: cloneManagedRotation(rotation), State: dnsid.SubmissionStatePrepared, TransientFailure: true, RetrySameBytes: true, Err: err}
	}
	return submitManagedRotation(ctx, opts.KeyProvider, target, opts.Client, opts.PublicationVerifier, opts.WireSigner, opts.RegistryClient, rotation, opts.Store, opts.ApplicationSigning)
}

// ResumeManagedOperationalKeyRotation retries only a persisted rotation's
// exact completed bytes and idempotency key, or finishes local reconciliation
// after an accepted submission.
func ResumeManagedOperationalKeyRotation(ctx context.Context, opts ResumeManagedKeyRotationOptions) (*ManagedKeyRotationState, error) {
	if opts.ResolveProvider == nil || opts.Client == nil || opts.PublicationVerifier == nil || opts.WireSigner == nil || opts.Store == nil || opts.ApplicationSigning == nil || opts.RegistryClient == nil {
		return nil, dnsid.NewArgumentError("dnsid: recovery requires saved-provider resolver, client, publication verifier and signer wiring", nil)
	}
	rotation := cloneManagedRotation(opts.Rotation)
	if rotation == nil || rotation.Domain == "" || rotation.LogReference == "" || len(rotation.EntryBytes) == 0 || validateManagedIdempotencyKey(rotation.IdempotencyKey) != nil || rotation.PreviousKid == "" || rotation.PreviousThumbprint == "" || rotation.NewKid == "" || rotation.NewThumbprint == "" {
		return nil, dnsid.NewArgumentError("dnsid: complete persisted managed key rotation state is required", nil)
	}
	if err := validatePersistedManagedRotation(rotation); err != nil {
		return nil, dnsid.NewValidationError("dnsid: persisted managed key rotation state failed integrity validation", err)
	}
	if rotation.Submission != nil && rotation.Submission.State == dnsid.SubmissionStateRejected {
		return rotation, &ManagedKeyRotationSubmissionError{Rotation: cloneManagedRotation(rotation), State: dnsid.SubmissionStateRejected, RetrySameBytes: false, Err: fmt.Errorf("registry rejected the prepared KEY_ROTATION: %s", rotation.Submission.ErrorCode)}
	}
	if err := opts.ApplicationSigning.SetApplicationSigningPaused(ctx, true); err != nil {
		return rotation, &ManagedKeyRotationActivationError{Rotation: cloneManagedRotation(rotation), Err: err}
	}
	rotation.ApplicationSigningPaused = true
	if opts.Client.ref.String() != rotation.LogReference {
		return rotation, &ManagedKeyRotationActivationError{Rotation: cloneManagedRotation(rotation), Err: dnsid.NewValidationError("dnsid: recovery client mismatches saved log", nil)}
	}
	previous, err := opts.ResolveProvider(ctx, rotation.PreviousProviderRef)
	if err != nil {
		return rotation, &ManagedKeyRotationActivationError{Rotation: cloneManagedRotation(rotation), Err: err}
	}
	target := previous
	if rotation.NewProviderRef != rotation.PreviousProviderRef {
		target, err = opts.ResolveProvider(ctx, rotation.NewProviderRef)
		if err != nil {
			return rotation, &ManagedKeyRotationActivationError{Rotation: cloneManagedRotation(rotation), Err: err}
		}
	}
	if previous == nil || target == nil {
		return rotation, &ManagedKeyRotationActivationError{Rotation: cloneManagedRotation(rotation), Err: dnsid.NewValidationError("dnsid: saved rotation provider unavailable", nil)}
	}
	if err := validateManagedProviderBindings(previous, target, rotation); err != nil {
		return rotation, &ManagedKeyRotationActivationError{Rotation: cloneManagedRotation(rotation), Err: err}
	}

	if rotation.Submission != nil && rotation.Submission.State == dnsid.SubmissionStateAccepted {
		return activateManagedRotation(ctx, previous, target, opts.Client, opts.PublicationVerifier, opts.WireSigner, rotation, opts.Store, opts.ApplicationSigning)
	}
	return submitManagedRotation(ctx, previous, target, opts.Client, opts.PublicationVerifier, opts.WireSigner, opts.RegistryClient, rotation, opts.Store, opts.ApplicationSigning)
}

func submitManagedRotation(ctx context.Context, previous, target dnsid.KeyProvider, client *Client, verifier LocalPublicationVerifier, wire func(context.Context, dnsid.KeyProvider) error, registry dnsid.RegistryPreparedEventClient, rotation *ManagedKeyRotationState, store ManagedKeyRotationStore, signing ApplicationSigningController) (*ManagedKeyRotationState, error) {
	result, err := registry.SubmitPreparedEvent(ctx, rotation.Domain, append([]byte(nil), rotation.EntryBytes...), rotation.IdempotencyKey)
	if err != nil {
		state, transient, retry := managedSubmissionFailure(err)
		next := cloneManagedRotation(rotation)
		next.Submission = &dnsid.SubmissionResult{State: state, EntryHash: rotation.EntryHash, ErrorCode: managedSubmissionErrorCode(err)}
		if persistErr := persistManagedRotation(ctx, store, next); persistErr != nil {
			return rotation, &ManagedKeyRotationSubmissionError{Rotation: cloneManagedRotation(rotation), State: state, TransientFailure: transient, RetrySameBytes: retry, Err: errors.Join(err, persistErr)}
		}
		return next, &ManagedKeyRotationSubmissionError{Rotation: cloneManagedRotation(next), State: state, TransientFailure: transient, RetrySameBytes: retry, Err: err}
	}
	if err := validateManagedSubmission(rotation, result); err != nil {
		return rotation, &ManagedKeyRotationSubmissionError{Rotation: cloneManagedRotation(rotation), State: dnsid.SubmissionStateRejected, RetrySameBytes: false, Err: err}
	}
	next := cloneManagedRotation(rotation)
	next.Submission = cloneSubmission(result)
	if err := persistManagedRotation(ctx, store, next); err != nil {
		return rotation, &ManagedKeyRotationSubmissionError{Rotation: cloneManagedRotation(rotation), State: result.State, TransientFailure: true, RetrySameBytes: true, Err: err}
	}
	if result.State == dnsid.SubmissionStateRejected {
		return next, &ManagedKeyRotationSubmissionError{Rotation: cloneManagedRotation(next), State: result.State, RetrySameBytes: false, Err: fmt.Errorf("registry rejected the prepared KEY_ROTATION: %s", result.ErrorCode)}
	}
	if result.State != dnsid.SubmissionStateAccepted {
		return next, nil
	}

	return activateManagedRotation(ctx, previous, target, client, verifier, wire, next, store, signing)
}

func activateManagedRotation(ctx context.Context, previous, target dnsid.KeyProvider, client *Client, verifier LocalPublicationVerifier, wire func(context.Context, dnsid.KeyProvider) error, next *ManagedKeyRotationState, store ManagedKeyRotationStore, signing ApplicationSigningController) (*ManagedKeyRotationState, error) {
	recoverable := next
	if err := verifyManagedRotationPublication(ctx, client, verifier, target, next); err != nil {
		return recoverable, &ManagedKeyRotationActivationError{Rotation: cloneManagedRotation(recoverable), Err: err}
	}
	if err := reconcileManagedRotation(previous, target, next); err != nil {
		return recoverable, &ManagedKeyRotationActivationError{Rotation: cloneManagedRotation(recoverable), Err: err}
	}
	activated := cloneManagedRotation(next)
	activated.Activated = true
	if err := persistManagedRotation(ctx, store, activated); err != nil {
		return recoverable, &ManagedKeyRotationActivationError{Rotation: cloneManagedRotation(recoverable), Err: err}
	}
	recoverable = activated
	if err := wire(ctx, target); err != nil {
		return recoverable, &ManagedKeyRotationActivationError{Rotation: cloneManagedRotation(recoverable), Err: err}
	}
	if err := signing.SetApplicationSigningPaused(ctx, false); err != nil {
		return recoverable, &ManagedKeyRotationActivationError{Rotation: cloneManagedRotation(recoverable), Err: err}
	}
	completed := cloneManagedRotation(activated)
	completed.ApplicationSigningPaused = false
	if err := persistManagedRotation(ctx, store, completed); err != nil {
		return recoverable, &ManagedKeyRotationActivationError{Rotation: cloneManagedRotation(recoverable), Err: err}
	}
	return completed, nil
}

func validateManagedRotationDependencies(provider dnsid.KeyProvider, registry dnsid.RegistryPreparedEventClient, store ManagedKeyRotationStore, signing ApplicationSigningController) error {
	switch {
	case provider == nil:
		return dnsid.NewArgumentError("dnsid: managed key rotation KeyProvider is required", nil)
	case registry == nil:
		return dnsid.NewArgumentError("dnsid: managed key rotation RegistryPreparedEventClient is required", nil)
	case store == nil:
		return dnsid.NewArgumentError("dnsid: managed key rotation persistence hook is required", nil)
	case signing == nil:
		return dnsid.NewArgumentError("dnsid: managed key rotation application-signing pause hook is required", nil)
	default:
		return nil
	}
}

func validateManagedIdempotencyKey(key string) error {
	if len(key) == 0 || len(key) > 200 || strings.TrimSpace(key) != key {
		return dnsid.NewArgumentError("dnsid: managed key rotation idempotency key must be 1 to 200 bytes without surrounding whitespace", nil)
	}
	return nil
}

func validatePersistedManagedRotation(rotation *ManagedKeyRotationState) error {
	if rotation.Activated && (rotation.Submission == nil || rotation.Submission.State != dnsid.SubmissionStateAccepted) {
		return fmt.Errorf("activated rotation is missing saved acceptance")
	}
	if rotation.Submission != nil {
		if err := validateManagedSubmission(rotation, rotation.Submission); err != nil {
			return err
		}
	}
	if strings.TrimSpace(rotation.PreviousProviderRef) == "" || strings.TrimSpace(rotation.NewProviderRef) == "" || !rotation.PreviousAlgorithm.Valid() || !rotation.NewAlgorithm.Valid() {
		return fmt.Errorf("persisted provider references and algorithms are required")
	}
	domain, err := dnsid.NormalizeFQDN(rotation.Domain)
	if err != nil {
		return fmt.Errorf("invalid persisted domain: %w", err)
	}
	if domain != rotation.Domain {
		return fmt.Errorf("persisted domain is not normalized")
	}
	ref, err := ParseReference(rotation.LogReference)
	if err != nil {
		return fmt.Errorf("invalid persisted log reference: %w", err)
	}
	if ref.StreamID == domain {
		return fmt.Errorf("persisted stream ID equals the identity domain")
	}
	sum := sha256.Sum256(rotation.EntryBytes)
	if rotation.EntryHash != hex.EncodeToString(sum[:]) {
		return fmt.Errorf("persisted entry hash does not match entry bytes")
	}
	payload, err := payloadObjectFromEntry(rotation.EntryBytes)
	if err != nil {
		return err
	}
	if bound, _ := payload["lr"].(string); bound != rotation.LogReference {
		return fmt.Errorf("persisted entry belongs to a different log reference")
	}
	event, err := LogEventFromEntry(rotation.EntryBytes)
	if err != nil {
		return err
	}
	if event.Type != dnsidlog.LogEventKeyRotation || event.Domain != domain || event.PreviousOperationalKid != rotation.PreviousKid || event.PreviousOperationalThumbprint != rotation.PreviousThumbprint || event.NewOperationalThumbprint != rotation.NewThumbprint || event.PreviousOperationalSignature == "" || event.NewOperationalSignature == "" || rotation.NewThumbprint == rotation.PreviousThumbprint {
		return fmt.Errorf("persisted rotation metadata does not match entry bytes")
	}
	newKid, newThumb, newAlg, err := managedRotationKey(event.NewOperationalPublicKey)
	if err != nil {
		return err
	}
	if newKid != rotation.NewKid || newThumb != rotation.NewThumbprint || newAlg != rotation.NewAlgorithm {
		return fmt.Errorf("persisted new key does not match entry bytes")
	}
	return nil
}

func managedRotationKey(key jwk.Key) (string, string, dnsid.JoseAlg, error) {
	if key == nil {
		return "", "", "", dnsid.NewArgumentError("dnsid: managed key rotation key is required", nil)
	}
	kid, ok := key.KeyID()
	if !ok || kid == "" {
		return "", "", "", dnsid.NewValidationError("dnsid: managed key rotation key is missing kid", nil)
	}
	algorithm, ok := key.Algorithm()
	if !ok {
		return "", "", "", dnsid.NewValidationError("dnsid: managed key rotation key is missing alg", nil)
	}
	alg := dnsid.JoseAlg(algorithm.String())
	if !alg.Valid() {
		return "", "", "", dnsid.NewValidationError(fmt.Sprintf("dnsid: managed key rotation key uses unsupported alg %q", alg), nil)
	}
	thumb, err := thumbprint(key)
	if err != nil {
		return "", "", "", err
	}
	return kid, thumb, alg, nil
}

func validateManagedPreparedRotation(prepared *PreparedEvent, domain, previousThumb, newKid, newThumb string, newKey jwk.Key) error {
	event, err := prepared.Event()
	if err != nil {
		return err
	}
	if event.Type != dnsidlog.LogEventKeyRotation || event.Domain != domain {
		return dnsid.NewValidationError("dnsid: registry preparation is not the expected KEY_ROTATION", nil)
	}
	if event.PreviousOperationalThumbprint != previousThumb {
		return dnsid.NewValidationError("dnsid: registry KEY_ROTATION previous thumbprint does not match the active key", nil)
	}
	actualKid, actualThumb, _, err := managedRotationKey(event.NewOperationalPublicKey)
	if err != nil {
		return err
	}
	expectedKid, expectedThumb, _, err := managedRotationKey(newKey)
	if err != nil {
		return err
	}
	if actualKid != newKid || expectedKid != newKid || actualThumb != newThumb || expectedThumb != newThumb || event.NewOperationalThumbprint != newThumb {
		return dnsid.NewValidationError("dnsid: registry KEY_ROTATION new key does not match the generated pending key", nil)
	}
	return nil
}

func validateManagedSubmission(rotation *ManagedKeyRotationState, result *dnsid.SubmissionResult) error {
	if result == nil {
		return dnsid.NewValidationError("dnsid: registry returned no managed key rotation submission result", nil)
	}
	if rotation.Submission != nil && rotation.Submission.EntryHash != "" && result.EntryHash != "" && rotation.Submission.EntryHash != result.EntryHash {
		return dnsid.NewValidationError("dnsid: registry reconciled a different entry hash for this managed key rotation", nil)
	}
	switch result.State {
	case dnsid.SubmissionStatePrepared, dnsid.SubmissionStateSubmitting, dnsid.SubmissionStatePending, dnsid.SubmissionStateIndeterminate, dnsid.SubmissionStateRejected:
		return nil
	case dnsid.SubmissionStateAccepted:
	default:
		return dnsid.NewValidationError(fmt.Sprintf("dnsid: unknown managed key rotation submission state %q", result.State), nil)
	}
	sum := sha256.Sum256(rotation.EntryBytes)
	expectedHash := hex.EncodeToString(sum[:])
	if rotation.EntryHash != expectedHash || result.EntryHash != expectedHash {
		return dnsid.NewValidationError("dnsid: accepted submission entry hash does not match the exact managed key rotation bytes", nil)
	}
	if result.KeyID != "" && result.KeyID != rotation.NewKid {
		return dnsid.NewValidationError("dnsid: accepted submission key_id does not match the pending key", nil)
	}
	if result.Index == nil || result.LogRef == "" {
		return dnsid.NewValidationError("dnsid: accepted submission is missing its final c2sp-tlog reference", nil)
	}
	ref, index, err := ParseFinalEventRef(dnsidlog.LogRef(result.LogRef))
	if err != nil || ref.String() != rotation.LogReference || index != *result.Index {
		return dnsid.NewValidationError("dnsid: accepted submission final reference does not match the managed key rotation stream and index", err)
	}
	return nil
}

func verifyManagedRotationPublication(ctx context.Context, client *Client, verifier LocalPublicationVerifier, target dnsid.KeyProvider, rotation *ManagedKeyRotationState) error {
	if rotation.Submission == nil || rotation.Submission.State != dnsid.SubmissionStateAccepted {
		return dnsid.NewValidationError("dnsid: activation requires saved acceptance", nil)
	}
	if err := validateManagedSubmission(rotation, rotation.Submission); err != nil {
		return err
	}
	if verifier.Domain() != rotation.Domain || verifier.LogReference() != rotation.LogReference {
		return dnsid.NewValidationError("dnsid: publication verifier belongs to another identity", nil)
	}
	if _, err := client.readEvent(ctx, dnsidlog.LogRef(rotation.Submission.LogRef), rotation.EntryBytes); err != nil {
		return err
	}
	_, err := verifier.VerifyLocalOperationalKey(ctx, target, rotation.NewKid)
	return err
}

func validateManagedProviderBindings(previous, target dnsid.KeyProvider, rotation *ManagedKeyRotationState) error {
	pending := target.JWK(rotation.NewKid)
	kid, thumb, alg, err := managedRotationKey(pending)
	if err != nil || kid != rotation.NewKid || thumb != rotation.NewThumbprint || alg != rotation.NewAlgorithm {
		return dnsid.NewValidationError("dnsid: saved target key binding is unavailable or changed", err)
	}
	// Supersession may already have removed the previous key after a crash.
	old := previous.JWK(rotation.PreviousKid)
	if rotation.PreviousProviderRef != rotation.NewProviderRef {
		if active := previous.JWK(); active != nil {
			kid, thumb, alg, err := managedRotationKey(active)
			if err != nil || old == nil || kid != rotation.PreviousKid || thumb != rotation.PreviousThumbprint || alg != rotation.PreviousAlgorithm {
				return dnsid.NewValidationError("dnsid: saved previous provider has an unexpected active key", err)
			}
		}
	}
	if old != nil {
		kid, thumb, alg, err := managedRotationKey(old)
		if err != nil || kid != rotation.PreviousKid || thumb != rotation.PreviousThumbprint || alg != rotation.PreviousAlgorithm {
			return dnsid.NewValidationError("dnsid: saved previous key binding changed", err)
		}
	} else {
		if slices.Contains(previous.ListKeyIds(), rotation.PreviousKid) {
			return dnsid.NewValidationError("dnsid: saved previous key is listed but unavailable", nil)
		}
		if rotation.Submission == nil || rotation.Submission.State != dnsid.SubmissionStateAccepted {
			return dnsid.NewValidationError("dnsid: previous key unavailable before saved acceptance", nil)
		}
		activeKid, activeThumb, activeAlg, err := managedRotationKey(target.JWK())
		if err != nil || activeKid != rotation.NewKid || activeThumb != rotation.NewThumbprint || activeAlg != rotation.NewAlgorithm {
			return dnsid.NewValidationError("dnsid: previous key missing before target activation", err)
		}
	}
	return nil
}

func reconcileManagedRotation(previous, target dnsid.KeyProvider, rotation *ManagedKeyRotationState) error {
	if err := validateManagedProviderBindings(previous, target, rotation); err != nil {
		return err
	}
	if err := target.Activate(rotation.NewKid); err != nil {
		return err
	}
	activeKid, activeThumb, activeAlg, err := managedRotationKey(target.JWK())
	if err != nil || activeKid != rotation.NewKid || activeThumb != rotation.NewThumbprint || activeAlg != rotation.NewAlgorithm {
		return dnsid.NewValidationError("dnsid: activated signer does not match saved target binding", err)
	}
	if previous.JWK(rotation.PreviousKid) != nil {
		return previous.Supersede(rotation.PreviousKid)
	}
	return nil
}

func persistManagedRotation(ctx context.Context, store ManagedKeyRotationStore, rotation *ManagedKeyRotationState) error {
	if err := store.PersistManagedKeyRotation(ctx, cloneManagedRotation(rotation)); err != nil {
		return fmt.Errorf("dnsid: persisting managed key rotation: %w", err)
	}
	return nil
}

func cloneManagedRotation(rotation *ManagedKeyRotationState) *ManagedKeyRotationState {
	if rotation == nil {
		return nil
	}
	copy := *rotation
	copy.EntryBytes = append([]byte(nil), rotation.EntryBytes...)
	copy.Submission = cloneSubmission(rotation.Submission)
	return &copy
}

func cloneSubmission(result *dnsid.SubmissionResult) *dnsid.SubmissionResult {
	if result == nil {
		return nil
	}
	copy := *result
	if result.Index != nil {
		index := *result.Index
		copy.Index = &index
	}
	return &copy
}
