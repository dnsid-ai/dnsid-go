package c2sptlog

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"testing"
	"time"

	dnsid "github.com/dnsid-ai/dnsid-go"
	dnsidlog "github.com/dnsid-ai/dnsid-go/log"
	"github.com/lestrrat-go/jwx/v3/jwk"
)

type memoryManagedIssuanceStore struct {
	state     *ManagedIssuanceState
	persisted []*ManagedIssuanceState
	loadCalls int
}

func (s *memoryManagedIssuanceStore) CreateManagedIssuance(_ context.Context, initial *ManagedIssuanceState) (*ManagedIssuanceState, error) {
	if s.state != nil {
		return cloneManagedIssuance(s.state), nil
	}
	s.state = cloneManagedIssuance(initial)
	s.persisted = append(s.persisted, cloneManagedIssuance(initial))
	return nil, nil
}

func (s *memoryManagedIssuanceStore) LoadManagedIssuance(_ context.Context, _ string) (*ManagedIssuanceState, error) {
	s.loadCalls++
	return cloneManagedIssuance(s.state), nil
}

func (s *memoryManagedIssuanceStore) PersistManagedIssuance(_ context.Context, state *ManagedIssuanceState) error {
	s.state = cloneManagedIssuance(state)
	s.persisted = append(s.persisted, cloneManagedIssuance(state))
	return nil
}

type managedIssuanceRegistry struct {
	client          *Client
	entity          dnsid.KeyProvider
	operational     jwk.Key
	governanceID    string
	state           dnsid.SubmissionState
	prepareCalls    int
	submissions     [][]byte
	idempotencyKeys []string
	submitErr       error
	prepareErr      error
	persisted       func() bool
	blocked         func() bool
}

func (r *managedIssuanceRegistry) PrepareIssuance(ctx context.Context, domain, _ string) (*dnsid.PreparedRegistryEvent, error) {
	r.prepareCalls++
	if r.prepareErr != nil {
		return nil, r.prepareErr
	}
	prepared, err := r.client.PrepareEvent(dnsidlog.LogEvent{
		Type: dnsidlog.LogEventIssuance, Domain: domain, GovernanceID: r.governanceID,
		Timestamp: time.Unix(1782172800, 0).UTC(), InitialEntityPublicKey: r.entity.JWK(), InitialOperationalPublicKey: r.operational,
	})
	if err != nil {
		return nil, err
	}
	prepared, err = r.client.SignPreparedEvent(ctx, prepared, SignerEntity, r.entity)
	if err != nil {
		return nil, err
	}
	entry, err := prepared.Bytes()
	if err != nil {
		return nil, err
	}
	return &dnsid.PreparedRegistryEvent{EntryBytes: entry, LogReference: r.client.ref.String()}, nil
}

func (r *managedIssuanceRegistry) PrepareKeyRotation(context.Context, string, *dnsid.KeyRotationPreparationRequest, string) (*dnsid.PreparedRegistryEvent, error) {
	return nil, errors.New("unexpected PrepareKeyRotation")
}

func (r *managedIssuanceRegistry) SubmitPreparedEvent(_ context.Context, _ string, entry []byte, idempotencyKey string) (*dnsid.SubmissionResult, error) {
	if r.persisted != nil && !r.persisted() {
		return nil, errors.New("submission happened before exact bytes were persisted")
	}
	if r.blocked != nil && !r.blocked() {
		return nil, errors.New("submission happened before activation was blocked")
	}
	r.submissions = append(r.submissions, append([]byte(nil), entry...))
	r.idempotencyKeys = append(r.idempotencyKeys, idempotencyKey)
	if r.submitErr != nil {
		err := r.submitErr
		r.submitErr = nil
		return nil, err
	}
	result := &dnsid.SubmissionResult{State: r.state}
	if r.state == dnsid.SubmissionStateAccepted {
		sum := sha256.Sum256(entry)
		index := uint64(0)
		result.EntryHash = hex.EncodeToString(sum[:])
		result.Index = &index
		result.LogRef = string(r.client.ref.FinalEventRef(index))
		result.KeyID, _ = r.operational.KeyID()
	}
	return result, nil
}

func managedIssuanceFixture(t *testing.T) (*Client, dnsid.KeyProvider, dnsid.KeyProvider) {
	t.Helper()
	client, err := New("c2sp-tlog:testnet:https://log.example#issuance_AAAAAAAAAAAAAAAAAAAAAA")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	entity := dnsid.GenerateEd25519KeyProvider()
	operational := dnsid.GenerateEd25519KeyProvider()
	return client, entity, operational
}

func TestManagedIssuanceAcceptedRemainsBlockedUntilCompletion(t *testing.T) {
	client, entity, operational := managedIssuanceFixture(t)
	store := &memoryManagedIssuanceStore{}
	blocked := false
	registry := &managedIssuanceRegistry{client: client, entity: entity, operational: operational.JWK(), governanceID: "example.com", state: dnsid.SubmissionStateAccepted}
	registry.persisted = func() bool { return store.state != nil && len(store.state.EntryBytes) > 0 }
	registry.blocked = func() bool { return blocked }
	activation := ManagedIssuanceActivationControllerFunc(func(_ context.Context, value bool) error { blocked = value; return nil })
	issuance, err := BeginManagedIssuance(context.Background(), ManagedIssuanceOptions{
		Domain: "agent.example.com", GovernanceID: "example.com", Client: client, EntityPublicKey: entity.JWK(),
		KeyProvider: operational, RegistryClient: registry, IdempotencyKey: "issuance-1", Store: store, ActivationControl: activation,
	})
	if err != nil {
		t.Fatalf("BeginManagedIssuance: %v", err)
	}
	if issuance.Submission == nil || issuance.Submission.State != dnsid.SubmissionStateAccepted || !issuance.ActivationBlocked || issuance.Complete || !blocked {
		t.Fatalf("accepted issuance = %#v blocked=%v", issuance, blocked)
	}
	if len(registry.submissions) != 1 || !bytes.Equal(registry.submissions[0], issuance.EntryBytes) || registry.idempotencyKeys[0] != "issuance-1" {
		t.Fatalf("submission did not use exact persisted bytes and key")
	}
	issuance, err = CompleteManagedIssuance(context.Background(), "agent.example.com", store, activation)
	if err != nil || !issuance.Complete || issuance.ActivationBlocked || blocked {
		t.Fatalf("CompleteManagedIssuance = %#v, %v blocked=%v", issuance, err, blocked)
	}
}

func TestManagedIssuanceIndeterminateResumeReusesExactBytes(t *testing.T) {
	client, entity, operational := managedIssuanceFixture(t)
	store := &memoryManagedIssuanceStore{}
	registry := &managedIssuanceRegistry{
		client: client, entity: entity, operational: operational.JWK(), governanceID: "example.com", state: dnsid.SubmissionStateAccepted,
		submitErr: &dnsid.RegistryAPIError{StatusCode: 503, Code: "TLOG_SUBMISSION_INDETERMINATE", Message: "unknown append outcome"},
	}
	activation := ManagedIssuanceActivationControllerFunc(func(context.Context, bool) error { return nil })
	issuance, err := BeginManagedIssuance(context.Background(), ManagedIssuanceOptions{
		Domain: "agent.example.com", GovernanceID: "example.com", Client: client, EntityPublicKey: entity.JWK(),
		KeyProvider: operational, RegistryClient: registry, IdempotencyKey: "issuance-1", Store: store, ActivationControl: activation,
	})
	var submissionErr *ManagedIssuanceOperationError
	if !errors.As(err, &submissionErr) || submissionErr.State != dnsid.SubmissionStateIndeterminate || !submissionErr.Transient() || !submissionErr.RetrySameBytes {
		t.Fatalf("error = %#v, want transient indeterminate exact-byte retry", err)
	}
	if store.state.Submission == nil || store.state.Submission.State != dnsid.SubmissionStateIndeterminate {
		t.Fatalf("indeterminate state was not persisted: %#v", store.state)
	}
	first := append([]byte(nil), issuance.EntryBytes...)
	issuance, err = ResumeManagedIssuance(context.Background(), ResumeManagedIssuanceOptions{
		Domain: "agent.example.com", Client: client, EntityPublicKey: entity.JWK(), KeyProvider: operational,
		RegistryClient: registry, Store: store, ActivationControl: activation,
	})
	if err != nil || issuance.Submission == nil || issuance.Submission.State != dnsid.SubmissionStateAccepted {
		t.Fatalf("ResumeManagedIssuance = %#v, %v", issuance, err)
	}
	if registry.prepareCalls != 1 || len(registry.submissions) != 2 || !bytes.Equal(first, registry.submissions[1]) || registry.idempotencyKeys[1] != "issuance-1" {
		t.Fatalf("resume regenerated preparation or changed exact submission")
	}
}

func TestManagedIssuanceAcceptedResumeDoesNotRequireRetiredOperationalKey(t *testing.T) {
	client, entity, operational := managedIssuanceFixture(t)
	store := &memoryManagedIssuanceStore{}
	blocked := false
	registry := &managedIssuanceRegistry{
		client: client, entity: entity, operational: operational.JWK(), governanceID: "example.com", state: dnsid.SubmissionStateAccepted,
	}
	activation := ManagedIssuanceActivationControllerFunc(func(_ context.Context, value bool) error { blocked = value; return nil })
	issuance, err := BeginManagedIssuance(context.Background(), ManagedIssuanceOptions{
		Domain: "agent.example.com", GovernanceID: "example.com", Client: client, EntityPublicKey: entity.JWK(),
		KeyProvider: operational, RegistryClient: registry, IdempotencyKey: "issuance-1", Store: store, ActivationControl: activation,
	})
	if err != nil || issuance.Submission == nil || issuance.Submission.State != dnsid.SubmissionStateAccepted || !blocked {
		t.Fatalf("BeginManagedIssuance = %#v, %v blocked=%v", issuance, err, blocked)
	}

	rotated := dnsid.GenerateEd25519KeyProvider()
	issuance, err = ResumeManagedIssuance(context.Background(), ResumeManagedIssuanceOptions{
		Domain: "agent.example.com", Client: client, EntityPublicKey: entity.JWK(), KeyProvider: rotated,
		RegistryClient: registry, Store: store, ActivationControl: activation,
	})
	if err != nil || issuance.Submission == nil || issuance.Submission.State != dnsid.SubmissionStateAccepted || !blocked {
		t.Fatalf("ResumeManagedIssuance after key retirement = %#v, %v blocked=%v", issuance, err, blocked)
	}
	if len(registry.submissions) != 1 {
		t.Fatalf("accepted issuance was unexpectedly resubmitted %d times", len(registry.submissions))
	}
}

func TestManagedIssuanceExistingStateBlocksFreshPreparation(t *testing.T) {
	client, entity, operational := managedIssuanceFixture(t)
	store := &memoryManagedIssuanceStore{state: &ManagedIssuanceState{Domain: "agent.example.com"}}
	registry := &managedIssuanceRegistry{client: client, entity: entity, operational: operational.JWK(), governanceID: "example.com"}
	_, err := BeginManagedIssuance(context.Background(), ManagedIssuanceOptions{
		Domain: "agent.example.com", GovernanceID: "example.com", Client: client, EntityPublicKey: entity.JWK(),
		KeyProvider: operational, RegistryClient: registry, IdempotencyKey: "issuance-2", Store: store,
		ActivationControl: ManagedIssuanceActivationControllerFunc(func(context.Context, bool) error { return nil }),
	})
	var inProgress *ManagedIssuanceInProgressError
	if !errors.As(err, &inProgress) || registry.prepareCalls != 0 {
		t.Fatalf("error/prepareCalls = %v/%d", err, registry.prepareCalls)
	}
}

func TestManagedIssuanceTerminalPreparationFailureIsDurable(t *testing.T) {
	client, entity, operational := managedIssuanceFixture(t)
	store := &memoryManagedIssuanceStore{}
	registry := &managedIssuanceRegistry{
		client: client, entity: entity, operational: operational.JWK(), governanceID: "example.com",
		prepareErr: &dnsid.RegistryAPIError{StatusCode: 409, Code: "TLOG_IDEMPOTENCY_MISMATCH", Message: "different intent"},
	}
	activation := ManagedIssuanceActivationControllerFunc(func(context.Context, bool) error { return nil })
	issuance, err := BeginManagedIssuance(context.Background(), ManagedIssuanceOptions{
		Domain: "agent.example.com", GovernanceID: "example.com", Client: client, EntityPublicKey: entity.JWK(),
		KeyProvider: operational, RegistryClient: registry, IdempotencyKey: "issuance-1", Store: store, ActivationControl: activation,
	})
	var operationErr *ManagedIssuanceOperationError
	if !errors.As(err, &operationErr) || operationErr.Transient() || !issuance.TerminalFailure || issuance.LastErrorCode != "TLOG_IDEMPOTENCY_MISMATCH" {
		t.Fatalf("terminal preparation = %#v, %#v", issuance, err)
	}
	registry.prepareErr = nil
	_, err = ResumeManagedIssuance(context.Background(), ResumeManagedIssuanceOptions{
		Domain: "agent.example.com", Client: client, EntityPublicKey: entity.JWK(), KeyProvider: operational,
		RegistryClient: registry, Store: store, ActivationControl: activation,
	})
	if !errors.As(err, &operationErr) || registry.prepareCalls != 1 {
		t.Fatalf("terminal resume error/prepareCalls = %v/%d", err, registry.prepareCalls)
	}
}

func TestCompleteManagedIssuanceLoadsAndRejectsTamperedDurableState(t *testing.T) {
	client, entity, operational := managedIssuanceFixture(t)
	store := &memoryManagedIssuanceStore{}
	blocked := false
	registry := &managedIssuanceRegistry{client: client, entity: entity, operational: operational.JWK(), governanceID: "example.com", state: dnsid.SubmissionStateAccepted}
	activation := ManagedIssuanceActivationControllerFunc(func(_ context.Context, value bool) error { blocked = value; return nil })
	_, err := BeginManagedIssuance(context.Background(), ManagedIssuanceOptions{
		Domain: "agent.example.com", GovernanceID: "example.com", Client: client, EntityPublicKey: entity.JWK(),
		KeyProvider: operational, RegistryClient: registry, IdempotencyKey: "issuance-1", Store: store, ActivationControl: activation,
	})
	if err != nil {
		t.Fatalf("BeginManagedIssuance: %v", err)
	}
	store.state.EntryBytes[0] ^= 1
	_, err = CompleteManagedIssuance(context.Background(), "agent.example.com", store, activation)
	if err == nil || !blocked {
		t.Fatalf("tampered durable completion error/blocked = %v/%v", err, blocked)
	}
}

func TestPublicC2spDataErrorsUseSharedTaxonomy(t *testing.T) {
	_, err := LogEventFromEntry([]byte("not-json"))
	var parseErr *dnsid.ParseError
	if !errors.As(err, &parseErr) {
		t.Fatalf("LogEventFromEntry error = %T, want *dnsid.ParseError", err)
	}
	_, err = ParsePolicy([]byte("unknown directive"))
	if !errors.As(err, &parseErr) {
		t.Fatalf("ParsePolicy error = %T, want *dnsid.ParseError", err)
	}
}
