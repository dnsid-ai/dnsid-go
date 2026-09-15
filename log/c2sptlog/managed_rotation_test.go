package c2sptlog

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"testing"
	"time"

	dnsid "github.com/dnsid-ai/dnsid-go"
	dnsidlog "github.com/dnsid-ai/dnsid-go/log"
	"github.com/lestrrat-go/jwx/v3/jwk"
)

type managedRotationRegistry struct {
	client                    *Client
	state                     dnsid.SubmissionState
	prepareCalls              int
	submissions               [][]byte
	idempotencyKeys           []string
	newKid                    string
	persistedBeforeSubmission func() bool
	applicationPaused         func() bool
	badFinalReference         bool
	submitErr                 error
}

func (r *managedRotationRegistry) PrepareIssuance(context.Context, string, string) (*dnsid.PreparedRegistryEvent, error) {
	return nil, errors.New("unexpected PrepareIssuance")
}

func (r *managedRotationRegistry) PrepareKeyRotation(ctx context.Context, domain string, req *dnsid.KeyRotationPreparationRequest, _ string) (*dnsid.PreparedRegistryEvent, error) {
	r.prepareCalls++
	newKey, ok := req.PublicKey.(jwk.Key)
	if !ok {
		return nil, fmt.Errorf("unexpected public key %T", req.PublicKey)
	}
	r.newKid, _ = newKey.KeyID()
	newThumb, err := thumbprint(newKey)
	if err != nil {
		return nil, err
	}
	event := dnsidlog.LogEvent{
		Type:                          dnsidlog.LogEventKeyRotation,
		Domain:                        domain,
		Timestamp:                     time.Unix(1782259200, 0).UTC(),
		PreviousOperationalThumbprint: req.PreviousKeyID,
		NewOperationalPublicKey:       newKey,
		NewOperationalThumbprint:      newThumb,
	}
	chain, err := r.client.ChainForWrite(ctx, event)
	if err != nil {
		return nil, err
	}
	prepared, err := r.client.PrepareEventWithChain(event, chain)
	if err != nil {
		return nil, err
	}
	entry, err := prepared.Bytes()
	if err != nil {
		return nil, err
	}
	return &dnsid.PreparedRegistryEvent{EntryBytes: entry, LogReference: r.client.ref.String()}, nil
}

func (r *managedRotationRegistry) SubmitPreparedEvent(_ context.Context, _ string, entry []byte, idempotencyKey string) (*dnsid.SubmissionResult, error) {
	if r.persistedBeforeSubmission != nil && !r.persistedBeforeSubmission() {
		return nil, errors.New("submission happened before persistence")
	}
	if r.applicationPaused != nil && !r.applicationPaused() {
		return nil, errors.New("submission happened before application signing was paused")
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
		index := uint64(1)
		result.EntryHash = hex.EncodeToString(sum[:])
		result.Index = &index
		result.KeyID = r.newKid
		result.LogRef = string(r.client.ref.FinalEventRef(index))
		if r.badFinalReference {
			result.LogRef = string(r.client.ref.FinalEventRef(2))
		}
	}
	return result, nil
}

func managedRotationFixture(t *testing.T) (*Client, dnsid.KeyProvider) {
	t.Helper()
	lr := "c2sp-tlog:testnet:https://log.example#instance_AAAAAAAAAAAAAAAAAAAAAA"
	writer, err := New(lr)
	if err != nil {
		t.Fatalf("New writer: %v", err)
	}
	entity := dnsid.GenerateEd25519KeyProvider()
	operational := dnsid.GenerateEd25519KeyProvider()
	issuance, err := writer.PrepareEvent(dnsidlog.LogEvent{
		Type:                        dnsidlog.LogEventIssuance,
		Domain:                      "agent.example.com",
		GovernanceID:                "example.com",
		Timestamp:                   time.Unix(1782172800, 0).UTC(),
		InitialEntityPublicKey:      entity.JWK(),
		InitialOperationalPublicKey: operational.JWK(),
	})
	if err != nil {
		t.Fatalf("PrepareEvent issuance: %v", err)
	}
	issuance, err = writer.SignPreparedEvent(context.Background(), issuance, SignerEntity, entity)
	if err != nil {
		t.Fatalf("sign entity: %v", err)
	}
	issuance, err = writer.SignPreparedEvent(context.Background(), issuance, SignerOperationalCountersignature, operational)
	if err != nil {
		t.Fatalf("sign operational: %v", err)
	}
	entry, err := writer.PreparedEntryBytes(context.Background(), issuance)
	if err != nil {
		t.Fatalf("issuance bytes: %v", err)
	}
	client, err := New(lr,
		WithSource(memorySource{complete: true, entries: []ProvenEntry{{Index: 0, Entry: entry}}}),
		WithPolicy(Policy{Now: func() time.Time { return time.Unix(1782259201, 0).UTC() }}),
		withProofVerifySkipped(),
	)
	if err != nil {
		t.Fatalf("New client: %v", err)
	}
	return client, operational
}

func TestManagedOperationalKeyRotationAccepted(t *testing.T) {
	client, provider := managedRotationFixture(t)
	var persisted []*ManagedKeyRotationState
	var pauses []bool
	signingPaused := false
	registry := &managedRotationRegistry{client: client, state: dnsid.SubmissionStateAccepted}
	registry.persistedBeforeSubmission = func() bool { return len(persisted) > 0 }
	registry.applicationPaused = func() bool { return signingPaused }
	rotation, err := RotateManagedOperationalKey(context.Background(), ManagedKeyRotationOptions{
		Domain:         "agent.example.com",
		Client:         client,
		KeyProvider:    provider,
		RegistryClient: registry,
		IdempotencyKey: "rotation-1",
		Store: ManagedKeyRotationStoreFunc(func(_ context.Context, state *ManagedKeyRotationState) error {
			persisted = append(persisted, cloneManagedRotation(state))
			return nil
		}),
		ApplicationSigning: ApplicationSigningControllerFunc(func(_ context.Context, requested bool) error {
			pauses = append(pauses, requested)
			// Record the externally enforced state, not merely the requested sequence.
			signingPaused = requested
			return nil
		}),
	})
	if err != nil {
		t.Fatalf("RotateManagedOperationalKey: %v", err)
	}
	if !rotation.Activated || rotation.ApplicationSigningPaused || len(pauses) != 2 || !pauses[0] || pauses[1] {
		t.Fatalf("rotation/pauses = %#v/%v", rotation, pauses)
	}
	activeKid, _ := provider.JWK().KeyID()
	if activeKid != rotation.NewKid || containsString(provider.ListKeyIds(), rotation.PreviousKid) {
		t.Fatalf("provider state active=%q keys=%v rotation=%#v", activeKid, provider.ListKeyIds(), rotation)
	}
	if len(registry.submissions) != 1 || !bytes.Equal(registry.submissions[0], rotation.EntryBytes) || registry.idempotencyKeys[0] != "rotation-1" {
		t.Fatalf("submission did not use exact persisted bytes and key")
	}
	event, err := LogEventFromEntry(rotation.EntryBytes)
	if err != nil || event.PreviousOperationalSignature == "" || event.NewOperationalSignature == "" {
		t.Fatalf("completed KEY_ROTATION signatures: event=%#v err=%v", event, err)
	}
	if len(persisted) != 4 || persisted[0].Submission != nil || persisted[1].Submission.State != dnsid.SubmissionStateAccepted || !persisted[2].Activated || !persisted[2].ApplicationSigningPaused || persisted[3].ApplicationSigningPaused {
		t.Fatalf("persisted states = %#v", persisted)
	}
}

func TestManagedOperationalKeyRotationPendingResumeReusesExactBytes(t *testing.T) {
	client, provider := managedRotationFixture(t)
	registry := &managedRotationRegistry{client: client, state: dnsid.SubmissionStatePending}
	persist := func(_ context.Context, _ *ManagedKeyRotationState) error { return nil }
	pause := func(_ context.Context, _ bool) error { return nil }
	rotation, err := RotateManagedOperationalKey(context.Background(), ManagedKeyRotationOptions{
		Domain: "agent.example.com", Client: client, KeyProvider: provider, RegistryClient: registry, IdempotencyKey: "rotation-1", Store: ManagedKeyRotationStoreFunc(persist), ApplicationSigning: ApplicationSigningControllerFunc(pause),
	})
	if err != nil {
		t.Fatalf("RotateManagedOperationalKey: %v", err)
	}
	if rotation.Activated || !rotation.ApplicationSigningPaused {
		t.Fatalf("pending rotation = %#v", rotation)
	}
	first := append([]byte(nil), rotation.EntryBytes...)
	registry.state = dnsid.SubmissionStateAccepted
	rotation, err = ResumeManagedOperationalKeyRotation(context.Background(), ResumeManagedKeyRotationOptions{
		KeyProvider: provider, RegistryClient: registry, Rotation: rotation, Store: ManagedKeyRotationStoreFunc(persist), ApplicationSigning: ApplicationSigningControllerFunc(pause),
	})
	if err != nil {
		t.Fatalf("ResumeManagedOperationalKeyRotation: %v", err)
	}
	if !rotation.Activated || len(registry.submissions) != 2 || !bytes.Equal(first, registry.submissions[1]) || registry.idempotencyKeys[1] != "rotation-1" {
		t.Fatalf("resumed rotation/submissions = %#v/%d", rotation, len(registry.submissions))
	}
}

func TestManagedOperationalKeyRotationIndeterminateResumeReusesExactBytes(t *testing.T) {
	client, provider := managedRotationFixture(t)
	registry := &managedRotationRegistry{client: client, state: dnsid.SubmissionStateIndeterminate}
	persist := func(context.Context, *ManagedKeyRotationState) error { return nil }
	pause := func(context.Context, bool) error { return nil }
	rotation, err := RotateManagedOperationalKey(context.Background(), ManagedKeyRotationOptions{
		Domain: "agent.example.com", Client: client, KeyProvider: provider, RegistryClient: registry, IdempotencyKey: "rotation-1", Store: ManagedKeyRotationStoreFunc(persist), ApplicationSigning: ApplicationSigningControllerFunc(pause),
	})
	if err != nil {
		t.Fatalf("RotateManagedOperationalKey: %v", err)
	}
	first := append([]byte(nil), rotation.EntryBytes...)
	registry.state = dnsid.SubmissionStateAccepted
	rotation, err = ResumeManagedOperationalKeyRotation(context.Background(), ResumeManagedKeyRotationOptions{
		KeyProvider: provider, RegistryClient: registry, Rotation: rotation, Store: ManagedKeyRotationStoreFunc(persist), ApplicationSigning: ApplicationSigningControllerFunc(pause),
	})
	if err != nil {
		t.Fatalf("ResumeManagedOperationalKeyRotation: %v", err)
	}
	if !rotation.Activated || !bytes.Equal(first, registry.submissions[1]) || registry.idempotencyKeys[1] != "rotation-1" {
		t.Fatalf("indeterminate resume did not reuse exact bytes: %#v", rotation)
	}
}

func TestManagedOperationalKeyRotationTransportFailurePersistsIndeterminateState(t *testing.T) {
	client, provider := managedRotationFixture(t)
	var persisted []*ManagedKeyRotationState
	registry := &managedRotationRegistry{client: client, state: dnsid.SubmissionStateAccepted, submitErr: errors.New("connection reset")}
	persist := func(_ context.Context, state *ManagedKeyRotationState) error {
		persisted = append(persisted, cloneManagedRotation(state))
		return nil
	}
	rotation, err := RotateManagedOperationalKey(context.Background(), ManagedKeyRotationOptions{
		Domain: "agent.example.com", Client: client, KeyProvider: provider, RegistryClient: registry, IdempotencyKey: "rotation-1",
		Store: ManagedKeyRotationStoreFunc(persist), ApplicationSigning: ApplicationSigningControllerFunc(func(context.Context, bool) error { return nil }),
	})
	var submissionErr *ManagedKeyRotationSubmissionError
	if !errors.As(err, &submissionErr) || submissionErr.State != dnsid.SubmissionStateIndeterminate || !submissionErr.Transient() || !submissionErr.RetrySameBytes {
		t.Fatalf("error = %#v, want transient indeterminate exact-byte retry", err)
	}
	if rotation.Submission == nil || rotation.Submission.State != dnsid.SubmissionStateIndeterminate || persisted[len(persisted)-1].Submission.State != dnsid.SubmissionStateIndeterminate {
		t.Fatalf("indeterminate state not persisted: rotation=%#v persisted=%#v", rotation, persisted)
	}
	first := append([]byte(nil), rotation.EntryBytes...)
	rotation, err = ResumeManagedOperationalKeyRotation(context.Background(), ResumeManagedKeyRotationOptions{
		KeyProvider: provider, RegistryClient: registry, Rotation: rotation, Store: ManagedKeyRotationStoreFunc(persist),
		ApplicationSigning: ApplicationSigningControllerFunc(func(context.Context, bool) error { return nil }),
	})
	if err != nil || !rotation.Activated || len(registry.submissions) != 2 || !bytes.Equal(first, registry.submissions[1]) {
		t.Fatalf("resume = %#v, %v submissions=%d", rotation, err, len(registry.submissions))
	}
}

func TestManagedOperationalKeyRotationResumesAfterActivationPersistenceFailure(t *testing.T) {
	client, provider := managedRotationFixture(t)
	registry := &managedRotationRegistry{client: client, state: dnsid.SubmissionStateAccepted}
	failActivatedPersist := true
	persist := func(_ context.Context, state *ManagedKeyRotationState) error {
		if state.Activated && failActivatedPersist {
			return errors.New("store unavailable")
		}
		return nil
	}
	pause := func(context.Context, bool) error { return nil }
	rotation, err := RotateManagedOperationalKey(context.Background(), ManagedKeyRotationOptions{
		Domain: "agent.example.com", Client: client, KeyProvider: provider, RegistryClient: registry, IdempotencyKey: "rotation-1", Store: ManagedKeyRotationStoreFunc(persist), ApplicationSigning: ApplicationSigningControllerFunc(pause),
	})
	var activationErr *ManagedKeyRotationActivationError
	if !errors.As(err, &activationErr) || rotation.Activated || rotation.Submission == nil || rotation.Submission.State != dnsid.SubmissionStateAccepted {
		t.Fatalf("rotation/error = %#v/%v, want recoverable accepted state", rotation, err)
	}
	failActivatedPersist = false
	rotation, err = ResumeManagedOperationalKeyRotation(context.Background(), ResumeManagedKeyRotationOptions{
		KeyProvider: provider, RegistryClient: registry, Rotation: rotation, Store: ManagedKeyRotationStoreFunc(persist), ApplicationSigning: ApplicationSigningControllerFunc(pause),
	})
	if err != nil || !rotation.Activated || rotation.ApplicationSigningPaused {
		t.Fatalf("resumed rotation/error = %#v/%v", rotation, err)
	}
	if len(registry.submissions) != 2 || !bytes.Equal(registry.submissions[0], registry.submissions[1]) {
		t.Fatalf("recovery did not replay exact bytes")
	}
}

func TestManagedOperationalKeyRotationRejectsAcceptedReferenceMismatch(t *testing.T) {
	client, provider := managedRotationFixture(t)
	registry := &managedRotationRegistry{client: client, state: dnsid.SubmissionStateAccepted, badFinalReference: true}
	_, err := RotateManagedOperationalKey(context.Background(), ManagedKeyRotationOptions{
		Domain: "agent.example.com", Client: client, KeyProvider: provider, RegistryClient: registry, IdempotencyKey: "rotation-1",
		Store:              ManagedKeyRotationStoreFunc(func(context.Context, *ManagedKeyRotationState) error { return nil }),
		ApplicationSigning: ApplicationSigningControllerFunc(func(context.Context, bool) error { return nil }),
	})
	var submissionErr *ManagedKeyRotationSubmissionError
	if !errors.As(err, &submissionErr) || submissionErr.RetrySameBytes {
		t.Fatalf("error = %v, want terminal submission validation", err)
	}
	activeKid, _ := provider.JWK().KeyID()
	if activeKid != submissionErr.Rotation.PreviousKid {
		t.Fatalf("active kid = %q, want previous %q", activeKid, submissionErr.Rotation.PreviousKid)
	}
}

func TestManagedOperationalKeyRotationRejectsTamperedPersistedBytes(t *testing.T) {
	client, provider := managedRotationFixture(t)
	registry := &managedRotationRegistry{client: client, state: dnsid.SubmissionStatePending}
	persist := func(context.Context, *ManagedKeyRotationState) error { return nil }
	pause := func(context.Context, bool) error { return nil }
	rotation, err := RotateManagedOperationalKey(context.Background(), ManagedKeyRotationOptions{
		Domain: "agent.example.com", Client: client, KeyProvider: provider, RegistryClient: registry, IdempotencyKey: "rotation-1", Store: ManagedKeyRotationStoreFunc(persist), ApplicationSigning: ApplicationSigningControllerFunc(pause),
	})
	if err != nil {
		t.Fatalf("RotateManagedOperationalKey: %v", err)
	}
	rotation.EntryBytes[0] ^= 1
	_, err = ResumeManagedOperationalKeyRotation(context.Background(), ResumeManagedKeyRotationOptions{
		KeyProvider: provider, RegistryClient: registry, Rotation: rotation, Store: ManagedKeyRotationStoreFunc(persist), ApplicationSigning: ApplicationSigningControllerFunc(pause),
	})
	if err == nil || len(registry.submissions) != 1 {
		t.Fatalf("tampered state error/submissions = %v/%d", err, len(registry.submissions))
	}
}

func TestManagedOperationalKeyRotationRequiresDurabilityHooks(t *testing.T) {
	client, provider := managedRotationFixture(t)
	registry := &managedRotationRegistry{client: client, state: dnsid.SubmissionStateAccepted}
	_, err := RotateManagedOperationalKey(context.Background(), ManagedKeyRotationOptions{
		Domain: "agent.example.com", Client: client, KeyProvider: provider, RegistryClient: registry, IdempotencyKey: "rotation-1",
	})
	if err == nil || registry.prepareCalls != 0 || len(registry.submissions) != 0 {
		t.Fatalf("missing hooks error/calls = %v/%d/%d", err, registry.prepareCalls, len(registry.submissions))
	}
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
