package foundry

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	dnsid "github.com/dnsid-ai/dnsid-go"
	"github.com/dnsid-ai/dnsid-go/config"
)

type failingStore struct {
	FoundryStore
	remaining int
	failed    bool
}

func (s *failingStore) Lock(ctx context.Context, key OperationKey) (FoundryLease, error) {
	lease, err := s.FoundryStore.Lock(ctx, key)
	if err != nil {
		return nil, err
	}
	return &failingLease{FoundryLease: lease, store: s}, nil
}

type failingLease struct {
	FoundryLease
	store *failingStore
}

func (l *failingLease) Save(ctx context.Context, doc *RecoveryDocument) error {
	if !l.store.failed {
		l.store.remaining--
		if l.store.remaining == 0 {
			l.store.failed = true
			return errors.New("injected durable write failure")
		}
	}
	return l.FoundryLease.Save(ctx, doc)
}

func TestRecoveryAfterEachDurableWrite(t *testing.T) {
	for boundary := 1; boundary <= 15; boundary++ {
		t.Run(strings.Repeat("x", boundary), func(t *testing.T) {
			f := newFixture(t)
			f.registry.challenge = true
			faults := &failingStore{FoundryStore: f.store, remaining: boundary}
			f.client.deps.Store = faults
			id, err := f.client.Create(context.Background(), "recover")
			if err == nil {
				_, err = id.Active(context.Background())
			}
			if err != nil && !faults.failed {
				t.Fatalf("unexpected failure: %v", err)
			}
			f.client.deps.Store = f.store
			reopened, err := f.client.Create(context.Background(), "recover")
			if err != nil {
				t.Fatal(err)
			}
			if _, err := reopened.Active(context.Background()); err != nil {
				t.Fatal(err)
			}
			if f.document("recover").Phase != "complete" {
				t.Fatal("recovery did not complete")
			}
			if f.registry.createCalls > 2 || len(f.registry.submissions) > 2 {
				t.Fatal("recovery recreated identity or duplicated accepted issuance")
			}
			if len(f.registry.submissions) == 2 && !bytes.Equal(f.registry.submissions[0], f.registry.submissions[1]) {
				t.Fatal("recovery changed submitted bytes")
			}
		})
	}
}

type corruptingProvider struct {
	dnsid.KeyProvider
	corrupt bool
}

func (p *corruptingProvider) SignKey(kid string, data []byte) (*dnsid.KeySignature, error) {
	result, err := p.KeyProvider.SignKey(kid, data)
	if err == nil && p.corrupt {
		result.Signature[0] ^= 1
	}
	return result, err
}
func (p *corruptingProvider) Sign(data []byte) (*dnsid.KeySignature, error) {
	result, err := p.KeyProvider.Sign(data)
	if err == nil && p.corrupt {
		result.Signature[0] ^= 1
	}
	return result, err
}

func TestInvalidCountersignatureDoesNotPoisonIssuance(t *testing.T) {
	f := newFixture(t)
	provider := &corruptingProvider{KeyProvider: f.operational, corrupt: true}
	f.client.deps.KeyProvider = provider
	id, err := f.client.Create(context.Background(), "signature")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := id.Active(context.Background()); err == nil {
		t.Fatal("invalid countersignature accepted")
	}
	if len(f.registry.submissions) != 0 {
		t.Fatal("invalid countersignature sent to registry")
	}
	provider.corrupt = false
	if _, err := id.Active(context.Background()); err != nil {
		t.Fatal(err)
	}
	if f.registry.prepareCalls != 1 || len(f.registry.submissions) != 1 {
		t.Fatal("prepared bytes or issuance key poisoned")
	}
}

func TestCompletedResumeUsesSavedCurrentKeyWithoutInitialPrivateKey(t *testing.T) {
	f := newFixture(t)
	id, err := f.client.Create(context.Background(), "rotated")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := id.Active(context.Background()); err != nil {
		t.Fatal(err)
	}
	successor := dnsid.GenerateES256KeyProvider()
	lease, err := f.store.Lock(context.Background(), id.key)
	if err != nil {
		t.Fatal(err)
	}
	doc, err := lease.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	// This fixture represents the saved result of an authorized external rotation;
	// rotation orchestration itself is outside Foundry create's scope.
	doc.CurrentPublicKey, err = json.Marshal(successor.JWK())
	if err != nil {
		t.Fatal(err)
	}
	if err := lease.Save(context.Background(), doc); err != nil {
		t.Fatal(err)
	}
	if err := lease.Close(); err != nil {
		t.Fatal(err)
	}
	before := f.publicCalls
	client := f.newClient(successor, f.store)
	reopened, err := client.Create(context.Background(), "rotated")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := reopened.Sign([]byte("data")); err != nil {
		t.Fatal(err)
	}
	if f.publicCalls != before || len(f.registry.submissions) != 1 {
		t.Fatal("completed resume required public evidence or reissuance")
	}
	_, err = f.client.Create(context.Background(), "rotated")
	requireKind(t, err, KeyMismatch)
}

func TestActiveAuthorizesCurrentProviderThroughFreshContinuity(t *testing.T) {
	f := newFixture(t)
	id, err := f.client.Create(context.Background(), "successor")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := id.Active(context.Background()); err != nil {
		t.Fatal(err)
	}
	kid, err := f.operational.GenerateKey(dnsid.JoseAlgES256)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.operational.Activate(kid); err != nil {
		t.Fatal(err)
	}
	f.publish(f.operational, "governance.example", testLR, dnsid.AgentStateActive)
	f.log.currentThumb, err = keyThumb(f.operational.JWK())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := id.Active(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(f.document("successor").CurrentPublicKey) == 0 {
		t.Fatal("verified current binding was not saved")
	}
	reopened, err := f.client.Create(context.Background(), "successor")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := reopened.Sign([]byte("data")); err != nil {
		t.Fatal(err)
	}
	if f.registry.prepareCalls != 1 || len(f.registry.submissions) != 1 {
		t.Fatal("current binding refresh reissued the identity")
	}
}

func TestCompletedResumeRestoresSavedCurrentProviderReference(t *testing.T) {
	f := newFixture(t)
	directory := t.TempDir()
	initialPath := filepath.Join(directory, "initial.jwk")
	initial, err := dnsid.LoadOrCreateLocalKeyProvider(initialPath, dnsid.JoseAlgEdDSA)
	if err != nil {
		t.Fatal(err)
	}
	f.operational = initial
	f.publish(initial, "governance.example", testLR, dnsid.AgentStateActive)
	deps := f.client.deps
	deps.KeyProvider = nil
	f.client, err = New(config.Loaded{Registry: f.client.loaded.Registry, KeySource: config.KeySource{Provider: "file", KeyRef: initialPath}}, deps)
	if err != nil {
		t.Fatal(err)
	}
	id, err := f.client.Create(context.Background(), "provider-recovery")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := id.Active(context.Background()); err != nil {
		t.Fatal(err)
	}
	currentPath := filepath.Join(directory, "current.jwk")
	current, err := dnsid.LoadOrCreateLocalKeyProvider(currentPath, dnsid.JoseAlgEdDSA)
	if err != nil {
		t.Fatal(err)
	}
	lease, err := f.store.Lock(context.Background(), id.key)
	if err != nil {
		t.Fatal(err)
	}
	doc, err := lease.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	doc.CurrentKeySource = &config.KeySource{Provider: "file", KeyRef: currentPath}
	doc.CurrentPublicKey, err = json.Marshal(current.JWK())
	if err != nil {
		t.Fatal(err)
	}
	if err := lease.Save(context.Background(), doc); err != nil {
		t.Fatal(err)
	}
	if err := lease.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(initialPath); err != nil {
		t.Fatal(err)
	}
	calls := f.publicCalls
	reopened, err := f.client.Create(context.Background(), "provider-recovery")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := reopened.Sign([]byte("data")); err != nil {
		t.Fatal(err)
	}
	if f.publicCalls != calls || f.registry.prepareCalls != 1 {
		t.Fatal("provider recovery fetched public evidence or reissued")
	}
}

type slowSigningProvider struct {
	dnsid.KeyProvider
	delay time.Duration
}

func (p slowSigningProvider) SignKey(kid string, data []byte) (*dnsid.KeySignature, error) {
	time.Sleep(p.delay)
	return p.KeyProvider.SignKey(kid, data)
}
func (p slowSigningProvider) Sign(data []byte) (*dnsid.KeySignature, error) {
	time.Sleep(p.delay)
	return p.KeyProvider.Sign(data)
}

func TestProviderDeadlineCheckedAfterNonCancellableSigning(t *testing.T) {
	f := newFixture(t)
	f.client.deps.KeyProvider = slowSigningProvider{KeyProvider: f.operational, delay: 40 * time.Millisecond}
	id, err := f.client.Create(context.Background(), "deadline")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	_, err = id.Active(ctx)
	requireKind(t, err, Deadline)
	if len(f.registry.submissions) != 0 {
		t.Fatal("submitted after provider exceeded deadline")
	}
}

func TestRefreshBindingMismatchDurablyPausesSigning(t *testing.T) {
	f := newFixture(t)
	id, err := f.client.Create(context.Background(), "mismatch")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := id.Active(context.Background()); err != nil {
		t.Fatal(err)
	}
	f.publish(dnsid.GenerateEd25519KeyProvider(), "governance.example", testLR, dnsid.AgentStateActive)
	if _, err := id.Active(context.Background()); err == nil {
		t.Fatal("mismatched public key accepted")
	}
	if !f.document("mismatch").SigningPaused {
		t.Fatal("pause was not durable")
	}
	reopened, err := f.client.Create(context.Background(), "mismatch")
	if err != nil {
		t.Fatal(err)
	}
	_, err = reopened.Sign([]byte("data"))
	requirePaused(t, err)
}
