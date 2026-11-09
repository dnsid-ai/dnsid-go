//go:build dnsid_foundry

package foundry

import (
	"context"
	"testing"

	dnsid "github.com/dnsid-ai/dnsid-go"
)

func TestCreatePreservesFactsFromInvalidResponse(t *testing.T) {
	f := newFixture(t)
	f.registry.createResponseErr = dnsid.NewValidationError("invalid replay domain", nil)
	_, err := f.client.Create(context.Background(), "invalid-response")
	outcome := requireKind(t, err, Integrity)
	saved := f.document("invalid-response")
	if outcome.IdentityID != "agent-id" || saved.IdentityID != "agent-id" || saved.RequestID != f.registry.requestID || saved.Domain != "" {
		t.Fatalf("validation failure lost creation facts or accepted invalid domain: %+v", saved)
	}
}

func TestReadyWithoutSavedIssuanceWaitsForHistory(t *testing.T) {
	f := newFixture(t)
	f.registry.status = "READY"
	id, err := f.client.Create(context.Background(), "ready")
	if err != nil {
		t.Fatal(err)
	}
	_, err = id.Active(context.Background())
	outcome := requireKind(t, err, Unresolved)
	if !outcome.Resumable || f.registry.prepareCalls != 0 || len(f.registry.submissions) != 0 || f.log.historyCalls != 1 {
		t.Fatal("READY with lagging history prepared or submitted an ISSUANCE")
	}
}

func TestRefreshInterruptedInsideCompleteRestoresSigningOnReopen(t *testing.T) {
	f := newFixture(t)
	id, err := f.client.Create(context.Background(), "complete-refresh")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := id.Active(context.Background()); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	store := &interruptCompletionStore{FoundryStore: f.store, cancel: cancel}
	f.client.deps.Store = store
	_, err = id.Active(ctx)
	requireKind(t, err, Deadline)
	if !store.interrupted {
		t.Fatal("refresh did not reach CompleteManagedIssuance")
	}
	saved := f.document("complete-refresh")
	if saved.Phase != "complete" || saved.SigningPaused || !saved.Issuance.Operation.ActivationBlocked {
		t.Fatal("refresh discarded the previously completed signing state")
	}
	f.client.deps.Store = f.store
	before := f.publicCalls
	reopened, err := f.client.Create(context.Background(), "complete-refresh")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := reopened.Sign([]byte("data")); err != nil {
		t.Fatal(err)
	}
	if f.publicCalls != before || f.registry.prepareCalls != 1 || len(f.registry.submissions) != 1 {
		t.Fatal("reopen needed public verification or another ISSUANCE")
	}
}

type interruptCompletionStore struct {
	FoundryStore
	cancel      context.CancelFunc
	interrupted bool
}

func (s *interruptCompletionStore) Lock(ctx context.Context, key OperationKey) (FoundryLease, error) {
	lease, err := s.FoundryStore.Lock(ctx, key)
	if err != nil {
		return nil, err
	}
	return interruptCompletionLease{FoundryLease: lease, store: s}, nil
}

type interruptCompletionLease struct {
	FoundryLease
	store *interruptCompletionStore
}

func (l interruptCompletionLease) Save(ctx context.Context, doc *RecoveryDocument) error {
	if err := l.FoundryLease.Save(ctx, doc); err != nil {
		return err
	}
	if doc.Issuance != nil && doc.Issuance.Operation != nil && doc.Issuance.Operation.Complete && doc.Issuance.Operation.ActivationBlocked {
		l.store.interrupted = true
		l.store.cancel()
	}
	return nil
}

func TestRegistryTerminalPauseSurvivesRestartAndStaleActive(t *testing.T) {
	for _, status := range []string{"REVOKED", "RETIRED"} {
		t.Run(status, func(t *testing.T) {
			f := newFixture(t)
			id, err := f.client.Create(context.Background(), "terminal-registry")
			if err != nil {
				t.Fatal(err)
			}
			if _, err := id.Active(context.Background()); err != nil {
				t.Fatal(err)
			}
			f.registry.status = status
			_, err = id.Active(context.Background())
			requireKind(t, err, Terminal)
			saved := f.document("terminal-registry")
			if saved.RegistryStatus != status || !saved.SigningPaused {
				t.Fatal("terminal observation was not saved")
			}
			f.registry.status = "READY"
			_, err = f.client.Create(context.Background(), "terminal-registry")
			requireKind(t, err, Terminal)
			_, err = id.Active(context.Background())
			requireKind(t, err, Terminal)
			_, err = id.Sign([]byte("data"))
			requirePaused(t, err)
		})
	}
}
