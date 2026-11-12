//go:build dnsid_foundry

package foundry

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	dnsid "github.com/dnsid-ai/dnsid-go"
	"github.com/dnsid-ai/dnsid-go/config"
)

func TestCreateMissingFileKey(t *testing.T) {
	for _, location := range []string{"keyRef", "cliDirectory"} {
		t.Run(location, func(t *testing.T) {
			f := newFixture(t)
			loaded := f.client.loaded
			loaded.KeySource = config.KeySource{Provider: "file"}
			directory := t.TempDir()
			if location == "keyRef" {
				loaded.KeySource.KeyRef = filepath.Join(directory, "private.jwk")
			} else {
				loaded.KeySource.CliDirectory = directory
			}
			deps := f.client.deps
			deps.KeyProvider = nil
			client, err := New(loaded, deps)
			if err != nil {
				t.Fatal(err)
			}
			_, err = client.Create(context.Background(), "missing-file-key")
			requireKind(t, err, KeyMissing)
			if !errors.Is(err, os.ErrNotExist) || !strings.Contains(err.Error(), "create the signing key first") || f.registry.createCalls != 0 {
				t.Fatalf("missing file key lost its remedy or triggered registration: %v", err)
			}
		})
	}
}

func TestNewRejectsOrdinaryIdentity(t *testing.T) {
	f := newFixture(t)
	loaded := f.client.loaded
	loaded.Dnsid.Identity = &dnsid.IdentityConfig{Domain: testDomain, GovernanceID: "governance.example"}
	_, err := New(loaded, f.client.deps)
	var argument *dnsid.ArgumentError
	if !errors.As(err, &argument) {
		t.Fatalf("ordinary identity accepted: %v", err)
	}
	if f.registry.createCalls != 0 {
		t.Fatal("ordinary identity triggered registration")
	}
}

func TestActiveRejectsChangedOIDCIssuer(t *testing.T) {
	f := newFixture(t)
	f.registry.oidcIssuerURL = "https://issuer.example"
	id, err := f.client.Create(context.Background(), "issuer")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := id.Active(context.Background()); err != nil {
		t.Fatal(err)
	}
	if f.document("issuer").OIDCIssuerURL != f.registry.oidcIssuerURL {
		t.Fatal("initial issuer was not saved")
	}
	f.registry.oidcIssuerURL = "https://other-issuer.example"
	_, err = id.Active(context.Background())
	requireKind(t, err, Integrity)
	if !strings.Contains(err.Error(), "registry changed saved OIDC issuer") {
		t.Fatalf("issuer change was not detected: %v", err)
	}
	if saved := f.document("issuer"); saved.OIDCIssuerURL != "https://issuer.example" || !saved.SigningPaused {
		t.Fatal("issuer change replaced the saved binding or did not pause signing")
	}
}

func TestCreatePreservesFactsFromInvalidResponse(t *testing.T) {
	f := newFixture(t)
	f.registry.createResponseErr = dnsid.NewValidationError("invalid replay domain", nil)
	_, err := f.client.Create(context.Background(), "invalid-response")
	outcome := requireKind(t, err, Integrity)
	saved := f.document("invalid-response")
	if outcome.IdentityID != "agent-id" || saved.IdentityID != "agent-id" || saved.RegistrationKey != f.registry.requestID || saved.Domain != testDomain {
		t.Fatalf("validation failure lost known creation facts: %+v", saved)
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
