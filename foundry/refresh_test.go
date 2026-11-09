//go:build dnsid_foundry

package foundry

import (
	"context"
	"errors"
	"net/url"
	"testing"
	"time"

	dnsid "github.com/dnsid-ai/dnsid-go"
	dnsidlog "github.com/dnsid-ai/dnsid-go/log"
)

func TestFoundryDoesNotExposeApplicationSigningOverride(t *testing.T) {
	f := newFixture(t)
	id, err := f.client.Create(context.Background(), "no-override")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := id.Active(context.Background()); err != nil {
		t.Fatal(err)
	}
	manager, err := id.IdentityManager()
	if err != nil {
		t.Fatal(err)
	}
	for _, api := range []any{id, manager.KeyProvider()} {
		if _, ok := api.(interface {
			SetApplicationSigningPaused(context.Context, bool) error
		}); ok {
			t.Fatalf("%T exposes an application signing override", api)
		}
	}
}

func TestRefreshCancellationPreservesVerifiedSigning(t *testing.T) {
	for _, stage := range []string{"publication", "log evidence", "saved acceptance", "state load"} {
		t.Run(stage, func(t *testing.T) {
			f := newFixture(t)
			resolver := &cancellingDNS{DNSResolver: fakeDNS{f}}
			if stage == "publication" {
				f.client.deps.DNSResolver = resolver
			}
			f.registry.competing = stage == "saved acceptance"
			id, err := f.client.Create(context.Background(), "refresh")
			if err != nil {
				t.Fatal(err)
			}
			if _, err := id.Active(context.Background()); err != nil {
				t.Fatal(err)
			}
			manager, err := id.IdentityManager()
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			reached := false
			interrupt := func() { reached = true; cancel() }
			switch stage {
			case "publication":
				resolver.cancel = interrupt
			case "log evidence", "saved acceptance":
				reader := &cancellingLog{fakeLog: f.log, cancel: interrupt, binding: stage == "saved acceptance"}
				if err := id.logs.Register("c2sp-tlog", func(string) dnsidlog.LogReader { return reader }); err != nil {
					t.Fatal(err)
				}
			case "state load":
				id.client.deps.Store = cancellingLoadStore{FoundryStore: f.store, cancel: interrupt}
			}
			_, err = id.Active(ctx)
			workflow := requireKind(t, err, Deadline)
			if !reached || !errors.Is(err, context.Canceled) || !workflow.Resumable {
				t.Fatalf("did not preserve observation cancellation: %v", err)
			}
			if _, err := id.Sign([]byte("still verified")); err != nil {
				t.Fatal(err)
			}
			if _, err := manager.KeyProvider().Sign([]byte("still verified")); err != nil {
				t.Fatal(err)
			}
			if f.document("refresh").SigningPaused {
				t.Fatal("refresh cancellation persisted a signing pause")
			}
		})
	}
}

func TestRefreshRequestTimeoutPreservesVerifiedSigning(t *testing.T) {
	for _, test := range []struct {
		name string
		err  error
	}{
		{"HTTP timeout", &url.Error{Op: "Get", URL: "https://log.example", Err: context.DeadlineExceeded}},
		{"transient verification", dnsid.NewVerificationError(dnsid.VerificationCodeLogError, true, "log request timed out", context.DeadlineExceeded)},
	} {
		t.Run(test.name, func(t *testing.T) {
			f := newFixture(t)
			f.registry.competing = true
			id, err := f.client.Create(context.Background(), "request-timeout")
			if err != nil {
				t.Fatal(err)
			}
			if _, err := id.Active(context.Background()); err != nil {
				t.Fatal(err)
			}
			f.log.bindingErr = test.err
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			_, err = id.Active(ctx)
			workflow := requireKind(t, err, Deadline)
			if ctx.Err() != nil || !workflow.Resumable || !errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("request timeout with live caller is not resumable: %v", err)
			}
			if f.document("request-timeout").SigningPaused {
				t.Fatal("request timeout persisted a signing pause")
			}
			if _, err := id.Sign([]byte("still verified")); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestConfirmedPauseSurvivesCallerDeadlineAndRestart(t *testing.T) {
	for _, kind := range []ErrorKind{Terminal, KeyMismatch} {
		t.Run(string(kind), func(t *testing.T) {
			f := newFixture(t)
			id, err := f.client.Create(context.Background(), "durable-pause")
			if err != nil {
				t.Fatal(err)
			}
			if _, err := id.Active(context.Background()); err != nil {
				t.Fatal(err)
			}
			if kind == Terminal {
				f.setStatus(dnsid.AgentStateRetired)
			} else {
				successor := dnsid.GenerateEd25519KeyProvider()
				f.publish(successor, "governance.example", testLR, dnsid.AgentStateActive)
				f.log.currentThumb, err = keyThumb(successor.JWK())
				if err != nil {
					t.Fatal(err)
				}
			}
			ctx := &controlledDeadlineContext{Context: context.Background(), done: make(chan struct{}), deadline: time.Now().Add(time.Hour)}
			store := &expireOnPauseStore{FoundryStore: f.store, caller: ctx}
			id.client.deps.Store = store
			_, err = id.Active(ctx)
			requireKind(t, err, kind)
			if !store.attempted || !store.detached || !store.bounded || !errors.Is(ctx.Err(), context.DeadlineExceeded) {
				t.Fatal("pause was not written with a detached, bounded context after expiry")
			}
			if !f.document("durable-pause").SigningPaused {
				t.Fatal("confirmed pause was lost after the caller deadline")
			}
			_, err = id.Sign([]byte("data"))
			requirePaused(t, err)
			id.client.deps.Store = f.store
			reopened, err := f.client.Create(context.Background(), "durable-pause")
			if kind == Terminal {
				requireKind(t, err, Terminal)
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			_, err = reopened.Sign([]byte("data"))
			requirePaused(t, err)
		})
	}
}

// Expiry is triggered only after Active has classified the unsafe observation.
type controlledDeadlineContext struct {
	context.Context
	done     chan struct{}
	deadline time.Time
}

func (c *controlledDeadlineContext) Deadline() (time.Time, bool) { return c.deadline, true }
func (c *controlledDeadlineContext) Done() <-chan struct{}       { return c.done }
func (c *controlledDeadlineContext) Err() error {
	select {
	case <-c.done:
		return context.DeadlineExceeded
	default:
		return nil
	}
}

type expireOnPauseStore struct {
	FoundryStore
	caller                       *controlledDeadlineContext
	attempted, detached, bounded bool
}

func (s *expireOnPauseStore) Lock(ctx context.Context, key OperationKey) (FoundryLease, error) {
	lease, err := s.FoundryStore.Lock(ctx, key)
	if err != nil {
		return nil, err
	}
	return expireOnPauseLease{FoundryLease: lease, store: s}, nil
}

type expireOnPauseLease struct {
	FoundryLease
	store *expireOnPauseStore
}

func (l expireOnPauseLease) Save(ctx context.Context, doc *RecoveryDocument) error {
	if doc.SigningPaused {
		close(l.store.caller.done)
		l.store.attempted = true
		l.store.detached = ctx.Err() == nil
		deadline, ok := ctx.Deadline()
		remaining := time.Until(deadline)
		l.store.bounded = ok && remaining > 0 && remaining <= 5*time.Second
	}
	return l.FoundryLease.Save(ctx, doc)
}

type cancellingDNS struct {
	dnsid.DNSResolver
	cancel context.CancelFunc
}

func (r *cancellingDNS) FetchTXT(ctx context.Context, name string) ([]dnsid.TXTRecordRData, dnsid.DNSSECState, error) {
	if r.cancel == nil {
		return r.DNSResolver.FetchTXT(ctx, name)
	}
	r.cancel()
	return nil, "", ctx.Err()
}

type cancellingLog struct {
	*fakeLog
	cancel  context.CancelFunc
	binding bool
}

func (r *cancellingLog) VerifyBilateralBinding(ctx context.Context, input dnsidlog.BilateralBindingInput) (dnsidlog.BilateralBinding, error) {
	if r.binding {
		r.cancel()
		return dnsidlog.BilateralBinding{}, ctx.Err()
	}
	return r.fakeLog.VerifyBilateralBinding(ctx, input)
}
func (r *cancellingLog) VerifyNonRevocation(ctx context.Context, _ string, _ time.Time) (dnsidlog.LoggedStateEvidence, error) {
	r.cancel()
	return dnsidlog.LoggedStateEvidence{}, ctx.Err()
}

type cancellingLoadStore struct {
	FoundryStore
	cancel context.CancelFunc
}

func (s cancellingLoadStore) Lock(ctx context.Context, key OperationKey) (FoundryLease, error) {
	lease, err := s.FoundryStore.Lock(ctx, key)
	if err != nil {
		return nil, err
	}
	return cancellingLoadLease{FoundryLease: lease, cancel: s.cancel}, nil
}

type cancellingLoadLease struct {
	FoundryLease
	cancel context.CancelFunc
}

func (l cancellingLoadLease) Load(ctx context.Context) (*RecoveryDocument, error) {
	l.cancel()
	return nil, ctx.Err()
}
