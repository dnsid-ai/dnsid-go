//go:build dnsid_foundry

package foundry

import (
	"context"
	"errors"
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
