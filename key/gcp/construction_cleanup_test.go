package gcpkms_test

import (
	"context"
	"errors"
	"google.golang.org/grpc"
	"sync"
	"testing"

	dnsid "github.com/dnsid-ai/dnsid-go"
	"github.com/dnsid-ai/dnsid-go/config"
	gcpkms "github.com/dnsid-ai/dnsid-go/key/gcp"
	"google.golang.org/api/option"
	"google.golang.org/grpc/connectivity"
)

var cleanupRegister sync.Once

type cleanupContextKey struct{}
type cleanupOpenState struct {
	conn   *grpc.ClientConn
	opened *gcpkms.Provider
	opens  int
}

type cleanupDNS struct {
	calls int
	err   error
}

func (d *cleanupDNS) FetchTXT(context.Context, string) ([]dnsid.TXTRecordRData, dnsid.DNSSECState, error) {
	d.calls++
	return nil, dnsid.DNSSECStateUnsigned, d.err
}

// Mode: fake-only (local KMS RPC, real official client/connection and provider).
// Public registration routes selection through Open with a dedicated official
// transport; no production hook or Google credentials are needed. The otherwise
// unlinked Azure slot is only a test routing seam, not an Azure implementation.
func TestConstruct_GCPClientReleasedOnPublicationFailure(t *testing.T) {
	f := newFake(t)
	conn := localKMS(t, &localKMSServer{fake: f})
	state := &cleanupOpenState{conn: conn}
	cleanupRegister.Do(func() {
		config.RegisterKeyProviderFactory("azure-key-vault", config.KeyProviderFactory{
			Validate: func(config.KeySource) error { return nil },
			Open: func(ctx context.Context, src config.KeySource, _ string) (dnsid.KeyProvider, error) {
				state := ctx.Value(cleanupContextKey{}).(*cleanupOpenState)
				state.opens++
				var err error
				state.opened, err = gcpkms.Open(ctx, config.KeySource{Provider: "google-kms", KeyRef: src.KeyRef}, option.WithGRPCConn(state.conn))
				return state.opened, err
			},
		})
	})
	// Fallback cleanup runs only after observing the connection state.
	t.Cleanup(func() {
		if state.opened != nil {
			_ = state.opened.Close()
		}
	})
	sentinel := errors.New("fixture DNS publication unavailable after GCP open")
	resolver := &cleanupDNS{err: sentinel}
	loaded := config.Loaded{Dnsid: dnsid.Config{Identity: &dnsid.IdentityConfig{Domain: "agent.example.com", GovernanceID: "example.com", LogRef: "algorand:ADDR", StatusURL: "https://agent.example.com/status.json", KeyURL: "https://agent.example.com/ku.json", EntityKeyURL: "https://example.com/ek.json"}}, KeySource: config.KeySource{Provider: "azure-key-vault", KeyRef: version}}
	// When opening succeeds but subsequent publication fails, Then no manager is
	// returned and the construction-owned official connection is closed.
	m, err := config.Construct(context.WithValue(context.Background(), cleanupContextKey{}, state), loaded, config.Dependencies{DNSResolver: resolver, EntityKeyProvider: dnsid.GenerateES256KeyProvider()})
	if m != nil || !errors.Is(err, sentinel) || resolver.calls == 0 {
		t.Fatalf("not intended publication failure: manager=%v calls=%d err=%v", m != nil, resolver.calls, err)
	}
	if state.opens != 1 || state.opened == nil || f.gets == 0 {
		t.Fatalf("GCP opening did not succeed: opens=%d provider=%v GetPublicKey=%d", state.opens, state.opened != nil, f.gets)
	}
	if got := conn.GetState(); got != connectivity.Shutdown {
		t.Fatalf("construction-owned GCP connection state=%s, want SHUTDOWN after publication failure", got)
	}
}
