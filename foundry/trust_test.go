//go:build dnsid_foundry

package foundry

import (
	"context"
	"path/filepath"
	"testing"

	dnsid "github.com/dnsid-ai/dnsid-go"
	"github.com/dnsid-ai/dnsid-go/config"
	dnsidlog "github.com/dnsid-ai/dnsid-go/log"
)

func TestLogTrustIsCheckedBeforeCountersigningWithoutScanning(t *testing.T) {
	f := newFixture(t)
	loaded := config.Loaded{Registry: f.client.loaded.Registry, LogTrust: config.LogTrust{Managed: true}}
	deps := f.client.deps
	deps.LogRegistry = nil
	client, err := New(loaded, deps)
	if err != nil {
		t.Fatal(err)
	}
	id, err := client.Create(context.Background(), "trust")
	if err != nil {
		t.Fatal(err)
	}
	// The embedded catalog does not authorize the fake's testnet/log.example stream.
	_, err = id.Active(context.Background())
	requireKind(t, err, Integrity)
	if len(f.registry.submissions) != 0 || f.log.historyCalls != 0 {
		t.Fatal("untrusted log was countersigned or blindly scanned")
	}
}

func TestLazyLogTrustConstructionDoesNotFetchPolicy(t *testing.T) {
	registry, trust, err := newLazyLogRegistry(config.Loaded{LogTrust: config.LogTrust{PolicyURL: "https://unreachable.invalid/policy"}})
	if err != nil {
		t.Fatal(err)
	}
	if trust.resolved != nil {
		t.Fatal("policy fetched during construction")
	}
	reader, err := registry.NewReader(testLR)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := reader.(*lazyLogReader); !ok {
		t.Fatal("manager did not receive a configured deferred trust reader")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := reader.RebuildHistory(ctx, testDomain); err == nil {
		t.Fatal("trust fetch ignored cancellation")
	}
	if trust.resolved != nil {
		t.Fatal("cancelled policy resolution was cached")
	}
}

func TestNoStateReplicaAfterRotationReturnsKeyMismatch(t *testing.T) {
	f := newFixture(t)
	id, err := f.client.Create(context.Background(), "rotated-replica")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := id.Active(context.Background()); err != nil {
		t.Fatal(err)
	}
	successor := dnsid.GenerateEd25519KeyProvider()
	store, err := NewFileFoundryStore(filepath.Join(t.TempDir(), "replica"))
	if err != nil {
		t.Fatal(err)
	}
	f.store = store
	client := f.newClient(successor, store)
	before := f.publicCalls
	_, err = client.Create(context.Background(), "rotated-replica")
	requireKind(t, err, KeyMismatch)
	if f.publicCalls != before || f.log.historyCalls != 0 || f.registry.prepareCalls != 1 {
		t.Fatal("no-state replica tried to resolve or adopt a rotated identity")
	}
}

func TestNewRejectsInvalidTrustBeforeDiscovery(t *testing.T) {
	f := newFixture(t)
	for _, trust := range []config.LogTrust{{}, {Managed: true, PolicyURL: "https://policy.example"}, {PolicyURL: "http://policy.example"}} {
		_, err := New(config.Loaded{Registry: f.client.loaded.Registry, LogTrust: trust}, Dependencies{KeyProvider: f.operational, RegistryClient: f.registry, Store: f.store})
		if err == nil {
			t.Fatal("invalid trust accepted")
		}
	}
	// An injected registry displaces invalid loaded selection without resolving it.
	if _, err := New(config.Loaded{LogTrust: config.LogTrust{PolicyURL: "not a URL"}}, Dependencies{KeyProvider: f.operational, RegistryClient: f.registry, Store: f.store, LogRegistry: dnsidlog.NewLogRegistry()}); err != nil {
		t.Fatal(err)
	}
	if f.registry.createCalls != 0 {
		t.Fatal("constructor created an identity")
	}
}
