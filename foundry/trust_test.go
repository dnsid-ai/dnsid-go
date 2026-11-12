//go:build dnsid_foundry

package foundry

import (
	"context"
	"encoding/json"
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

func TestNoStateReplicaAfterRotationRecoversCurrentKey(t *testing.T) {
	for _, scenario := range []string{"verified rotation", "rejected preparation", "unrelated key", "wrong signed ku"} {
		t.Run(scenario, func(t *testing.T) {
			f := newFixture(t)
			id, err := f.client.Create(context.Background(), "rotated-replica")
			if err != nil {
				t.Fatal(err)
			}
			if _, err := id.Active(context.Background()); err != nil {
				t.Fatal(err)
			}
			original := f.document("rotated-replica")
			successor := dnsid.GenerateEd25519KeyProvider()
			currentThumb, err := keyThumb(successor.JWK())
			if err != nil {
				t.Fatal(err)
			}
			f.publish(successor, "governance.example", testLR, dnsid.AgentStateActive)
			if scenario != "unrelated key" {
				f.log.currentThumb = currentThumb
				f.log.events = append(f.log.events, dnsidlog.LogEvent{Type: dnsidlog.LogEventKeyRotation, Domain: testDomain, NewOperationalPublicKey: successor.JWK(), NewOperationalThumbprint: currentThumb})
			}
			if scenario == "wrong signed ku" {
				f.publish(f.operational, "governance.example", testLR, dnsid.AgentStateActive)
			}
			// Server rotation replaces the stored key used for caller-key replay.
			f.registry.initial, err = json.Marshal(successor.JWK())
			if err != nil {
				t.Fatal(err)
			}
			f.registry.status = "PROVISIONING"
			f.registry.statuses = []string{"READY"}
			if scenario == "rejected preparation" {
				f.registry.statuses = []string{"PROVISIONING", "PROVISIONING", "READY"}
			}
			store, err := NewFileFoundryStore(filepath.Join(t.TempDir(), "replica"))
			if err != nil {
				t.Fatal(err)
			}
			f.store = store
			client := f.newClient(successor, store)
			replica, err := client.Create(context.Background(), "rotated-replica")
			if err != nil {
				t.Fatal(err)
			}
			_, err = replica.Sign([]byte("data"))
			requirePaused(t, err)
			_, err = replica.Active(context.Background())
			switch scenario {
			case "unrelated key":
				requireKind(t, err, Integrity)
			case "wrong signed ku":
				requireKind(t, err, Integrity)
			default:
				if err != nil {
					t.Fatal(err)
				}
				saved := f.document("rotated-replica")
				if !sameJSON(saved.InitialPublicKey, original.InitialPublicKey) || !sameJSON(saved.CurrentPublicKey, saved.CreationInput.PublicKey) || !sameJSON(saved.CurrentPublicKey, f.registry.initial) || saved.RegistrationKey == original.RegistrationKey || !saved.Issuance.Recovered {
					t.Fatal("recovery lost initial, current, or creation key bindings")
				}
				if _, err := replica.Sign([]byte("data")); err != nil {
					t.Fatal(err)
				}
				reopened, err := client.Create(context.Background(), "rotated-replica")
				if err != nil {
					t.Fatal(err)
				}
				if _, err := reopened.Sign([]byte("data")); err != nil {
					t.Fatal(err)
				}
			}
			preparations := 1
			if scenario == "rejected preparation" {
				preparations++
			}
			if f.log.historyCalls != 1 || f.registry.prepareCalls != preparations || len(f.registry.submissions) != 1 {
				t.Fatal("recovery prepared or submitted another ISSUANCE")
			}
		})
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
