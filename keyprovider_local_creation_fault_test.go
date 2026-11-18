package dnsid

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"sync"
	"testing"
	"time"
)

// Mode: fake-only (file-sync failure; isolated real temporary filesystem).
// Guard: a failed concurrent initializer must not erase a successful key store.
func TestLoadOrCreateLocalKeyProvider_ConcurrentFileSyncFailureCannotEraseSuccess(t *testing.T) {
	// Given an absent store, hold the first initializer at file durability sync.
	path := filepath.Join(t.TempDir(), "keys.json")
	injected := errors.New("test: ordinary file sync failure")
	const bound = 5 * time.Second
	entered, release := make(chan struct{}), make(chan struct{})
	var enterOnce, releaseOnce sync.Once
	unblock := func() { releaseOnce.Do(func() { close(release) }) }
	type result struct {
		provider *LocalKeyProvider
		err      error
	}
	first, second := make(chan result, 1), make(chan result, 1)
	firstDone, secondDone := make(chan struct{}), make(chan struct{})
	startedSecond := false
	// Registered after TempDir: release and join workers before directory cleanup.
	t.Cleanup(func() {
		unblock()
		workers := []<-chan struct{}{firstDone}
		if startedSecond {
			workers = append(workers, secondDone)
		}
		for i, done := range workers {
			select {
			case <-done:
			case <-time.After(bound):
				t.Errorf("caller %d did not terminate after gate release", i+1)
			}
		}
	})
	go func() {
		defer close(firstDone)
		p, err := loadOrCreateLocalKeyProvider(path, JoseAlgEdDSA, func(_ *os.File) error {
			enterOnce.Do(func() { close(entered) })
			select {
			case <-release:
				return injected
			case <-time.After(3 * bound):
				return injected
			}
		})
		first <- result{p, err}
	}()
	select {
	case <-entered:
	case <-time.After(bound):
		t.Fatal("first initializer did not reach file-sync seam")
	}

	// When a second actual public caller attempts the same store while held.
	attempting := make(chan struct{})
	startedSecond = true
	go func() {
		defer close(secondDone)
		close(attempting)
		p, err := LoadOrCreateLocalKeyProvider(path, JoseAlgEdDSA)
		second <- result{p, err}
	}()
	select {
	case <-attempting:
	case <-time.After(bound):
		t.Fatal("second caller was not scheduled")
	}
	var b result
	haveB := false
	select {
	case b = <-second:
		haveB = true
	case <-time.After(bound / 5): // Scheduling allowance, NOT proof of blocking.
	}
	// Waiting, converging, or explicit failure are all allowed; release either way.
	unblock()
	var a result
	select {
	case a = <-first:
	case <-time.After(bound):
		t.Fatal("first caller did not return after sync failure")
	}
	if !haveB {
		select {
		case b = <-second:
		case <-time.After(bound):
			t.Fatal("second caller did not return after gate release")
		}
	}
	// Join both workers before inspecting their owned parent directory.
	for i, done := range []<-chan struct{}{firstDone, secondDone} {
		select {
		case <-done:
		case <-time.After(bound):
			t.Fatalf("caller %d did not terminate before parent inventory", i+1)
		}
	}
	if a.err == nil {
		t.Error("initializer whose file sync failed reported success")
	}

	// Then EVERY reported success remains reloadable after both callers finish.
	type snapshot struct {
		ids    []string
		public any
	}
	capture := func(p *LocalKeyProvider) snapshot {
		t.Helper()
		if p == nil {
			t.Fatal("successful call returned nil provider")
		}
		ids := p.ListKeyIds()
		if len(ids) != 1 || ids[0] == "" {
			t.Fatalf("fresh store must have one active key: %v", ids)
		}
		key := p.JWK(ids[0])
		if key == nil {
			t.Fatal("successful provider has no active public JWK")
		}
		raw, err := json.Marshal(key)
		if err != nil {
			t.Fatalf("marshal public JWK: %v", err)
		}
		var public any
		if err := json.Unmarshal(raw, &public); err != nil {
			t.Fatalf("decode public JWK: %v", err)
		}
		return snapshot{append([]string(nil), ids...), public}
	}
	var winner *snapshot
	for _, r := range []result{a, b} {
		if r.err != nil {
			continue
		} // Explicit errors promise no usable provider.
		got := capture(r.provider)
		loaded, err := NewLocalKeyProvider(path)
		if err != nil {
			t.Fatalf("successful key disappeared after concurrent initialization: %v", err)
		}
		if !reflect.DeepEqual(got, capture(loaded)) {
			t.Fatal("successful caller's key differs from persisted winner")
		}
		if winner != nil && !reflect.DeepEqual(*winner, got) {
			t.Fatal("successful replicas did not converge")
		}
		saved := got
		winner = &saved
	}
	// Internal cleanup characterization only: both may fail with an empty parent,
	// or leave only the store; this does not promise general shared-writer safety.
	if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
		assertOwnedInitialParent(t, filepath.Dir(path))
	} else {
		assertOwnedInitialParent(t, filepath.Dir(path), "keys.json")
	}
	// Both may explicitly fail; a clean retry must create/reuse persistent state.
	recovered, err := LoadOrCreateLocalKeyProvider(path, JoseAlgEdDSA)
	if err != nil {
		t.Fatalf("clean create/reuse retry failed: %v", err)
	}
	recoveredKey := capture(recovered)
	if winner != nil && !reflect.DeepEqual(*winner, recoveredKey) {
		t.Fatal("retry replaced a reported successful winner")
	}
	reloaded, err := NewLocalKeyProvider(path)
	if err != nil {
		t.Fatalf("clean retry's key cannot be reloaded: %v", err)
	}
	if !reflect.DeepEqual(recoveredKey, capture(reloaded)) {
		t.Fatal("clean retry did not persist its returned key")
	}
	assertOwnedInitialParent(t, filepath.Dir(path), "keys.json")
}
