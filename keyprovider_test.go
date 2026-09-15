package dnsid

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestLoadOrCreateLocalKeyProviderWritesStoreAndPersistsRotation(t *testing.T) {
	path := t.TempDir() + "/key.json"

	kp, err := LoadOrCreateLocalKeyProvider(path, JoseAlgES256)
	if err != nil {
		t.Fatalf("LoadOrCreateLocalKeyProvider create: %v", err)
	}
	initialKid := kp.ListKeyIds()[0]
	assertKeyStoreFile(t, path, initialKid, 0, 0)

	pending, err := kp.GenerateKey(JoseAlgEdDSA)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	assertKeyStoreFile(t, path, initialKid, 0, 1)

	if err := kp.Activate(pending); err != nil {
		t.Fatalf("Activate: %v", err)
	}
	assertKeyStoreFile(t, path, pending, 1, 0)

	loaded, err := LoadOrCreateLocalKeyProvider(path, JoseAlgES256)
	if err != nil {
		t.Fatalf("LoadOrCreateLocalKeyProvider load: %v", err)
	}
	if got := loaded.ListKeyIds(); len(got) != 2 || got[0] != pending || got[1] != initialKid {
		t.Fatalf("loaded key ids = %v", got)
	}
}

func TestLocalKeyProviderNamedSigningAndSupersede(t *testing.T) {
	kp := GenerateEd25519KeyProvider()
	active := kp.ListKeyIds()[0]
	pending, err := kp.GenerateKey(JoseAlgEdDSA)
	if err != nil {
		t.Fatal(err)
	}
	if sig, err := kp.SignKey(pending, []byte("rotation proof")); err != nil || sig.Kid != pending {
		t.Fatalf("SignKey pending = (%v, %v)", sig, err)
	}
	if err := kp.Activate(pending); err != nil {
		t.Fatal(err)
	}
	if _, err := kp.SignKey(active, []byte("too late")); err == nil {
		t.Fatal("superseded key remained available for signing")
	}
	if err := kp.Supersede(active); err != nil {
		t.Fatal(err)
	}
	if kp.JWK(active) != nil {
		t.Fatal("superseded key remained in provider")
	}
}

func TestLocalKeyProviderRollsBackOnPersistFailure(t *testing.T) {
	path := t.TempDir() + "/key.json"
	kp, err := LoadOrCreateLocalKeyProvider(path, JoseAlgEdDSA)
	if err != nil {
		t.Fatal(err)
	}
	initial := kp.ListKeyIds()[0]
	pending, err := kp.GenerateKey(JoseAlgEdDSA)
	if err != nil {
		t.Fatal(err)
	}

	kp.path = t.TempDir()
	if err := kp.Activate(pending); err == nil {
		t.Fatal("Activate succeeded with unwritable key store path")
	}
	if got := kp.ListKeyIds(); len(got) != 1 || got[0] != initial {
		t.Fatalf("key ids after failed activate = %v", got)
	}
}

func TestNewLocalKeyProviderAcceptsFlatJWK(t *testing.T) {
	path := t.TempDir() + "/key.json"
	kp := GenerateEd25519KeyProvider()
	kp.mu.RLock()
	key, err := privateJWKForEntry(kp.activeEntryLocked())
	kp.mu.RUnlock()
	if err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(key)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}

	loaded, err := NewLocalKeyProvider(path)
	if err != nil {
		t.Fatalf("NewLocalKeyProvider flat JWK: %v", err)
	}
	if got, want := loaded.ListKeyIds()[0], kp.ListKeyIds()[0]; got != want {
		t.Fatalf("loaded kid = %q, want %q", got, want)
	}
}

func TestNewLocalKeyProviderMalformedFileIsParseError(t *testing.T) {
	path := filepath.Join(t.TempDir(), "private.jwk")
	if err := os.WriteFile(path, []byte(`{"kty":`), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := NewLocalKeyProvider(path)
	var parseErr *ParseError
	if !errors.As(err, &parseErr) {
		t.Fatalf("NewLocalKeyProvider error = %T %v, want *ParseError", err, err)
	}
}

func TestLocalKeyProvider_SyncFailures(t *testing.T) {
	for _, operation := range []string{"generate", "activate", "purge"} {
		for _, failAt := range []string{"file", "directory", "none"} {
			t.Run(operation+"/"+failAt, func(t *testing.T) {
				path := filepath.Join(t.TempDir(), "key.json")
				kp, err := LoadOrCreateLocalKeyProvider(path, JoseAlgEdDSA)
				if err != nil {
					t.Fatal(err)
				}
				pending, err := kp.GenerateKey(JoseAlgES256)
				if err != nil {
					t.Fatal(err)
				}
				before, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				injected := errors.New("sync failed")
				var calls []string
				kp.syncFile = func(f *os.File) error {
					info, err := f.Stat()
					if err != nil {
						t.Fatal(err)
					}
					stage := "file"
					if info.IsDir() {
						stage = "directory"
					}
					calls = append(calls, stage)
					visible, err := os.ReadFile(path)
					if err != nil {
						t.Fatal(err)
					}
					if bytes.Equal(visible, before) != (stage == "file") {
						t.Fatalf("wrong publication ordering at %s sync", stage)
					}
					if stage == failAt {
						return injected
					}
					return f.Sync()
				}
				var generated string
				switch operation {
				case "generate":
					generated, err = kp.GenerateKey(JoseAlgEdDSA)
				case "activate":
					err = kp.Activate(pending)
				case "purge":
					err = kp.Purge(pending)
				}
				if (err == nil) != (failAt == "none") || errors.Is(err, injected) != (failAt != "none") {
					t.Fatalf("error = %v", err)
				}
				if errors.Is(err, ErrKeyStoreDurability) != (failAt == "directory") {
					t.Fatalf("durability classification = %v", err)
				}
				wantCalls := []string{"file", "directory"}
				if failAt == "file" {
					wantCalls = wantCalls[:1]
				}
				if !reflect.DeepEqual(calls, wantCalls) {
					t.Fatalf("sync calls = %v, want %v", calls, wantCalls)
				}
				loaded, err := NewLocalKeyProvider(path)
				if err != nil {
					t.Fatal(err)
				}
				if loaded.activeKid != kp.activeKid || len(loaded.keys) != len(kp.keys) {
					t.Fatal("memory and disk diverged")
				}
				for kid, entry := range kp.keys {
					if loaded.keys[kid] == nil || loaded.keys[kid].state != entry.state {
						t.Fatalf("memory and disk differ for %s", kid)
					}
				}
				if operation == "generate" && (generated != "") != (failAt != "file") {
					t.Fatalf("generated kid = %q", generated)
				}
				files, err := os.ReadDir(filepath.Dir(path))
				if err != nil || len(files) != 1 || files[0].Name() != "key.json" {
					t.Fatalf("temporary file leaked: %v, %v", files, err)
				}
				// Re-persist the current state without generating or activating a new key.
				calls = nil
				kp.syncFile = func(f *os.File) error {
					calls = append(calls, f.Name())
					return f.Sync()
				}
				if err := kp.Activate(kp.activeKid); err != nil || len(calls) != 2 {
					t.Fatalf("durability retry: %v, calls %v", err, calls)
				}
			})
		}
	}
}

func TestLoadOrCreateLocalKeyProvider_SyncFailures(t *testing.T) {
	for _, failAt := range []int{0, 1, 2} {
		t.Run(fmt.Sprint(failAt), func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "key.json")
			injected := errors.New("sync failed")
			calls := 0
			_, err := loadOrCreateLocalKeyProvider(path, JoseAlgEdDSA, func(f *os.File) error {
				calls++
				info, err := f.Stat()
				if err != nil {
					t.Fatal(err)
				}
				if info.IsDir() != (calls == 2) {
					t.Fatal("must sync file before directory")
				}
				if calls == failAt {
					return injected
				}
				return f.Sync()
			})
			if (err == nil) != (failAt == 0) || errors.Is(err, injected) != (failAt != 0) {
				t.Fatalf("error = %v", err)
			}
			if errors.Is(err, ErrKeyStoreDurability) != (failAt == 2) {
				t.Fatalf("durability classification = %v", err)
			}
			if failAt == 1 {
				if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
					t.Fatalf("failed creation left file: %v", err)
				}
				return
			}
			if calls != 2 {
				t.Fatalf("sync calls = %d", calls)
			}
			loaded, err := NewLocalKeyProvider(path)
			if err != nil {
				t.Fatal(err)
			}
			info, err := os.Stat(path)
			if err != nil || info.Mode().Perm() != 0o600 {
				t.Fatalf("permissions: %v, %v", info, err)
			}
			// An existing key must never be overwritten or replaced by a new key.
			again, err := LoadOrCreateLocalKeyProvider(path, JoseAlgES256)
			if err != nil || again.activeKid != loaded.activeKid {
				t.Fatalf("existing key was replaced: %v", err)
			}
		})
	}
}

func assertKeyStoreFile(t *testing.T, path, activeKid string, retained, pending int) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var store struct {
		Active struct {
			Kid string `json:"kid"`
		} `json:"active"`
		Retained []json.RawMessage `json:"retained"`
		Pending  []json.RawMessage `json:"pending"`
	}
	if err := json.Unmarshal(data, &store); err != nil {
		t.Fatal(err)
	}
	if store.Active.Kid != activeKid || len(store.Retained) != retained || len(store.Pending) != pending {
		t.Fatalf("store = active %q retained %d pending %d", store.Active.Kid, len(store.Retained), len(store.Pending))
	}
}
