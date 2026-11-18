package dnsid

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sync"
	"testing"
	"time"
)

// TestConcurrentCreateOnlyMissingSuccess characterizes one controlled overlap,
// not stress, cross-process, or full SDK behavior.
func TestConcurrentCreateOnlyMissingSuccess(t *testing.T) {
	// GIVEN an absent absolute local store and A held at its first file sync.
	path := filepath.Join(t.TempDir(), "keys.json")
	const resultBound = 5 * time.Second
	const callbackBound = 20 * time.Second
	type result struct {
		provider *LocalKeyProvider
		err      error
	}
	held := make(chan struct{})
	release := make(chan struct{})
	var releaseOnce sync.Once
	unhold := func() { releaseOnce.Do(func() { close(release) }) }
	var holdOnce sync.Once
	aResult := make(chan result, 1)
	bResult := make(chan result, 1)
	aDone := make(chan struct{})
	bDone := make(chan struct{})
	bStarted := false
	// Registered after TempDir, so release and joins precede directory removal.
	t.Cleanup(func() {
		unhold()
		join := func(name string, done <-chan struct{}) {
			timer := time.NewTimer(resultBound)
			defer timer.Stop()
			select {
			case <-done:
			case <-timer.C:
				t.Errorf("cleanup: %s did not finish within %s; executor process timeout remains required", name, resultBound)
			}
		}
		join("A", aDone)
		if bStarted {
			join("B", bDone)
		}
	})
	go func() {
		defer close(aDone)
		p, err := loadOrCreateLocalKeyProvider(path, JoseAlgEdDSA, func(f *os.File) error {
			info, err := f.Stat()
			if err != nil {
				return err
			}
			var holdErr error
			if info.Mode().IsRegular() {
				holdOnce.Do(func() {
					close(held)
					timer := time.NewTimer(callbackBound)
					defer timer.Stop()
					select {
					case <-release:
					case <-timer.C:
						holdErr = fmt.Errorf("file-sync hold exceeded %s", callbackBound)
					}
				})
			}
			if holdErr != nil {
				return holdErr
			}
			// Both the released regular file and directory callbacks really sync.
			return f.Sync()
		})
		aResult <- result{p, err}
	}()
	await := func(name string, ch <-chan result) result {
		t.Helper()
		timer := time.NewTimer(resultBound)
		defer timer.Stop()
		select {
		case r := <-ch:
			return r
		case <-timer.C:
			t.Fatalf("%s did not complete within %s", name, resultBound)
			return result{}
		}
	}
	timer := time.NewTimer(resultBound)
	select {
	case <-held:
		timer.Stop()
	case r := <-aResult:
		timer.Stop()
		t.Fatalf("A returned before the file-sync hold: provider present=%t, err=%v", r.provider != nil, r.err)
	case <-timer.C:
		t.Fatal("A did not reach its file-sync hold within the bound")
	}

	// WHEN B uses the public entry point while A remains held, B must finish
	// successfully BEFORE A is released. A timeout is failure, not blocking proof.
	bStarted = true
	go func() {
		defer close(bDone)
		p, err := LoadOrCreateLocalKeyProvider(path, JoseAlgEdDSA)
		bResult <- result{p, err}
	}()
	b := await("B while A is held", bResult)
	if b.err != nil || b.provider == nil {
		t.Fatalf("B while A is held: provider present=%t, err=%v", b.provider != nil, b.err)
	}
	unhold()
	a := await("A after release", aResult)
	if a.err != nil || a.provider == nil {
		t.Fatalf("A after release: provider present=%t, err=%v", a.provider != nil, a.err)
	}

	// THEN both returned providers, a reload, and clean create/reuse agree on
	// exactly one active-first kid and its decoded public JWK (not JSON ordering).
	type identity struct {
		kid    string
		public map[string]interface{}
	}
	readIdentity := func(name string, p *LocalKeyProvider) identity {
		t.Helper()
		ids := p.ListKeyIds()
		if len(ids) != 1 || ids[0] == "" {
			t.Fatalf("%s: want exactly one nonempty active-first kid, got %v", name, ids)
		}
		decode := func(encoded []byte, err error) map[string]interface{} {
			t.Helper()
			if err != nil {
				t.Fatalf("%s: marshal public JWK: %v", name, err)
			}
			var key map[string]interface{}
			if err := json.Unmarshal(encoded, &key); err != nil {
				t.Fatalf("%s: decode public JWK: %v", name, err)
			}
			if key == nil || key["kty"] == nil || key["x"] == nil {
				t.Fatalf("%s: missing public key material", name)
			}
			if _, private := key["d"]; private {
				t.Fatalf("%s: public JWK contains private material", name)
			}
			return key
		}
		public := decode(json.Marshal(p.JWK(ids[0])))
		active := decode(json.Marshal(p.JWK()))
		if !reflect.DeepEqual(public, active) {
			t.Fatalf("%s: default public JWK differs from active-first kid", name)
		}
		return identity{ids[0], public}
	}
	want := readIdentity("B", b.provider)
	check := func(name string, p *LocalKeyProvider, err error) {
		t.Helper()
		if err != nil || p == nil {
			t.Fatalf("%s: provider present=%t, err=%v", name, p != nil, err)
		}
		if got := readIdentity(name, p); !reflect.DeepEqual(got, want) {
			t.Fatalf("%s: kid or decoded public JWK changed", name)
		}
	}
	check("A", a.provider, a.err)
	p, err := NewLocalKeyProvider(path)
	check("reload", p, err)
	p, err = LoadOrCreateLocalKeyProvider(path, JoseAlgEdDSA)
	check("clean create/reuse", p, err)
	p, err = NewLocalKeyProvider(path)
	check("reload after reuse", p, err)
}
