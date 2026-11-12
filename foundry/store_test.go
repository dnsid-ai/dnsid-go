//go:build dnsid_foundry

package foundry

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestFileFoundryStore_PortableRoundTripAndUnknownMembers(t *testing.T) {
	f := newFixture(t)
	id, err := f.client.Create(context.Background(), "portable😀")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := id.Active(context.Background()); err != nil {
		t.Fatal(err)
	}
	original, err := f.document("portable😀").Export()
	if err != nil {
		t.Fatal(err)
	}
	var obj map[string]any
	if err := json.Unmarshal(original, &obj); err != nil {
		t.Fatal(err)
	}
	obj["future"] = map[string]any{"\ue000": 2, "😀": 1, "signature": "must survive"}
	obj["keySource"].(map[string]any)["futureKeySetting"] = true
	issuance := obj["issuance"].(map[string]any)
	issuance["futureIssuanceSetting"] = "kept"
	data, err := json.Marshal(obj)
	if err != nil {
		t.Fatal(err)
	}
	doc, err := ParseRecoveryDocument(data)
	if err != nil {
		t.Fatal(err)
	}
	exported, err := doc.Export()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(exported, []byte(`"signature":"must survive"`)) || !bytes.Contains(exported, []byte("futureKeySetting")) || !bytes.Contains(exported, []byte("futureIssuanceSetting")) {
		t.Fatal("unknown members lost")
	}
	parsed, err := ParseRecoveryDocument(exported)
	if err != nil {
		t.Fatal(err)
	}
	again, err := parsed.Export()
	if err != nil || !bytes.Equal(exported, again) {
		t.Fatal("export is not stable JCS")
	}
	if !bytes.Equal(doc.Issuance.Operation.EntryBytes, parsed.Issuance.Operation.EntryBytes) {
		t.Fatal("exact bytes changed across portable encoding")
	}
	destination, err := NewFileFoundryStore(filepath.Join(t.TempDir(), "imported"))
	if err != nil {
		t.Fatal(err)
	}
	if err := destination.Import(context.Background(), exported); err != nil {
		t.Fatal(err)
	}
	var indented bytes.Buffer
	if err := json.Indent(&indented, exported, "", "  "); err != nil {
		t.Fatal(err)
	}
	if err := destination.Import(context.Background(), indented.Bytes()); err != nil {
		t.Fatalf("identical indented backup conflicts: %v", err)
	}
	loaded, err := destination.LoadIdentity(context.Background(), doc.RegistryURL, doc.OrganizationID, doc.IdentityID)
	if err != nil || loaded == nil {
		t.Fatalf("historical identity: %v", err)
	}
	if loaded.Name != doc.Name {
		t.Fatal("history lost exact name")
	}
	if info, err := os.Stat(destination.directory); err != nil || info.Mode().Perm() != 0700 && runtime.GOOS != "windows" {
		t.Fatalf("directory permissions: %v %v", info, err)
	}
	files, err := os.ReadDir(destination.directory)
	if err != nil {
		t.Fatal(err)
	}
	for _, file := range files {
		info, err := file.Info()
		if err != nil || info.Mode().Perm() != 0600 && runtime.GOOS != "windows" {
			t.Fatalf("file permissions %s: %v %v", file.Name(), info, err)
		}
	}
}

func TestRecoveryDocumentRejectsCorruption(t *testing.T) {
	f := newFixture(t)
	_, err := f.client.Create(context.Background(), "state")
	if err != nil {
		t.Fatal(err)
	}
	good, err := f.document("state").Export()
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name   string
		change func([]byte) []byte
	}{
		{"duplicate", func(b []byte) []byte { return append([]byte(`{"schemaVersion":2,`), b[1:]...) }},
		{"old version", func(b []byte) []byte {
			return bytes.Replace(b, []byte(`"schemaVersion":2`), []byte(`"schemaVersion":1`), 1)
		}},
		{"unknown version", func(b []byte) []byte {
			return bytes.Replace(b, []byte(`"schemaVersion":2`), []byte(`"schemaVersion":3`), 1)
		}},
		{"old phase", func(b []byte) []byte {
			return bytes.Replace(b, []byte(`"identity-known"`), []byte(`"proof-pending"`), 1)
		}},
		{"missing registration key", func(b []byte) []byte {
			return bytes.Replace(b, []byte(`"registrationKey":`), []byte(`"requestId":`), 1)
		}},
		{"missing issuance key", func(b []byte) []byte {
			return bytes.Replace(b, []byte(`"issuanceKey":`), []byte(`"oldIssuanceKey":`), 1)
		}},
		{"unknown phase", func(b []byte) []byte { return bytes.Replace(b, []byte(`"identity-known"`), []byte(`"future"`), 1) }},
		{"unpaired high surrogate", func(b []byte) []byte { return bytes.Replace(b, []byte(`"state"`), []byte(`"\ud800"`), 1) }},
		{"unpaired low surrogate", func(b []byte) []byte { return bytes.Replace(b, []byte(`"state"`), []byte(`"\udfff"`), 1) }},
		{"wrong name", func(b []byte) []byte { return bytes.Replace(b, []byte(`"name":"state"`), []byte(`"name":"State"`), 1) }},
		{"missing domain", func(b []byte) []byte { return bytes.Replace(b, []byte(`"domain":"agent.example",`), nil, 1) }},
		{"secret", func(b []byte) []byte { return append([]byte(`{"credentials":"secret",`), b[1:]...) }},
		{"private JWK", func(b []byte) []byte {
			return bytes.Replace(b, []byte(`"initialPublicKey":{`), []byte(`"initialPublicKey":{"d":"private",`), 1)
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := ParseRecoveryDocument(test.change(good)); err == nil {
				t.Fatal("accepted corrupt document")
			}
		})
	}
	if _, err := decodeObject([]byte(`{"pair":"\ud83d\ude00"}`)); err != nil {
		t.Fatal(err)
	}
}

func TestFileFoundryStore_LockAndClosedLease(t *testing.T) {
	f := newFixture(t)
	key := OperationKey{f.client.loaded.Registry.RegistryURL, testOrg, "locked"}
	first, err := f.store.Lock(context.Background(), key)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	_, err = f.store.Lock(ctx, key)
	e := requireKind(t, err, Busy)
	if !errors.Is(e, context.DeadlineExceeded) {
		t.Fatal("lost deadline cause")
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := first.Load(context.Background()); err == nil {
		t.Fatal("load after release")
	}
	second, err := f.store.Lock(context.Background(), key)
	if err != nil {
		t.Fatal(err)
	}
	if err := second.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestFileFoundryStore_ProcessLockHelper(t *testing.T) {
	directory := os.Getenv("DNSID_FOUNDRY_LOCK_TEST_DIRECTORY")
	if directory == "" {
		return
	}
	store, err := NewFileFoundryStore(directory)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Millisecond)
	defer cancel()
	_, err = store.Lock(ctx, OperationKey{"https://registry.example", testOrg, "process"})
	requireKind(t, err, Busy)
}

func TestFileFoundryStore_CrossProcessLock(t *testing.T) {
	f := newFixture(t)
	lease, err := f.store.Lock(context.Background(), OperationKey{f.client.loaded.Registry.RegistryURL, testOrg, "process"})
	if err != nil {
		t.Fatal(err)
	}
	defer lease.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestFileFoundryStore_ProcessLockHelper$")
	command.Env = append(os.Environ(), "DNSID_FOUNDRY_LOCK_TEST_DIRECTORY="+f.store.directory)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("child lock: %v\n%s", err, output)
	}
}

func TestCreateConcurrentSameName(t *testing.T) {
	f := newFixture(t)
	var group sync.WaitGroup
	failures := make(chan error, 2)
	for range 2 {
		group.Go(func() { _, err := f.client.Create(context.Background(), "same"); failures <- err })
	}
	group.Wait()
	close(failures)
	for err := range failures {
		if err != nil {
			t.Fatal(err)
		}
	}
	if f.registry.createCalls != 1 {
		t.Fatal("concurrent same-name create duplicated registration")
	}
}

func TestFileFoundryStore_DefaultDirectory(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	if runtime.GOOS == "windows" {
		t.Setenv("USERPROFILE", home)
	}
	store, err := NewFileFoundryStore("")
	if err != nil {
		t.Fatal(err)
	}
	if store.directory != filepath.Join(home, ".dnsid", "foundry") {
		t.Fatal(store.directory)
	}
	if _, err := os.Stat(store.directory); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("constructor created state")
	}
}

func TestFileFoundryStore_RejectsUnsupportedStateWithoutMutation(t *testing.T) {
	for _, replacement := range []struct{ old, next string }{
		{`"schemaVersion":2`, `"schemaVersion":1`},
		{`"schemaVersion":2`, `"schemaVersion":3`},
		{`"identity-known"`, `"proof-pending"`},
		{`"identity-known"`, `"future"`},
	} {
		t.Run(replacement.next, func(t *testing.T) {
			f := newFixture(t)
			id, err := f.client.Create(context.Background(), "unsupported")
			if err != nil {
				t.Fatal(err)
			}
			good, err := f.document("unsupported").Export()
			if err != nil {
				t.Fatal(err)
			}
			publicBefore, err := json.Marshal(f.operational.JWK())
			if err != nil {
				t.Fatal(err)
			}
			rejected := bytes.Replace(good, []byte(replacement.old), []byte(replacement.next), 1)
			path := filepath.Join(f.store.directory, id.key.digest()+".json")
			if err := os.WriteFile(path, rejected, 0600); err != nil {
				t.Fatal(err)
			}
			for _, operation := range []func() error{
				func() error { _, err := f.client.Create(context.Background(), "unsupported"); return err },
				func() error { return f.store.Import(context.Background(), good) },
				func() error { return f.store.Import(context.Background(), rejected) },
			} {
				if err := operation(); err == nil {
					t.Fatal("unsupported state accepted")
				}
				after, err := os.ReadFile(path)
				if err != nil || !bytes.Equal(after, rejected) {
					t.Fatalf("unsupported state changed: %v", err)
				}
			}
			if f.registry.createCalls != 1 || f.registry.prepareCalls != 0 || !sameJSON(json.RawMessage(publicBefore), f.operational.JWK()) {
				t.Fatal("unsupported state caused registry or provider-key mutation")
			}
		})
	}
}

func TestRecoveryDocumentJCSOrderingAndUnicode(t *testing.T) {
	obj, err := decodeObject([]byte(`{"\ue000":1,"\ud83d\ude00":2,"text":"\u2028<&","zero":-0.0}`))
	if err != nil {
		t.Fatal(err)
	}
	data, err := canonical(obj)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Index(string(data), "😀") > strings.Index(string(data), "\ue000") {
		t.Fatal("keys are not ordered by UTF-16")
	}
	if !bytes.Contains(data, []byte("\u2028<&")) || !bytes.Contains(data, []byte(`"zero":0`)) {
		t.Fatalf("non-JCS JSON: %s", data)
	}
}
