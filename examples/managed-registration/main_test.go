package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	dnsid "github.com/dnsid-ai/dnsid-go"
	"github.com/dnsid-ai/dnsid-go/log/c2sptlog"
)

func TestLoadState_PreservesRequestAndRequiresOriginalKey(t *testing.T) {
	directory := t.TempDir()
	initial, key, err := loadState(directory)
	if err != nil {
		t.Fatal(err)
	}
	initial.Issuance = &c2sptlog.ManagedIssuanceState{Domain: "agent.sandbox.dev.dnsid.ai", EntryBytes: []byte("exact completed bytes")}
	path := filepath.Join(directory, "recovery.json")
	store := &issuanceStore{path: path, state: initial}
	if err := store.PersistManagedIssuance(context.Background(), initial.Issuance); err != nil {
		t.Fatal(err)
	}
	resumed, resumedKey, err := loadState(directory)
	if err != nil {
		t.Fatal(err)
	}
	initialKid, _ := key.JWK().KeyID()
	resumedKid, _ := resumedKey.JWK().KeyID()
	if initial.RegistrationKey != resumed.RegistrationKey || initial.IssuanceKey != resumed.IssuanceKey || initialKid != resumedKid || !bytes.Equal(initial.Issuance.EntryBytes, resumed.Issuance.EntryBytes) {
		t.Fatal("changed recovery facts")
	}
	if resumed.Input.Environment != "sandbox" || resumed.Input.Name != "" {
		t.Fatal("unexpected registration selectors")
	}
	resumedStore := &issuanceStore{path: path, state: resumed}
	existing, err := resumedStore.CreateManagedIssuance(context.Background(), &c2sptlog.ManagedIssuanceState{Domain: "replacement"})
	if err != nil || existing.Domain != initial.Issuance.Domain {
		t.Fatal("replaced durable operation")
	}
	if _, err := resumedStore.LoadManagedIssuance(context.Background(), "other.domain"); err == nil {
		t.Fatal("accepted wrong domain")
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm()&0077 != 0 {
		t.Fatal("state is not owner-only")
	}
	keyPath := filepath.Join(directory, "operational-key.json")
	if err := os.Remove(keyPath); err != nil {
		t.Fatal(err)
	}
	if _, _, err := loadState(directory); err == nil {
		t.Fatal("replaced missing registered private key")
	}
	if _, err := os.Stat(keyPath); !os.IsNotExist(err) {
		t.Fatal("created a replacement key")
	}
}

func TestRetryRead_FailsImmediatelyOnIntegrityFailure(t *testing.T) {
	calls := 0
	failure := dnsid.NewVerificationError(dnsid.VerificationCodeRecordInvalid, false, "invalid signature", nil)
	err := retryRead(context.Background(), func() error { calls++; return failure })
	if !errors.Is(err, failure) || calls != 1 {
		t.Fatalf("calls=%d err=%v", calls, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err = retryRead(ctx, func() error {
		return dnsid.NewVerificationError(dnsid.VerificationCodeDNSResolution, false, "DNS not visible", nil)
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatal("ignored read deadline")
	}
}

func TestRun_RejectsChangedOperationalKeyBeforeNetwork(t *testing.T) {
	directory := t.TempDir()
	if err := os.Chmod(directory, 0700); err != nil {
		t.Fatal(err)
	}
	s, _, err := loadState(directory)
	if err != nil {
		t.Fatal(err)
	}
	s.Input.PublicKeyJWK = dnsid.GenerateEd25519KeyProvider().JWK()
	if err := saveState(filepath.Join(directory, "recovery.json"), s); err != nil {
		t.Fatal(err)
	}
	if err := run(context.Background(), directory, "test-token"); err == nil || err.Error() != "saved registration and operational key do not match" {
		t.Fatalf("unexpected error: %v", err)
	}
}
