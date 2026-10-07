package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/dnsid-ai/dnsid-go/registration"
)

func TestRun_RequiresVerifiedServerContractBeforeEffects(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "new-setup")
	if err := run(context.Background(), directory, "test-token", false); err == nil {
		t.Fatal("enabled automatic recovery without a verified server contract")
	}
	if _, err := os.Stat(directory); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("created state before contract confirmation: %v", err)
	}
}

func TestRun_RejectsInvalidTokenBeforeSetup(t *testing.T) {
	for _, token := range []string{"", "two tokens", "token\n"} {
		if err := run(context.Background(), "", token, true); err == nil {
			t.Fatalf("accepted token %q", token)
		}
	}
}

func TestRun_RejectsDifferentRegistry(t *testing.T) {
	t.Setenv("DNSID_REGISTRY_URL", "https://other.example")
	if err := run(context.Background(), "", "test-token", true); err == nil || err.Error() != "this example supports only the dev registry" {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestRun_RejectsLegacyRecoveryWithoutReplacingKey(t *testing.T) {
	t.Setenv("DNSID_REGISTRY_URL", "")
	directory := t.TempDir()
	if err := os.Chmod(directory, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "recovery.json")
	const legacy = `{"registration_key":"original-request","issuance_key":"original-issuance"}`
	if err := os.WriteFile(path, []byte(legacy), 0600); err != nil {
		t.Fatal(err)
	}
	err := run(context.Background(), directory, "test-token", true)
	var setup *registration.Error
	if !errors.As(err, &setup) || setup.Phase != "recovery" || setup.Code != "store" {
		t.Fatalf("unexpected error: %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil || string(data) != legacy {
		t.Fatalf("changed original recovery: %s, %v", data, err)
	}
	if _, err := os.Stat(filepath.Join(directory, "operational-key.json")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("created a replacement key: %v", err)
	}
}
