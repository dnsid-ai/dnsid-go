package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/dnsid-ai/dnsid-go/config"
	"github.com/dnsid-ai/dnsid-go/registration"
)

func TestRun_DisabledUntilServerIntegrationChecksPass(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "new-setup")
	err := run(context.Background(), "must-not-read.json", directory, "test-token")
	if err == nil || !strings.Contains(err.Error(), "disabled") {
		t.Fatalf("enabled unverified server contract: %v", err)
	}
	if _, err := os.Stat(directory); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("created state before server readiness: %v", err)
	}
}

func TestRun_RejectsInvalidTokenBeforeSetup(t *testing.T) {
	for _, token := range []string{"", "two tokens", "token\n"} {
		if err := run(context.Background(), "", "", token); err == nil {
			t.Fatalf("accepted token %q", token)
		}
	}
}

func TestSDK_RejectsLegacyRecoveryWithoutReplacingKey(t *testing.T) {
	directory := t.TempDir()
	if err := os.Chmod(directory, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "recovery.json")
	const legacy = `{"registration_key":"original-request","issuance_key":"original-issuance"}`
	if err := os.WriteFile(path, []byte(legacy), 0600); err != nil {
		t.Fatal(err)
	}
	loaded := config.Loaded{
		Registry:     config.Registry{RegistryURL: registryURL},
		LogTrust:     config.LogTrust{Managed: true},
		Registration: config.ManagedRegistrationConfig{OrganizationID: "original-org", GovernanceID: "dev.dnsid.ai", EntityKeyURL: "https://dnsid.dev.dnsid.ai/.well-known/dnsid-ek.json"},
	}
	_, err := registration.RegisterManagedIdentity(context.Background(), identityName, loaded, "test-token", registration.NewFileRegistrationStore(directory), nil)
	var setup *registration.Error
	if !errors.As(err, &setup) || setup.Phase != "recovery" || setup.Code != "store" {
		t.Fatalf("unexpected error: %v", err)
	}
	data, readErr := os.ReadFile(path)
	if readErr != nil || string(data) != legacy {
		t.Fatalf("changed original recovery: %s, %v", data, readErr)
	}
	entries, readErr := os.ReadDir(directory)
	if readErr != nil || len(entries) != 1 {
		t.Fatal("created replacement state/key")
	}
}
