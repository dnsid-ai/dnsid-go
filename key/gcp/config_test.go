package gcpkms_test

import (
	"github.com/dnsid-ai/dnsid-go/config"
	_ "github.com/dnsid-ai/dnsid-go/key/gcp"
	"testing"
)

// Mode: fake-only (no cloud credentials or service). Given an immutable existing
// GCP version, When validating selection, Then the supported selection is accepted.
// Authority: configuration-loading Operational Key Source Selection; #56.
// Baseline RED was captured without the optional provider import.
func TestGCPExistingVersionSelection(t *testing.T) {
	err := config.ValidateKeySource(config.KeySource{Provider: "google-kms", KeyRef: "projects/test-project/locations/global/keyRings/agents/cryptoKeys/signing/cryptoKeyVersions/1"})
	if err != nil {
		t.Fatalf("valid immutable GCP key selection rejected: %v", err)
	}
}
