package gcpkms_test

import (
	"testing"

	"github.com/dnsid-ai/dnsid-go/config"
	_ "github.com/dnsid-ai/dnsid-go/key/gcp"
)

// Mode: fake-only (no cloud credentials or service). Given an immutable existing
// GCP version, When validating selection, Then the supported selection is accepted.
// The linked provider validates immutable selection without opening a cloud key.
func TestGCPExistingVersionSelection(t *testing.T) {
	err := config.ValidateKeySource(config.KeySource{Provider: "google-kms", KeyRef: "projects/test-project/locations/global/keyRings/agents/cryptoKeys/signing/cryptoKeyVersions/1"})
	if err != nil {
		t.Fatalf("valid immutable GCP key selection rejected: %v", err)
	}
}
