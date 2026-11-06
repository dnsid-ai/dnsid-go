package config

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"log"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/lestrrat-go/jwx/v3/jwk"
)

// Mode: real-capable. Real deployment loading, persisted keys, construction and
// ES256 signing; no network. Guards known-foundry#57 / configuration section 12.
func TestConstruct_LocalWarningEveryStartup(t *testing.T) {
	if path := os.Getenv("DNSID_TEST_WARNING_DEPLOYMENT"); path != "" {
		// When a fresh application loads the existing deployment and constructs.
		loaded, err := LoadDeploymentFile(path)
		if err != nil {
			t.Fatal(err)
		}
		manager, err := Construct(context.Background(), loaded, Dependencies{})
		if err != nil {
			t.Fatal(err)
		}
		if got := activeKid(manager.KeyProvider()); got != os.Getenv("DNSID_TEST_WARNING_KID") {
			t.Fatalf("reopened kid = %q", got)
		}
		payload := []byte("startup signing proof")
		sig, err := manager.KeyProvider().Sign(payload)
		if err != nil {
			t.Fatal(err)
		}
		var pub ecdsa.PublicKey
		if err := jwk.Export(manager.KeyProvider().JWK(), &pub); err != nil {
			t.Fatal(err)
		}
		digest := sha256.Sum256(payload)
		if len(sig.Signature) != 64 || !ecdsa.Verify(&pub, digest[:], new(big.Int).SetBytes(sig.Signature[:32]), new(big.Int).SetBytes(sig.Signature[32:])) {
			t.Fatal("reopened operational key signature did not verify")
		}
		return
	}
	for _, provider := range []string{"", "file"} {
		name := provider
		if name == "" {
			name = "default"
		}
		t.Run(name, func(t *testing.T) {
			// Given an already provisioned local key and deployment (never recreated
			// between startups), for both default and explicit file selection.
			dir := t.TempDir()
			keyPath := filepath.Join(dir, "private.jwk")
			key := newKey(t, keyPath)
			path := filepath.Join(dir, "deployment.json")
			writeJSON(t, path, map[string]any{
				"dnsid":     map[string]any{"identity": map[string]any{"domain": "agent.example.com", "governanceId": "example.com", "statusUrl": "https://api.example.com/status", "logRef": "m:1"}},
				"keySource": KeySource{Provider: provider, KeyStorePath: keyPath},
			})
			before, err := os.ReadFile(keyPath)
			if err != nil {
				t.Fatal(err)
			}
			for startup := 1; startup <= 2; startup++ {
				cmd := exec.Command(os.Args[0], "-test.run=^TestConstruct_LocalWarningEveryStartup$")
				cmd.Env = append(os.Environ(), "DNSID_TEST_WARNING_DEPLOYMENT="+path, "DNSID_TEST_WARNING_KID="+activeKid(key))
				output, err := cmd.CombinedOutput()
				if err != nil {
					t.Fatalf("startup %d: %v\n%s", startup, err, output)
				}
				// Then each fresh startup emits the native production warning and cloud
				// guidance. No exact count within one process or fixed message/channel.
				text := strings.ToLower(string(output))
				if !strings.Contains(text, "warn") || !strings.Contains(text, "unsuitable for production") || !strings.Contains(text, "cloud") {
					t.Fatalf("startup %d missing local-key warning/cloud guidance:\n%s", startup, output)
				}
			}
			after, err := os.ReadFile(keyPath)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(before, after) {
				t.Fatal("startup changed the existing key store")
			}
		})
	}
}

// Capture the native Go logging sink without replacing key selection or warning
// emission. These tests are serial because the default logger is process-global.
func captureLocalWarnings(t *testing.T) *bytes.Buffer {
	t.Helper()
	var output bytes.Buffer
	previous := log.Writer()
	log.SetOutput(&output)
	t.Cleanup(func() { log.SetOutput(previous) })
	return &output
}

func assertNoLocalWarning(t *testing.T, output *bytes.Buffer) {
	t.Helper()
	if strings.Contains(strings.ToLower(output.String()), "unsuitable for production") {
		t.Fatalf("unexpected operational local-key warning:\n%s", output.String())
	}
}

// Mode: fake-only for the unavailable Google package; this is failure/no-fallback
// proof, not evidence of a working Google KMS implementation.
func TestConstruct_UnavailableGoogleHasNoLocalWarning(t *testing.T) {
	loaded := mustLoadEnv(t, fullIdentityEnv())
	loaded.KeySource = KeySource{Provider: "google-kms", KeyRef: "existing-key"}
	output := captureLocalWarnings(t)
	_, err := Construct(context.Background(), loaded, Dependencies{})
	wantArgumentError(t, err)
	if !strings.Contains(err.Error(), "google-kms") {
		t.Fatalf("provider error: %v", err)
	}
	assertNoLocalWarning(t, output)
}
