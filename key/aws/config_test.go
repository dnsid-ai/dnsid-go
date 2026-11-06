package awskms

import (
	"bytes"
	"context"
	"encoding/json"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	dnsid "github.com/dnsid-ai/dnsid-go"
	"github.com/dnsid-ai/dnsid-go/config"
)

func TestConfigFactory_OpensExistingKeys(t *testing.T) {
	const reference = "arn:aws:kms:us-east-1:123456789012:key/11111111-1111-4111-8111-111111111111"
	for _, test := range []struct {
		name      string
		algorithm string
		mismatch  bool
	}{
		{"default ES256", "", false},
		{"explicit ES256", "ES256", false},
		{"EdDSA", "EdDSA", false},
		{"different ARN", "ES256", true},
	} {
		t.Run(test.name, func(t *testing.T) {
			// Mode: fake-only for AWS (official client, loopback GetPublicKey);
			// real deployment loading and local entity key. No live KMS claim.
			var warnings bytes.Buffer
			previous := log.Writer()
			log.SetOutput(&warnings)
			defer log.SetOutput(previous)
			defer func() {
				if strings.Contains(strings.ToLower(warnings.String()), "unsuitable for production") {
					t.Errorf("AWS selection emitted local-key warning:\n%s", warnings.String())
				}
			}()
			fake := newFakeKMS(t, reference)
			wantAlgorithm := dnsid.JoseAlgES256
			if test.algorithm == "EdDSA" {
				fake = newFakeEd25519KMS(t, reference)
				wantAlgorithm = dnsid.JoseAlgEdDSA
			}
			public, err := fake.GetPublicKey(context.Background(), GetPublicKeyInput{KeyID: reference})
			if err != nil {
				t.Fatal(err)
			}
			if test.mismatch {
				public.KeyID = reference + "-different"
			}
			var calls atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				var input struct {
					KeyID string `json:"KeyId"`
				}
				if r.Header.Get("X-Amz-Target") != "TrentService.GetPublicKey" || json.NewDecoder(r.Body).Decode(&input) != nil || input.KeyID != reference {
					t.Error("factory must only fetch the configured existing key")
					w.WriteHeader(http.StatusBadRequest)
					return
				}
				w.Header().Set("Content-Type", "application/x-amz-json-1.1")
				if err := json.NewEncoder(w).Encode(map[string]any{
					"KeyId": public.KeyID, "PublicKey": public.PublicKey,
					"KeySpec": public.KeySpec, "KeyUsage": public.KeyUsage,
					"SigningAlgorithms": public.SigningAlgorithms,
				}); err != nil {
					t.Error(err)
				}
			}))
			defer server.Close()
			t.Setenv("AWS_ENDPOINT_URL_KMS", server.URL)
			t.Setenv("AWS_IGNORE_CONFIGURED_ENDPOINT_URLS", "false")
			t.Setenv("AWS_ACCESS_KEY_ID", "test")
			t.Setenv("AWS_SECRET_ACCESS_KEY", "test")
			t.Setenv("AWS_SESSION_TOKEN", "")
			t.Setenv("AWS_PROFILE", "")
			t.Setenv("AWS_CONFIG_FILE", filepath.Join(t.TempDir(), "missing"))
			t.Setenv("AWS_SHARED_CREDENTIALS_FILE", filepath.Join(t.TempDir(), "missing"))
			source := config.KeySource{Provider: "aws-kms", KeyRef: reference, Settings: map[string]string{"region": "us-east-1"}}
			if test.algorithm != "" {
				source.Settings["algorithm"] = test.algorithm
			}
			// Given a deployment selecting AWS with independent local entity keys.
			entityPath := filepath.Join(t.TempDir(), "entity.jwk")
			if _, err := dnsid.LoadOrCreateLocalKeyProvider(entityPath, dnsid.JoseAlgES256); err != nil {
				t.Fatal(err)
			}
			source.EntityKeyPath = entityPath
			path := filepath.Join(t.TempDir(), "deployment.json")
			document, err := json.Marshal(map[string]any{
				"dnsid":     map[string]any{"identity": map[string]any{"domain": "agent.example", "governanceId": "account.example", "statusUrl": "https://agent.example/status", "entityKeyUrl": "https://account.example/ek", "logRef": "m:1"}},
				"keySource": source,
			})
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, document, 0600); err != nil {
				t.Fatal(err)
			}
			loaded, err := config.LoadDeploymentFile(path)
			if err != nil {
				t.Fatal(err)
			}
			// When constructing through the actual configuration factory.
			manager, err := config.Construct(context.Background(), loaded, config.Dependencies{})
			var provider dnsid.KeyProvider
			if manager != nil {
				provider = manager.KeyProvider()
			}
			// Then key selection/failure is preserved, with no local operational warning.
			if test.mismatch {
				if err == nil || provider != nil {
					t.Fatal("factory accepted another immutable key reference")
				}
			} else {
				if err != nil {
					t.Fatal(err)
				}
				key := provider.JWK()
				kid, _ := key.KeyID()
				algorithm, _ := key.Algorithm()
				if kid != reference || algorithm.String() != string(wantAlgorithm) {
					t.Fatalf("loaded key = %s/%s", kid, algorithm)
				}
			}
			if calls.Load() != 1 {
				t.Fatalf("GetPublicKey calls = %d, want 1", calls.Load())
			}
		})
	}
}

func TestConfigFactory_ValidatesImmutableExistingKeys(t *testing.T) {
	const arn = "arn:aws:kms:us-east-1:123456789012:key/11111111-1111-4111-8111-111111111111"
	valid := config.KeySource{Provider: "aws-kms", KeyRef: arn, Settings: map[string]string{"region": "us-east-1", "algorithm": "ES256"}}
	if err := config.ValidateKeySource(valid); err != nil {
		t.Fatalf("factory was not registered: %v", err)
	}
	for _, invalid := range []config.KeySource{
		{Provider: "aws-kms", KeyRef: "alias/active"},
		{Provider: "aws-kms", KeyRef: arn, Settings: map[string]string{"algorithm": "RS256"}},
		{Provider: "aws-kms", KeyRef: arn, Settings: map[string]string{"accessKey": "secret"}},
	} {
		if err := config.ValidateKeySource(invalid); err == nil {
			t.Fatalf("accepted invalid settings: %#v", invalid)
		}
	}
}
