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

	"github.com/aws/aws-sdk-go-v2/service/kms/types"
	dnsid "github.com/dnsid-ai/dnsid-go"
	"github.com/dnsid-ai/dnsid-go/config"
)

// Regional configuration preserves exact ARN binding. Mode: real-capable (AWS=loopback fake); mismatched response: fake-only.
func TestConfigFactory_RegionalEd25519Binding(t *testing.T) {
	for _, region := range []string{"us-east-1", "us-west-2"} {
		reference := "arn:aws:kms:" + region + ":123456789012:key/mrk-0123456789abcdef0123456789abcdef"
		for _, test := range []struct {
			name     string
			mismatch bool
		}{

			{"EdDSA", false},
			{"different ARN", true},
		} {
			t.Run(region+"/"+test.name, func(t *testing.T) {
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
				fake := newFakeEd25519KMS(t, reference)
				wantAlgorithm := dnsid.JoseAlgEdDSA
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
				source := config.KeySource{Provider: "aws-kms", KeyRef: reference, Settings: map[string]string{"region": region, "algorithm": "EdDSA"}}
				// Given a deployment selecting AWS with independent local entity keys.
				entityPath := filepath.Join(t.TempDir(), "entity.jwk")
				if _, err := dnsid.LoadOrCreateLocalKeyProvider(entityPath, dnsid.JoseAlgES256); err != nil {
					t.Fatal(err)
				}
				source.EntityKeyPath = entityPath
				path := filepath.Join(t.TempDir(), "deployment.json")
				document, err := json.Marshal(map[string]any{
					"dnsid":     map[string]any{"identity": map[string]any{"domain": "agent.example", "governanceId": "account.example", "statusUrl": "https://agent.example/status", "keyUrl": "https://agent.example/keys", "entityKeyUrl": "https://account.example/ek", "logRef": "m:1"}},
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
				// Establish publication before configuration startup with the independent
				// fixture provider. Startup itself still opens the official AWS client.
				algorithm := types.SigningAlgorithmSpecEd25519Sha512
				fixtureProvider, err := New(context.Background(), fake, Config{State: State{ActiveKeyID: reference}, Algorithm: algorithm})
				if err != nil {
					t.Fatal(err)
				}
				deps := setupAWSPublication(t, loaded.Dnsid, fixtureProvider)
				// When constructing through the actual configuration factory.
				manager, err := config.Construct(context.Background(), loaded, deps)
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
}
