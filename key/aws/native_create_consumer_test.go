package awskms_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	dnsid "github.com/dnsid-ai/dnsid-go"
	awskms "github.com/dnsid-ai/dnsid-go/key/aws"
)

// Mode: fake-only for AWS: official kms.Client and SDKClient over loopback HTTP,
// not live cloud custody or protocol issuance. Core manager/provider are real.
// Given native KMS creation, When the caller uses the returned pending state and
// explicitly activates it, Then the manager publishes the independently known
// operational public key and its runtime signatures verify with that same key.
func TestCreate_NativeConsumer(t *testing.T) {
	for _, tc := range []struct {
		name                string
		badMetadata, denied bool
	}{
		{name: "manager operational JWKS"},
		{name: "invalid native key usage", badMetadata: true},
		{name: "native create denied", denied: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			private, public := firstFixture(t) // RFC8032 oracle, never obtained from provider.
			der, err := x509.MarshalPKIXPublicKey(public)
			if err != nil {
				t.Fatal(err)
			}
			payload := []byte("native first-key possession and application payload")
			var creates, reads, signs, unexpected atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				defer r.Body.Close()
				w.Header().Set("Content-Type", "application/x-amz-json-1.1")
				respond := func(value any) {
					if err := json.NewEncoder(w).Encode(value); err != nil {
						t.Error(err)
					}
				}
				switch r.Header.Get("X-Amz-Target") {
				case "TrentService.CreateKey":
					creates.Add(1)
					var in struct{ KeySpec, KeyUsage string }
					if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
						t.Error(err)
						w.WriteHeader(http.StatusBadRequest)
						return
					}
					if in.KeySpec != "ECC_NIST_EDWARDS25519" || in.KeyUsage != "SIGN_VERIFY" {
						t.Errorf("native CreateKey spec/usage = %q/%q", in.KeySpec, in.KeyUsage)
						w.WriteHeader(http.StatusBadRequest)
						return
					}
					if tc.denied {
						w.Header().Set("X-Amzn-Errortype", "AccessDeniedException")
						w.WriteHeader(http.StatusBadRequest)
						respond(map[string]any{"__type": "AccessDeniedException", "message": "fixture create denied"})
						return
					}
					// A bare ID alongside ARN ensures the public handoff prefers canonical ARN.
					respond(map[string]any{"KeyMetadata": map[string]any{"Arn": firstARN, "KeyId": "11111111-1111-4111-8111-111111111111", "KeySpec": "ECC_NIST_EDWARDS25519", "KeyUsage": "SIGN_VERIFY"}})
				case "TrentService.GetPublicKey":
					reads.Add(1)
					var in struct {
						KeyID string `json:"KeyId"`
					}
					if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
						t.Error(err)
						w.WriteHeader(http.StatusBadRequest)
						return
					}
					if in.KeyID != firstARN {
						t.Errorf("GetPublicKey reference = %q", in.KeyID)
						w.WriteHeader(http.StatusBadRequest)
						return
					}
					usage := "SIGN_VERIFY"
					if tc.badMetadata {
						usage = "ENCRYPT_DECRYPT"
					}
					respond(map[string]any{"KeyId": firstARN, "PublicKey": der, "KeySpec": "ECC_NIST_EDWARDS25519", "KeyUsage": usage, "SigningAlgorithms": []string{"ED25519_SHA_512"}})
				case "TrentService.Sign":
					signs.Add(1)
					var in struct {
						KeyID                         string `json:"KeyId"`
						Message                       []byte
						MessageType, SigningAlgorithm string
					}
					if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
						t.Error(err)
						w.WriteHeader(http.StatusBadRequest)
						return
					}
					if in.KeyID != firstARN || in.MessageType != "RAW" || in.SigningAlgorithm != "ED25519_SHA_512" || !bytes.Equal(in.Message, payload) {
						t.Errorf("native Sign did not preserve canonical reference, RAW Ed25519, and payload")
						w.WriteHeader(http.StatusBadRequest)
						return
					}
					respond(map[string]any{"KeyId": firstARN, "SigningAlgorithm": "ED25519_SHA_512", "Signature": ed25519.Sign(private, in.Message)})
				default:
					unexpected.Add(1) // Includes any destructive cleanup or unrelated API.
					t.Errorf("unexpected native API %q", r.Header.Get("X-Amz-Target"))
					w.WriteHeader(http.StatusBadRequest)
				}
			}))
			defer server.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			native := kms.New(kms.Options{
				Region: "us-east-1", BaseEndpoint: aws.String(server.URL), HTTPClient: server.Client(), RetryMaxAttempts: 1,
				Credentials: aws.CredentialsProviderFunc(func(context.Context) (aws.Credentials, error) {
					return aws.Credentials{AccessKeyID: "fixture", SecretAccessKey: "fixture"}, nil
				}),
			})
			// When: actual public creation through the official SDK adapter.
			provider, err := awskms.Create(ctx, awskms.SDKClient{Client: native}, firstConfig())
			if tc.denied || tc.badMetadata {
				if err == nil || provider != nil {
					t.Fatalf("native failure returned provider=%v err=%v", provider, err)
				}
				wantReads := int32(1)
				if tc.denied {
					wantReads = 0
				}
				if creates.Load() != 1 || reads.Load() != wantReads || signs.Load() != 0 || unexpected.Load() != 0 {
					t.Fatalf("failure calls create/read/sign/unexpected = %d/%d/%d/%d", creates.Load(), reads.Load(), signs.Load(), unexpected.Load())
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if provider == nil {
				t.Fatal("missing created provider")
			}
			state := provider.State()
			if state.ActiveKeyID != "" || !reflect.DeepEqual(state.PendingKeyIDs, []string{firstARN}) || len(state.RetainedKeyIDs) != 0 {
				t.Fatalf("not canonical pending handoff: %+v", state)
			}
			// Caller action uses the returned handoff, not the fixture's expected ID.
			kid := state.PendingKeyIDs[0]
			if provider.JWK() != nil || len(provider.ListKeyIds()) != 0 {
				t.Fatal("native create implicitly activated key")
			}
			if _, err := provider.Sign(payload); err == nil {
				t.Fatal("pending application signing allowed")
			}
			if signs.Load() != 0 {
				t.Fatal("pending application signing reached KMS")
			}
			firstJWK(t, provider.JWK(kid), firstARN, public)
			sig, err := provider.SignKey(kid, payload)
			firstSignature(t, sig, err, firstARN, payload, public)
			if err := provider.Activate(kid); err != nil {
				t.Fatal(err)
			}
			manager, err := dnsid.NewIdentityManager(dnsid.Config{Identity: &dnsid.IdentityConfig{
				Domain: "agent.example.com", GovernanceID: "example.com", StatusURL: "https://agent.example.com/status",
				KeyURL: "https://agent.example.com/jwks", EntityKeyURL: "https://example.com/entity-jwks",
				LogRef: "c2sp-tlog:public:https://log.example.com#issuance_AAAAAAAAAAAAAAAAAAAAAA",
			}}, provider)
			if err != nil {
				t.Fatal(err)
			}
			set := manager.GetKeySet()
			if set == nil || set.Raw().Len() != 1 {
				t.Fatal("manager must publish exactly one operational public key")
			}
			key, ok := set.Raw().Key(0)
			if !ok {
				t.Fatal("missing operational public key")
			}
			firstJWK(t, key, firstARN, public)
			sig, err = manager.KeyProvider().Sign(payload)
			firstSignature(t, sig, err, firstARN, payload, public)
			if creates.Load() != 1 || reads.Load() != 1 || signs.Load() != 2 || unexpected.Load() != 0 {
				t.Fatalf("success calls create/read/sign/unexpected = %d/%d/%d/%d", creates.Load(), reads.Load(), signs.Load(), unexpected.Load())
			}
		})
	}
}
