package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	dnsid "github.com/dnsid-ai/dnsid-go"
	"github.com/dnsid-ai/dnsid-go/config"
	dnsidlog "github.com/dnsid-ai/dnsid-go/log"
)

func TestAWSDeployment_ConstructAndSign(t *testing.T) {
	const arn = "arn:aws:kms:us-east-1:123456789012:key/11111111-1111-4111-8111-111111111111"
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	public, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	var reads, signs atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var input struct {
			KeyID            string `json:"KeyId"`
			Message          []byte
			MessageType      string
			SigningAlgorithm string
		}
		if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
			t.Error(err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		auth := r.Header.Get("Authorization")
		if input.KeyID != arn || !strings.HasPrefix(auth, "AWS4-HMAC-SHA256 Credential=test/") || !strings.Contains(auth, "/us-east-1/kms/aws4_request") {
			t.Error("SDK did not use the configured key, region, and ambient test credentials")
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/x-amz-json-1.1")
		var response any
		switch r.Header.Get("X-Amz-Target") {
		case "TrentService.GetPublicKey":
			reads.Add(1)
			response = map[string]any{
				"KeyId": arn, "PublicKey": public, "KeySpec": "ECC_NIST_P256",
				"KeyUsage": "SIGN_VERIFY", "SigningAlgorithms": []string{"ECDSA_SHA_256"},
			}
		case "TrentService.Sign":
			signs.Add(1)
			if input.MessageType != "RAW" || input.SigningAlgorithm != "ECDSA_SHA_256" {
				t.Error("unexpected signing mode")
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			digest := sha256.Sum256(input.Message)
			signature, err := ecdsa.SignASN1(rand.Reader, key, digest[:])
			if err != nil {
				t.Error(err)
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			response = map[string]any{"KeyId": arn, "Signature": signature, "SigningAlgorithm": "ECDSA_SHA_256"}
		default:
			t.Error("unexpected KMS operation; only GetPublicKey and Sign are allowed")
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if err := json.NewEncoder(w).Encode(response); err != nil {
			t.Error(err)
		}
	}))
	defer server.Close()
	for name, value := range map[string]string{
		"AWS_ENDPOINT_URL_KMS": server.URL, "AWS_IGNORE_CONFIGURED_ENDPOINT_URLS": "false",
		"AWS_ACCESS_KEY_ID": "test", "AWS_SECRET_ACCESS_KEY": "test", "AWS_SESSION_TOKEN": "",
		"AWS_PROFILE": "", "AWS_EC2_METADATA_DISABLED": "true",
		"AWS_CONFIG_FILE":             filepath.Join(t.TempDir(), "missing"),
		"AWS_SHARED_CREDENTIALS_FILE": filepath.Join(t.TempDir(), "missing"),
	} {
		t.Setenv(name, value)
	}

	data, err := os.ReadFile("deployment.aws.json")
	if err != nil {
		t.Fatal(err)
	}
	document := strings.ReplaceAll(string(data), "<immutable signing-key ARN>", arn)
	document = strings.ReplaceAll(document, "<persisted lifecycle-log reference>", "c2sp-tlog:public:https://log.dnsid.ai#issuance_AAAAAAAAAAAAAAAAAAAAAA")
	path := filepath.Join(t.TempDir(), "deployment.json")
	if err := os.WriteFile(path, []byte(document), 0600); err != nil {
		t.Fatal(err)
	}
	loaded, err := config.LoadDeploymentFile(path)
	if err != nil {
		t.Fatal(err)
	}
	// Isolate provider loading from log/publication verification in this test.
	manager, err := config.Construct(context.Background(), loaded, config.Dependencies{LogRegistry: dnsidlog.NewLogRegistry()})
	if err != nil {
		t.Fatal(err)
	}
	current, err := manager.GetKeySet().CurrentOperationalSigningKey(dnsid.DefaultPublishProfile)
	if err != nil || current.Kid() != arn || current.Alg() != dnsid.JoseAlgES256 {
		t.Fatalf("loaded operational key = %v, error = %v", current, err)
	}
	message := []byte("deployment example signing check")
	signature, err := manager.KeyProvider().Sign(message)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(message)
	if signature.Kid != arn || signature.Alg != dnsid.JoseAlgES256 || len(signature.Signature) != 64 {
		t.Fatal("unexpected ES256 signature metadata or encoding")
	}
	if !ecdsa.Verify(&key.PublicKey, digest[:], new(big.Int).SetBytes(signature.Signature[:32]), new(big.Int).SetBytes(signature.Signature[32:])) {
		t.Fatal("KMS signature did not verify with the loaded public key")
	}
	if reads.Load() != 1 || signs.Load() != 1 {
		t.Fatalf("KMS calls: GetPublicKey=%d Sign=%d, want one each", reads.Load(), signs.Load())
	}
}
