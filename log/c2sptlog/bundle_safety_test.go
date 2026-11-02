package c2sptlog

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"golang.org/x/mod/sumdb/note"
)

func TestVerifyStreamBundle_RejectsCheckpointExpansion(t *testing.T) {
	v := loadStreamBundleVector(t)
	object, err := decodeJSONObject([]byte(v.Bundle))
	if err != nil {
		t.Fatal(err)
	}
	checkpoint, err := base64.RawURLEncoding.DecodeString(object["checkpoint"].(string))
	if err != nil {
		t.Fatal(err)
	}
	// Unknown signatures do not change the signed checkpoint body or the head.
	checkpoint = append(checkpoint, []byte("— unknown.example "+base64.StdEncoding.EncodeToString(make([]byte, 64<<10))+"\n")...)
	object["checkpoint"] = base64.RawURLEncoding.EncodeToString(checkpoint)
	events := make([]any, defaultMaxStreamBundleEvents)
	for i := range events {
		events[i] = map[string]any{"index": i, "entry": "AA", "proof": ""}
	}
	object["events"] = events
	data, err := json.Marshal(object)
	if err != nil {
		t.Fatal(err)
	}
	if len(data) > defaultMaxStreamBundleBytes {
		t.Fatal("attack fixture exceeds the input limit")
	}
	verifier, err := note.NewVerifier(v.Trust.BundleVerifierKey)
	if err != nil {
		t.Fatal(err)
	}
	_, err = VerifyStreamBundle(context.Background(), data, StreamBundleTrust{
		PolicyDocument:    []byte(v.Policy),
		BundleVerifier:    verifier,
		Now:               func() time.Time { return time.Unix(v.Trust.Now, 0) },
		MaxBundleLifetime: time.Duration(v.Trust.MaxBundleLifetime) * time.Millisecond,
		MaxCheckpointAge:  time.Duration(v.Trust.CheckpointFreshness) * time.Millisecond,
	})
	if err == nil || !strings.Contains(err.Error(), "reconstructed history exceeds byte limit") {
		t.Fatalf("checkpoint expansion error = %v", err)
	}
}

func TestVerifyStreamBundle_IgnoresUnrelatedEntriesButRequiresTheirProofs(t *testing.T) {
	for name, mutate := range map[string]func(map[string]any){
		"other stream": func(p map[string]any) { p["stream_id"] = "other" },
		"other domain": func(p map[string]any) { p["fqdn"] = "other.example" },
		"other kind":   func(p map[string]any) { p["kind"] = "other" },
	} {
		t.Run(name, func(t *testing.T) {
			v := streamBundleWithCopies(t, func(entries [][]byte) {
				entries[2] = canonicalEntryMutation(t, string(entries[1]), mutate)
			})
			verifier, err := note.NewVerifier(v.Trust.BundleVerifierKey)
			if err != nil {
				t.Fatal(err)
			}
			trust := StreamBundleTrust{
				PolicyDocument:    []byte(v.Policy),
				BundleVerifier:    verifier,
				Now:               func() time.Time { return time.Unix(v.Trust.Now, 0) },
				MaxBundleLifetime: time.Duration(v.Trust.MaxBundleLifetime) * time.Millisecond,
				MaxCheckpointAge:  time.Duration(v.Trust.CheckpointFreshness) * time.Millisecond,
			}
			verified, err := VerifyStreamBundle(context.Background(), []byte(v.Bundle), trust)
			if err != nil {
				t.Fatal(err)
			}
			if len(verified.Events) != 2 {
				t.Fatalf("applied events = %d, want 2", len(verified.Events))
			}
			object, err := decodeJSONObject([]byte(v.Bundle))
			if err != nil {
				t.Fatal(err)
			}
			entry := object["events"].([]any)[2].(map[string]any)
			proof, err := base64.RawURLEncoding.DecodeString(entry["proof"].(string))
			if err != nil {
				t.Fatal(err)
			}
			proof[0] ^= 1
			entry["proof"] = base64.RawURLEncoding.EncodeToString(proof)
			data, err := json.Marshal(object)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := VerifyStreamBundle(context.Background(), data, trust); err == nil || !strings.Contains(err.Error(), "inclusion") {
				t.Fatalf("unrelated entry's invalid proof error = %v", err)
			}
		})
	}
}

func TestStreamHeadTrust_RejectsRenamedCheckpointKeys(t *testing.T) {
	v := loadStreamBundleVector(t)
	for name, seedByte := range map[string]byte{"log": 4, "witness": 5, "independent": 6} {
		t.Run(name, func(t *testing.T) {
			seed := bytes.Repeat([]byte{seedByte}, ed25519.SeedSize)
			public := ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)
			key, err := note.NewEd25519VerifierKey("indexer.example", public)
			if err != nil {
				t.Fatal(err)
			}
			verifier, err := note.NewVerifier(key)
			if err != nil {
				t.Fatal(err)
			}
			object, err := decodeJSONObject([]byte(v.Bundle))
			if err != nil {
				t.Fatal(err)
			}
			head, err := testBundleHead(t, object).MarshalText()
			if err != nil {
				t.Fatal(err)
			}
			object["head"] = signTestNote(t, "indexer.example", seed, head)
			data, err := json.Marshal(object)
			if err != nil {
				t.Fatal(err)
			}
			_, bundleErr := VerifyStreamBundle(context.Background(), data, StreamBundleTrust{
				PolicyDocument:    []byte(v.Policy),
				BundleVerifier:    verifier,
				Now:               func() time.Time { return time.Unix(v.Trust.Now, 0) },
				MaxBundleLifetime: time.Duration(v.Trust.MaxBundleLifetime) * time.Millisecond,
				MaxCheckpointAge:  time.Duration(v.Trust.CheckpointFreshness) * time.Millisecond,
			})
			_, registryErr := NewVerificationRegistry(context.Background(), VerificationRegistryConfig{
				PolicyDocument:    []byte(v.Policy),
				BundleVerifiers:   []note.Verifier{verifier},
				MaxBundleLifetime: time.Minute,
			})
			for path, err := range map[string]error{"offline": bundleErr, "registry": registryErr} {
				if name == "independent" {
					if err != nil {
						t.Errorf("%s rejected an independent key: %v", path, err)
					}
				} else if err == nil || !strings.Contains(err.Error(), "independent") {
					t.Errorf("%s key independence error = %v", path, err)
				}
			}
		})
	}
}
