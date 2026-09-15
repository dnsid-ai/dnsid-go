package c2sptlog

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	dnsid "github.com/dnsid-ai/dnsid-go"
	dnsidlog "github.com/dnsid-ai/dnsid-go/log"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"golang.org/x/mod/sumdb/note"
)

type randomES256Provider struct {
	dnsid.KeyProvider
	private *ecdsa.PrivateKey
}

func newRandomES256Provider(t *testing.T) *randomES256Provider {
	t.Helper()
	private, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	key, err := jwk.Import(private)
	if err != nil {
		t.Fatal(err)
	}
	if err := key.Set(jwk.AlgorithmKey, "ES256"); err != nil {
		t.Fatal(err)
	}
	thumb, err := thumbprint(key)
	if err != nil {
		t.Fatal(err)
	}
	if err := key.Set(jwk.KeyIDKey, thumb); err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(key)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "key.jwk")
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	provider, err := dnsid.NewLocalKeyProvider(path)
	if err != nil {
		t.Fatal(err)
	}
	return &randomES256Provider{provider, private}
}
func (p *randomES256Provider) Sign(payload []byte) (*dnsid.KeySignature, error) {
	digest := sha256.Sum256(payload)
	r, s, err := ecdsa.Sign(rand.Reader, p.private, digest[:])
	if err != nil {
		return nil, err
	}
	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	s.FillBytes(sig[32:])
	kid, _ := p.JWK().KeyID()
	return &dnsid.KeySignature{Kid: kid, Alg: dnsid.JoseAlgES256, Signature: sig}, nil
}

func TestEventIdentity_GoldenHashes(t *testing.T) {
	data, err := os.ReadFile("testdata/c2sp-event-identity.json")
	if err != nil {
		t.Fatal(err)
	}
	var vectors struct {
		Vectors []struct {
			Domain, Canonical, Hash string
			Value                   json.RawMessage
		}
	}
	if err := json.Unmarshal(data, &vectors); err != nil {
		t.Fatal(err)
	}
	for _, v := range vectors.Vectors {
		object, err := decodeJSONObject(v.Value)
		if err != nil {
			t.Fatal(err)
		}
		canonical, err := canonicalJSON(object)
		if err != nil {
			t.Fatal(err)
		}
		if string(canonical) != v.Canonical {
			t.Fatal("canonical mismatch")
		}
		got := EventID(canonical)
		if v.Domain == "state" {
			got = lifecycleStateHash(object)
		}
		if got != v.Hash {
			t.Fatalf("%s hash=%s, want %s", v.Domain, got, v.Hash)
		}
	}
}

func signLogical(t *testing.T, c *Client, event dnsidlog.LogEvent, chain Chain, keys ...dnsid.KeyProvider) string {
	t.Helper()
	prepared, err := c.PrepareEventWithChain(event, chain)
	if err != nil {
		t.Fatal(err)
	}
	sigs := map[string]any{}
	for i, role := range prepared.RequiredSignatures() {
		sig, err := keys[i].Sign(prepared.SignedBytes())
		if err != nil {
			t.Fatal(err)
		}
		sigs[signatureName(role)] = map[string]any{"kid": sig.Kid, "sig": base64.RawURLEncoding.EncodeToString(sig.Signature)}
	}
	prepared.envelope["sigs"] = sigs
	entry, err := canonicalJSON(prepared.envelope)
	if err != nil {
		t.Fatal(err)
	}
	return string(entry)
}

func es256Copy(t *testing.T, entry string) string {
	t.Helper()
	return string(canonicalEntryMutation(t, entry, func(payload map[string]any) {
		for _, v := range payload["sigs"].(map[string]any) {
			sig := v.(map[string]any)
			b, err := base64.RawURLEncoding.DecodeString(sig["sig"].(string))
			if err != nil || len(b) != 64 {
				t.Fatal("invalid ES256 fixture")
			}
			s := new(big.Int).SetBytes(b[32:])
			s.Sub(elliptic.P256().Params().N, s)
			s.FillBytes(b[32:])
			sig["sig"] = base64.RawURLEncoding.EncodeToString(b)
		}
	}))
}

type occurrenceSource struct{ memorySource }

func (s occurrenceSource) ReadEvent(_ context.Context, ref dnsidlog.LogRef) (ProvenEntry, error) {
	_, index, err := ParseFinalEventRef(ref)
	if err != nil {
		return ProvenEntry{}, err
	}
	for _, e := range s.entries {
		if e.Index == index {
			return e, nil
		}
	}
	return ProvenEntry{}, errors.New("missing occurrence")
}

func TestLogicalIdentity_ES256ReplayAndHistoricalForks(t *testing.T) {
	for _, scope := range []string{"public", "testnet", "private-test"} {
		t.Run(scope, func(t *testing.T) {
			lr := "c2sp-tlog:" + scope + ":https://log.example#instance-01"
			writer, err := New(lr)
			if err != nil {
				t.Fatal(err)
			}
			entity, op, next := newRandomES256Provider(t), newRandomES256Provider(t), newRandomES256Provider(t)
			entityThumb, _ := thumbprint(entity.JWK())
			opThumb, _ := thumbprint(op.JWK())
			nextThumb, _ := thumbprint(next.JWK())
			issuance := dnsidlog.LogEvent{Type: dnsidlog.LogEventIssuance, Domain: "agent.example", GovernanceID: "example", Timestamp: time.Unix(1782172800, 0), InitialEntityPublicKey: entity.JWK(), InitialOperationalPublicKey: op.JWK()}
			first := signLogical(t, writer, issuance, Chain{}, entity, op)
			firstSigned, _ := CanonicalFromEntry([]byte(first))
			chain := Chain{Sequence: 1, PreviousEventID: EventID(firstSigned), PreviousStateHash: lifecycleStateHash(activeLifecycleState("agent.example", entityThumb, opThumb))}
			rotation := dnsidlog.LogEvent{Type: dnsidlog.LogEventKeyRotation, Domain: "agent.example", Timestamp: issuance.Timestamp.Add(time.Hour), PreviousOperationalThumbprint: opThumb, NewOperationalPublicKey: next.JWK(), NewOperationalThumbprint: nextThumb}
			second := signLogical(t, writer, rotation, chain, op, next)
			secondSigned, _ := CanonicalFromEntry([]byte(second))
			terminal := dnsidlog.LogEvent{Type: dnsidlog.LogEventRevocation, Domain: "agent.example", Timestamp: rotation.Timestamp.Add(time.Hour), Reason: "keyCompromise"}
			third := signLogical(t, writer, terminal, Chain{Sequence: 2, PreviousEventID: EventID(secondSigned), PreviousStateHash: lifecycleStateHash(activeLifecycleState("agent.example", entityThumb, nextThumb))}, entity)
			copy := es256Copy(t, first)
			if LeafHash([]byte(copy)) == LeafHash([]byte(first)) {
				t.Fatal("signature copy must have different leaf hash")
			}
			signed, _ := CanonicalFromEntry([]byte(copy))
			if EventID(signed) != EventID(firstSigned) {
				t.Fatal("copy changed logical identity")
			}
			resigned := signLogical(t, writer, issuance, Chain{}, entity, op)
			if resigned == first {
				t.Fatal("expected independently randomized ECDSA signatures")
			}
			bad := string(canonicalEntryMutation(t, second, func(p map[string]any) { p["sigs"].(map[string]any)["new_op"].(map[string]any)["sig"] = "AA" }))
			stripped := string(canonicalEntryMutation(t, second, func(p map[string]any) { delete(p["sigs"].(map[string]any), "new_op") }))
			build := func(entries ...string) *Client {
				source := occurrenceSource{memorySource: memorySource{complete: true, freshness: terminal.Timestamp.Add(time.Second)}}
				for i, e := range entries {
					source.entries = append(source.entries, ProvenEntry{Index: uint64(i), Entry: []byte(e)})
				}
				c, err := New(lr, WithSource(source), withProofVerifySkipped())
				if err != nil {
					t.Fatal(err)
				}
				return c
			}
			reader := build(copy, first, resigned, bad, stripped, second, third, es256Copy(t, second), es256Copy(t, third), bad)
			history, err := reader.RebuildHistory(context.Background(), "agent.example")
			if err != nil || len(history) != 3 {
				t.Fatalf("replay history=%v, %v", history, err)
			}
			accepted, _, err := reader.rebuildVerifiedHistory(context.Background(), "agent.example")
			if err != nil || accepted[0].index != 0 || accepted[1].index != 5 {
				t.Fatalf("first occurrence moved: %v (%d, %d)", err, accepted[0].index, accepted[1].index)
			}
			if _, err := reader.ReadEvent(context.Background(), reader.ref.FinalEventRef(7)); err != nil {
				t.Fatalf("valid later signed copy: %v", err)
			}
			if _, err := reader.ReadEvent(context.Background(), reader.ref.FinalEventRef(9)); err == nil {
				t.Fatal("invalid signed copy returned as valid occurrence")
			}
			collision := rotation
			collision.NewOperationalPublicKey = entity.JWK()
			collision.NewOperationalThumbprint = entityThumb
			collisionEntry := signLogical(t, writer, collision, chain, op, entity)
			if _, err := build(first, collisionEntry).RebuildHistory(context.Background(), "agent.example"); err == nil {
				t.Fatal("rotation reused entity key as operational key")
			}
			fork := rotation
			fork.Timestamp = fork.Timestamp.Add(time.Second)
			forkEntry := signLogical(t, writer, fork, chain, op, next)
			for _, entries := range [][]string{{first, second, forkEntry}, {first, second, third, forkEntry}} {
				if _, err := build(entries...).RebuildHistory(context.Background(), "agent.example"); err == nil {
					t.Fatal("historical-key fork or new terminal conflict hidden")
				}
			}
			for _, field := range []string{"prev_index", "prev_leaf_hash", "event_id", "seq", "prev_event_id"} {
				payload, _ := payloadObjectFromEntry([]byte(second))
				payload[field] = "invalid"
				delete(payload, "sigs")
				signed, err := canonicalJSON(payload)
				if err != nil {
					t.Fatal(err)
				}
				sigs := map[string]any{}
				for i, key := range []dnsid.KeyProvider{op, next} {
					sig, _ := key.Sign(signed)
					role := []string{"prev_op", "new_op"}[i]
					sigs[role] = map[string]any{"kid": sig.Kid, "sig": base64.RawURLEncoding.EncodeToString(sig.Signature)}
				}
				payload["sigs"] = sigs
				entry, _ := canonicalJSON(payload)
				if _, err := build(first, string(entry)).RebuildHistory(context.Background(), "agent.example"); err == nil {
					t.Fatalf("authenticated bad %s hidden", field)
				}
			}
		})
	}
}

func TestRebuildHistory_MalformedKeysDoNotPanic(t *testing.T) {
	for _, tc := range []struct{ entry, key string }{
		{issuanceEntry, "ek"}, {issuanceEntry, "ku"}, {keyRotationEntry, "new_ku"},
	} {
		t.Run(tc.key, func(t *testing.T) {
			bad := canonicalEntryMutation(t, tc.entry, func(p map[string]any) { delete(p, tc.key) })
			reader, err := New("c2sp-tlog:testnet:http://dnsid-ledger:8080/log#identity-01", WithSource(globalMemorySource{memorySource{entries: []ProvenEntry{
				{Index: 0, Entry: bad}, {Index: 1, Entry: []byte(issuanceEntry)}, {Index: 2, Entry: bad}, {Index: 3, Entry: []byte(keyRotationEntry)},
			}}}), withProofVerifySkipped())
			if err != nil {
				t.Fatal(err)
			}
			if _, err := LogEventFromEntry(bad); err == nil {
				t.Fatal("malformed key accepted by parser")
			}
			if _, err := reader.ParsePreparedEvent(bad); err == nil {
				t.Fatal("malformed key accepted for signing")
			}
			history, err := reader.RebuildHistory(context.Background(), "agent.example")
			if err != nil || len(history) != 2 {
				t.Fatalf("malformed key was not ignored safely: %v, %v", history, err)
			}
		})
	}
}

func TestRebuildHistory_AuthenticatesBeforeRejectingSemanticErrors(t *testing.T) {
	for _, value := range []any{nil, -1, "invalid"} {
		payload, err := payloadObjectFromEntry([]byte(revocationEntry))
		if err != nil {
			t.Fatal(err)
		}
		payload["ts"] = value
		entry := signFixturePayload(payload)
		for _, signed := range []bool{true, false} {
			candidate := []byte(entry)
			if !signed {
				candidate = canonicalEntryMutation(t, entry, func(p map[string]any) { p["sigs"].(map[string]any)["ae"].(map[string]any)["sig"] = "AA" })
			}
			reader, err := New("c2sp-tlog:testnet:http://dnsid-ledger:8080/log#identity-01", WithSource(globalMemorySource{memorySource{entries: []ProvenEntry{
				{Index: 0, Entry: []byte(issuanceEntry)}, {Index: 1, Entry: []byte(keyRotationEntry)}, {Index: 2, Entry: candidate},
			}}}), withProofVerifySkipped())
			if err != nil {
				t.Fatal(err)
			}
			history, err := reader.RebuildHistory(context.Background(), "agent.example")
			if signed && err == nil {
				t.Fatalf("authenticated invalid timestamp %v was hidden", value)
			}
			if !signed && (err != nil || len(history) != 2) {
				t.Fatalf("unauthenticated invalid timestamp was fatal: %v", err)
			}
			if _, err := reader.ParsePreparedEvent(candidate); err == nil {
				t.Fatal("invalid timestamp accepted for signing")
			}
		}
	}
}

func TestHistoricalBundle_IsNotCorrectedChainEvidence(t *testing.T) {
	data, err := os.ReadFile("testdata/c2sp-stream-bundle-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var v streamBundleVector
	if err := json.Unmarshal(data, &v); err != nil {
		t.Fatal(err)
	}
	verifier, err := note.NewVerifier(v.Trust.BundleVerifierKey)
	if err != nil {
		t.Fatal(err)
	}
	_, err = VerifyStreamBundle(context.Background(), []byte(v.Bundle), StreamBundleTrust{PolicyDocument: []byte(v.Policy), BundleVerifier: verifier, Now: func() time.Time { return time.Unix(v.Trust.Now, 0) }, MaxBundleLifetime: time.Duration(v.Trust.MaxBundleLifetime) * time.Millisecond, MaxCheckpointAge: time.Duration(v.Trust.CheckpointFreshness) * time.Millisecond})
	var ve *dnsid.VerificationError
	if !errors.As(err, &ve) || ve.Code() != dnsid.VerificationCodeChainContinuity {
		t.Fatalf("old chain accepted or wrong reason: %v", err)
	}
}
