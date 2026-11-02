package c2sptlog

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/mod/sumdb/note"
	"golang.org/x/mod/sumdb/tlog"
)

// Build a four-entry fixture with optional mutations before signing its checkpoint.
func streamBundleWithCopies(t *testing.T, mutations ...func([][]byte)) streamBundleVector {
	t.Helper()
	v := loadStreamBundleVector(t)
	object, err := decodeJSONObject([]byte(v.Bundle))
	if err != nil {
		t.Fatal(err)
	}
	policy, err := ParsePolicy([]byte(v.Policy))
	if err != nil {
		t.Fatal(err)
	}
	var entries [][]byte
	for _, item := range object["events"].([]any) {
		entry, err := base64.RawURLEncoding.DecodeString(item.(map[string]any)["entry"].(string))
		if err != nil {
			t.Fatal(err)
		}
		entries = append(entries, entry)
	}
	bad := canonicalEntryMutation(t, string(entries[1]), func(p map[string]any) { p["sigs"].(map[string]any)["new_op"].(map[string]any)["sig"] = "AA" })
	entries = append(entries, entries[1], bad)
	for _, mutate := range mutations {
		mutate(entries)
	}
	leaves := []tlog.Hash{LeafHash(entries[0]), LeafHash(entries[1]), LeafHash(entries[2]), LeafHash(entries[3])}
	parents := []tlog.Hash{tlog.NodeHash(leaves[0], leaves[1]), tlog.NodeHash(leaves[2], leaves[3])}
	root := tlog.NodeHash(parents[0], parents[1])
	var events []any
	for i, entry := range entries {
		proof := append(append([]byte(nil), leaves[i^1][:]...), parents[(i/2)^1][:]...)
		events = append(events, map[string]any{"index": i, "entry": base64.RawURLEncoding.EncodeToString(entry), "proof": base64.RawURLEncoding.EncodeToString(proof)})
	}
	object["events"] = events
	checkpoint := fmt.Sprintf("log.example\n4\n%s\n", base64.StdEncoding.EncodeToString(root[:]))
	var signatures string
	for i, verifier := range []note.Verifier{policy.LogVerifier, policy.WitnessVerifiers[0]} {
		input := []byte(checkpoint)
		prefix := binary.BigEndian.AppendUint32(nil, verifier.KeyHash())
		if i == 1 {
			input = fmt.Appendf(nil, "cosignature/v1\ntime %d\n%s", v.Trust.Now, checkpoint)
			prefix = binary.BigEndian.AppendUint64(prefix, uint64(v.Trust.Now))
		}
		key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{byte(4 + i)}, 32)) // Shared disposable log/witness seeds.
		signatures += fmt.Sprintf("— %s %s\n", verifier.Name(), base64.StdEncoding.EncodeToString(append(prefix, ed25519.Sign(key, input)...)))
	}
	object["checkpoint"] = base64.RawURLEncoding.EncodeToString([]byte(checkpoint + "\n" + signatures))
	v.Bundle = string(signTestBundle(t, object))
	return v
}

// testStreamHeadSeed is the disposable Ed25519 seed of the fixture stream-head
// key bundle.example+b0fef33a.
var testStreamHeadSeed = bytes.Repeat([]byte{6}, 32)

func signTestStreamHead(t *testing.T, head StreamHead) string {
	t.Helper()
	text, err := head.MarshalText()
	if err != nil {
		t.Fatal(err)
	}
	return signTestNote(t, "bundle.example", testStreamHeadSeed, text)
}

// signTestNote signs text as a signed note and returns it as unpadded base64url.
func signTestNote(t *testing.T, name string, seed []byte, text []byte) string {
	t.Helper()
	public := ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)
	verifierKey, err := note.NewEd25519VerifierKey(name, public)
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := note.NewVerifier(verifierKey)
	if err != nil {
		t.Fatal(err)
	}
	signerKey := fmt.Sprintf("PRIVATE+KEY+%s+%08x+%s", name, verifier.KeyHash(), base64.StdEncoding.EncodeToString(append([]byte{1}, seed...)))
	signer, err := note.NewSigner(signerKey)
	if err != nil {
		t.Fatal(err)
	}
	signed, err := note.Sign(&note.Note{Text: string(text)}, signer)
	if err != nil {
		t.Fatal(err)
	}
	return base64.RawURLEncoding.EncodeToString(signed)
}

// testBundleHead returns the unverified statement carried by object.
func testBundleHead(t *testing.T, object map[string]any) StreamHead {
	t.Helper()
	raw, err := base64.RawURLEncoding.DecodeString(object["head"].(string))
	if err != nil {
		t.Fatal(err)
	}
	opened, err := note.Open(raw, note.VerifierList())
	var unverified *note.UnverifiedNoteError
	if !errors.As(err, &unverified) {
		t.Fatalf("opening fixture head: %v", err)
	}
	opened = unverified.Note
	head, err := ParseStreamHead([]byte(opened.Text))
	if err != nil {
		t.Fatal(err)
	}
	return head
}

// signTestBundle re-signs object's statement for its current checkpoint and
// optionally changes the statement before signing.
func signTestBundle(t *testing.T, object map[string]any, edits ...func(*StreamHead)) []byte {
	t.Helper()
	head := testBundleHead(t, object)
	checkpoint, err := base64.RawURLEncoding.DecodeString(object["checkpoint"].(string))
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.SplitN(string(checkpoint), "\n", 4)
	if head.TreeSize, err = strconv.ParseUint(lines[1], 10, 64); err != nil {
		t.Fatal(err)
	}
	if head.RootHash, err = base64.StdEncoding.DecodeString(lines[2]); err != nil {
		t.Fatal(err)
	}
	for _, edit := range edits {
		edit(&head)
	}
	object["head"] = signTestStreamHead(t, head)
	encoded, err := json.Marshal(object)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func TestStreamBundleAndScanner_LogicalCopiesAndExactProofs(t *testing.T) {
	v := streamBundleWithCopies(t)
	verifier, err := note.NewVerifier(v.Trust.BundleVerifierKey)
	if err != nil {
		t.Fatal(err)
	}
	trust := StreamBundleTrust{PolicyDocument: []byte(v.Policy), BundleVerifier: verifier, Now: func() time.Time { return time.Unix(v.Trust.Now, 0) }, MaxBundleLifetime: time.Duration(v.Trust.MaxBundleLifetime) * time.Millisecond, MaxCheckpointAge: time.Duration(v.Trust.CheckpointFreshness) * time.Millisecond}
	bundle, err := VerifyStreamBundle(context.Background(), []byte(v.Bundle), trust)
	if err != nil {
		t.Fatal(err)
	}
	if len(bundle.Events) != 2 {
		t.Fatalf("logical event count = %d", len(bundle.Events))
	}
	policy, err := ParsePolicy([]byte(v.Policy))
	if err != nil {
		t.Fatal(err)
	}
	policy.Now = trust.Now
	policy.MaxCheckpointAge = trust.MaxCheckpointAge
	reader, err := New(bundle.Reference.String(), WithSource(bundle.Source), WithPolicy(policy))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := reader.ReadEvent(context.Background(), bundle.Reference.FinalEventRef(2)); err != nil {
		t.Fatalf("valid copy occurrence: %v", err)
	}
	if _, err := reader.ReadEvent(context.Background(), bundle.Reference.FinalEventRef(3)); err == nil {
		t.Fatal("invalid copy returned as signed occurrence")
	}
	cutoff, err := reader.RebuildHistoryThrough(context.Background(), bundle.FQDN, bundle.Reference.FinalEventRef(2))
	if err != nil {
		t.Fatal(err)
	}
	if len(cutoff.PriorHistory) != 2 || cutoff.FinalOccurrence.Index != 2 || !bytes.Equal(cutoff.FinalOccurrence.Proof, bundle.Source.entries[2].Proof) || cutoff.PriorHistoryReferences[1] != bundle.Reference.FinalEventRef(2) {
		t.Fatal("migration substituted the first occurrence's evidence")
	}
	if _, err := reader.RebuildHistoryThrough(context.Background(), bundle.FQDN, bundle.Reference.FinalEventRef(3)); err == nil {
		t.Fatal("invalid signature copy accepted as migration cutoff")
	}
	prefix, err := reader.RebuildHistoryThrough(context.Background(), bundle.FQDN, bundle.Reference.FinalEventRef(0))
	if err != nil || len(prefix.PriorHistory) != 1 {
		t.Fatalf("source events after exact cutoff imported: %v", err)
	}
	// The scanner consumes exactly the same leaves, not a prefiltered logical list.
	var entries, tile []byte
	for _, entry := range bundle.Source.entries {
		entries = append(entries, byte(len(entry.Entry)>>8), byte(len(entry.Entry)))
		entries = append(entries, entry.Entry...)
		leaf := LeafHash(entry.Entry)
		tile = append(tile, leaf[:]...)
	}
	resources := map[string][]byte{"/checkpoint": bundle.Source.checkpoint, "/tile/entries/000.p/4": entries, "/tile/0/000.p/4": tile}
	scan, err := NewScanSource(policy, ScanSourceConfig{Transport: scanHTTPClient(resources).Transport})
	if err != nil {
		t.Fatal(err)
	}
	scanner, err := New(bundle.Reference.String(), WithSource(scan), WithPolicy(policy))
	if err != nil {
		t.Fatal(err)
	}
	history, err := scanner.RebuildHistory(context.Background(), bundle.FQDN)
	if err != nil || len(history) != 2 {
		t.Fatalf("scanner disagrees with bundle: %v, %v", history, err)
	}
	// Even the ignored invalid-signature copy's supplied inclusion proof is mandatory.
	object, err := decodeJSONObject([]byte(v.Bundle))
	if err != nil {
		t.Fatal(err)
	}
	listed := object["events"].([]any)
	item := listed[3].(map[string]any)
	proof, err := base64.RawURLEncoding.DecodeString(item["proof"].(string))
	if err != nil {
		t.Fatal(err)
	}
	proof[0] ^= 1
	item["proof"] = base64.RawURLEncoding.EncodeToString(proof)
	corrupt := signTestBundle(t, object)
	if _, err := VerifyStreamBundle(context.Background(), corrupt, trust); err == nil {
		t.Fatal("ignored copy's invalid Merkle proof accepted")
	}
}
