package c2sptlog

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/mod/sumdb/note"
)

// Method §20 stream-head statement vector.
func TestStreamHeadMethodVector(t *testing.T) {
	const (
		verifierKey = "indexer.testnet.dnsid.example+7d5d55eb+AepKbGPinFIKvvVQexMuxfmVR3auvr57kkIe6mkURtIs"
		text        = "dnsid-c2sp-stream-head@v1\n" +
			"lr c2sp-tlog:testnet:https://testnet.dnsid.example/log#Q2hWbW5Ta0x5R0JtM3B0dw\n" +
			"checkpoint 3 H3aq5vryyX/jMIrSuLhjl/64vwD/yvpOfXUxGjzC5Ns=\n" +
			"head J-odfRVwktq5YRgXEesz663r5AYJbYgT6qhwmfnyjxQ\n" +
			"expires 1782432000\n"
		signed = text + "\n— indexer.testnet.dnsid.example fV1V63KXqsFYpXw0AAh/oI+Dyrzz2T7V8vxOdWmxdLBBqsZeW8uF20a1qfkJSOgnCXyXaWyegBfmly00wsIFdohXeQQ=\n"
	)
	root, _ := base64.StdEncoding.DecodeString("H3aq5vryyX/jMIrSuLhjl/64vwD/yvpOfXUxGjzC5Ns=")
	head := StreamHead{
		LR:          "c2sp-tlog:testnet:https://testnet.dnsid.example/log#Q2hWbW5Ta0x5R0JtM3B0dw",
		TreeSize:    3,
		RootHash:    root,
		HeadEventID: "J-odfRVwktq5YRgXEesz663r5AYJbYgT6qhwmfnyjxQ",
		Expires:     time.Unix(1782432000, 0),
	}
	marshaled, err := head.MarshalText()
	if err != nil || string(marshaled) != text {
		t.Fatalf("MarshalText = %q, %v", marshaled, err)
	}
	encoded := signTestNote(t, "indexer.testnet.dnsid.example", bytes.Repeat([]byte{7}, 32), marshaled)
	if got, _ := base64.RawURLEncoding.DecodeString(encoded); string(got) != signed {
		t.Fatalf("signed statement = %q, want %q", got, signed)
	}
	verifier, err := note.NewVerifier(verifierKey)
	if err != nil {
		t.Fatal(err)
	}
	opened, kid, err := OpenStreamHead([]byte(signed), []note.Verifier{verifier})
	if err != nil || kid != "indexer.testnet.dnsid.example+7d5d55eb" || opened.HeadEventID != head.HeadEventID || !bytes.Equal(opened.RootHash, root) {
		t.Fatalf("OpenStreamHead = %+v, %q, %v", opened, kid, err)
	}
}

func TestStreamHeadMarshalRejectsInvalidFields(t *testing.T) {
	valid := StreamHead{LR: "c2sp-tlog:public:https://log.example#stream", RootHash: make([]byte, 32), HeadEventID: EventID(nil), Expires: time.Unix(1, 0)}
	if _, err := valid.MarshalText(); err != nil {
		t.Fatal(err)
	}
	for name, edit := range map[string]func(*StreamHead){
		"short root":       func(h *StreamHead) { h.RootHash = make([]byte, 31) },
		"bad head":         func(h *StreamHead) { h.HeadEventID = "head" },
		"lr with space":    func(h *StreamHead) { h.LR += " x" },
		"negative expires": func(h *StreamHead) { h.Expires = time.Unix(-1, 0) },
		"tree too large":   func(h *StreamHead) { h.TreeSize = maxJSONInteger + 1 },
	} {
		head := valid
		edit(&head)
		if _, err := head.MarshalText(); err == nil {
			t.Errorf("%s: MarshalText accepted an invalid statement", name)
		}
	}
}

func TestReferenceRejectsLongLR(t *testing.T) {
	prefix := "c2sp-tlog:public:https://log.example#"
	if _, err := ParseReference(prefix + strings.Repeat("a", maxLRBytes-len(prefix))); err != nil {
		t.Fatalf("1024-byte lr rejected: %v", err)
	}
	if _, err := ParseReference(prefix + strings.Repeat("a", maxLRBytes-len(prefix)+1)); err == nil {
		t.Fatal("1025-byte lr accepted")
	}
	if _, err := ParseReference("c2sp-tlog:public:https://log.example/" + strings.Repeat("p", 256) + "#stream"); err == nil {
		t.Fatal("origin longer than 255 bytes accepted")
	}
}

func TestVerifyCheckpointRejectsNonCanonicalBase64(t *testing.T) {
	_, policy, raw := checkpointReaderFixture(t)
	ref, err := ParseReference("c2sp-tlog:public:https://log.example#EREREREREREREREREREREQ")
	if err != nil {
		t.Fatal(err)
	}
	root := base64.StdEncoding.EncodeToString(merkleRoot(raw))
	body := fmt.Sprintf("log.example\n%d\n%s\n", len(raw), root)
	if _, err := policy.verifyCheckpoint(ref, signTestCheckpoint(policy, body)); err != nil {
		t.Fatalf("canonical checkpoint rejected: %v", err)
	}
	// Set an unused low bit in the final base64 character; lenient decoders ignore it.
	bump := func(s string) string {
		trimmed := strings.TrimRight(s, "=")
		last := strings.IndexByte("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/", trimmed[len(trimmed)-1])
		return trimmed[:len(trimmed)-1] + string("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"[last|1]) + s[len(trimmed):]
	}
	if _, err := policy.verifyCheckpoint(ref, signTestCheckpoint(policy, fmt.Sprintf("log.example\n%d\n%s\n", len(raw), bump(root)))); err == nil {
		t.Fatal("non-canonical root hash accepted")
	}
	if _, err := policy.verifyCheckpoint(ref, signTestCheckpoint(policy, fmt.Sprintf("log.example\n0%d\n%s\n", len(raw), root))); err == nil {
		t.Fatal("tree size with a leading zero accepted")
	}
	signed := string(signTestCheckpoint(policy, body))
	lines := strings.Split(signed, "\n")
	for i, line := range lines {
		if strings.HasPrefix(line, "— log.example ") {
			lines[i] = "— log.example " + bump(strings.TrimPrefix(line, "— log.example "))
		}
	}
	if _, err := policy.verifyCheckpoint(ref, []byte(strings.Join(lines, "\n"))); err == nil || !strings.Contains(err.Error(), "canonical base64") {
		t.Fatalf("non-canonical signature error = %v", err)
	}
}

func TestTrustProfileRejectsStreamHeadKeyNamedAsWitness(t *testing.T) {
	key := func(name string, seed byte) string {
		vkey, err := note.NewEd25519VerifierKey(name, ed25519.NewKeyFromSeed(bytes.Repeat([]byte{seed}, 32)).Public().(ed25519.PublicKey))
		if err != nil {
			t.Fatal(err)
		}
		return vkey
	}
	profile := func(witnessName string) []byte {
		return fmt.Appendf(nil, `{"version":1,"scope":"testnet","log_prefix":"https://log.example","tlog_policy":"log %s\nquorum none\nwitness w %s\n","bundle_verifier_keys":[%q]}`,
			key("log.example", 1), key(witnessName, 2), key("dnsid-stream-bundle", 3))
	}
	if _, err := ParseTrustProfile(profile("witness.example")); err != nil {
		t.Fatalf("valid profile rejected: %v", err)
	}
	if _, err := ParseTrustProfile(profile("dnsid-stream-bundle")); err == nil || !strings.Contains(err.Error(), "must differ") {
		t.Fatalf("colliding key name error = %v", err)
	}
}

// Shared vectors copied verbatim from dnsid-sdk-compliance/fixtures/c2sp-stream-bundle-v2.json.
func TestVerifyStreamBundleSharedVectors(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("testdata", "c2sp-stream-bundle-v2.json"))
	if err != nil {
		t.Fatal(err)
	}
	var vector struct {
		streamBundleVector
		ValidVariants   []struct{ Name, Reason, Bundle string } `json:"valid_variants"`
		NegativeVectors []struct{ Name, Reason, Bundle string } `json:"negative_vectors"`
		StatementVector struct {
			VerifierKey string `json:"verifier_key"`
			SignedNote  string `json:"signed_note"`
		} `json:"statement_vector"`
		ReferenceVectors []struct {
			LR    string `json:"lr"`
			Valid bool   `json:"valid"`
		} `json:"reference_vectors"`
	}
	if err := json.Unmarshal(data, &vector); err != nil {
		t.Fatal(err)
	}
	verifier, err := note.NewVerifier(vector.Trust.BundleVerifierKey)
	if err != nil {
		t.Fatal(err)
	}
	trust := StreamBundleTrust{
		PolicyDocument:    []byte(vector.Policy),
		BundleVerifier:    verifier,
		Now:               func() time.Time { return time.Unix(vector.Trust.Now, 0).UTC() },
		MaxBundleLifetime: time.Duration(vector.Trust.MaxBundleLifetime) * time.Millisecond,
		MaxCheckpointAge:  time.Duration(vector.Trust.CheckpointFreshness) * time.Millisecond,
	}
	for _, valid := range vector.ValidVariants {
		verified, err := VerifyStreamBundle(context.Background(), []byte(valid.Bundle), trust)
		if err != nil || len(verified.Events) != vector.Expected.EventCount || verified.LoggedState != vector.Expected.Status {
			t.Errorf("valid %s (%s): %v", valid.Name, valid.Reason, err)
		}
	}
	for _, negative := range vector.NegativeVectors {
		if _, err := VerifyStreamBundle(context.Background(), []byte(negative.Bundle), trust); err == nil {
			t.Errorf("negative %s (%s) accepted", negative.Name, negative.Reason)
		}
	}
	statementVerifier, err := note.NewVerifier(vector.StatementVector.VerifierKey)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := OpenStreamHead([]byte(vector.StatementVector.SignedNote), []note.Verifier{statementVerifier}); err != nil {
		t.Errorf("statement vector: %v", err)
	}
	for _, reference := range vector.ReferenceVectors {
		if _, err := ParseReference(reference.LR); (err == nil) != reference.Valid {
			t.Errorf("ParseReference(%d bytes) error = %v, want valid %v", len(reference.LR), err, reference.Valid)
		}
	}
}
