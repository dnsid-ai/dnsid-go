package c2sptlog

import (
	"crypto/rand"
	"errors"
	"fmt"
	"testing"
	"time"

	dnsid "github.com/dnsid-ai/dnsid-go"
	formatlog "github.com/transparency-dev/formats/log"
	formatnote "github.com/transparency-dev/formats/note"
	"golang.org/x/mod/sumdb/note"
)

// cosignedCheckpointFixture returns a tlog-policy document requiring one
// witness, and checkpoint notes for one entry signed by the log alone and by
// the log and the witness.
func cosignedCheckpointFixture(t *testing.T, origin string) (policy []byte, logOnly, cosigned []byte, root []byte) {
	t.Helper()
	skey, vkey, err := note.GenerateKey(rand.Reader, origin)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	signer, err := note.NewSigner(skey)
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}
	wskey, wvkey, err := note.GenerateKey(rand.Reader, "witness.example")
	if err != nil {
		t.Fatalf("GenerateKey witness: %v", err)
	}
	witness, err := formatnote.NewSignerForCosignatureV1(wskey)
	if err != nil {
		t.Fatalf("NewSignerForCosignatureV1: %v", err)
	}
	cosigKey, err := formatnote.VKeyToCosignatureV1(wvkey)
	if err != nil {
		t.Fatalf("VKeyToCosignatureV1: %v", err)
	}
	leaf := LeafHash([]byte(issuanceEntry))
	text := string((&formatlog.Checkpoint{Origin: origin, Size: 1, Hash: leaf[:]}).Marshal())
	if logOnly, err = note.Sign(&note.Note{Text: text}, signer); err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if cosigned, err = note.Sign(&note.Note{Text: text}, signer, witness); err != nil {
		t.Fatalf("Sign cosigned: %v", err)
	}
	policy = []byte(fmt.Sprintf("log %s\nwitness w1 %s\nquorum w1\n", vkey, cosigKey))
	return policy, logOnly, cosigned, leaf[:]
}

func TestPolicyVerifyCheckpoint_AcceptsCosignedCheckpoint(t *testing.T) {
	doc, _, cosigned, root := cosignedCheckpointFixture(t, "dnsid-ledger:8080/log")
	policy, err := ParsePolicy(doc)
	if err != nil {
		t.Fatalf("ParsePolicy: %v", err)
	}
	ref, err := ParseReference(fixtureLR)
	if err != nil {
		t.Fatalf("ParseReference: %v", err)
	}
	before := time.Now().Add(-time.Second)
	got, err := policy.VerifyCheckpoint(ref, cosigned)
	if err != nil {
		t.Fatalf("VerifyCheckpoint: %v", err)
	}
	if got.Checkpoint.Size != 1 || string(got.Checkpoint.Hash) != string(root) || got.Index != 0 {
		t.Fatalf("checkpoint = %+v, index %d", got.Checkpoint, got.Index)
	}
	if ft := got.CheckpointFreshnessTime; ft.Before(before.Truncate(time.Second)) || ft.After(time.Now()) {
		t.Fatalf("freshness time = %s, want the cosignature time", ft)
	}
}

func TestPolicyVerifyCheckpoint_Rejects(t *testing.T) {
	doc, logOnly, cosigned, _ := cosignedCheckpointFixture(t, "dnsid-ledger:8080/log")
	policy, err := ParsePolicy(doc)
	if err != nil {
		t.Fatalf("ParsePolicy: %v", err)
	}
	otherDoc, _, _, _ := cosignedCheckpointFixture(t, "dnsid-ledger:8080/log")
	otherKey, err := ParsePolicy(otherDoc)
	if err != nil {
		t.Fatalf("ParsePolicy: %v", err)
	}
	stale := policy
	stale.MaxCheckpointAge = time.Hour
	stale.Now = func() time.Time { return time.Now().Add(2 * time.Hour) }
	ref, err := ParseReference(fixtureLR)
	if err != nil {
		t.Fatalf("ParseReference: %v", err)
	}
	otherRef, err := ParseReference("c2sp-tlog:testnet:http://other.example/log#identity-01")
	if err != nil {
		t.Fatalf("ParseReference: %v", err)
	}
	tests := []struct {
		name       string
		policy     Policy
		ref        Reference
		checkpoint []byte
	}{
		{"witness quorum not met", policy, ref, logOnly},
		{"another log key", otherKey, ref, cosigned},
		{"another origin", policy, otherRef, cosigned},
		{"stale", stale, ref, cosigned},
		{"not a note", policy, ref, []byte("checkpoint")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := tt.policy.VerifyCheckpoint(tt.ref, tt.checkpoint)
			var verr *dnsid.VerificationError
			if !errors.As(err, &verr) || verr.Code() != dnsid.VerificationCodeInvalidEvidence {
				t.Fatalf("VerifyCheckpoint error = %v, want INVALID_EVIDENCE", err)
			}
		})
	}
}
