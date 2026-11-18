//go:build dnsid_foundry

package foundry

import (
	"context"
	"encoding/base64"
	"errors"
	"net/http"
	"testing"
	"time"

	dnsid "github.com/dnsid-ai/dnsid-go"
)

func saveExpiredSubmittedProof(t *testing.T, f *fixture, id *FoundryIdentity) *ProofState {
	t.Helper()
	lease, err := f.store.Lock(context.Background(), id.key)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := lease.Close(); err != nil {
			t.Error(err)
		}
	}()
	doc, err := lease.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	// Model a submitted proof whose response was lost before its expiry.
	message, err := base64.RawURLEncoding.Strict().DecodeString(doc.Proof.ChallengeMessage)
	if err != nil {
		t.Fatal(err)
	}
	signature, err := f.operational.Sign(message)
	if err != nil {
		t.Fatal(err)
	}
	doc.Proof.Signature = base64.RawURLEncoding.EncodeToString(signature.Signature)
	doc.Proof.Outcome = "submitting"
	if err := lease.Save(context.Background(), doc); err != nil {
		t.Fatal(err)
	}
	proof := *doc.Proof
	return &proof
}

func TestExpiredSubmittedProof_ReissueConflictWaitsForRegistry(t *testing.T) {
	f := newFixture(t)
	f.registry.challenge, f.registry.expired = true, true
	f.registry.status = "PROVISIONING"
	id, err := f.client.Create(context.Background(), "expired-proof")
	if err != nil {
		t.Fatal(err)
	}
	original := saveExpiredSubmittedProof(t, f, id)
	f.registry.reissueErr = &dnsid.RegistryAPIError{StatusCode: http.StatusConflict}
	f.registry.statuses = []string{"PROVISIONING", "PROVISIONING", "VERIFIED"}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if _, err := id.Active(ctx); err != nil {
		t.Fatal(err)
	}
	if f.registry.reissueCalls != 1 || f.registry.proofCalls != 0 || len(f.registry.statuses) != 0 {
		t.Fatal("used challenge was resubmitted or registry readiness was not polled")
	}
	saved := f.document("expired-proof")
	if saved.Proof.Challenge != original.Challenge || saved.Proof.Signature != original.Signature || saved.Proof.Outcome != "accepted" || saved.Phase != "complete" {
		t.Fatal("used proof was replaced or not settled after registry readiness")
	}
}

type unavailableProofSigner struct {
	dnsid.KeyProvider
	err error
}

func (p *unavailableProofSigner) Sign(data []byte) (*dnsid.KeySignature, error) {
	if p.err != nil {
		return nil, p.err
	}
	return p.KeyProvider.Sign(data)
}

func TestExpiredSubmittedProof_ReissueReplacesDurableProof(t *testing.T) {
	f := newFixture(t)
	provider := &unavailableProofSigner{KeyProvider: f.operational, err: errors.New("signer unavailable")}
	f.client.deps.KeyProvider = provider
	f.registry.challenge, f.registry.expired = true, true
	f.registry.status = "PROVISIONING"
	id, err := f.client.Create(context.Background(), "expired-proof")
	if err != nil {
		t.Fatal(err)
	}
	original := saveExpiredSubmittedProof(t, f, id)
	_, err = id.Active(context.Background())
	requireKind(t, err, Unresolved)
	if !errors.Is(err, provider.err) {
		t.Fatal(err)
	}
	saved := f.document("expired-proof")
	if saved.Proof.Challenge != "replacement" || saved.Proof.ChallengeMessage == original.ChallengeMessage || saved.Proof.Signature != "" || saved.Proof.Outcome != "" || saved.Phase != "proof-pending" {
		t.Fatal("successful reissue did not durably replace and clear the submitted proof")
	}
	if f.registry.proofCalls != 0 {
		t.Fatal("expired proof was resubmitted")
	}
	provider.err = nil
	f.registry.status = "VERIFIED"
	if _, err := id.Active(context.Background()); err != nil {
		t.Fatal(err)
	}
	completed := f.document("expired-proof")
	if f.registry.reissueCalls != 1 || f.registry.proofCalls != 1 || completed.Proof.Signature == original.Signature || completed.Proof.Outcome != "accepted" {
		t.Fatal("replacement proof did not resume with a new signature")
	}
}
