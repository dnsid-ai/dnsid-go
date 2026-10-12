package awskms

import (
	"context"
	"testing"
)

func TestProvider_CrossProviderSupersessionAndRestart(t *testing.T) {
	kms := newFakeKMS(t, "previous", "target")
	p, err := Load(context.Background(), kms, Config{State: State{ActiveKeyID: "previous", PendingKeyIDs: []string{"target"}}})
	if err != nil {
		t.Fatal(err)
	}
	if err := p.Supersede("previous"); err != nil {
		t.Fatal(err)
	}
	if !p.State().Inactive || p.JWK() != nil || len(p.ListKeyIds()) != 0 {
		t.Fatal("superseded provider retained active signer")
	}
	if _, err := p.Sign([]byte("unsafe")); err == nil {
		t.Fatal("inactive provider signed")
	}
	restored, err := Load(context.Background(), kms, Config{State: p.State()})
	if err != nil {
		t.Fatal(err)
	}
	if restored.JWK() != nil || restored.JWK("target") == nil {
		t.Fatal("inactive state failed restart")
	}
	if err := restored.Activate("target"); err != nil {
		t.Fatal(err)
	}
	if err := restored.Activate("target"); err != nil {
		t.Fatal("active-key restoration was not idempotent", err)
	}
	if restored.State().Inactive || restored.JWK() == nil {
		t.Fatal("saved signer was not restored")
	}
}
