package gcpkms_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"cloud.google.com/go/kms/apiv1/kmspb"
	gcpkms "github.com/dnsid-ai/dnsid-go/key/gcp"
)

// Mode: fake-only (substituted native readiness metadata, no cloud resources).
// Given a valid newly created immutable version is PENDING_GENERATION,
// When its first readiness poll reports an enabled but different version,
// Then Create fails with the original recovery reference and no usable provider,
// without recreating, opening public material, signing, or closing caller custody.
func TestCreate_InitialPendingPollRejectsWrongVersion(t *testing.T) {
	f := newFirstService(t)
	f.pending = true
	f.mutateVersion = func(v *kmspb.CryptoKeyVersion) {
		// The shared fixture leaves the create response valid and changes only
		// the polled resource binding, after transitioning to ENABLED.
		if f.gets > 0 {
			v.Name = firstVersion + "9"
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	firstNoFiles(t)

	p, _, _, err := gcpkms.Create(ctx, f, firstParent)
	if err == nil {
		t.Fatal("accepted a different version from the initial readiness poll")
	}
	if !strings.Contains(err.Error(), firstVersion) {
		t.Errorf("failure omitted original recovery reference %q: %v", firstVersion, err)
	}
	if p != nil {
		t.Error("readiness binding failure returned a provider")
		if len(p.ListKeyIds()) != 0 || p.JWK() != nil {
			t.Error("readiness binding failure exposed an active signer")
		}
		if _, signErr := p.Sign([]byte("no fallback")); signErr == nil {
			t.Error("readiness binding failure allowed application signing")
		}
	}
	if f.creates != 1 || f.gets != 1 || f.publics != 0 || f.signs != 0 || f.closes != 0 {
		t.Fatalf("creates=%d polls=%d public reads=%d signs=%d closes=%d", f.creates, f.gets, f.publics, f.signs, f.closes)
	}
}
