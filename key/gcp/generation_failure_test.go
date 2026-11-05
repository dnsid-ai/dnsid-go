package gcpkms_test

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"cloud.google.com/go/kms/apiv1/kmspb"
	dnsid "github.com/dnsid-ai/dnsid-go"
	gcpkms "github.com/dnsid-ai/dnsid-go/key/gcp"
	"github.com/googleapis/gax-go/v2"
)

type generationFailureKMS struct {
	*lifecycleKMS
	pending   bool
	createErr error
}

func (f *generationFailureKMS) CreateCryptoKeyVersion(ctx context.Context, r *kmspb.CreateCryptoKeyVersionRequest, opts ...gax.CallOption) (*kmspb.CryptoKeyVersion, error) {
	if f.createErr != nil {
		return nil, f.createErr
	}
	result, err := f.lifecycleKMS.CreateCryptoKeyVersion(ctx, r, opts...)
	if err == nil && f.pending {
		result.State = kmspb.CryptoKeyVersion_PENDING_GENERATION
	}
	return result, err
}
func (f *generationFailureKMS) GetPublicKey(ctx context.Context, r *kmspb.GetPublicKeyRequest, opts ...gax.CallOption) (*kmspb.PublicKey, error) {
	if r.GetName() == successorVersion && f.pending {
		return nil, errors.New("generated version not ready")
	}
	return f.lifecycleKMS.GetPublicKey(ctx, r, opts...)
}

// Mode: fake-only (creation error or documented PENDING_GENERATION response).
// Given an active signer, When generation cannot yield a ready public key,
// Then it surfaces failure and preserves the active signer and live inventory.
// This does not require blocking/polling or define asynchronous readiness policy.
func TestGenerationFailurePreservesActiveSigner(t *testing.T) {
	for _, pending := range []bool{false, true} {
		name := "create denied"
		if pending {
			name = "pending generation unavailable"
		}
		t.Run(name, func(t *testing.T) {
			f := &generationFailureKMS{lifecycleKMS: lifecycleFake(t), pending: pending}
			if !pending {
				f.createErr = errors.New("creation denied")
			}
			p, err := gcpkms.New(context.Background(), f, gcpkms.Config{KeyVersionName: version})
			if err != nil {
				t.Fatal(err)
			}
			old := lifecycleKid(t, p)
			kid, err := p.GenerateKey(dnsid.JoseAlgEdDSA)
			if err == nil || kid != "" {
				t.Fatalf("unready/failed generation returned successful key: kid=%q error=%v", kid, err)
			}
			if lifecycleKid(t, p) != old || !reflect.DeepEqual(p.ListKeyIds(), []string{old}) {
				t.Fatal("failed generation changed active signer or live inventory")
			}
			f.want = []byte("still active")
			sig, err := p.Sign(f.want)
			_, public := fixture(t)
			lifecycleSignature(t, sig, err, old, f.want, public)
		})
	}
}
