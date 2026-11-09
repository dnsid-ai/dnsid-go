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
	createErr error
}

func (f *generationFailureKMS) CreateCryptoKeyVersion(ctx context.Context, r *kmspb.CreateCryptoKeyVersionRequest, opts ...gax.CallOption) (*kmspb.CryptoKeyVersion, error) {
	if f.createErr != nil {
		return nil, f.createErr
	}
	result, err := f.lifecycleKMS.CreateCryptoKeyVersion(ctx, r, opts...)

	return result, err
}
func (f *generationFailureKMS) GetPublicKey(ctx context.Context, r *kmspb.GetPublicKeyRequest, opts ...gax.CallOption) (*kmspb.PublicKey, error) {

	return f.lifecycleKMS.GetPublicKey(ctx, r, opts...)
}

// Mode: fake-only (creation permission error).
// Given an active signer, When creation fails, Then failure preserves the
// active signer and live inventory. Normal cloud pending readiness is separate.
func TestGenerationFailurePreservesActiveSigner(t *testing.T) {
	f := &generationFailureKMS{lifecycleKMS: lifecycleFake(t), createErr: errors.New("creation denied")}
	p, err := gcpkms.New(context.Background(), f, gcpkms.Config{KeyVersionName: version})
	if err != nil {
		t.Fatal(err)
	}
	old := lifecycleKid(t, p)
	kid, err := p.GenerateKey(dnsid.JoseAlgEdDSA)
	if err == nil || kid != "" {
		t.Fatalf("failed generation returned successful key: kid=%q error=%v", kid, err)
	}
	if lifecycleKid(t, p) != old || !reflect.DeepEqual(p.ListKeyIds(), []string{old}) {
		t.Fatal("failed generation changed active signer or live inventory")
	}
	f.want = []byte("still active")
	sig, err := p.Sign(f.want)
	_, public := fixture(t)
	lifecycleSignature(t, sig, err, old, f.want, public)
}
