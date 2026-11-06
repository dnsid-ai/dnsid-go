package gcpkms_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"reflect"
	"sync"
	"testing"
	"time"

	"cloud.google.com/go/kms/apiv1/kmspb"
	dnsid "github.com/dnsid-ai/dnsid-go"
	gcpkms "github.com/dnsid-ai/dnsid-go/key/gcp"
	"github.com/googleapis/gax-go/v2"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"google.golang.org/protobuf/proto"
)

// All mutable coordination is channel-controlled. Public responses are cloned so
// concurrent generation never shares a mutable protobuf with the provider.
type gatedGenerationKMS struct {
	*fakeKMS
	candidate         *kmspb.PublicKey
	stage             string
	entered           chan struct{}
	release           chan struct{}
	createErr, getErr error
}

func newGatedGenerationKMS(t *testing.T, stage string) *gatedGenerationKMS {
	t.Helper()
	fixture := lifecycleFake(t)
	candidate, err := fixture.GetPublicKey(context.Background(), &kmspb.GetPublicKeyRequest{Name: successorVersion})
	if err != nil {
		t.Fatal(err)
	}
	return &gatedGenerationKMS{fakeKMS: fixture.fakeKMS, candidate: candidate, stage: stage, entered: make(chan struct{}, 2), release: make(chan struct{})}
}
func (f *gatedGenerationKMS) gate(ctx context.Context, stage string) error {
	if f.stage != stage {
		return nil
	}
	f.entered <- struct{}{}
	select {
	case <-f.release:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
func (f *gatedGenerationKMS) CreateCryptoKeyVersion(ctx context.Context, _ *kmspb.CreateCryptoKeyVersionRequest, _ ...gax.CallOption) (*kmspb.CryptoKeyVersion, error) {
	if err := f.gate(ctx, "create"); err != nil {
		return nil, err
	}
	if f.createErr != nil {
		return nil, f.createErr
	}
	return &kmspb.CryptoKeyVersion{Name: successorVersion, Algorithm: kmspb.CryptoKeyVersion_EC_SIGN_ED25519, State: kmspb.CryptoKeyVersion_ENABLED, ProtectionLevel: kmspb.ProtectionLevel_SOFTWARE}, nil
}
func (f *gatedGenerationKMS) GetPublicKey(ctx context.Context, req *kmspb.GetPublicKeyRequest, opts ...gax.CallOption) (*kmspb.PublicKey, error) {
	if req.GetName() == version {
		return f.fakeKMS.GetPublicKey(ctx, req, opts...)
	}
	if req.GetName() != successorVersion {
		return nil, errors.New("unexpected candidate version")
	}
	if err := f.gate(ctx, "get"); err != nil {
		return nil, err
	}
	if f.getErr != nil {
		return nil, f.getErr
	}
	return proto.Clone(f.candidate).(*kmspb.PublicKey), nil
}

type generationResult struct {
	kid string
	err error
}
type signingResult struct {
	sig *dnsid.KeySignature
	err error
}

// Mode: fake-only (channel-held Create/Get I/O; actual Ed25519 cryptography).
// Given an active signer, When generation is held inside either network call,
// Then Sign completes before release; the eventual candidate stays pending.
func TestGenerateKeyNetworkDoesNotBlockActiveSign(t *testing.T) {
	for _, stage := range []string{"create", "get"} {
		t.Run(stage, func(t *testing.T) {
			f := newGatedGenerationKMS(t, stage)
			f.want = []byte("existing active signer remains available")
			p, err := gcpkms.New(context.Background(), f, gcpkms.Config{KeyVersionName: version})
			if err != nil {
				t.Fatal(err)
			}
			old := lifecycleKid(t, p)
			generated := make(chan generationResult, 1)
			go func() { kid, err := p.GenerateKey(dnsid.JoseAlgEdDSA); generated <- generationResult{kid, err} }()
			var releaseOnce sync.Once
			release := func() { releaseOnce.Do(func() { close(f.release) }) }
			defer release()
			select {
			case <-f.entered:
			case <-time.After(5 * time.Second):
				t.Fatal("generation never entered fake network call")
			}
			signed := make(chan signingResult, 1)
			go func() { sig, err := p.Sign(f.want); signed <- signingResult{sig, err} }()
			// The deadline is a deadlock watchdog, not a sleep or ordering mechanism.
			// Release is owned solely by this test and cannot occur before this select.
			signCompleted := false
			select {
			case result := <-signed:
				signCompleted = true
				_, public := fixture(t)
				lifecycleSignature(t, result.sig, result.err, old, f.want, public)
			case <-time.After(2 * time.Second):
				t.Errorf("active Sign did not complete while GenerateKey %s I/O was held", stage)
			}
			release()
			if !signCompleted {
				select {
				case result := <-signed:
					_, public := fixture(t)
					lifecycleSignature(t, result.sig, result.err, old, f.want, public)
				case <-time.After(5 * time.Second):
					t.Fatal("active Sign did not finish after release")
				}
			}
			var result generationResult
			select {
			case result = <-generated:
			case <-time.After(5 * time.Second):
				t.Fatal("generation did not finish after release")
			}
			if result.err != nil || result.kid == "" || result.kid == old {
				t.Fatalf("candidate insertion: kid=%q err=%v", result.kid, result.err)
			}
			if lifecycleKid(t, p) != old || !reflect.DeepEqual(p.ListKeyIds(), []string{old}) {
				t.Fatal("generation changed active signer or live inventory")
			}
			key := p.JWK(result.kid)
			if key == nil || key.Has("d") {
				t.Fatal("pending candidate public key missing or private")
			}
			var public ed25519.PublicKey
			if err := jwk.Export(key, &public); err != nil {
				t.Fatal(err)
			}
			expected := lifecycleFake(t).successor.Public().(ed25519.PublicKey)
			if !bytes.Equal(public, expected) {
				t.Fatal("pending candidate public key not bound to generated version")
			}
		})
	}
}

// Mode: fake-only (create/get failures and corrupt candidate metadata).
// Given an active signer, When candidate creation or validation fails, Then no
// candidate is returned and the original signer/inventory remain usable.
func TestGenerateKeyCandidateFailurePreservesInventory(t *testing.T) {
	for _, failure := range []string{"create denied", "get denied", "bad checksum", "wrong version", "wrong algorithm"} {
		t.Run(failure, func(t *testing.T) {
			f := newGatedGenerationKMS(t, "")
			f.want = []byte("after failed candidate")
			switch failure {
			case "create denied":
				f.createErr = errors.New("create denied")
			case "get denied":
				f.getErr = errors.New("get denied")
			case "bad checksum":
				f.candidate.PemCrc32C.Value ^= 1
			case "wrong version":
				f.candidate.Name = version
			case "wrong algorithm":
				f.candidate.Algorithm = kmspb.CryptoKeyVersion_EC_SIGN_P256_SHA256
			}
			p, err := gcpkms.New(context.Background(), f, gcpkms.Config{KeyVersionName: version})
			if err != nil {
				t.Fatal(err)
			}
			old := lifecycleKid(t, p)
			if kid, err := p.GenerateKey(dnsid.JoseAlgEdDSA); err == nil || kid != "" {
				t.Fatalf("failed candidate accepted: kid=%q err=%v", kid, err)
			}
			if lifecycleKid(t, p) != old || !reflect.DeepEqual(p.ListKeyIds(), []string{old}) {
				t.Fatal("failed generation mutated active inventory")
			}
			sig, err := p.Sign(f.want)
			_, public := fixture(t)
			lifecycleSignature(t, sig, err, old, f.want, public)
		})
	}
}

// Mode: fake-only (two concurrent creates return the same immutable version).
// Given duplicate candidate responses, When generation overlaps, Then exactly
// one insertion succeeds and the candidate remains pending with a valid key.
func TestGenerateKeyConcurrentDuplicateInsertionIsAtomic(t *testing.T) {
	f := newGatedGenerationKMS(t, "create")
	p, err := gcpkms.New(context.Background(), f, gcpkms.Config{KeyVersionName: version})
	if err != nil {
		t.Fatal(err)
	}
	old := lifecycleKid(t, p)
	results := make(chan generationResult, 2)
	start := make(chan struct{})
	var ready sync.WaitGroup
	ready.Add(2)
	for i := 0; i < 2; i++ {
		go func() {
			ready.Done()
			<-start
			kid, err := p.GenerateKey(dnsid.JoseAlgEdDSA)
			results <- generationResult{kid, err}
		}()
	}
	ready.Wait()
	close(start)
	select {
	case <-f.entered:
	case <-time.After(5 * time.Second):
		close(f.release)
		t.Fatal("no create entered")
	}
	select {
	case <-f.entered:
	case <-time.After(2 * time.Second):
		t.Error("second GenerateKey could not enter Create while first Create I/O was held")
	}
	close(f.release)
	successes := 0
	var pending string
	for i := 0; i < 2; i++ {
		select {
		case result := <-results:
			if result.err == nil {
				successes++
				pending = result.kid
			} else if result.kid != "" {
				t.Fatal("failed duplicate returned a kid")
			}
		case <-time.After(5 * time.Second):
			t.Fatal("duplicate generation failed to finish")
		}
	}
	if successes != 1 || pending == "" || pending == old {
		t.Fatalf("duplicate insertion successes=%d pending=%q; want exactly one", successes, pending)
	}
	if lifecycleKid(t, p) != old || !reflect.DeepEqual(p.ListKeyIds(), []string{old}) {
		t.Fatal("duplicate insertion changed active inventory")
	}
	key := p.JWK(pending)
	if key == nil {
		t.Fatal("winning pending candidate missing")
	}
	var public ed25519.PublicKey
	if err := jwk.Export(key, &public); err != nil {
		t.Fatal(err)
	}
	expected := lifecycleFake(t).successor.Public().(ed25519.PublicKey)
	if !bytes.Equal(public, expected) {
		t.Fatal("duplicate insertion retained wrong public key")
	}
}
