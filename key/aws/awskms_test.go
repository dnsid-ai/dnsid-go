package awskms

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"reflect"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/aws/smithy-go"
	dnsid "github.com/dnsid-ai/dnsid-go"
	"github.com/lestrrat-go/jwx/v3/jwk"
)

type fakeKMS struct {
	keys         map[string]any
	created      int
	deleted      []string
	getPublicErr error
	deleteErr    error
	beforeDelete func()
}

func newFakeKMS(t *testing.T, kids ...string) *fakeKMS {
	t.Helper()
	f := &fakeKMS{keys: map[string]any{}}
	for _, kid := range kids {
		priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		f.keys[kid] = priv
	}
	return f
}

func newFakeEd25519KMS(t *testing.T, kids ...string) *fakeKMS {
	t.Helper()
	f := &fakeKMS{keys: map[string]any{}}
	for _, kid := range kids {
		_, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		f.keys[kid] = priv
	}
	return f
}

func (f *fakeKMS) CreateSigningKey(context.Context, CreateSigningKeyInput) (CreateSigningKeyOutput, error) {
	f.created++
	kid := fmt.Sprintf("generated-%d", f.created)
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return CreateSigningKeyOutput{}, err
	}
	f.keys[kid] = priv
	return CreateSigningKeyOutput{KeyID: kid}, nil
}

func (f *fakeKMS) GetPublicKey(_ context.Context, in GetPublicKeyInput) (GetPublicKeyOutput, error) {
	if f.getPublicErr != nil {
		return GetPublicKeyOutput{}, f.getPublicErr
	}
	priv := f.keys[in.KeyID]
	if priv == nil {
		return GetPublicKeyOutput{}, fmt.Errorf("missing key %s", in.KeyID)
	}
	switch priv := priv.(type) {
	case *ecdsa.PrivateKey:
		spki, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
		if err != nil {
			return GetPublicKeyOutput{}, err
		}
		return GetPublicKeyOutput{KeyID: in.KeyID, PublicKey: spki, KeySpec: types.KeySpecEccNistP256, KeyUsage: types.KeyUsageTypeSignVerify, SigningAlgorithms: []types.SigningAlgorithmSpec{types.SigningAlgorithmSpecEcdsaSha256}}, nil
	case ed25519.PrivateKey:
		spki, err := x509.MarshalPKIXPublicKey(priv.Public())
		if err != nil {
			return GetPublicKeyOutput{}, err
		}
		return GetPublicKeyOutput{KeyID: in.KeyID, PublicKey: spki, KeySpec: types.KeySpecEccNistEdwards25519, KeyUsage: types.KeyUsageTypeSignVerify, SigningAlgorithms: []types.SigningAlgorithmSpec{types.SigningAlgorithmSpecEd25519Sha512}}, nil
	default:
		return GetPublicKeyOutput{}, fmt.Errorf("bad fake key %T", priv)
	}
}

func (f *fakeKMS) Sign(_ context.Context, in SignInput) (SignOutput, error) {
	priv := f.keys[in.KeyID]
	if priv == nil {
		return SignOutput{}, fmt.Errorf("missing key %s", in.KeyID)
	}
	switch priv := priv.(type) {
	case *ecdsa.PrivateKey:
		digest := in.Message
		if !in.Digest {
			h := sha256.Sum256(in.Message)
			digest = h[:]
		}
		sig, err := ecdsa.SignASN1(rand.Reader, priv, digest)
		if err != nil {
			return SignOutput{}, err
		}
		return SignOutput{KeyID: in.KeyID, Signature: sig, Algorithm: in.Algorithm}, nil
	case ed25519.PrivateKey:
		return SignOutput{KeyID: in.KeyID, Signature: ed25519.Sign(priv, in.Message), Algorithm: in.Algorithm}, nil
	default:
		return SignOutput{}, fmt.Errorf("bad fake key %T", priv)
	}
}

func (f *fakeKMS) ScheduleKeyDeletion(_ context.Context, in ScheduleKeyDeletionInput) error {
	if f.beforeDelete != nil {
		f.beforeDelete()
	}
	if f.deleteErr != nil {
		return f.deleteErr
	}
	f.deleted = append(f.deleted, in.KeyID)
	return nil
}

func TestProviderJWKWithErrorReportsFetchFailure(t *testing.T) {
	kms := newFakeKMS(t, "active", "old")
	p, err := New(context.Background(), kms, Config{State: State{ActiveKeyID: "active", RetainedKeyIDs: []string{"old"}}})
	if err != nil {
		t.Fatal(err)
	}
	p.cache = map[string]jwk.Key{}
	kms.getPublicErr = fmt.Errorf("boom")
	key, err := p.JWKWithError("old")
	if err == nil || key != nil {
		t.Fatalf("JWKWithError = (%v, %v), want nil key and error", key, err)
	}
	if key := p.JWK("old"); key != nil {
		t.Fatal("JWK should keep interface-compatible nil on error")
	}
}

func TestProviderSignsEd25519(t *testing.T) {
	kms := newFakeEd25519KMS(t, "active")
	p, err := New(context.Background(), kms, Config{
		State:     State{ActiveKeyID: "active"},
		Algorithm: types.SigningAlgorithmSpecEd25519Sha512,
	})
	if err != nil {
		t.Fatal(err)
	}
	sig, err := p.Sign([]byte("payload"))
	if err != nil {
		t.Fatal(err)
	}
	if sig.Kid != "active" || sig.Alg != dnsid.JoseAlgEdDSA || len(sig.Signature) != ed25519.SignatureSize {
		t.Fatalf("bad signature metadata: %#v", sig)
	}
	var pub ed25519.PublicKey
	if err := jwk.Export(p.JWK("active"), &pub); err != nil {
		t.Fatal(err)
	}
	if !ed25519.Verify(pub, []byte("payload"), sig.Signature) {
		t.Fatal("signature does not verify against exported JWK")
	}
}

func TestGenerateKeySchedulesDeletionWhenValidationFails(t *testing.T) {
	kms := newFakeKMS(t, "active")
	p, err := New(context.Background(), kms, Config{
		State:                   State{ActiveKeyID: "active"},
		ScheduleDeletionOnPurge: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	kms.getPublicErr = fmt.Errorf("boom")
	kid, err := p.GenerateKey(dnsid.JoseAlgES256)
	if err == nil || kid != "generated-1" {
		t.Fatalf("GenerateKey = (%q, %v), want generated key ID and error", kid, err)
	}
	if state := p.State(); len(state.PendingKeyIDs) != 0 {
		t.Fatalf("pending = %v, want none", state.PendingKeyIDs)
	}
	if len(kms.deleted) != 1 || kms.deleted[0] != kid {
		t.Fatalf("deleted = %v", kms.deleted)
	}
}

func TestProviderNamedSigningAndSupersede(t *testing.T) {
	kms := newFakeKMS(t, "active", "pending")
	p, err := New(context.Background(), kms, Config{State: State{ActiveKeyID: "active", PendingKeyIDs: []string{"pending"}}})
	if err != nil {
		t.Fatal(err)
	}
	if sig, err := p.SignKey("pending", []byte("rotation proof")); err != nil || sig.Kid != "pending" {
		t.Fatalf("SignKey pending = (%v, %v)", sig, err)
	}
	if err := p.Activate("pending"); err != nil {
		t.Fatal(err)
	}
	if _, err := p.SignKey("active", []byte("too late")); err == nil {
		t.Fatal("retained key remained available for signing")
	}
	if err := p.Supersede("active"); err != nil {
		t.Fatal(err)
	}
	if p.JWK("active") != nil {
		t.Fatal("superseded key remained in provider")
	}
}

func TestProviderAllowsPendingJWKAndPurge(t *testing.T) {
	kms := newFakeKMS(t, "active")
	p, err := New(context.Background(), kms, Config{
		State:                   State{ActiveKeyID: "active"},
		ScheduleDeletionOnPurge: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	kid, err := p.GenerateKey(dnsid.JoseAlgES256)
	if err != nil {
		t.Fatal(err)
	}
	if key := p.JWK(kid); key == nil {
		t.Fatal("missing pending JWK")
	}
	if err := p.Purge(kid); err != nil {
		t.Fatal(err)
	}
	if len(kms.deleted) != 1 || kms.deleted[0] != kid {
		t.Fatalf("deleted = %v", kms.deleted)
	}
	if state := p.State(); len(state.PendingKeyIDs) != 0 {
		t.Fatalf("pending = %v", state.PendingKeyIDs)
	}
}

func TestPurgeRollbackToleratesConcurrentLifecycleChange(t *testing.T) {
	kms := newFakeKMS(t, "active", "p1", "p2")
	p, err := New(context.Background(), kms, Config{
		State:                   State{ActiveKeyID: "active", PendingKeyIDs: []string{"p1", "p2"}},
		ScheduleDeletionOnPurge: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	kms.deleteErr = fmt.Errorf("boom")
	kms.beforeDelete = func() {
		if err := p.Activate("p1"); err != nil {
			t.Fatal(err)
		}
	}
	if err := p.Purge("p2"); err == nil {
		t.Fatal("expected purge error")
	}
	if state := p.State(); state.ActiveKeyID != "p1" || !contains(state.PendingKeyIDs, "p2") {
		t.Fatalf("state = %#v", state)
	}
}

func TestProviderJWKReturnsClone(t *testing.T) {
	kms := newFakeKMS(t, "active")
	p, err := New(context.Background(), kms, Config{State: State{ActiveKeyID: "active"}})
	if err != nil {
		t.Fatal(err)
	}
	key := p.JWK("active")
	if key == nil {
		t.Fatal("missing JWK")
	}
	_ = key.Set(jwk.KeyIDKey, "mutated")
	kid, _ := p.JWK("active").KeyID()
	if kid != "active" {
		t.Fatalf("cached kid mutated to %q", kid)
	}
}

func TestProviderRejectsMismatchedKeySpec(t *testing.T) {
	kms := newFakeKMS(t, "active")
	_, err := New(context.Background(), kms, Config{
		State:     State{ActiveKeyID: "active"},
		Algorithm: types.SigningAlgorithmSpecEcdsaSha256,
		KeySpec:   types.KeySpecEccNistEdwards25519,
	})
	if err == nil {
		t.Fatal("expected mismatched key spec error")
	}
}

func TestProviderSignsAndRotates(t *testing.T) {
	kms := newFakeKMS(t, "active", "old")
	p, err := New(context.Background(), kms, Config{
		State:                   State{ActiveKeyID: "active", RetainedKeyIDs: []string{"old"}},
		Algorithm:               types.SigningAlgorithmSpecEcdsaSha256,
		ScheduleDeletionOnPurge: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := p.ListKeyIds(); len(got) != 2 || got[0] != "active" || got[1] != "old" {
		t.Fatalf("ListKeyIds = %v", got)
	}
	if key := p.JWK("active"); key == nil {
		t.Fatal("missing active JWK")
	}
	sig, err := p.Sign([]byte("payload"))
	if err != nil {
		t.Fatal(err)
	}
	if sig.Kid != "active" || sig.Alg != dnsid.JoseAlgES256 || len(sig.Signature) != 64 {
		t.Fatalf("bad signature metadata: %#v", sig)
	}
	var pub ecdsa.PublicKey
	if err := jwk.Export(p.JWK("active"), &pub); err != nil {
		t.Fatal(err)
	}
	h := sha256.Sum256([]byte("payload"))
	if !ecdsa.Verify(&pub, h[:], new(big.Int).SetBytes(sig.Signature[:32]), new(big.Int).SetBytes(sig.Signature[32:])) {
		t.Fatal("signature does not verify against exported JWK")
	}

	kid, err := p.GenerateKey(dnsid.JoseAlgES256)
	if err != nil {
		t.Fatal(err)
	}
	if err := p.Activate(kid); err != nil {
		t.Fatal(err)
	}
	if got := p.ListKeyIds(); got[0] != kid || got[1] != "old" || got[2] != "active" {
		t.Fatalf("after activate ListKeyIds = %v", got)
	}
	if err := p.Purge("old"); err != nil {
		t.Fatal(err)
	}
	if len(kms.deleted) != 1 || kms.deleted[0] != "old" {
		t.Fatalf("deleted = %v", kms.deleted)
	}
}

// f1FaultKMS records attempts before errors, including forbidden mutations.
// Only the four public Client operations are measured; this is not a global fallback spy.
type f1FaultKMS struct {
	*fakeKMS
	boundary  string
	fault     error
	calls     []string
	forbidden int
}

func (f *f1FaultKMS) GetPublicKey(ctx context.Context, in GetPublicKeyInput) (GetPublicKeyOutput, error) {
	f.calls = append(f.calls, "read:"+in.KeyID)
	if f.boundary == "open" {
		return GetPublicKeyOutput{}, f.fault
	}
	return f.fakeKMS.GetPublicKey(ctx, in)
}
func (f *f1FaultKMS) Sign(ctx context.Context, in SignInput) (SignOutput, error) {
	f.calls = append(f.calls, "sign:"+in.KeyID)
	return SignOutput{}, f.fault
}
func (f *f1FaultKMS) CreateSigningKey(context.Context, CreateSigningKeyInput) (CreateSigningKeyOutput, error) {
	f.forbidden++
	return CreateSigningKeyOutput{}, fmt.Errorf("forbidden generation")
}
func (f *f1FaultKMS) ScheduleKeyDeletion(context.Context, ScheduleKeyDeletionInput) error {
	f.forbidden++
	return fmt.Errorf("forbidden deletion")
}

// Mode: fake-only. Given an exact existing Ed25519 ARN, When read/sign fails,
// Then no provider/signature, mutation, other reference or selected-key change escapes.
func TestExistingKeyFaultsFailClosed(t *testing.T) {
	const ref = "arn:aws:kms:us-east-1:111122223333:key/11111111-1111-4111-8111-111111111111"
	for _, tc := range []struct {
		name  string
		fault error
	}{
		{"denied", &smithy.GenericAPIError{Code: "AccessDeniedException", Message: "denied selected existing key"}},
		{"disabled", &types.DisabledException{}},
		{"missing-key", &types.NotFoundException{}},
		{"service-failure", &types.KMSInternalException{}},
	} {
		for _, boundary := range []string{"open", "sign"} {
			t.Run(tc.name+"/"+boundary, func(t *testing.T) {
				home := t.TempDir()
				t.Setenv("HOME", home)
				f := &f1FaultKMS{fakeKMS: newFakeEd25519KMS(t, ref), boundary: boundary, fault: tc.fault}
				p, err := Load(context.Background(), f, Config{State: State{ActiveKeyID: ref}, Algorithm: types.SigningAlgorithmSpecEd25519Sha512})
				want := []string{"read:" + ref}
				if boundary == "open" {
					if err == nil || p != nil {
						t.Fatalf("fault returned provider=%v error=%v", p, err)
					}
				} else {
					if err != nil || p == nil {
						t.Fatalf("healthy open failed: %v", err)
					}
					before, _ := json.Marshal(p.JWK())
					ids := p.ListKeyIds()
					if len(ids) != 1 || p.JWK() == nil {
						t.Fatal("healthy public signer missing")
					}
					sig, err := p.Sign([]byte("must not sign"))
					if err == nil || sig != nil {
						t.Fatalf("fault returned signature=%v error=%v", sig, err)
					}
					after, _ := json.Marshal(p.JWK())
					if string(before) != string(after) || !reflect.DeepEqual(ids, p.ListKeyIds()) {
						t.Fatal("selected public signer changed")
					}
					want = append(want, "sign:"+ref)
				}
				if !reflect.DeepEqual(f.calls, want) || f.forbidden != 0 {
					t.Fatalf("calls=%v want=%v forbidden=%d", f.calls, want, f.forbidden)
				}
				entries, err := os.ReadDir(home)
				if err != nil || len(entries) != 0 {
					t.Fatalf("local files=%v error=%v", entries, err)
				}
			})
		}
	}
}
