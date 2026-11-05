package gcpkms_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"reflect"
	"strings"
	"testing"

	"cloud.google.com/go/kms/apiv1/kmspb"
	dnsid "github.com/dnsid-ai/dnsid-go"
	gcpkms "github.com/dnsid-ai/dnsid-go/key/gcp"
	"github.com/googleapis/gax-go/v2"
	"github.com/lestrrat-go/jwx/v3/jwk"
)

// Provisional contract: sdk-compliance 3e5d4d7ca662270739aa28b9e0d86fac2a704949,
// 01 KeyProvider Interface and 12 Operational Key Source Selection (PR #56).
// No manager orchestration, persistence, or crash-recovery claims are made here.

const successorVersion = "projects/test-project/locations/global/keyRings/agents/cryptoKeys/signing/cryptoKeyVersions/2"

// The runtime fake must fail if merely opening/signing unexpectedly generates.
// Signature matches the official Google client; no provider-specific RPC types.
func (f *fakeKMS) CreateCryptoKeyVersion(context.Context, *kmspb.CreateCryptoKeyVersionRequest, ...gax.CallOption) (*kmspb.CryptoKeyVersion, error) {
	f.t.Fatal("runtime open/sign unexpectedly created a cloud version")
	return nil, nil
}

type lifecycleKMS struct {
	*fakeKMS
	successor                 ed25519.PrivateKey
	creates, cloudRetirements int
}

func lifecycleFake(t *testing.T) *lifecycleKMS {
	seed := sha256.Sum256([]byte("DNSid #56 independent pending Ed25519 fixture"))
	return &lifecycleKMS{fakeKMS: newFake(t), successor: ed25519.NewKeyFromSeed(seed[:])}
}
func (f *lifecycleKMS) CreateCryptoKeyVersion(ctx context.Context, req *kmspb.CreateCryptoKeyVersionRequest, _ ...gax.CallOption) (*kmspb.CryptoKeyVersion, error) {
	f.creates++
	parent := strings.TrimSuffix(version, "/cryptoKeyVersions/1")
	if req.GetParent() != parent {
		f.t.Errorf("created under %q want configured CryptoKey %q", req.GetParent(), parent)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	// Google chooses the algorithm from the parent CryptoKey version template;
	// the response, not an invented request algorithm field, identifies the result.
	return &kmspb.CryptoKeyVersion{Name: successorVersion, Algorithm: kmspb.CryptoKeyVersion_EC_SIGN_ED25519, State: kmspb.CryptoKeyVersion_ENABLED, ProtectionLevel: kmspb.ProtectionLevel_SOFTWARE}, nil
}
func (f *lifecycleKMS) GetPublicKey(ctx context.Context, req *kmspb.GetPublicKeyRequest, opts ...gax.CallOption) (*kmspb.PublicKey, error) {
	if req.GetName() == version {
		return f.fakeKMS.GetPublicKey(ctx, req, opts...)
	}
	if req.GetName() != successorVersion {
		f.t.Fatalf("unexpected public-key version %q", req.GetName())
	}
	der, err := x509.MarshalPKIXPublicKey(f.successor.Public())
	if err != nil {
		f.t.Fatal(err)
	}
	encoded := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
	return &kmspb.PublicKey{Name: successorVersion, Pem: string(encoded), PemCrc32C: checksum(encoded), Algorithm: kmspb.CryptoKeyVersion_EC_SIGN_ED25519, ProtectionLevel: kmspb.ProtectionLevel_SOFTWARE}, nil
}
func (f *lifecycleKMS) AsymmetricSign(ctx context.Context, req *kmspb.AsymmetricSignRequest, opts ...gax.CallOption) (*kmspb.AsymmetricSignResponse, error) {
	if req.GetName() == version {
		return f.fakeKMS.AsymmetricSign(ctx, req, opts...)
	}
	if req.GetName() != successorVersion {
		f.t.Fatalf("unexpected signing version %q", req.GetName())
	}
	if req.GetDigest() != nil || !bytes.Equal(req.GetData(), f.want) || req.GetDataCrc32C() == nil || req.GetDataCrc32C().Value != checksum(f.want).Value {
		f.t.Fatal("pending signature must use exact RAW data and CRC32C")
	}
	sig := ed25519.Sign(f.successor, req.GetData())
	return &kmspb.AsymmetricSignResponse{Name: successorVersion, Signature: sig, SignatureCrc32C: checksum(sig), VerifiedDataCrc32C: true, ProtectionLevel: kmspb.ProtectionLevel_SOFTWARE}, nil
}

// These additional official API methods detect accidental cloud retirement even
// if the provider later consumes an optional wider client interface.
func (f *lifecycleKMS) UpdateCryptoKeyVersion(context.Context, *kmspb.UpdateCryptoKeyVersionRequest, ...gax.CallOption) (*kmspb.CryptoKeyVersion, error) {
	f.cloudRetirements++
	f.t.Error("local supersession must not disable cloud version")
	return nil, nil
}
func (f *lifecycleKMS) DestroyCryptoKeyVersion(context.Context, *kmspb.DestroyCryptoKeyVersionRequest, ...gax.CallOption) (*kmspb.CryptoKeyVersion, error) {
	f.cloudRetirements++
	f.t.Error("local supersession must not schedule cloud destruction")
	return nil, nil
}

func lifecycleKid(t *testing.T, p dnsid.KeyProvider) string {
	t.Helper()
	k := p.JWK()
	if k == nil {
		t.Fatal("missing current public JWK")
	}
	kid, ok := k.KeyID()
	if !ok || kid == "" {
		t.Fatal("missing current kid")
	}
	return kid
}
func lifecycleSignature(t *testing.T, s *dnsid.KeySignature, err error, kid string, payload []byte, public ed25519.PublicKey) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
	if s == nil || s.Kid != kid || s.Alg != dnsid.JoseAlgEdDSA || !ed25519.Verify(public, payload, s.Signature) {
		t.Fatalf("signature must verify for eligible kid %q: %+v", kid, s)
	}
}

// Mode: fake-only (deterministic cloud client; no live-service runner).
// Given an opened immutable version, When explicitly generating a successor,
// Then it remains pending, public and proof-signable, without changing current
// signing, listing, or the caller's immutable configuration.
func TestProviderGenerateKeepsSuccessorPending(t *testing.T) {
	f := lifecycleFake(t)
	cfg := gcpkms.Config{KeyVersionName: version}
	original := cfg
	p, err := gcpkms.New(context.Background(), f, cfg)
	if err != nil {
		t.Fatal(err)
	}
	old := lifecycleKid(t, p)
	if f.creates != 0 {
		t.Fatal("opening existing key generated a version")
	}
	pending, err := p.GenerateKey(dnsid.JoseAlgEdDSA)
	if err != nil {
		t.Fatalf("explicit Ed25519 generation must create pending version: %v", err)
	}
	if pending == "" || pending == old || strings.Contains(pending, "#") {
		t.Fatalf("invalid pending kid %q", pending)
	}
	if f.creates != 1 {
		t.Fatalf("created %d versions want 1", f.creates)
	}
	if !reflect.DeepEqual(cfg, original) {
		t.Fatal("generation mutated caller configuration")
	}
	if lifecycleKid(t, p) != old || !reflect.DeepEqual(p.ListKeyIds(), []string{old}) {
		t.Fatal("generation changed current signer/live inventory")
	}
	key := p.JWK(pending)
	if key == nil || key.Has("d") {
		t.Fatal("pending public JWK missing or exports private material")
	}
	var public ed25519.PublicKey
	if err := jwk.Export(key, &public); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(public, f.successor.Public().(ed25519.PublicKey)) {
		t.Fatal("pending JWK not bound to generated version")
	}
	f.want = []byte{0, 255, 17}
	s, err := p.SignKey(pending, f.want)
	lifecycleSignature(t, s, err, pending, f.want, public)
	_, oldPublic := fixture(t)
	s, err = p.Sign(f.want)
	lifecycleSignature(t, s, err, old, f.want, oldPublic)
	// Reopening the unchanged configured version must not silently select the
	// cloud-enabled successor. Application state restoration is out of scope.
	reopened, err := gcpkms.New(context.Background(), f, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if lifecycleKid(t, reopened) != old {
		t.Fatal("reopen implicitly promoted generated cloud version")
	}
}

// Mode: fake-only (deterministic cloud client).
// Given a pending successor, When explicitly activating and superseding locally,
// Then only the successor is current; superseded keys cannot sign, cloud state
// is untouched, and superseding the last active key leaves no active inventory.
func TestProviderActivateAndSupersedeAreLocal(t *testing.T) {
	f := lifecycleFake(t)
	p, err := gcpkms.New(context.Background(), f, gcpkms.Config{KeyVersionName: version})
	if err != nil {
		t.Fatal(err)
	}
	old := lifecycleKid(t, p)
	pending, err := p.GenerateKey(dnsid.JoseAlgEdDSA)
	if err != nil {
		t.Fatalf("generate pending: %v", err)
	}
	if err := p.Activate(pending); err != nil {
		t.Fatalf("explicit activation: %v", err)
	}
	if lifecycleKid(t, p) != pending || !reflect.DeepEqual(p.ListKeyIds(), []string{pending}) {
		t.Fatal("activation must expose only successor")
	}
	f.want = []byte("post activation")
	s, err := p.Sign(f.want)
	lifecycleSignature(t, s, err, pending, f.want, f.successor.Public().(ed25519.PublicKey))
	s, err = p.SignKey(old, f.want)
	if err == nil || s != nil {
		t.Fatal("previous active key remained signing-eligible after promotion")
	}
	if err := p.Supersede(old); err != nil {
		t.Fatalf("supersede retained previous key: %v", err)
	}
	if lifecycleKid(t, p) != pending || !reflect.DeepEqual(p.ListKeyIds(), []string{pending}) {
		t.Fatal("superseding previous key cleared successor")
	}
	s, err = p.SignKey(old, f.want)
	if err == nil || s != nil {
		t.Fatal("superseded previous key can sign")
	}
	if err := p.Supersede(pending); err != nil {
		t.Fatalf("supersede current key: %v", err)
	}
	if len(p.ListKeyIds()) != 0 {
		t.Fatalf("no active key but live inventory=%v", p.ListKeyIds())
	}
	s, err = p.Sign(f.want)
	if err == nil || s != nil {
		t.Fatal("signing succeeded with no active key")
	}
	s, err = p.SignKey(pending, f.want)
	if err == nil || s != nil {
		t.Fatal("superseded successor can sign")
	}
	if f.cloudRetirements != 0 {
		t.Fatal("local transitions retired a cloud version")
	}
}
