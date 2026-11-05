package gcpkms_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"hash/crc32"
	"os"
	"reflect"
	"strings"
	"testing"

	kms "cloud.google.com/go/kms/apiv1"
	"cloud.google.com/go/kms/apiv1/kmspb"
	dnsid "github.com/dnsid-ai/dnsid-go"
	gcpkms "github.com/dnsid-ai/dnsid-go/key/gcp"
	"github.com/googleapis/gax-go/v2"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

const version = "projects/test-project/locations/global/keyRings/agents/cryptoKeys/signing/cryptoKeyVersions/1"

var _ gcpkms.Client = (*kms.KeyManagementClient)(nil)
var _ dnsid.KeyProvider = (*gcpkms.Provider)(nil)

func checksum(b []byte) *wrapperspb.Int64Value {
	return wrapperspb.Int64(int64(crc32.Checksum(b, crc32.MakeTable(crc32.Castagnoli))))
}

// RFC 8032 section 7.1 test 1; no fixture comes from executing the provider.
func fixture(t *testing.T) (ed25519.PrivateKey, ed25519.PublicKey) {
	t.Helper()
	seed, err := hex.DecodeString("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
	if err != nil {
		t.Fatal(err)
	}
	public, err := hex.DecodeString("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
	if err != nil {
		t.Fatal(err)
	}
	return ed25519.NewKeyFromSeed(seed), ed25519.PublicKey(public)
}

type fakeKMS struct {
	t               *testing.T
	private         ed25519.PrivateKey
	public          *kmspb.PublicKey
	signMutate      func(*kmspb.AsymmetricSignResponse)
	getErr, signErr error
	gets            int
	want            []byte
}

func newFake(t *testing.T) *fakeKMS {
	t.Helper()
	private, public := fixture(t)
	der, err := x509.MarshalPKIXPublicKey(public)
	if err != nil {
		t.Fatal(err)
	}
	encoded := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
	return &fakeKMS{t: t, private: private, public: &kmspb.PublicKey{Name: version, Pem: string(encoded), PemCrc32C: checksum(encoded), Algorithm: kmspb.CryptoKeyVersion_EC_SIGN_ED25519, ProtectionLevel: kmspb.ProtectionLevel_SOFTWARE}}
}
func (f *fakeKMS) GetPublicKey(ctx context.Context, req *kmspb.GetPublicKeyRequest, _ ...gax.CallOption) (*kmspb.PublicKey, error) {
	f.gets++
	if req.GetName() != version {
		f.t.Errorf("GetPublicKey name=%q want immutable %q", req.GetName(), version)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return f.public, f.getErr
}
func (f *fakeKMS) AsymmetricSign(ctx context.Context, req *kmspb.AsymmetricSignRequest, _ ...gax.CallOption) (*kmspb.AsymmetricSignResponse, error) {
	if req.GetName() != version {
		f.t.Errorf("sign name=%q want %q", req.GetName(), version)
	}
	if req.GetDigest() != nil || req.GetDigestCrc32C() != nil {
		f.t.Error("Ed25519 request must send data, not digest")
	}
	if !bytes.Equal(req.GetData(), f.want) {
		f.t.Errorf("data=%x want exact RAW %x", req.GetData(), f.want)
	}
	if req.GetDataCrc32C() == nil || req.GetDataCrc32C().GetValue() != checksum(f.want).GetValue() {
		f.t.Errorf("data CRC32C=%v want %v", req.GetDataCrc32C(), checksum(f.want))
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if f.signErr != nil {
		return nil, f.signErr
	}
	sig := ed25519.Sign(f.private, req.GetData())
	response := &kmspb.AsymmetricSignResponse{Name: version, Signature: sig, SignatureCrc32C: checksum(sig), VerifiedDataCrc32C: true, ProtectionLevel: kmspb.ProtectionLevel_SOFTWARE}
	if f.signMutate != nil {
		f.signMutate(response)
	}
	return response, nil
}

// Mode: fake-only (deterministic GCP client; no live-service runner).
// Given an existing software Ed25519 version, When opened twice and signing RAW
// payloads, Then only the public key is exposed, kid is stable/safe, and signatures
// independently verify. Lifecycle operations are deliberately reserved.
func TestProviderExistingEd25519RAW(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	f := newFake(t)
	p, err := gcpkms.New(context.Background(), f, gcpkms.Config{KeyVersionName: version})
	if err != nil {
		t.Fatal(err)
	}
	q, err := gcpkms.New(context.Background(), newFake(t), gcpkms.Config{KeyVersionName: version})
	if err != nil {
		t.Fatal(err)
	}
	key := p.JWK()
	if key == nil {
		t.Fatal("public JWK missing")
	}
	kid, ok := key.KeyID()
	if !ok || kid == "" || strings.Contains(kid, "#") {
		t.Fatalf("unsafe kid=%q", kid)
	}
	other, ok := q.JWK().KeyID()
	if !ok || kid != other {
		t.Fatalf("kid changed across reopen: %q / %q", kid, other)
	}
	if !reflect.DeepEqual(p.ListKeyIds(), []string{kid}) {
		t.Fatalf("active IDs=%v want [%s]", p.ListKeyIds(), kid)
	}
	if key.Has("d") {
		t.Fatal("private material exported in JWK")
	}
	alg, ok := key.Algorithm()
	if !ok || alg.String() != "EdDSA" {
		t.Fatalf("JWK alg=%v want EdDSA", alg)
	}
	var exported ed25519.PublicKey
	if err := jwk.Export(key, &exported); err != nil {
		t.Fatal(err)
	}
	_, public := fixture(t)
	if !bytes.Equal(exported, public) {
		t.Fatalf("public key=%x want RFC8032 key %x", exported, public)
	}
	for _, payload := range [][]byte{nil, {}, []byte("DNSid RAW bytes"), {0, 255, 128, 0, 10, 13}} {
		t.Run(hex.EncodeToString(payload), func(t *testing.T) {
			f.want = payload
			for _, sign := range []func([]byte) (*dnsid.KeySignature, error){p.Sign, func(b []byte) (*dnsid.KeySignature, error) { return p.SignKey(kid, b) }} {
				sig, err := sign(payload)
				if err != nil {
					t.Fatal(err)
				}
				if sig == nil {
					t.Fatal("missing signature")
				}
				if sig.Kid != kid || sig.Alg != dnsid.JoseAlgEdDSA {
					t.Fatalf("signature metadata kid=%q alg=%q", sig.Kid, sig.Alg)
				}
				if !ed25519.Verify(public, payload, sig.Signature) {
					t.Fatal("signature does not independently verify over exact RAW bytes")
				}
				if !bytes.Equal(sig.Signature, ed25519.Sign(f.private, payload)) {
					t.Fatal("signature differs from independent stdlib Ed25519 fixture")
				}
			}
		})
	}
	entries, err := os.ReadDir(home)
	if err != nil || len(entries) != 0 {
		t.Fatalf("provider wrote local files: %v %v", entries, err)
	}
}

// Mode: fake-only (injected faulty GCP response).
// Given corrupted or wrongly bound signing responses, When signing, Then no
// successful signature escapes.
func TestProviderRejectsUntrustedSigningResponses(t *testing.T) {
	cases := map[string]func(*kmspb.AsymmetricSignResponse){
		"different version": func(r *kmspb.AsymmetricSignResponse) { r.Name = version + "2" },
		"missing version":   func(r *kmspb.AsymmetricSignResponse) { r.Name = "" },
		"unverified data":   func(r *kmspb.AsymmetricSignResponse) { r.VerifiedDataCrc32C = false },
		"digest verification is not data verification": func(r *kmspb.AsymmetricSignResponse) { r.VerifiedDataCrc32C = false; r.VerifiedDigestCrc32C = true },
		"missing CRC32C": func(r *kmspb.AsymmetricSignResponse) { r.SignatureCrc32C = nil },
		"wrong CRC32C": func(r *kmspb.AsymmetricSignResponse) {
			r.SignatureCrc32C = wrapperspb.Int64(r.SignatureCrc32C.Value ^ 1)
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			f := newFake(t)
			f.signMutate = mutate
			p, err := gcpkms.New(context.Background(), f, gcpkms.Config{KeyVersionName: version})
			if err != nil {
				t.Fatal(err)
			}
			sig, err := p.Sign(nil)
			if err == nil || sig != nil {
				t.Fatalf("untrusted response accepted: signature=%v error=%v", sig, err)
			}
		})
	}
}

// Mode: fake-only (unsupported metadata, invalid key selection, service errors).
// Given invalid metadata or a failed service, When opening/signing, Then fail
// closed without substituting another signer.
func TestProviderRejectsInvalidMetadataAndServiceFailures(t *testing.T) {
	for _, name := range []string{"wrong version", "wrong algorithm", "invalid PEM", "bad PEM checksum"} {
		t.Run(name, func(t *testing.T) {
			f := newFake(t)
			switch name {
			case "wrong version":
				f.public.Name = version + "2"
			case "wrong algorithm":
				f.public.Algorithm = kmspb.CryptoKeyVersion_EC_SIGN_P256_SHA256
			case "invalid PEM":
				f.public.Pem = "not a public key"
				f.public.PemCrc32C = checksum([]byte(f.public.Pem))
			case "bad PEM checksum":
				f.public.PemCrc32C = wrapperspb.Int64(f.public.PemCrc32C.Value ^ 1)
			}
			p, err := gcpkms.New(context.Background(), f, gcpkms.Config{KeyVersionName: version})
			if err == nil || p != nil {
				t.Fatalf("bad public key accepted: provider=%v error=%v", p, err)
			}
		})
	}
	sentinel := errors.New("KMS permission denied")
	t.Run("public fetch denied", func(t *testing.T) {
		f := newFake(t)
		f.getErr = sentinel
		p, err := gcpkms.New(context.Background(), f, gcpkms.Config{KeyVersionName: version})
		if err == nil || p != nil {
			t.Fatalf("denied fetch accepted: %v %v", p, err)
		}
	})
	t.Run("sign denied", func(t *testing.T) {
		f := newFake(t)
		p, err := gcpkms.New(context.Background(), f, gcpkms.Config{KeyVersionName: version})
		if err != nil {
			t.Fatal(err)
		}
		f.signErr = sentinel
		sig, err := p.Sign(nil)
		if err == nil || sig != nil {
			t.Fatalf("denied signature accepted: %v %v", sig, err)
		}
	})
	for _, ref := range []string{"", strings.TrimSuffix(version, "/cryptoKeyVersions/1"), strings.TrimSuffix(version, "1") + "latest"} {
		t.Run("reference="+ref, func(t *testing.T) {
			f := newFake(t)
			p, err := gcpkms.New(context.Background(), f, gcpkms.Config{KeyVersionName: ref})
			if err == nil || p != nil {
				t.Fatalf("mutable/invalid reference accepted: %v %v", p, err)
			}
			if f.gets != 0 {
				t.Fatal("invalid reference reached cloud API")
			}
		})
	}
}
