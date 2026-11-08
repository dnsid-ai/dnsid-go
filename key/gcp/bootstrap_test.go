package gcpkms_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"hash/crc32"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"cloud.google.com/go/kms/apiv1/kmspb"
	dnsid "github.com/dnsid-ai/dnsid-go"
	gcpkms "github.com/dnsid-ai/dnsid-go/key/gcp"
	"github.com/googleapis/gax-go/v2"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

const firstParent = "projects/first-project/locations/global/keyRings/agents/cryptoKeys/signing"
const firstVersion = firstParent + "/cryptoKeyVersions/1"

// Fixture private material exists only in the fake service. RFC8032 section 7.1
// test 1 supplies the independent public oracle; no SDK crypto helpers used.
func firstFixture(t *testing.T) (ed25519.PrivateKey, ed25519.PublicKey) {
	t.Helper()
	seed, err := hex.DecodeString("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
	if err != nil {
		t.Fatal(err)
	}
	pub, err := hex.DecodeString("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
	if err != nil {
		t.Fatal(err)
	}
	return ed25519.NewKeyFromSeed(seed), ed25519.PublicKey(pub)
}
func firstThumb(pub ed25519.PublicKey) string {
	canonical := fmt.Sprintf(`{"crv":"Ed25519","kty":"OKP","x":"%s"}`, base64.RawURLEncoding.EncodeToString(pub))
	sum := sha256.Sum256([]byte(canonical))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}
func firstJWK(t *testing.T, k jwk.Key, kid string, pub ed25519.PublicKey) {
	t.Helper()
	if k == nil {
		t.Fatal("missing public JWK")
	}
	raw, err := json.Marshal(k)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	for name, want := range map[string]string{"kty": "OKP", "crv": "Ed25519", "x": base64.RawURLEncoding.EncodeToString(pub), "kid": kid, "alg": "EdDSA"} {
		if m[name] != want {
			t.Errorf("JWK %s=%v want %s", name, m[name], want)
		}
	}
	if _, exists := m["d"]; exists {
		t.Fatal("private JWK material exposed")
	}
	// Rebuild the RFC7638 input from returned public fields, not SDK Thumbprint.
	sum := sha256.Sum256([]byte(fmt.Sprintf(`{"crv":"%s","kty":"%s","x":"%s"}`, m["crv"], m["kty"], m["x"])))
	if base64.RawURLEncoding.EncodeToString(sum[:]) != firstThumb(pub) {
		t.Fatal("wrong independent thumbprint")
	}
}
func firstSignature(t *testing.T, s *dnsid.KeySignature, err error, kid string, payload []byte, pub ed25519.PublicKey) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
	if s == nil || s.Kid != kid || s.Alg != dnsid.JoseAlgEdDSA || !ed25519.Verify(pub, payload, s.Signature) {
		t.Fatalf("invalid independent RAW signature: %+v", s)
	}
	if ed25519.Verify(pub, append(append([]byte(nil), payload...), '!'), s.Signature) {
		t.Fatal("signature accepted altered payload")
	}
	other := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{42}, ed25519.SeedSize)).Public().(ed25519.PublicKey)
	if ed25519.Verify(other, payload, s.Signature) {
		t.Fatal("signature accepted other public key")
	}
}

// Fake-only filesystem invariant. This covers the setup directory, NOT arbitrary
// process paths, authentication caches, or memory-only local key generation.
func firstNoFiles(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	t.Chdir(dir)
	t.Setenv("HOME", dir)
	t.Setenv("XDG_CONFIG_HOME", dir)
	t.Cleanup(func() {
		entries, err := os.ReadDir(dir)
		if err != nil {
			t.Error(err)
		} else if len(entries) != 0 {
			t.Errorf("SDK created setup files: %v", entries)
		}
	})
}
func firstCRC(b []byte) *wrapperspb.Int64Value {
	return wrapperspb.Int64(int64(crc32.Checksum(b, crc32.MakeTable(crc32.Castagnoli))))
}

type firstService struct {
	t                                              *testing.T
	private                                        ed25519.PrivateKey
	creates, parents, gets, publics, signs, closes int
	created, pending                               bool
	createErr, publicErr                           error
	template                                       *kmspb.CryptoKeyVersionTemplate
	mutateParent                                   func(*kmspb.CryptoKey)
	mutateVersion                                  func(*kmspb.CryptoKeyVersion)
	mutatePublic                                   func(*kmspb.PublicKey)
}

func newFirstService(t *testing.T) *firstService {
	priv, _ := firstFixture(t)
	return &firstService{t: t, private: priv, template: &kmspb.CryptoKeyVersionTemplate{Algorithm: kmspb.CryptoKeyVersion_EC_SIGN_ED25519, ProtectionLevel: kmspb.ProtectionLevel_SOFTWARE}}
}
func (f *firstService) Close() error { f.closes++; return nil }
func (f *firstService) GetCryptoKey(ctx context.Context, req *kmspb.GetCryptoKeyRequest, _ ...gax.CallOption) (*kmspb.CryptoKey, error) {
	f.parents++
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if req.GetName() != firstParent {
		return nil, errors.New("wrong existing parent")
	}
	// Existing compatible parent has NO primary or prior version.
	out := &kmspb.CryptoKey{Name: firstParent, Purpose: kmspb.CryptoKey_ASYMMETRIC_SIGN, VersionTemplate: f.template}
	if f.mutateParent != nil {
		f.mutateParent(out)
	}
	return out, nil
}
func (f *firstService) metadata() *kmspb.CryptoKeyVersion {
	state := kmspb.CryptoKeyVersion_ENABLED
	if f.pending {
		state = kmspb.CryptoKeyVersion_PENDING_GENERATION
	}
	v := &kmspb.CryptoKeyVersion{Name: firstVersion, Algorithm: kmspb.CryptoKeyVersion_EC_SIGN_ED25519, State: state, ProtectionLevel: kmspb.ProtectionLevel_SOFTWARE}
	if f.mutateVersion != nil {
		f.mutateVersion(v)
	}
	return v
}
func (f *firstService) CreateCryptoKeyVersion(ctx context.Context, req *kmspb.CreateCryptoKeyVersionRequest, _ ...gax.CallOption) (*kmspb.CryptoKeyVersion, error) {
	f.creates++
	if req.GetParent() != firstParent {
		f.t.Errorf("wrong create parent %q", req.GetParent())
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if f.createErr != nil {
		return nil, f.createErr
	}
	f.created = true
	return f.metadata(), nil
}
func (f *firstService) GetCryptoKeyVersion(ctx context.Context, req *kmspb.GetCryptoKeyVersionRequest, _ ...gax.CallOption) (*kmspb.CryptoKeyVersion, error) {
	f.gets++
	if !f.created || req.GetName() != firstVersion {
		f.t.Errorf("read nonexistent prior version %q", req.GetName())
		return nil, errors.New("prior version forbidden")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	f.pending = false
	return f.metadata(), nil
}
func (f *firstService) GetPublicKey(ctx context.Context, req *kmspb.GetPublicKeyRequest, _ ...gax.CallOption) (*kmspb.PublicKey, error) {
	f.publics++
	if !f.created || req.GetName() != firstVersion {
		f.t.Errorf("opened prior/substituted version %q", req.GetName())
		return nil, errors.New("no prior version")
	}
	if f.pending {
		return nil, errors.New("public read before ready")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if f.publicErr != nil {
		return nil, f.publicErr
	}
	der, err := x509.MarshalPKIXPublicKey(f.private.Public())
	if err != nil {
		return nil, err
	}
	encoded := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
	out := &kmspb.PublicKey{Name: firstVersion, Pem: string(encoded), PemCrc32C: firstCRC(encoded), Algorithm: kmspb.CryptoKeyVersion_EC_SIGN_ED25519, ProtectionLevel: kmspb.ProtectionLevel_SOFTWARE}
	if f.mutatePublic != nil {
		f.mutatePublic(out)
	}
	return out, nil
}
func (f *firstService) AsymmetricSign(ctx context.Context, req *kmspb.AsymmetricSignRequest, _ ...gax.CallOption) (*kmspb.AsymmetricSignResponse, error) {
	f.signs++
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if !f.created || req.GetName() != firstVersion || req.GetDigest() != nil || req.GetDataCrc32C() == nil || req.GetDataCrc32C().Value != firstCRC(req.GetData()).Value {
		return nil, errors.New("not exact version RAW Ed25519 with CRC32C")
	}
	sig := ed25519.Sign(f.private, req.GetData())
	return &kmspb.AsymmetricSignResponse{Name: firstVersion, Signature: sig, SignatureCrc32C: firstCRC(sig), VerifiedDataCrc32C: true, ProtectionLevel: kmspb.ProtectionLevel_SOFTWARE}, nil
}
func (f *firstService) DestroyCryptoKeyVersion(context.Context, *kmspb.DestroyCryptoKeyVersionRequest, ...gax.CallOption) (*kmspb.CryptoKeyVersion, error) {
	f.t.Error("destructive cloud cleanup forbidden")
	return nil, errors.New("forbidden")
}
func (f *firstService) UpdateCryptoKeyVersion(context.Context, *kmspb.UpdateCryptoKeyVersionRequest, ...gax.CallOption) (*kmspb.CryptoKeyVersion, error) {
	f.t.Error("local activation changed remote state")
	return nil, errors.New("forbidden")
}

// Mode: real-capable (GCP dependency fake here); exact RPC counts, caller-client
// ownership and setup-directory checks are separate fake-only invariants.
// Given a compatible existing parent with zero versions, When explicitly creating,
// Then only the first new version is opened, pending until explicit activation;
// immutable reopen returns identical independent JWK/signing identity.
func TestCreate_FirstVersionPendingActivateReopen(t *testing.T) {
	for _, pending := range []bool{false, true} {
		t.Run(fmt.Sprintf("cloud-pending-%t", pending), func(t *testing.T) {
			firstNoFiles(t)
			f := newFirstService(t)
			f.pending = pending
			_, pub := firstFixture(t)
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			p, kid, ref, err := gcpkms.Create(ctx, f, firstParent)
			if err != nil {
				t.Fatal(err)
			}
			if kid != firstThumb(pub) {
				t.Fatalf("returned pending kid=%q want independent thumbprint %q", kid, firstThumb(pub))
			}
			if p == nil {
				t.Fatal("missing provider")
			}
			if ref != firstVersion {
				t.Fatalf("not immutable created version: %q", ref)
			}
			if len(p.ListKeyIds()) != 0 || p.JWK() != nil {
				t.Fatal("first key implicitly active")
			}
			if _, err := p.Sign([]byte("before activation")); err == nil {
				t.Fatal("pending key signed as active")
			}
			firstJWK(t, p.JWK(kid), kid, pub)
			payload := []byte("first GCP native raw payload\x00")
			sig, err := p.SignKey(kid, payload)
			firstSignature(t, sig, err, kid, payload, pub)
			if err := p.Activate(kid); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(p.ListKeyIds(), []string{kid}) {
				t.Fatal("activation listing wrong")
			}
			sig, err = p.Sign(payload)
			firstSignature(t, sig, err, kid, payload, pub)
			reopened, err := gcpkms.New(ctx, f, gcpkms.Config{KeyVersionName: ref})
			if err != nil {
				t.Fatal(err)
			}
			firstJWK(t, reopened.JWK(), kid, pub)
			sig, err = reopened.Sign(payload)
			firstSignature(t, sig, err, kid, payload, pub)
			if err := p.Close(); err != nil {
				t.Fatal(err)
			}
			if err := reopened.Close(); err != nil {
				t.Fatal(err)
			}
			if f.closes != 0 {
				t.Fatal("closed caller-owned client")
			}
			if f.creates != 1 {
				t.Fatalf("create count=%d want one", f.creates)
			}
			if pending && f.gets == 0 {
				t.Fatal("cloud pending was never checked for readiness")
			}
		})
	}
}

// Mode: fake-only (malformed metadata/integrity/service faults).
// Given a native failure, When creating first version, Then fail closed without
// activation, substituted signing, duplicate creation, or local files.
func TestCreate_FirstVersionFailures(t *testing.T) {
	denied := status.Error(codes.PermissionDenied, "native denied")
	cases := []struct {
		name     string
		setup    func(*firstService)
		wantCode codes.Code
	}{
		{"permission", func(f *firstService) { f.createErr = denied }, codes.PermissionDenied},
		{"empty-reference", func(f *firstService) { f.mutateVersion = func(v *kmspb.CryptoKeyVersion) { v.Name = "" } }, codes.OK},
		{"wrong-parent", func(f *firstService) {
			f.mutateVersion = func(v *kmspb.CryptoKeyVersion) { v.Name = strings.Replace(firstVersion, "/signing/", "/other/", 1) }
		}, codes.OK},
		{"wrong-algorithm", func(f *firstService) {
			f.mutateVersion = func(v *kmspb.CryptoKeyVersion) { v.Algorithm = kmspb.CryptoKeyVersion_EC_SIGN_P256_SHA256 }
		}, codes.OK},
		{"wrong-protection", func(f *firstService) {
			f.mutateVersion = func(v *kmspb.CryptoKeyVersion) { v.ProtectionLevel = kmspb.ProtectionLevel_HSM }
		}, codes.OK},
		{"disabled", func(f *firstService) {
			f.mutateVersion = func(v *kmspb.CryptoKeyVersion) { v.State = kmspb.CryptoKeyVersion_DISABLED }
		}, codes.OK},
		{"public-service", func(f *firstService) { f.publicErr = denied }, codes.PermissionDenied},
		{"public-binding", func(f *firstService) { f.mutatePublic = func(v *kmspb.PublicKey) { v.Name = firstVersion + "9" } }, codes.OK},
		{"public-algorithm", func(f *firstService) {
			f.mutatePublic = func(v *kmspb.PublicKey) { v.Algorithm = kmspb.CryptoKeyVersion_EC_SIGN_P256_SHA256 }
		}, codes.OK},
		{"public-crc", func(f *firstService) { f.mutatePublic = func(v *kmspb.PublicKey) { v.PemCrc32C.Value ^= 1 } }, codes.OK},
		{"malformed-public", func(f *firstService) {
			f.mutatePublic = func(v *kmspb.PublicKey) { v.Pem = "not PEM"; v.PemCrc32C = firstCRC([]byte(v.Pem)) }
		}, codes.OK},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			firstNoFiles(t)
			f := newFirstService(t)
			tc.setup(f)
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			p, _, _, err := gcpkms.Create(ctx, f, firstParent)
			if err == nil {
				t.Fatal("accepted invalid create")
			}
			if tc.wantCode != codes.OK && status.Code(err) != tc.wantCode {
				t.Fatalf("lost service status: %v", err)
			}
			if p != nil {
				if len(p.ListKeyIds()) != 0 {
					t.Fatal("failed create exposed active key")
				}
				if _, e := p.Sign([]byte("fallback")); e == nil {
					t.Fatal("failure substituted usable signer")
				}
			}
			if f.creates != 1 || f.signs != 0 || f.closes != 0 {
				t.Fatalf("creates=%d signs=%d caller closes=%d", f.creates, f.signs, f.closes)
			}
		})
	}
}

// Mode: fake-only (parent prerequisites and malformed operator inputs).
// Given an incompatible parent or non-parent selector, When creating, Then no
// version is created and no existing version is read.
func TestCreate_RejectsParentPrerequisites(t *testing.T) {
	for _, name := range []string{"empty", "version-not-parent", "wrong-template", "wrong-protection", "wrong-parent-name", "wrong-purpose"} {
		t.Run(name, func(t *testing.T) {
			firstNoFiles(t)
			f := newFirstService(t)
			parent := firstParent
			switch name {
			case "empty":
				parent = ""
			case "version-not-parent":
				parent = firstVersion
			case "wrong-parent-name":
				f.mutateParent = func(p *kmspb.CryptoKey) { p.Name = firstParent + "-other" }
			case "wrong-purpose":
				f.mutateParent = func(p *kmspb.CryptoKey) { p.Purpose = kmspb.CryptoKey_ENCRYPT_DECRYPT }
			case "wrong-template":
				f.template.Algorithm = kmspb.CryptoKeyVersion_EC_SIGN_P256_SHA256
			case "wrong-protection":
				f.template.ProtectionLevel = kmspb.ProtectionLevel_HSM
			}
			p, kid, ref, err := gcpkms.Create(context.Background(), f, parent)
			if err == nil || p != nil || kid != "" || ref != "" {
				t.Fatalf("Create = (%v, %q, %q, %v), want nil provider, empty references and error", p, kid, ref, err)
			}
			if f.creates != 0 || f.gets != 0 || f.publics != 0 {
				t.Fatalf("invalid parent caused mutations/prior reads: %+v", f)
			}
		})
	}
}

// Mode: fake-only (deterministic cancellation while first remote create waits).
// Given create is canceled in flight, When bootstrapping, Then return promptly
// without retry, activating a fallback, or closing caller-owned client.
type firstCanceledService struct{ *firstService }

func (f *firstCanceledService) CreateCryptoKeyVersion(ctx context.Context, req *kmspb.CreateCryptoKeyVersionRequest, _ ...gax.CallOption) (*kmspb.CryptoKeyVersion, error) {
	f.creates++
	<-ctx.Done()
	return nil, ctx.Err()
}
func TestCreate_CanceledFirstVersion(t *testing.T) {
	firstNoFiles(t)
	f := &firstCanceledService{newFirstService(t)}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	p, _, _, err := gcpkms.Create(ctx, f, firstParent)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("lost create deadline: %v", err)
	}
	if p != nil && len(p.ListKeyIds()) != 0 {
		t.Fatal("canceled create exposed active key")
	}
	if f.creates != 1 || f.publics != 0 || f.signs != 0 || f.closes != 0 {
		t.Fatal("canceled create retried/opened/signed/closed client")
	}
}

// Mode: fake-only (readiness metadata service stalls after one successful create).
// Given first-version generation is pending, When metadata cannot become ready
// before cancellation, Then error without opening public material or recreation.
type firstPendingService struct{ *firstService }

func (f *firstPendingService) GetCryptoKeyVersion(ctx context.Context, req *kmspb.GetCryptoKeyVersionRequest, _ ...gax.CallOption) (*kmspb.CryptoKeyVersion, error) {
	f.gets++
	if req.GetName() != firstVersion {
		f.t.Error("read prior/substituted version")
	}
	<-ctx.Done()
	return nil, ctx.Err()
}
func TestCreate_CanceledFirstVersionReadiness(t *testing.T) {
	firstNoFiles(t)
	base := newFirstService(t)
	base.pending = true
	f := &firstPendingService{base}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	p, _, _, err := gcpkms.Create(ctx, f, firstParent)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("lost readiness deadline: %v", err)
	}
	if p != nil && len(p.ListKeyIds()) != 0 {
		t.Fatal("readiness failure exposed active key")
	}
	if f.creates != 1 || f.gets == 0 || f.publics != 0 || f.signs != 0 || f.closes != 0 {
		t.Fatalf("wrong failed readiness calls: creates=%d gets=%d publics=%d signs=%d closes=%d", f.creates, f.gets, f.publics, f.signs, f.closes)
	}
}
