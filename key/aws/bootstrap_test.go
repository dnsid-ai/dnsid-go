package awskms_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/kms/types"
	dnsid "github.com/dnsid-ai/dnsid-go"
	awskms "github.com/dnsid-ai/dnsid-go/key/aws"
	"github.com/lestrrat-go/jwx/v3/jwk"
)

const firstARN = "arn:aws:kms:us-east-1:111122223333:key/11111111-1111-4111-8111-111111111111"

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

type firstService struct {
	t                              *testing.T
	private                        ed25519.PrivateKey
	creates, reads, signs, deletes int
	created                        bool
	createErr, publicErr           error
	createRef                      string
	mutate                         func(*awskms.GetPublicKeyOutput)
}

func newFirstService(t *testing.T) *firstService {
	priv, _ := firstFixture(t)
	return &firstService{t: t, private: priv, createRef: firstARN}
}
func (f *firstService) CreateSigningKey(ctx context.Context, in awskms.CreateSigningKeyInput) (awskms.CreateSigningKeyOutput, error) {
	f.creates++
	if in.KeySpec != types.KeySpecEccNistEdwards25519 {
		f.t.Errorf("create spec=%s, want native Ed25519", in.KeySpec)
	}
	if err := ctx.Err(); err != nil {
		return awskms.CreateSigningKeyOutput{}, err
	}
	if f.createErr != nil {
		return awskms.CreateSigningKeyOutput{}, f.createErr
	}
	f.created = true
	return awskms.CreateSigningKeyOutput{KeyID: f.createRef}, nil
}
func (f *firstService) GetPublicKey(ctx context.Context, in awskms.GetPublicKeyInput) (awskms.GetPublicKeyOutput, error) {
	f.reads++
	if err := ctx.Err(); err != nil {
		return awskms.GetPublicKeyOutput{}, err
	}
	if !f.created || in.KeyID != firstARN {
		return awskms.GetPublicKeyOutput{}, fmt.Errorf("no such key %q", in.KeyID)
	}
	if f.publicErr != nil {
		return awskms.GetPublicKeyOutput{}, f.publicErr
	}
	der, err := x509.MarshalPKIXPublicKey(f.private.Public())
	if err != nil {
		return awskms.GetPublicKeyOutput{}, err
	}
	out := awskms.GetPublicKeyOutput{KeyID: firstARN, PublicKey: der, KeySpec: types.KeySpecEccNistEdwards25519, KeyUsage: types.KeyUsageTypeSignVerify, SigningAlgorithms: []types.SigningAlgorithmSpec{types.SigningAlgorithmSpecEd25519Sha512}}
	if f.mutate != nil {
		f.mutate(&out)
	}
	return out, nil
}
func (f *firstService) Sign(ctx context.Context, in awskms.SignInput) (awskms.SignOutput, error) {
	f.signs++
	if err := ctx.Err(); err != nil {
		return awskms.SignOutput{}, err
	}
	if !f.created || in.KeyID != firstARN || in.Algorithm != types.SigningAlgorithmSpecEd25519Sha512 || in.Digest {
		return awskms.SignOutput{}, errors.New("not native RAW Ed25519 request")
	}
	return awskms.SignOutput{KeyID: firstARN, Signature: ed25519.Sign(f.private, in.Message), Algorithm: in.Algorithm}, nil
}
func (f *firstService) ScheduleKeyDeletion(context.Context, awskms.ScheduleKeyDeletionInput) error {
	f.deletes++
	return errors.New("unexpected destructive cleanup")
}
func firstConfig() awskms.Config {
	return awskms.Config{Algorithm: types.SigningAlgorithmSpecEd25519Sha512}
}

// Mode: real-capable (AWS dependency fake here); service call counts and no-file
// checks are fake-only invariants alongside the portable public behavior.
// Given no key exists, When explicitly creating, Then it is pending until local
// activation, signatures/JWK are independently correct and immutable reopen works.
func TestCreate_FirstKeyPendingActivateReopen(t *testing.T) {
	firstNoFiles(t)
	f := newFirstService(t)
	_, pub := firstFixture(t)
	p, err := awskms.Create(context.Background(), f, firstConfig())
	if err != nil {
		t.Fatal(err)
	}
	if p == nil {
		t.Fatal("missing provider")
	}
	state := p.State()
	if state.ActiveKeyID != "" || !reflect.DeepEqual(state.PendingKeyIDs, []string{firstARN}) || len(state.RetainedKeyIDs) != 0 {
		t.Fatalf("not pending canonical state: %+v", state)
	}
	if len(p.ListKeyIds()) != 0 || p.JWK() != nil {
		t.Fatal("first key implicitly active")
	}
	if _, err := p.Sign([]byte("before activation")); err == nil {
		t.Fatal("pending key signed as active")
	}
	firstJWK(t, p.JWK(firstARN), firstARN, pub)
	payload := []byte("KMS-first raw message\x00not a digest")
	sig, err := p.SignKey(firstARN, payload)
	firstSignature(t, sig, err, firstARN, payload, pub)
	if err := p.Activate(firstARN); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(p.ListKeyIds(), []string{firstARN}) {
		t.Fatal("activation did not expose exactly new key")
	}
	sig, err = p.Sign(payload)
	firstSignature(t, sig, err, firstARN, payload, pub)
	cfg := firstConfig()
	cfg.State = p.State()
	reopened, err := awskms.Load(context.Background(), f, cfg)
	if err != nil {
		t.Fatal(err)
	}
	firstJWK(t, reopened.JWK(), firstARN, pub)
	sig, err = reopened.Sign(payload)
	firstSignature(t, sig, err, firstARN, payload, pub)
	if f.creates != 1 || f.deletes != 0 {
		t.Fatalf("creates=%d deletions=%d", f.creates, f.deletes)
	}
}

// Mode: fake-only (fault injection into AWS native service responses).
// Given create or validation fails, When bootstrapping, Then no active fallback,
// automatic recreation, destructive cleanup, or setup file is produced.
func TestCreate_FirstKeyFailures(t *testing.T) {
	denied := errors.New("native permission denied")
	cases := []struct {
		name  string
		setup func(*firstService)
		want  error
	}{
		{"permission", func(f *firstService) { f.createErr = denied }, denied},
		{"empty-reference", func(f *firstService) { f.createRef = "" }, nil},
		{"public-service", func(f *firstService) { f.publicErr = denied }, denied},
		{"wrong-reference", func(f *firstService) { f.mutate = func(o *awskms.GetPublicKeyOutput) { o.KeyID = firstARN + "wrong" } }, nil},
		{"wrong-spec", func(f *firstService) {
			f.mutate = func(o *awskms.GetPublicKeyOutput) { o.KeySpec = types.KeySpecEccNistP256 }
		}, nil},
		{"wrong-algorithm", func(f *firstService) {
			f.mutate = func(o *awskms.GetPublicKeyOutput) {
				o.SigningAlgorithms = []types.SigningAlgorithmSpec{types.SigningAlgorithmSpecEcdsaSha256}
			}
		}, nil},
		{"invalid-public", func(f *firstService) {
			f.mutate = func(o *awskms.GetPublicKeyOutput) { o.PublicKey = []byte("not DER") }
		}, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			firstNoFiles(t)
			f := newFirstService(t)
			tc.setup(f)
			p, err := awskms.Create(context.Background(), f, firstConfig())
			if err == nil {
				t.Fatal("accepted invalid creation")
			}
			if tc.name != "permission" && tc.name != "empty-reference" && !strings.Contains(err.Error(), f.createRef) {
				t.Fatalf("error lost created key recovery reference %q: %v", f.createRef, err)
			}
			if tc.want != nil && !errors.Is(err, tc.want) {
				t.Fatalf("lost native error: %v", err)
			}
			if p != nil {
				if len(p.ListKeyIds()) != 0 {
					t.Fatal("failure exposed active key")
				}
				if _, e := p.Sign([]byte("fallback")); e == nil {
					t.Fatal("failure substituted usable signer")
				}
			}
			if f.creates != 1 || f.signs != 0 || f.deletes != 0 {
				t.Fatalf("unexpected mutation: creates=%d signs=%d deletes=%d", f.creates, f.signs, f.deletes)
			}
		})
	}
}

// Mode: fake-only (invalid local configuration must precede remote mutation).
// Given existing state or incompatible algorithm, When requesting first create,
// Then reject it rather than silently replace an established signer.
func TestCreate_RejectsExistingStateAndInvalidAlgorithm(t *testing.T) {
	for _, name := range []string{"active", "pending", "retained", "algorithm"} {
		t.Run(name, func(t *testing.T) {
			firstNoFiles(t)
			f := newFirstService(t)
			cfg := firstConfig()
			switch name {
			case "active":
				cfg.State.ActiveKeyID = firstARN
			case "pending":
				cfg.State.PendingKeyIDs = []string{firstARN}
			case "retained":
				cfg.State.RetainedKeyIDs = []string{firstARN}
			case "algorithm":
				cfg.Algorithm = types.SigningAlgorithmSpec("unsupported")
			}
			if _, err := awskms.Create(context.Background(), f, cfg); err == nil {
				t.Fatal("accepted invalid bootstrap config")
			}
			if f.creates != 0 || f.reads != 0 {
				t.Fatal("invalid config touched cloud")
			}
		})
	}
}

// Mode: fake-only (deterministic cancellation of the native create request).
// Given create waits for cancellation, When bootstrap's deadline expires, Then
// return the native context failure without retry, local fallback or key files.
type firstCanceledService struct{ *firstService }

func (f *firstCanceledService) CreateSigningKey(ctx context.Context, _ awskms.CreateSigningKeyInput) (awskms.CreateSigningKeyOutput, error) {
	f.creates++
	<-ctx.Done()
	return awskms.CreateSigningKeyOutput{}, ctx.Err()
}
func TestCreate_CanceledFirstKey(t *testing.T) {
	firstNoFiles(t)
	f := &firstCanceledService{newFirstService(t)}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	p, err := awskms.Create(ctx, f, firstConfig())
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("lost create deadline: %v", err)
	}
	if p != nil && len(p.ListKeyIds()) != 0 {
		t.Fatal("canceled create exposed active key")
	}
	if f.creates != 1 || f.reads != 0 || f.signs != 0 || f.deletes != 0 {
		t.Fatal("canceled create retried/opened/signed/deleted")
	}
}

// Mode: fake-only (caller cancellation after valid matching public output).
// Given opt-in purge deletion, When initial creation is canceled after its
// public read succeeds, Then reconciliation still belongs to the caller.
func TestCreate_LateCancellationLeavesOriginalForReconciliation(t *testing.T) {
	firstNoFiles(t)
	f := newFirstService(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	f.mutate = func(_ *awskms.GetPublicKeyOutput) { cancel() }
	cfg := firstConfig()
	cfg.ScheduleDeletionOnPurge = true
	p, err := awskms.Create(ctx, f, cfg)
	if p != nil || !errors.Is(err, context.Canceled) {
		t.Fatalf("Create = (%v, %v), want nil provider and caller cancellation", p, err)
	}
	if !strings.Contains(err.Error(), f.createRef) {
		t.Fatalf("error lost original created key recovery reference %q: %v", f.createRef, err)
	}
	if f.creates != 1 || f.reads != 1 || f.signs != 0 || f.deletes != 0 {
		t.Fatalf("creates=%d reads=%d signs=%d deletes=%d, want 1/1/0/0", f.creates, f.reads, f.signs, f.deletes)
	}
}
