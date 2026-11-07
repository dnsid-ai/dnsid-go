package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"testing"

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

// Caller entity custody is prepared before installing the no-random guard.
// Its private bytes never pass to the setup helper, only this provider does.
type setupEntity struct {
	dnsid.KeyProvider
	public  jwk.Key
	private ed25519.PrivateKey
	signs   int
}

func newSetupEntity(t *testing.T, same bool) *setupEntity {
	t.Helper()
	priv, pub := firstFixture(t)
	if !same {
		priv = ed25519.NewKeyFromSeed(bytes.Repeat([]byte{37}, 32))
		pub = priv.Public().(ed25519.PublicKey)
	}
	k, err := jwk.Import(pub)
	if err != nil {
		t.Fatal(err)
	}
	if err = k.Set("kid", firstThumb(pub)); err != nil {
		t.Fatal(err)
	}
	if err = k.Set("alg", "EdDSA"); err != nil {
		t.Fatal(err)
	}
	return &setupEntity{public: k, private: priv}
}
func (e *setupEntity) JWK(...string) jwk.Key { return e.public }
func (e *setupEntity) ListKeyIds() []string {
	return []string{firstThumb(e.private.Public().(ed25519.PublicKey))}
}
func (e *setupEntity) Sign(b []byte) (*dnsid.KeySignature, error) {
	e.signs++
	return &dnsid.KeySignature{Kid: e.ListKeyIds()[0], Alg: dnsid.JoseAlgEdDSA, Signature: ed25519.Sign(e.private, b)}, nil
}
func (e *setupEntity) SignKey(_ string, b []byte) (*dnsid.KeySignature, error) { return e.Sign(b) }
func (e *setupEntity) GenerateKey(dnsid.JoseAlg) (string, error) {
	return "", errors.New("helper must not generate entity key")
}
func (e *setupEntity) Activate(string) error {
	return errors.New("helper must not activate entity key")
}

type setupNoRandom struct{ t *testing.T }

func (r setupNoRandom) Read([]byte) (int, error) {
	r.t.Error("setup attempted local random generation")
	return 0, io.ErrClosedPipe
}
func setupGuard(t *testing.T) {
	t.Helper()
	firstNoFiles(t)
	saved := rand.Reader
	rand.Reader = setupNoRandom{t}
	t.Cleanup(func() { rand.Reader = saved })
}
func setupConfig() dnsid.Config {
	return dnsid.Config{Identity: &dnsid.IdentityConfig{Domain: "agent.example.com", GovernanceID: "example.com", StatusURL: "https://agent.example.com/status", KeyURL: "https://agent.example.com/jwks", EntityKeyURL: "https://example.com/entity-jwks", LogRef: "c2sp-tlog:public:https://log.example.com#issuance_AAAAAAAAAAAAAAAAAAAAAA"}}
}
func setupSet(t *testing.T, set *dnsid.JWKS, pub ed25519.PublicKey) {
	t.Helper()
	if set == nil {
		t.Fatal("missing manager JWKS")
	}
	raw, err := json.Marshal(set.Raw())
	if err != nil {
		t.Fatal(err)
	}
	var parsed struct {
		Keys []map[string]any `json:"keys"`
	}
	if err = json.Unmarshal(raw, &parsed); err != nil {
		t.Fatal(err)
	}
	if len(parsed.Keys) != 1 {
		t.Fatalf("JWKS must expose exactly one public key: %s", raw)
	}
	k := parsed.Keys[0]
	if k["x"] != base64.RawURLEncoding.EncodeToString(pub) || k["kty"] != "OKP" || k["crv"] != "Ed25519" {
		t.Fatalf("wrong published input: %s", raw)
	}
	if _, ok := k["d"]; ok {
		t.Fatal("manager exposed private key")
	}
}

// Mode: real-capable (native KMS fake); random/files/call counts fake-only.
// Given caller-owned distinct entity custody, When first setup invokes the actual
// helper, Then manager JWKS is the remotely created operational key, entity JWKS
// remains caller supplied, and saved immutable state reopens without recreation.
func TestPrepareFirstSetup_ConsumerSuccess(t *testing.T) {
	entity := newSetupEntity(t, false)
	f := newFirstService(t)
	_, pub := firstFixture(t)
	setupGuard(t)
	manager, state, err := PrepareFirstSetup(context.Background(), f, setupConfig(), entity)
	if err != nil {
		t.Fatal(err)
	}
	if state.ActiveKeyID != firstARN || len(state.PendingKeyIDs) != 0 || len(state.RetainedKeyIDs) != 0 {
		t.Fatalf("not explicitly activated immutable state: %+v", state)
	}
	setupSet(t, manager.GetKeySet(), pub)
	setupSet(t, manager.GetEntityKeySet(), entity.private.Public().(ed25519.PublicKey))
	cfg := firstConfig()
	cfg.State = state
	reopened, err := awskms.Load(context.Background(), f, cfg)
	if err != nil {
		t.Fatal(err)
	}
	payload := []byte("consumer immutable reopen")
	sig, err := reopened.Sign(payload)
	firstSignature(t, sig, err, firstARN, payload, pub)
	again, err := dnsid.NewIdentityManager(setupConfig(), reopened, dnsid.WithEntityKeyProvider(entity))
	if err != nil {
		t.Fatal(err)
	}
	setupSet(t, again.GetKeySet(), pub)
	if f.creates != 1 || f.deletes != 0 || entity.signs != 0 {
		t.Fatalf("unexpected creation/destruction/issuance: creates=%d deletes=%d entity signs=%d", f.creates, f.deletes, entity.signs)
	}
}

// Mode: fake-only (before/after native-create failures).
// Given missing entity, KMS failure, invalid identity, or shared entity custody,
// When actual helper fails, Then no fallback manager, duplicate create, deletion,
// setup files, entity mutation, or fabricated issuance is produced.
func TestPrepareFirstSetup_ConsumerFailures(t *testing.T) {
	for _, name := range []string{"missing-entity", "create-denied", "public-denied", "invalid-config-after-create", "same-custody-after-create"} {
		t.Run(name, func(t *testing.T) {
			entity := newSetupEntity(t, name == "same-custody-after-create")
			f := newFirstService(t)
			cfg := setupConfig()
			var custody dnsid.KeyProvider = entity
			denied := errors.New("native denied")
			switch name {
			case "missing-entity":
				custody = nil
			case "create-denied":
				f.createErr = denied
			case "public-denied":
				f.publicErr = denied
			case "invalid-config-after-create":
				cfg.Identity.Domain = ""
			}
			setupGuard(t)
			manager, state, err := PrepareFirstSetup(context.Background(), f, cfg, custody)
			if err == nil {
				t.Fatal("invalid setup accepted")
			}
			if manager != nil {
				t.Fatal("failed setup returned usable fallback manager")
			}
			wantCreates := 1
			if name == "missing-entity" {
				wantCreates = 0
			}
			if f.creates != wantCreates || f.deletes != 0 || f.signs != 0 || entity.signs != 0 {
				t.Fatalf("unexpected failure calls: creates=%d deletes=%d signs=%d entity signs=%d", f.creates, f.deletes, f.signs, entity.signs)
			}
			if name == "invalid-config-after-create" || name == "same-custody-after-create" {
				if state.ActiveKeyID != firstARN {
					t.Fatal("lost operator recovery reference after creation")
				}
			}
			if (name == "create-denied" || name == "public-denied") && !errors.Is(err, denied) {
				t.Fatalf("lost native error: %v", err)
			}
		})
	}
}
