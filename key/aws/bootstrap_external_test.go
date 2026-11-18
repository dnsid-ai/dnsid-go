package awskms_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/aws/smithy-go"
	dnsid "github.com/dnsid-ai/dnsid-go"
	awskms "github.com/dnsid-ai/dnsid-go/key/aws"
)

const bootAlias = "alias/dnsid/org/agent"
const bootA = "arn:aws:kms:us-east-1:123456789012:key/00000000-0000-0000-0000-000000000001"
const bootB = "arn:aws:kms:us-east-1:123456789012:key/00000000-0000-0000-0000-000000000002"

var bootAlgs = []types.SigningAlgorithmSpec{types.SigningAlgorithmSpecEcdsaSha256, types.SigningAlgorithmSpecEd25519Sha512}

type bootKey struct {
	out awskms.GetPublicKeyOutput
	ec  *ecdsa.PrivateKey
	ed  ed25519.PrivateKey
}

func bootFixture(t *testing.T, alg types.SigningAlgorithmSpec, id string, seed byte) bootKey {
	t.Helper()
	k := bootKey{out: awskms.GetPublicKeyOutput{KeyID: id, KeyUsage: types.KeyUsageTypeSignVerify, SigningAlgorithms: []types.SigningAlgorithmSpec{alg}}}
	var pub any
	if alg == types.SigningAlgorithmSpecEcdsaSha256 {
		// Preserve the fixed scalar seed+1 and distinct winner/candidate material.
		k.ec = bootECFixture(t, elliptic.P256(), int64(seed)+1)
		pub = &k.ec.PublicKey
		k.out.KeySpec = types.KeySpecEccNistP256
	} else {
		k.ed = ed25519.NewKeyFromSeed(bytes.Repeat([]byte{seed}, 32))
		pub = k.ed.Public()
		k.out.KeySpec = types.KeySpecEccNistEdwards25519
	}
	var err error
	k.out.PublicKey, err = x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// bootECFixture uses a fixed-width SEC 1 scalar, independent of product code.
func bootECFixture(t *testing.T, curve elliptic.Curve, scalar int64) *ecdsa.PrivateKey {
	t.Helper()
	raw := make([]byte, (curve.Params().N.BitLen()+7)/8)
	big.NewInt(scalar).FillBytes(raw)
	key, err := ecdsa.ParseRawPrivateKey(curve, raw)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

type bootFake struct {
	t                                 *testing.T
	mu                                *sync.Mutex
	keys                              map[string]bootKey
	aliases                           map[string]string
	next                              string
	gets                              map[string]int
	creates, acquires, deletes, signs int
	getHook                           func(string, int) (awskms.GetPublicKeyOutput, error, bool)
	createErr, aliasErr, signErr      error
	commitOnError                     bool
	beforeAlias                       func(context.Context, awskms.CreateAliasInput) error
}

func bootClient(t *testing.T, keys ...bootKey) *bootFake {
	f := &bootFake{t: t, mu: &sync.Mutex{}, keys: map[string]bootKey{}, aliases: map[string]string{}, gets: map[string]int{}, next: bootB}
	for _, k := range keys {
		f.keys[k.out.KeyID] = k
	}
	return f
}
func (f *bootFake) GetPublicKey(_ context.Context, in awskms.GetPublicKeyInput) (awskms.GetPublicKeyOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.gets[in.KeyID]++
	n := f.gets[in.KeyID]
	if n > 12 {
		f.t.Errorf("unbounded public-key reads for %q", in.KeyID)
		return awskms.GetPublicKeyOutput{}, errors.New("finite fake bound")
	}
	if f.getHook != nil {
		if o, e, ok := f.getHook(in.KeyID, n); ok {
			return o, e
		}
	}
	id := in.KeyID
	if v, ok := f.aliases[id]; ok {
		id = v
	}
	if k, ok := f.keys[id]; ok {
		return k.out, nil
	}
	return awskms.GetPublicKeyOutput{}, &types.NotFoundException{}
}
func (f *bootFake) CreateSigningKey(_ context.Context, in awskms.CreateSigningKeyInput) (awskms.CreateSigningKeyOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.creates++
	if f.creates > 2 {
		f.t.Error("extra allocation")
		return awskms.CreateSigningKeyOutput{}, errors.New("finite allocation bound")
	}
	if f.createErr != nil {
		return awskms.CreateSigningKeyOutput{}, f.createErr
	}
	if k, ok := f.keys[f.next]; ok && in.KeySpec != k.out.KeySpec {
		f.t.Errorf("candidate spec = %s; want %s", in.KeySpec, k.out.KeySpec)
	}
	if in.Description != "" || len(in.Tags) != 0 {
		f.t.Error("unexpected candidate options")
	}
	return awskms.CreateSigningKeyOutput{KeyID: f.next}, nil
}
func (f *bootFake) CreateAlias(ctx context.Context, in awskms.CreateAliasInput) error {
	f.mu.Lock()
	f.acquires++
	f.mu.Unlock()
	if f.beforeAlias != nil {
		if err := f.beforeAlias(ctx, in); err != nil {
			return err
		}
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if in.AliasName != bootAlias && in.AliasName != bootAlias+"-other" {
		f.t.Errorf("alias changed: %q", in.AliasName)
	}
	if in.TargetKeyID != f.next {
		f.t.Errorf("target changed: %q", in.TargetKeyID)
	}
	if f.aliasErr != nil {
		if f.commitOnError {
			f.aliases[in.AliasName] = in.TargetKeyID
		}
		return f.aliasErr
	}
	if _, ok := f.aliases[in.AliasName]; ok {
		return &types.AlreadyExistsException{}
	}
	f.aliases[in.AliasName] = in.TargetKeyID
	return nil
}
func (f *bootFake) ScheduleKeyDeletion(context.Context, awskms.ScheduleKeyDeletionInput) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.deletes++
	f.t.Error("bootstrap must never delete a possible winner")
	return errors.New("forbidden deletion")
}
func (f *bootFake) Sign(_ context.Context, in awskms.SignInput) (awskms.SignOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.signs++
	if f.signErr != nil {
		return awskms.SignOutput{}, f.signErr
	}
	k, ok := f.keys[in.KeyID]
	if !ok {
		return awskms.SignOutput{}, errors.New("sign must use immutable winner")
	}
	if in.Algorithm != k.out.SigningAlgorithms[0] {
		f.t.Error("sign algorithm changed")
	}
	var sig []byte
	var err error
	if k.ec != nil {
		h := sha256.Sum256(in.Message)
		digest := h[:]
		if in.Digest {
			digest = in.Message
		}
		sig, err = ecdsa.SignASN1(rand.Reader, k.ec, digest)
	} else {
		sig = ed25519.Sign(k.ed, in.Message)
	}
	return awskms.SignOutput{KeyID: in.KeyID, Algorithm: in.Algorithm, Signature: sig}, err
}
func bootCounts(t *testing.T, f *bootFake, alias string, reads, creates, acquires int) {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.gets[alias] != reads || f.creates != creates || f.acquires != acquires || f.deletes != 0 {
		t.Errorf("protocol counts alias=%d create=%d acquire=%d delete=%d; want %d/%d/%d/0", f.gets[alias], f.creates, f.acquires, f.deletes, reads, creates, acquires)
	}
}
func bootWinner(t *testing.T, r *awskms.BootstrapResult, err error, k bootKey) {
	t.Helper()
	if err != nil || r == nil || r.KeyProvider == nil {
		t.Fatalf("Then resolve a usable winner: result=%v error=%v", r, err)
	}
	if r.KeyRef != k.out.KeyID {
		t.Errorf("KeyRef=%q want exact %q", r.KeyRef, k.out.KeyID)
	}
	p := r.KeyProvider
	s := p.State()
	if s.ActiveKeyID != k.out.KeyID || len(s.PendingKeyIDs) != 0 || len(s.RetainedKeyIDs) != 0 {
		t.Errorf("winner state=%+v", s)
	}
	if !reflect.DeepEqual(p.ListKeyIds(), []string{k.out.KeyID}) {
		t.Errorf("winner IDs=%v", p.ListKeyIds())
	}
	j, e := p.JWKWithError()
	if e != nil || j == nil {
		t.Fatalf("winner JWK: %v", e)
	}
	raw, e := json.Marshal(j)
	if e != nil {
		t.Fatal(e)
	}
	var fields map[string]any
	if e = json.Unmarshal(raw, &fields); e != nil {
		t.Fatal(e)
	}
	if fields["kid"] != k.out.KeyID || fields["d"] != nil {
		t.Errorf("not public canonical JWK: %s", raw)
	}
	enc := base64.RawURLEncoding.EncodeToString
	if k.ec != nil {
		point, err := k.ec.PublicKey.Bytes()
		if err != nil {
			t.Fatal(err)
		}
		if fields["kty"] != "EC" || fields["crv"] != "P-256" || fields["x"] != enc(point[1:33]) || fields["y"] != enc(point[33:65]) {
			t.Errorf("JWK is not winner material: %s", raw)
		}
	} else {
		if fields["kty"] != "OKP" || fields["crv"] != "Ed25519" || fields["x"] != enc(k.ed.Public().(ed25519.PublicKey)) {
			t.Errorf("JWK is not winner material: %s", raw)
		}
	}
	if p.JWK() == nil {
		t.Error("active JWK absent")
	}
	msg := []byte("known62 independent winner proof")
	sig, e := p.Sign(msg)
	if e != nil || sig == nil {
		t.Fatalf("winner signing: %v", e)
	}
	if sig.Kid != k.out.KeyID {
		t.Errorf("signature kid=%q", sig.Kid)
	}
	if k.ec != nil {
		h := sha256.Sum256(msg)
		if sig.Alg != dnsid.JoseAlgES256 || len(sig.Signature) != 64 {
			t.Fatalf("not JOSE ES256: %+v", sig)
		}
		if !ecdsa.Verify(&k.ec.PublicKey, h[:], new(big.Int).SetBytes(sig.Signature[:32]), new(big.Int).SetBytes(sig.Signature[32:])) {
			t.Error("signature does not verify with winner")
		}
	} else if sig.Alg != dnsid.JoseAlgEdDSA || !ed25519.Verify(k.ed.Public().(ed25519.PublicKey), msg, sig.Signature) {
		t.Error("signature does not verify as winner EdDSA")
	}
}
func bootFailure(t *testing.T, r *awskms.BootstrapResult, err, want error) {
	t.Helper()
	if r != nil || err == nil {
		t.Fatalf("Then nil result and error: result=%v error=%v", r, err)
	}
	if want != nil && err != want { //nolint:errorlint // Contract requires the exact error object, not an equivalent error in its chain.
		t.Errorf("original error identity lost: got %v want %v", err, want)
	}
}
func bootWrap(err error) error {
	return &smithy.OperationError{ServiceID: "KMS", OperationName: "frozen", Err: fmt.Errorf("native wrapped: %w", err)}
}

// Mode: real-capable; executed offline with injected KMS. Given existing/missing
// aliases, When explicitly bootstrapped, Then public state and signatures name the winner.
func TestCreateOrReuse_PublicWinner(t *testing.T) {
	for _, alg := range bootAlgs {
		for _, existing := range []bool{true, false} {
			t.Run(fmt.Sprintf("%s/existing=%t", alg, existing), func(t *testing.T) {
				a, b := bootFixture(t, alg, bootA, 1), bootFixture(t, alg, bootB, 2)
				f := bootClient(t, a, b)
				winner := b
				reads, creates, acquires := 2, 1, 1
				if existing {
					f.aliases[bootAlias] = bootA
					winner = a
					reads, creates, acquires = 1, 0, 0
				}
				r, e := awskms.CreateOrReuse(context.Background(), f, awskms.BootstrapConfig{AliasName: bootAlias, Algorithm: alg})
				bootWinner(t, r, e, winner)
				bootCounts(t, f, bootAlias, reads, creates, acquires)
				// A fresh caller and ordinary Load must reuse the same immutable key.
				r, e = awskms.CreateOrReuse(context.Background(), f, awskms.BootstrapConfig{AliasName: bootAlias, Algorithm: alg})
				bootWinner(t, r, e, winner)
				bootCounts(t, f, bootAlias, reads+1, creates, acquires)
				p, e := awskms.Load(context.Background(), f, awskms.Config{State: awskms.State{ActiveKeyID: winner.out.KeyID}, Algorithm: alg})
				bootWinner(t, &awskms.BootstrapResult{KeyRef: winner.out.KeyID, KeyProvider: p}, e, winner)
				bootCounts(t, f, bootAlias, reads+1, creates, acquires)
			})
		}
	}
}

// Mode: fake-only (native error injection). Given stage faults, When bootstrapped,
// Then only native initial absence/native acquisition conflict permit recovery.
func TestCreateOrReuse_FiniteErrors(t *testing.T) {
	for _, alg := range bootAlgs {
		for _, tc := range []struct {
			name, stage string
			fault       error
			recover     bool
		}{
			{"initial-native", "initial", &types.NotFoundException{}, true}, {"initial-wrapped-native", "initial", bootWrap(&types.NotFoundException{}), true},
			{"initial-generic-code", "initial", &smithy.GenericAPIError{Code: "NotFoundException"}, false}, {"initial-denied", "initial", bootWrap(errors.New("denied")), false},
			{"create-error", "create", bootWrap(&types.NotFoundException{}), false}, {"acquire-error", "acquire", bootWrap(errors.New("response loss")), false},
			{"acquire-generic-code", "acquire", &smithy.GenericAPIError{Code: "AlreadyExistsException"}, false}, {"conflict-native", "acquire", &types.AlreadyExistsException{}, true}, {"conflict-wrapped", "acquire", bootWrap(&types.AlreadyExistsException{}), true},
			{"winner-notfound", "winner", bootWrap(&types.NotFoundException{}), false}, {"winner-denied", "winner", bootWrap(errors.New("winner denied")), false},
			{"conflict-winner-notfound", "conflict-winner", bootWrap(&types.NotFoundException{}), false},
		} {
			t.Run(string(alg)+"/"+tc.name, func(t *testing.T) {
				a, b := bootFixture(t, alg, bootA, 1), bootFixture(t, alg, bootB, 2)
				f := bootClient(t, a, b)
				f.getHook = func(id string, n int) (awskms.GetPublicKeyOutput, error, bool) {
					if id == bootAlias && n == 1 {
						if tc.stage == "initial" {
							return awskms.GetPublicKeyOutput{}, tc.fault, true
						}
						return awskms.GetPublicKeyOutput{}, bootWrap(&types.NotFoundException{}), true
					}
					if id == bootAlias && n == 2 {
						if tc.stage == "winner" || tc.stage == "conflict-winner" {
							return awskms.GetPublicKeyOutput{}, tc.fault, true
						}
						return a.out, nil, true
					}
					return awskms.GetPublicKeyOutput{}, nil, false
				}
				if tc.stage == "create" {
					f.createErr = tc.fault
				}
				if tc.stage == "acquire" {
					f.aliasErr = tc.fault
				}
				if tc.stage == "conflict-winner" {
					f.aliasErr = bootWrap(&types.AlreadyExistsException{})
				}
				r, e := awskms.CreateOrReuse(context.Background(), f, awskms.BootstrapConfig{AliasName: bootAlias, Algorithm: alg})
				reads, creates, acquires := 2, 1, 1
				if tc.recover {
					bootWinner(t, r, e, a)
				} else {
					bootFailure(t, r, e, tc.fault)
				}
				if tc.stage == "initial" && !tc.recover {
					reads, creates, acquires = 1, 0, 0
				}
				if tc.stage == "create" {
					reads, acquires = 1, 0
				}
				if tc.stage == "acquire" && !tc.recover {
					reads = 1
				}
				bootCounts(t, f, bootAlias, reads, creates, acquires)
			})
		}
	}
}

// Mode: fake-only (committed acquisition with lost response).
func TestCreateOrReuse_ResponseLossExplicitRecovery(t *testing.T) {
	for _, alg := range bootAlgs {
		t.Run(string(alg), func(t *testing.T) {
			k := bootFixture(t, alg, bootB, 2)
			f := bootClient(t, k)
			lost := bootWrap(context.DeadlineExceeded)
			f.aliasErr = lost
			f.commitOnError = true
			r, e := awskms.CreateOrReuse(context.Background(), f, awskms.BootstrapConfig{AliasName: bootAlias, Algorithm: alg})
			bootFailure(t, r, e, lost)
			bootCounts(t, f, bootAlias, 1, 1, 1)
			f.aliasErr = nil
			r, e = awskms.CreateOrReuse(context.Background(), f, awskms.BootstrapConfig{AliasName: bootAlias, Algorithm: alg})
			bootWinner(t, r, e, k)
			bootCounts(t, f, bootAlias, 2, 1, 1)
		})
	}
}

// Mode: real-capable; executed offline. Given invalid caller input, When called,
// Then ArgumentError precedes all dependency calls; empty algorithm defaults to ES256.
func TestCreateOrReuse_Inputs(t *testing.T) {
	for _, tc := range []struct {
		name, alias string
		alg         types.SigningAlgorithmSpec
		nilClient   bool
	}{
		{name: "nil", alias: bootAlias, nilClient: true}, {name: "empty"}, {name: "bare", alias: "org/name"}, {name: "empty-suffix", alias: "alias/"}, {name: "reserved", alias: "alias/aws/foo"}, {name: "fragment", alias: bootAlias + "#x"}, {name: "space", alias: " " + bootAlias}, {name: "unsupported", alias: bootAlias, alg: types.SigningAlgorithmSpecRsassaPssSha256},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := bootClient(t)
			var c awskms.BootstrapClient = f
			if tc.nilClient {
				c = nil
			}
			r, e := awskms.CreateOrReuse(context.Background(), c, awskms.BootstrapConfig{AliasName: tc.alias, Algorithm: tc.alg})
			bootFailure(t, r, e, nil)
			var arg *dnsid.ArgumentError
			if !errors.As(e, &arg) {
				t.Errorf("want ArgumentError; got %T", e)
			}
			bootCounts(t, f, tc.alias, 0, 0, 0)
		})
	}
	for _, suffix := range []string{"\n", "\r", "\r\n", "\u2028", "\u2029"} {
		t.Run(fmt.Sprintf("terminator-%x", []byte(suffix)), func(t *testing.T) {
			f := bootClient(t)
			r, e := awskms.CreateOrReuse(context.Background(), f, awskms.BootstrapConfig{AliasName: bootAlias + suffix})
			bootFailure(t, r, e, nil)
			var arg *dnsid.ArgumentError
			if !errors.As(e, &arg) {
				t.Errorf("want ArgumentError got %T", e)
			}
			bootCounts(t, f, bootAlias+suffix, 0, 0, 0)
		})
	}
	t.Run("default", func(t *testing.T) {
		k := bootFixture(t, bootAlgs[0], bootA, 1)
		f := bootClient(t, k)
		f.aliases[bootAlias] = bootA
		r, e := awskms.CreateOrReuse(context.Background(), f, awskms.BootstrapConfig{AliasName: bootAlias})
		bootWinner(t, r, e, k)
		bootCounts(t, f, bootAlias, 1, 0, 0)
	})
}

// Mode: real-capable for valid canonical identities; fake-only for corrupt remote
// identity injection. Given whole returned IDs, Then never accept a valid prefix.
func TestCreateOrReuse_CanonicalIdentity(t *testing.T) {
	valid := []string{"aBcDeF01-2345-0000-0000-123456789aBc", "mrk-0123456789abcdef0123456789ABCDEF", bootA, "arn:custom-partition:kms:region-1:123456789012:key/mrk-0123456789abcdef0123456789ABCDEF"}
	invalid := []string{"", " ", "arbitrary", "alias/name", "arn:aws:kms:us-east-1:123456789012:alias/name", "mrk-0123456789abcdef", "00000000-0000-0000-0000-000000000001/extra", "arn::kms:us-east-1:123456789012:key/00000000-0000-0000-0000-000000000001", "arn:aws:kms::123456789012:key/00000000-0000-0000-0000-000000000001", "arn:aws:kms:us-east-1:123:key/00000000-0000-0000-0000-000000000001", "arn:aws:s3:us-east-1:123456789012:key/00000000-0000-0000-0000-000000000001", bootA + "/extra", bootA + "#x", " " + bootA, bootA + " "}
	for _, suffix := range []string{"\n", "\r", "\r\n", "\u2028", "\u2029", "junk"} {
		for _, id := range valid {
			invalid = append(invalid, id+suffix)
		}
	}
	for _, alg := range bootAlgs {
		for _, created := range []bool{false, true} {
			for _, good := range []bool{true, false} {
				ids := invalid
				if good {
					ids = valid
				}
				for i, id := range ids {
					t.Run(fmt.Sprintf("%s/created=%t/valid=%t/%d", alg, created, good, i), func(t *testing.T) {
						k := bootFixture(t, alg, id, 1)
						f := bootClient(t, k)
						reads, creates, acquires := 1, 0, 0
						if created {
							f.next = id
							reads, creates, acquires = 2, 1, 1
							if !good {
								reads, acquires = 1, 0
							}
						} else {
							f.getHook = func(ref string, _ int) (awskms.GetPublicKeyOutput, error, bool) {
								if ref == bootAlias {
									return k.out, nil, true
								}
								return awskms.GetPublicKeyOutput{}, nil, false
							}
						}
						r, e := awskms.CreateOrReuse(context.Background(), f, awskms.BootstrapConfig{AliasName: bootAlias, Algorithm: alg})
						if good {
							bootWinner(t, r, e, k)
						} else {
							bootFailure(t, r, e, nil)
						}
						bootCounts(t, f, bootAlias, reads, creates, acquires)
					})
				}
			}
		}
	}
}

// Mode: fake-only (malformed remote metadata and material). Given a remote key,
// When resolving initial or acquired winners, Then incompatible data never succeeds.
func TestCreateOrReuse_InvalidRemote(t *testing.T) {
	for _, alg := range bootAlgs {
		for _, stage := range []string{"initial", "winner"} {
			for _, name := range []string{"missing-id", "bad-id", "usage", "spec", "algorithm", "der", "wrong-type", "wrong-curve", "identity-change", "material-change"} {
				t.Run(string(alg)+"/"+stage+"/"+name, func(t *testing.T) {
					a, b := bootFixture(t, alg, bootA, 1), bootFixture(t, alg, bootB, 2)
					bad := a.out
					bad.PublicKey = append([]byte(nil), bad.PublicKey...)
					switch name {
					case "missing-id":
						bad.KeyID = ""
					case "bad-id":
						bad.KeyID = bootA + "\n"
					case "usage":
						bad.KeyUsage = types.KeyUsageTypeEncryptDecrypt
					case "spec":
						bad.KeySpec = types.KeySpecRsa2048
					case "algorithm":
						bad.SigningAlgorithms = nil
					case "der":
						bad.PublicKey = []byte{1, 2, 3}
					case "wrong-type":
						other := bootAlgs[0]
						if alg == other {
							other = bootAlgs[1]
						}
						bad.PublicKey = bootFixture(t, other, bootA, 3).out.PublicKey
					case "wrong-curve":
						wrongCurve := bootECFixture(t, elliptic.P384(), 4)
						var err error
						bad.PublicKey, err = x509.MarshalPKIXPublicKey(&wrongCurve.PublicKey)
						if err != nil {
							t.Fatal(err)
						}
					}
					f := bootClient(t, a, b)
					f.getHook = func(id string, n int) (awskms.GetPublicKeyOutput, error, bool) {
						if id == bootAlias {
							if stage == "winner" && n == 1 {
								return awskms.GetPublicKeyOutput{}, &types.NotFoundException{}, true
							}
							return bad, nil, true
						}
						if id == bootA {
							if name == "identity-change" {
								return b.out, nil, true
							}
							if name == "material-change" {
								o := b.out
								o.KeyID = bootA
								return o, nil, true
							}
						}
						return awskms.GetPublicKeyOutput{}, nil, false
					}
					r, e := awskms.CreateOrReuse(context.Background(), f, awskms.BootstrapConfig{AliasName: bootAlias, Algorithm: alg})
					if name == "identity-change" || name == "material-change" {
						// Immutable reads are optional. If made, they must not switch identity/material.
						if f.gets[bootA] == 0 {
							bootWinner(t, r, e, a)
						} else {
							bootFailure(t, r, e, nil)
						}
					} else {
						bootFailure(t, r, e, nil)
					}
					reads, creates, acquires := 1, 0, 0
					if stage == "winner" {
						reads, creates, acquires = 2, 1, 1
					}
					bootCounts(t, f, bootAlias, reads, creates, acquires)
				})
			}
		}
	}
}

// Mode: fake-only (controlled interleaving). Given two fresh replicas and distinct
// candidates, When either acquires first, Then both sign as that exact winner.
func TestCreateOrReuse_ConcurrentConvergence(t *testing.T) {
	for _, alg := range bootAlgs {
		for _, alias := range []string{bootAlias, bootAlias + "-other"} {
			for _, first := range []int{0, 1} {
				t.Run(fmt.Sprintf("%s/%s/winner=%d", alg, alias, first), func(t *testing.T) {
					a, b := bootFixture(t, alg, bootA, 1), bootFixture(t, alg, bootB, 2)
					fs := []*bootFake{bootClient(t, a, b), bootClient(t, a, b)}
					fs[0].next = bootA
					fs[1].next = bootB
					fs[1].mu = fs[0].mu
					fs[1].aliases = fs[0].aliases
					ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
					defer cancel()
					arrived := make(chan int, 2)
					gates := []chan struct{}{make(chan struct{}), make(chan struct{})}
					var once [2]sync.Once
					release := func(i int) { once[i].Do(func() { close(gates[i]) }) }
					defer release(0)
					defer release(1)
					type answer struct {
						i int
						r *awskms.BootstrapResult
						e error
					}
					done := make(chan answer, 2)
					for i, f := range fs {
						f.beforeAlias = func(ctx context.Context, _ awskms.CreateAliasInput) error {
							arrived <- i
							select {
							case <-gates[i]:
								return nil
							case <-ctx.Done():
								return ctx.Err()
							}
						}
						go func(i int, f *bootFake) {
							r, e := awskms.CreateOrReuse(ctx, f, awskms.BootstrapConfig{AliasName: alias, Algorithm: alg})
							done <- answer{i, r, e}
						}(i, f)
					}
					results := make([]answer, 0, 2)
					reached := 0
					for reached < 2 && len(results) == 0 {
						select {
						case <-arrived:
							reached++
						case r := <-done:
							results = append(results, r)
						case <-ctx.Done():
							t.Error("barrier deadline")
							release(0)
							release(1)
							reached = 2
						}
					}
					release(first)
					if len(results) == 0 {
						select {
						case r := <-done:
							results = append(results, r)
							if r.i != first {
								t.Error("wrong barrier winner")
							}
						case <-ctx.Done():
							t.Error("first replica deadline")
						}
					}
					release(1 - first)
					for len(results) < 2 {
						select {
						case r := <-done:
							results = append(results, r)
						case <-time.After(4 * time.Second):
							t.Fatal("replicas did not terminate after bounded context")
						}
					}
					winner := []bootKey{a, b}[first]
					for _, r := range results {
						bootWinner(t, r.r, r.e, winner)
					}
					for _, f := range fs {
						bootCounts(t, f, alias, 2, 1, 1)
					}
				})
			}
		}
	}
}

// Mode: fake-only for injected signing/immutable errors. Given a valid existing
// winner, When a later public operation fails, Then preserve the native error value.
func TestCreateOrReuse_PublicErrorIdentity(t *testing.T) {
	for _, alg := range bootAlgs {
		t.Run(string(alg), func(t *testing.T) {
			k := bootFixture(t, alg, bootA, 1)
			f := bootClient(t, k)
			f.aliases[bootAlias] = bootA
			r, e := awskms.CreateOrReuse(context.Background(), f, awskms.BootstrapConfig{AliasName: bootAlias, Algorithm: alg})
			bootWinner(t, r, e, k)
			want := bootWrap(&types.NotFoundException{})
			f.signErr = want
			s, e := r.KeyProvider.Sign([]byte("failure"))
			if s != nil || e != want { //nolint:errorlint // Signing must return the exact injected error object without wrapping.
				t.Errorf("sign error identity: sig=%v err=%v", s, e)
			}
			bootCounts(t, f, bootAlias, 1, 0, 0)
		})
	}
}

// Mode: real-capable; offline characterization of unchanged public Load/GenerateKey.
// Given ordinary configuration, Then missing keys never bootstrap and generation
// always allocates a fresh pending key without replacing the active signer.
func TestBootstrapBoundary_OrdinaryLoadAndFreshGenerate(t *testing.T) {
	for _, alg := range bootAlgs {
		t.Run(string(alg), func(t *testing.T) {
			a, b := bootFixture(t, alg, bootA, 1), bootFixture(t, alg, bootB, 2)
			f := bootClient(t, a, b)
			p, e := awskms.Load(context.Background(), f, awskms.Config{State: awskms.State{ActiveKeyID: bootAlias}, Algorithm: alg})
			if p != nil || e == nil {
				t.Fatalf("missing Load unexpectedly succeeded: %v %v", p, e)
			}
			bootCounts(t, f, bootAlias, 1, 0, 0)
			p, e = awskms.Load(context.Background(), f, awskms.Config{State: awskms.State{ActiveKeyID: bootA}, Algorithm: alg})
			if e != nil {
				t.Fatal(e)
			}
			jose := dnsid.JoseAlgES256
			if alg == bootAlgs[1] {
				jose = dnsid.JoseAlgEdDSA
			}
			kid, e := p.GenerateKey(jose)
			if e != nil || kid != bootB {
				t.Fatalf("fresh pending: kid=%q err=%v", kid, e)
			}
			state := p.State()
			if state.ActiveKeyID != bootA || !reflect.DeepEqual(state.PendingKeyIDs, []string{bootB}) || len(state.RetainedKeyIDs) != 0 {
				t.Errorf("generation state=%+v", state)
			}
			if !reflect.DeepEqual(p.ListKeyIds(), []string{bootA}) {
				t.Errorf("pending key became public active: %v", p.ListKeyIds())
			}
			// Validate the unchanged active signer without assuming pending-free state.
			sig, e := p.Sign([]byte("active remains"))
			if e != nil || sig == nil || sig.Kid != bootA {
				t.Errorf("generation replaced signer: %v %v", sig, e)
			}
			bootCounts(t, f, bootAlias, 1, 1, 0)
		})
	}
}

// Mode: fake-only (optional immutable-read fault). Given a valid resolved winner,
// When an implementation elects an immutable validation read, Then its original
// error must propagate. No extra immutable read is required by this test.
func TestCreateOrReuse_OptionalCanonicalError(t *testing.T) {
	for _, alg := range bootAlgs {
		t.Run(string(alg), func(t *testing.T) {
			k := bootFixture(t, alg, bootA, 1)
			f := bootClient(t, k)
			want := bootWrap(errors.New("canonical read denied"))
			f.getHook = func(id string, _ int) (awskms.GetPublicKeyOutput, error, bool) {
				if id == bootAlias {
					return k.out, nil, true
				}
				if id == bootA {
					return awskms.GetPublicKeyOutput{}, want, true
				}
				return awskms.GetPublicKeyOutput{}, nil, false
			}
			r, e := awskms.CreateOrReuse(context.Background(), f, awskms.BootstrapConfig{AliasName: bootAlias, Algorithm: alg})
			if f.gets[bootA] > 0 {
				bootFailure(t, r, e, want)
			} else {
				f.getHook = nil
				bootWinner(t, r, e, k)
			}
			bootCounts(t, f, bootAlias, 1, 0, 0)
		})
	}
}
