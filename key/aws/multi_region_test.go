package awskms

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
	"testing"
)

func topology61() [][2]string {
	return [][2]string{{"arn:aws:kms:us-east-1:123456789012:key/mrk-0123456789abcdef0123456789abcdef", "arn:aws:kms:us-west-2:123456789012:key/mrk-0123456789abcdef0123456789abcdef"}}
}
func nativeKid61(ref, thumb string) string { return ref }

type regional61 struct {
	t       *testing.T
	ref     string
	private ed25519.PrivateKey
}

func (f *regional61) CreateSigningKey(context.Context, CreateSigningKeyInput) (CreateSigningKeyOutput, error) {
	f.t.Fatal("open/sign must not provision")
	return CreateSigningKeyOutput{}, nil
}
func (f *regional61) ScheduleKeyDeletion(context.Context, ScheduleKeyDeletionInput) error {
	f.t.Fatal("unexpected mutation")
	return nil
}
func (f *regional61) GetPublicKey(_ context.Context, in GetPublicKeyInput) (GetPublicKeyOutput, error) {
	if in.KeyID != f.ref {
		f.t.Fatal("regional request misbound")
	}
	der, err := x509.MarshalPKIXPublicKey(f.private.Public())
	return GetPublicKeyOutput{KeyID: f.ref, PublicKey: der, KeySpec: types.KeySpecEccNistEdwards25519, KeyUsage: types.KeyUsageTypeSignVerify, SigningAlgorithms: []types.SigningAlgorithmSpec{types.SigningAlgorithmSpecEd25519Sha512}}, err
}
func (f *regional61) Sign(_ context.Context, in SignInput) (SignOutput, error) {
	if in.KeyID != f.ref || in.Digest || in.Algorithm != types.SigningAlgorithmSpecEd25519Sha512 {
		f.t.Fatal("wrong regional RAW signing request")
	}
	return SignOutput{KeyID: f.ref, Signature: ed25519.Sign(f.private, in.Message), Algorithm: in.Algorithm}, nil
}
func open61(t *testing.T, ref string, private ed25519.PrivateKey) *Provider {
	t.Helper()
	p, err := Load(context.Background(), &regional61{t, ref, private}, Config{State: State{ActiveKeyID: ref}, Algorithm: types.SigningAlgorithmSpecEd25519Sha512})
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// #61 unchanged-contract characterization. Mode: real-capable (cloud=fake).
// Synthetic topology is NOT proof of service replication or location support.
func TestMultiRegionSameKey(t *testing.T) {
	seed, _ := hex.DecodeString("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
	private := ed25519.NewKeyFromSeed(seed)
	raw, _ := hex.DecodeString("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
	vector, _ := hex.DecodeString("e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b")
	if !ed25519.Verify(raw, nil, vector) {
		t.Fatal("RFC oracle failed")
	}
	x := base64.RawURLEncoding.EncodeToString(raw)
	digest := sha256.Sum256([]byte(`{"crv":"Ed25519","kty":"OKP","x":"` + x + `"}`))
	thumb := base64.RawURLEncoding.EncodeToString(digest[:])
	wrong := ed25519.NewKeyFromSeed(make([]byte, 32)).Public().(ed25519.PublicKey)
	wrongX := base64.RawURLEncoding.EncodeToString(wrong)
	wrongDigest := sha256.Sum256([]byte(`{"crv":"Ed25519","kty":"OKP","x":"` + wrongX + `"}`))
	if digest == wrongDigest {
		t.Fatal("different-key SAME-KEY oracle did not discriminate")
	}
	for _, refs := range topology61() {
		t.Run(refs[0], func(t *testing.T) {
			// Given two independent cloud clients with the same RFC public material.
			var keys []ed25519.PublicKey
			var signatures [][]byte
			payload := []byte("#61 bounded RAW cross-region payload")
			for restart := 0; restart < 2; restart++ {
				for _, ref := range refs {
					// When opening the exact configured reference with a fresh client/provider.
					p := open61(t, ref, private)
					key := p.JWK()
					encoded, err := json.Marshal(key)
					if err != nil {
						t.Fatal(err)
					}
					var j map[string]any
					if err = json.Unmarshal(encoded, &j); err != nil {
						t.Fatal(err)
					}
					// Then compare cryptographic members, never the complete JWK/native IDs.
					for k, v := range map[string]string{"kty": "OKP", "crv": "Ed25519", "alg": "EdDSA", "x": x} {
						if j[k] != v {
							t.Fatalf("%s = %v want %s", k, j[k], v)
						}
					}
					if _, ok := j["d"]; ok {
						t.Fatal("private key exposed")
					}
					gotDigest := sha256.Sum256([]byte(`{"crv":"Ed25519","kty":"OKP","x":"` + j["x"].(string) + `"}`))
					if base64.RawURLEncoding.EncodeToString(gotDigest[:]) != thumb {
						t.Fatal("thumbprint mismatch")
					}
					wantKid := nativeKid61(ref, thumb)
					if j["kid"] != wantKid {
						t.Fatalf("native kid=%v want %s", j["kid"], wantKid)
					}
					ids := p.ListKeyIds()
					if len(ids) != 1 || ids[0] != wantKid {
						t.Fatalf("ids=%v", ids)
					}
					resolved := p.JWK(wantKid)
					if resolved == nil {
						t.Fatal("native kid does not resolve")
					}
					resolvedJSON, _ := json.Marshal(resolved)
					var r map[string]any
					_ = json.Unmarshal(resolvedJSON, &r)
					if r["x"] != x {
						t.Fatal("kid resolves another key")
					}
					sig, err := p.Sign(payload)
					if err != nil {
						t.Fatal(err)
					}
					if sig.Kid != wantKid || string(sig.Alg) != "EdDSA" {
						t.Fatalf("signature binding=%+v", sig)
					}
					decoded, err := base64.RawURLEncoding.DecodeString(j["x"].(string))
					if err != nil {
						t.Fatal(err)
					}
					keys = append(keys, ed25519.PublicKey(decoded))
					signatures = append(signatures, sig.Signature)
				}
			}
			// Then every independent signature cross-verifies after fresh reopen.
			for _, sig := range signatures {
				for _, pub := range keys {
					if !ed25519.Verify(pub, payload, sig) {
						t.Fatal("cross verification failed")
					}
				}
				if ed25519.Verify(raw, append(append([]byte{}, payload...), 1), sig) || ed25519.Verify(wrong, payload, sig) {
					t.Fatal("tamper/wrong-key accepted")
				}
			}
		})
	}
}
