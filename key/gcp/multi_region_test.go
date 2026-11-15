package gcpkms_test

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"testing"

	"cloud.google.com/go/kms/apiv1/kmspb"
	gcpkms "github.com/dnsid-ai/dnsid-go/key/gcp"
	"github.com/googleapis/gax-go/v2"
)

func regionalKeyReferences() [][2]string {
	var out [][2]string
	for _, loc := range []string{"us", "global"} {
		ref := "projects/fixture/locations/" + loc + "/keyRings/agents/cryptoKeys/signer/cryptoKeyVersions/7"
		out = append(out, [2]string{ref, ref})
	}
	return out
}
func expectedNativeKeyID(ref, thumb string) string { return thumb }

type regionalFakeKMS struct {
	t       *testing.T
	ref     string
	private ed25519.PrivateKey
}

func (f *regionalFakeKMS) GetPublicKey(_ context.Context, in *kmspb.GetPublicKeyRequest, _ ...gax.CallOption) (*kmspb.PublicKey, error) {
	if in.Name != f.ref {
		f.t.Fatal("wrong version request")
	}
	der, err := x509.MarshalPKIXPublicKey(f.private.Public())
	if err != nil {
		return nil, err
	}
	b := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
	return &kmspb.PublicKey{Name: f.ref, Pem: string(b), PemCrc32C: checksum(b), Algorithm: kmspb.CryptoKeyVersion_EC_SIGN_ED25519, ProtectionLevel: kmspb.ProtectionLevel_SOFTWARE}, nil
}
func (f *regionalFakeKMS) AsymmetricSign(_ context.Context, in *kmspb.AsymmetricSignRequest, _ ...gax.CallOption) (*kmspb.AsymmetricSignResponse, error) {
	if in.Name != f.ref || in.Digest != nil || in.DataCrc32C == nil || in.DataCrc32C.Value != checksum(in.Data).Value {
		f.t.Fatal("wrong version/RAW/integrity request")
	}
	sig := ed25519.Sign(f.private, in.Data)
	return &kmspb.AsymmetricSignResponse{Name: f.ref, Signature: sig, SignatureCrc32C: checksum(sig), VerifiedDataCrc32C: true, ProtectionLevel: kmspb.ProtectionLevel_SOFTWARE}, nil
}
func openRegionalProvider(t *testing.T, ref string, private ed25519.PrivateKey) *gcpkms.Provider {
	t.Helper()
	p, err := gcpkms.New(context.Background(), &regionalFakeKMS{t, ref, private}, gcpkms.Config{KeyVersionName: ref})
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// Regional public-key binding and cross-signatures. Mode: real-capable (cloud=fake).
// Synthetic topology is NOT proof of service replication or location support.
func TestProvider_RegionalKeysPreservePublicBinding(t *testing.T) {
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
	for _, refs := range regionalKeyReferences() {
		t.Run(refs[0], func(t *testing.T) {
			// Given two independent cloud clients with the same RFC public material.
			var keys []ed25519.PublicKey
			var signatures [][]byte
			payload := []byte("bounded RAW cross-region payload")
			for restart := 0; restart < 2; restart++ {
				for _, ref := range refs {
					// When opening the exact configured reference with a fresh client/provider.
					p := openRegionalProvider(t, ref, private)
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
					wantKid := expectedNativeKeyID(ref, thumb)
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
