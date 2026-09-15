package dnsid

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"os"
	"strings"
	"testing"

	"github.com/lestrrat-go/jwx/v3/jwk"
)

type es256Vector struct {
	Kid       string `json:"kid"`
	D         string `json:"d"`
	X         string `json:"x"`
	Y         string `json:"y"`
	Payload   string `json:"payload"`
	Signature string `json:"signature"`
}

func TestJoseAlgValid(t *testing.T) {
	if !JoseAlgEdDSA.Valid() || !JoseAlgES256.Valid() {
		t.Fatal("expected EdDSA and ES256 to be valid")
	}
	for _, alg := range []JoseAlg{"", "none", "HS256", "ES384", "eddsa"} {
		if alg.Valid() {
			t.Fatalf("alg %q unexpectedly valid", alg)
		}
	}
}

func TestES256Vectors(t *testing.T) {
	var vectors []es256Vector
	data, err := os.ReadFile("testdata/es256/vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, &vectors); err != nil {
		t.Fatal(err)
	}
	if len(vectors) < 2 {
		t.Fatalf("got %d vectors, want at least 2", len(vectors))
	}

	for _, vector := range vectors {
		t.Run(vector.Kid, func(t *testing.T) {
			priv := privateKeyFromVector(t, vector)
			got, err := signES256(priv, []byte(vector.Payload))
			if err != nil {
				t.Fatalf("signES256: %v", err)
			}
			gotB64 := base64.RawURLEncoding.EncodeToString(got)
			if gotB64 != vector.Signature {
				t.Fatalf("signature = %s, want %s", gotB64, vector.Signature)
			}
			if !verifyES256(&priv.PublicKey, []byte(vector.Payload), got) {
				t.Fatal("verifyES256 rejected vector signature")
			}
		})
	}
}

func TestES256ValidationBranches(t *testing.T) {
	kp := GenerateES256KeyProvider()
	priv := testActiveECDSAPrivateKey(t, kp)
	payload := []byte("payload")
	sig, err := signES256(priv, payload)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := signES256(nil, payload); err == nil {
		t.Fatal("signES256 accepted nil private key")
	}
	wrongCurve, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if _, err := signES256(wrongCurve, payload); err == nil {
		t.Fatal("signES256 accepted P-384 key")
	}
	zeroD := *priv
	zeroD.D = big.NewInt(0) //nolint:staticcheck // Test intentionally corrupts the private scalar.
	if _, err := signES256(&zeroD, payload); err == nil {
		t.Fatal("signES256 accepted zero private scalar")
	}

	if verifyES256(nil, payload, sig) {
		t.Fatal("verifyES256 accepted nil public key")
	}
	badPub := &ecdsa.PublicKey{Curve: elliptic.P256(), X: big.NewInt(1), Y: big.NewInt(1)} //nolint:staticcheck // Intentionally malformed point.
	if verifyES256(badPub, payload, sig) {
		t.Fatal("verifyES256 accepted invalid P-256 point")
	}
	if verifyES256(&priv.PublicKey, payload, sig[:10]) {
		t.Fatal("verifyES256 accepted short signature")
	}
}

func TestES256RawFromDER(t *testing.T) {
	valid, err := asn1.Marshal(struct {
		R *big.Int
		S *big.Int
	}{R: big.NewInt(7), S: new(big.Int).Sub(p256Order, big.NewInt(7))})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := es256RawFromDER(valid)
	if err != nil {
		t.Fatalf("es256RawFromDER(valid): %v", err)
	}
	r, s := es256RawRS(raw)
	if r.Cmp(big.NewInt(7)) != 0 || s.Cmp(big.NewInt(7)) != 0 {
		t.Fatalf("raw R/S = %s/%s, want 7/7 after low-S normalization", r, s)
	}

	for name, der := range map[string][]byte{
		"garbage":  []byte("not-der"),
		"nil-r":    mustASN1(t, struct{ S *big.Int }{S: big.NewInt(1)}),
		"r-zero":   mustASN1(t, struct{ R, S *big.Int }{R: big.NewInt(0), S: big.NewInt(1)}),
		"s-zero":   mustASN1(t, struct{ R, S *big.Int }{R: big.NewInt(1), S: big.NewInt(0)}),
		"r>=n":     mustASN1(t, struct{ R, S *big.Int }{R: p256Order, S: big.NewInt(1)}),
		"s>=n":     mustASN1(t, struct{ R, S *big.Int }{R: big.NewInt(1), S: p256Order}),
		"trailing": append(append([]byte(nil), valid...), 0),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := es256RawFromDER(der); err == nil {
				t.Fatal("expected DER conversion error")
			}
		})
	}
}

func TestTXTRecordES256RoundTrip(t *testing.T) {
	esKP := GenerateES256KeyProvider()
	rec := testTXTRecord("es256.example.com")
	sig, err := signRecordWithKeyProvider(rec, esKP)
	if err != nil {
		t.Fatalf("signRecordWithKeyProvider: %v", err)
	}
	if strings.ContainsAny(sig, ":=") {
		t.Fatalf("sg= %q, want bare unpadded base64url", sig)
	}
	set := jwkSet(t, esKP.JWK())
	if err := verifyRecordSignatureWithJWKS(rec, set); err != nil {
		t.Fatalf("verifyRecordSignatureWithJWKS: %v", err)
	}
}

func TestTXTRecordRejectsOwnerUse(t *testing.T) {
	esKP := GenerateES256KeyProvider()
	rec := testTXTRecord("owner-precedence.example.com")
	if _, err := signRecordWithKeyProvider(rec, esKP); err != nil {
		t.Fatal(err)
	}

	edPub, _, _ := ed25519.GenerateKey(rand.Reader)
	ownerJWK, err := jwk.Import(edPub)
	if err != nil {
		t.Fatal(err)
	}
	_ = ownerJWK.Set(jwk.KeyIDKey, "ed-owner")
	_ = ownerJWK.Set(jwk.AlgorithmKey, mustJWA(t, JoseAlgEdDSA))
	_ = ownerJWK.Set(jwk.KeyUsageKey, "owner")

	err = verifyRecordSignatureWithJWKS(rec, jwkSet(t, ownerJWK, esKP.JWK()))
	if !errors.Is(err, ErrOwnerSignatureInvalidJWKS) {
		t.Fatalf("verifyRecordSignatureWithJWKS err = %v, want ErrOwnerSignatureInvalidJWKS", err)
	}
}

func TestJWKSValidationMixedAndNegative(t *testing.T) {
	edKP := GenerateEd25519KeyProvider()
	esKP := GenerateES256KeyProvider()
	doc := jwksJSON(t, edKP.JWK(), esKP.JWK())
	parsed, err := ParseJWKS(doc)
	if err != nil {
		t.Fatalf("ParseJWKS mixed: %v", err)
	}
	if parsed.set.Len() != 2 {
		t.Fatalf("mixed JWKS len = %d, want 2", parsed.set.Len())
	}

	if _, err := ParseJWKS(jwksJSON(t, esKP.JWK(), esKP.JWK())); err == nil {
		t.Fatal("duplicate kid JWKS accepted")
	}

	var bad map[string]any
	if err := json.Unmarshal(mustJSON(t, esKP.JWK()), &bad); err != nil {
		t.Fatal(err)
	}
	bad["y"] = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	badDoc, _ := json.Marshal(map[string]any{"keys": []any{bad}})
	if _, err := ParseJWKS(badDoc); err == nil {
		t.Fatal("invalid P-256 point accepted")
	}
}

func TestLocalKeyProviderLifecycleES256(t *testing.T) {
	kp := GenerateEd25519KeyProvider()
	previousActive := kp.ListKeyIds()[0]
	pending, err := kp.GenerateKey(JoseAlgES256)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	if ids := kp.ListKeyIds(); len(ids) != 1 || ids[0] != previousActive {
		t.Fatalf("ListKeyIds with pending = %v, want only active key", ids)
	}
	if kp.JWK(pending) == nil {
		t.Fatal("JWK(pending) = nil")
	}
	activeJWK := kp.JWK(previousActive)
	_ = activeJWK.Set(jwk.KeyIDKey, "mutated")
	if kid, _ := kp.JWK(previousActive).KeyID(); kid == "mutated" {
		t.Fatal("JWK returned mutable provider state")
	}
	if err := kp.Activate(pending); err != nil {
		t.Fatalf("Activate: %v", err)
	}
	if ids := kp.ListKeyIds(); len(ids) != 2 || ids[0] != pending || ids[1] != previousActive {
		t.Fatalf("ListKeyIds after activate = %v", ids)
	}
	if err := kp.Purge(previousActive); err != nil {
		t.Fatalf("Purge: %v", err)
	}
	if ids := kp.ListKeyIds(); len(ids) != 1 || ids[0] != pending {
		t.Fatalf("ListKeyIds after purge = %v", ids)
	}
}

func privateKeyFromVector(t *testing.T, vector es256Vector) *ecdsa.PrivateKey {
	t.Helper()
	dBytes, err := base64.RawURLEncoding.DecodeString(vector.D)
	if err != nil {
		t.Fatal(err)
	}
	xBytes, err := base64.RawURLEncoding.DecodeString(vector.X)
	if err != nil {
		t.Fatal(err)
	}
	yBytes, err := base64.RawURLEncoding.DecodeString(vector.Y)
	if err != nil {
		t.Fatal(err)
	}
	encodedPublic := make([]byte, 1+len(xBytes)+len(yBytes))
	encodedPublic[0] = 4
	copy(encodedPublic[1:], xBytes)
	copy(encodedPublic[1+len(xBytes):], yBytes)
	publicKey, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), encodedPublic)
	if err != nil {
		t.Fatal(err)
	}
	privateKey, err := ecdsa.ParseRawPrivateKey(elliptic.P256(), dBytes)
	if err != nil {
		t.Fatal(err)
	}
	if !publicKey.Equal(privateKey.Public()) {
		t.Fatal("vector public key does not match private key")
	}
	return privateKey
}

func testActiveECDSAPrivateKey(t *testing.T, kp *LocalKeyProvider) *ecdsa.PrivateKey {
	t.Helper()
	kp.mu.RLock()
	defer kp.mu.RUnlock()
	entry := kp.activeEntryLocked()
	if entry == nil {
		t.Fatal("no active key")
	}
	priv, ok := entry.signer.(*ecdsa.PrivateKey)
	if !ok {
		t.Fatalf("active key = %T, want *ecdsa.PrivateKey", entry.signer)
	}
	return priv
}

func testTXTRecord(fqdn string) *TXTRecord {
	return &TXTRecord{
		Version:      DefaultPublishProfile,
		GovernanceID: fqdn,
		EntityKeyURI: "https://" + fqdn + "/.well-known/entity-jwks.json",
		KeyURI:       "https://" + fqdn + "/.well-known/jwks.json",
		LogRef:       "algorand:ADDR123",
		StatusURI:    "https://status.example.com/" + fqdn,
	}
}

func jwkSet(t *testing.T, keys ...jwk.Key) jwk.Set {
	t.Helper()
	set := jwk.NewSet()
	for _, key := range keys {
		if err := set.AddKey(key); err != nil {
			t.Fatal(err)
		}
	}
	return set
}

func mustJWA(t *testing.T, alg JoseAlg) any {
	t.Helper()
	jwaAlg, ok := alg.jwa()
	if !ok {
		t.Fatalf("unsupported alg %q", alg)
	}
	return jwaAlg
}

func jwksJSON(t *testing.T, keys ...jwk.Key) []byte {
	t.Helper()
	rawKeys := make([]json.RawMessage, 0, len(keys))
	for _, key := range keys {
		rawKeys = append(rawKeys, mustJSON(t, key))
	}
	out, err := json.Marshal(struct {
		Keys []json.RawMessage `json:"keys"`
	}{Keys: rawKeys})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func mustJSON(t *testing.T, v any) json.RawMessage {
	t.Helper()
	data, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func mustASN1(t *testing.T, v any) []byte {
	t.Helper()
	data, err := asn1.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return data
}
