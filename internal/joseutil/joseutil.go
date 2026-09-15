package joseutil

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"fmt"
	"strings"

	"github.com/dnsid-ai/dnsid-go"
	"github.com/dnsid-ai/dnsid-go/internal/cryptoutil"
	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
)

type ProtectedHeader struct {
	Alg dnsid.JoseAlg
	Kid string
}

type SignatureParts struct {
	SigningInput []byte
	Signature    []byte
}

func LookupJWKByKid(set jwk.Set, kid string) (jwk.Key, bool) {
	if set == nil || kid == "" {
		return nil, false
	}
	for i := 0; i < set.Len(); i++ {
		key, ok := set.Key(i)
		if !ok {
			continue
		}
		if keyKid, ok := key.KeyID(); ok && keyKid == kid {
			return key, true
		}
	}
	return nil, false
}

func AlgForJWK(key jwk.Key) (dnsid.JoseAlg, bool) {
	if key == nil {
		return "", false
	}
	switch key.KeyType() {
	case jwa.OKP():
		if crv, ok := JWKCurve(key); ok && crv == jwa.Ed25519() {
			return dnsid.JoseAlgEdDSA, true
		}
	case jwa.EC():
		if crv, ok := JWKCurve(key); ok && crv == jwa.P256() {
			return dnsid.JoseAlgES256, true
		}
	}
	return "", false
}

func JWKCurve(key jwk.Key) (jwa.EllipticCurveAlgorithm, bool) {
	type curveKey interface {
		Crv() (jwa.EllipticCurveAlgorithm, bool)
	}
	if k, ok := key.(curveKey); ok {
		return k.Crv()
	}
	return jwa.EmptyEllipticCurveAlgorithm(), false
}

func JWKAlg(key jwk.Key) (dnsid.JoseAlg, bool) {
	alg, ok := key.Algorithm()
	if !ok || alg == nil {
		return "", false
	}
	return dnsid.JoseAlg(alg.String()), true
}

func JWKMatchesAlg(key jwk.Key, alg dnsid.JoseAlg) bool {
	binding, ok := AlgForJWK(key)
	if !ok || binding != alg {
		return false
	}
	if KeyUse(key) == "enc" {
		return false
	}
	if fieldAlg, ok := JWKAlg(key); ok && fieldAlg != alg {
		return false
	}
	return true
}

func SigningKeyEligible(key jwk.Key) bool {
	use := KeyUse(key)
	return use == "" || use == string(jwk.ForSignature)
}

func KeyUse(key jwk.Key) string {
	if key == nil {
		return ""
	}
	use, _ := key.KeyUsage()
	return use
}

func ActiveSigningMetadata(kp dnsid.KeyProvider) (string, dnsid.JoseAlg, error) {
	if kp == nil {
		return "", "", fmt.Errorf("dnsid: nil KeyProvider")
	}
	ids := kp.ListKeyIds()
	if len(ids) == 0 {
		return "", "", fmt.Errorf("dnsid: KeyProvider has no active key")
	}
	kid := ids[0]
	key := kp.JWK(kid)
	if key == nil {
		return "", "", fmt.Errorf("dnsid: KeyProvider returned no JWK for active kid %q", kid)
	}
	alg, ok := JWKAlg(key)
	if !ok {
		alg, ok = AlgForJWK(key)
	}
	if !ok || !alg.Valid() {
		return "", "", fmt.Errorf("dnsid: active key %q has unsupported alg", kid)
	}
	if !JWKMatchesAlg(key, alg) {
		return "", "", fmt.Errorf("dnsid: active key %q does not match alg %q", kid, alg)
	}
	return kid, alg, nil
}

func VerifySignature(header ProtectedHeader, parts SignatureParts, keys []jwk.Key) bool {
	for _, key := range keys {
		switch header.Alg {
		case dnsid.JoseAlgEdDSA:
			if len(parts.Signature) != ed25519.SignatureSize {
				return false
			}
			var pub ed25519.PublicKey
			if err := jwk.Export(key, &pub); err == nil && len(pub) == ed25519.PublicKeySize && ed25519.Verify(pub, parts.SigningInput, parts.Signature) {
				return true
			}
		case dnsid.JoseAlgES256:
			var pub ecdsa.PublicKey
			if err := jwk.Export(key, &pub); err == nil && cryptoutil.VerifyES256(&pub, parts.SigningInput, parts.Signature) {
				return true
			}
		}
	}
	return false
}

func SplitDNSIDKid(raw string) (domain, kid string, err error) {
	domainPart, kidPart, ok := strings.Cut(raw, "#")
	if !ok || domainPart == "" || kidPart == "" || strings.Contains(kidPart, "#") {
		return "", "", fmt.Errorf("kid must be {domain}#{kid}")
	}
	domain, err = dnsid.NormalizeFQDN(domainPart)
	if err != nil {
		return "", "", err
	}
	return domain, kidPart, nil
}
