package dnsid

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"github.com/lestrrat-go/jwx/v3/jwk"
)

// Sentinel causes for _dnsid record-signature verification failures,
// distinguishable with errors.Is: a malformed sg= value, an unusable entity
// JWKS, and a signature that no served key verifies. They intentionally share
// the same generic message so error text does not expose a verification
// oracle.
var (
	ErrOwnerSignatureMalformed     = errors.New("dnsid: signature verification failed")
	ErrOwnerSignatureInvalidJWKS   = errors.New("dnsid: signature verification failed")
	ErrOwnerSignatureNoMatchingKey = errors.New("dnsid: signature verification failed")
)

type parsedRecordSignature struct {
	alg       JoseAlg
	signature []byte
}

func encodeRecordSignatureForProfile(version string, alg JoseAlg, sig []byte) (string, error) {
	profile, ok := profileForVersion(version)
	if !ok {
		return "", fmt.Errorf("dnsid: unsupported signature profile %q", version)
	}
	switch profile.signatureFormat {
	case signatureFormatDraft01:
		if !alg.Valid() {
			return "", fmt.Errorf("dnsid: unsupported JOSE alg %q", alg)
		}
		return base64.RawURLEncoding.EncodeToString(sig), nil
	default:
		return "", fmt.Errorf("dnsid: unsupported signature format for profile %q", version)
	}
}

func verifyRecordSignatureWithJWKS(r *TXTRecord, set jwk.Set) error {
	_, err := verifiedRecordSigningKey(r, set)
	return err
}

func verifiedRecordSigningKey(r *TXTRecord, set jwk.Set) (jwk.Key, error) {
	if r == nil || r.Signature == "" {
		return nil, ownerSignatureError(ErrOwnerSignatureMalformed)
	}
	if err := validateJWKSet(set); err != nil {
		return nil, ownerSignatureError(ErrOwnerSignatureInvalidJWKS)
	}
	profile, ok := profileForVersion(r.Version)
	if !ok {
		return nil, ownerSignatureError(ErrOwnerSignatureMalformed)
	}
	switch profile.signatureFormat {
	case signatureFormatDraft01:
		return verifiedDraft01RecordSigningKey(r, set)
	default:
		return nil, ownerSignatureError(ErrOwnerSignatureMalformed)
	}
}

func verifiedDraft01RecordSigningKey(r *TXTRecord, set jwk.Set) (jwk.Key, error) {
	key, err := singleDraft01SigningKey(set)
	if err != nil {
		return nil, ownerSignatureError(ErrOwnerSignatureInvalidJWKS)
	}
	alg, _ := jwkAlg(key)
	if strings.ContainsAny(r.Signature, ":=") {
		return nil, ownerSignatureError(ErrOwnerSignatureMalformed)
	}
	sig, err := base64.RawURLEncoding.DecodeString(r.Signature)
	if err != nil {
		return nil, ownerSignatureError(ErrOwnerSignatureMalformed)
	}
	parsed := &parsedRecordSignature{alg: alg, signature: sig}
	switch alg {
	case JoseAlgEdDSA:
		if len(sig) != ed25519.SignatureSize {
			return nil, ownerSignatureError(ErrOwnerSignatureMalformed)
		}
	case JoseAlgES256:
		if !validES256Signature(sig) {
			return nil, ownerSignatureError(ErrOwnerSignatureMalformed)
		}
	default:
		return nil, ownerSignatureError(ErrOwnerSignatureInvalidJWKS)
	}
	if !verifyRecordSignatureWithKey(r, parsed, key) {
		return nil, ownerSignatureError(ErrOwnerSignatureNoMatchingKey)
	}
	return key, nil
}

func ownerSignatureError(reason error) error {
	return NewVerificationError(
		VerificationCodeSignatureInvalid,
		false,
		"dnsid: _dnsid owner signature verification failed",
		reason,
	)
}

// singleCurrentSigningKey returns the sole current signing key served by a JWKS,
// enforcing the draft-01 exactly-one-current-key contract for an endpoint whose
// key is not selected via an sg alg (e.g. ku= when checking ek/ku distinctness).
//
// This counts every current usable signing key: the whole set becomes the runtime
// key set, so extra signing keys must not be hidden from the exactly-one and
// ek/ku-distinctness gates.
func singleCurrentSigningKey(set jwk.Set) (jwk.Key, error) {
	if set == nil {
		return nil, fmt.Errorf("dnsid: nil JWKS")
	}
	var keys []jwk.Key
	for i := 0; i < set.Len(); i++ {
		key, ok := set.Key(i)
		if !ok || key == nil {
			continue
		}
		if signingKeyEligible(key) {
			keys = append(keys, key)
		}
	}
	if len(keys) != 1 {
		return nil, fmt.Errorf("JWKS must serve exactly one current signing key, got %d", len(keys))
	}
	return keys[0], nil
}

func singleDraft01SigningKey(set jwk.Set) (jwk.Key, error) {
	key, err := singleCurrentSigningKey(set)
	if err != nil {
		return nil, err
	}
	if kid, ok := key.KeyID(); !ok || kid == "" {
		return nil, fmt.Errorf("draft 01 signing key must include kid")
	}
	for i := 0; i < set.Len(); i++ {
		candidate, ok := set.Key(i)
		if !ok || candidate == nil {
			continue
		}
		if alg, ok := candidate.Algorithm(); !ok || alg == nil {
			return nil, fmt.Errorf("draft 01 JWKS key at index %d must include alg", i)
		}
	}
	alg, ok := jwkAlg(key)
	if !ok || !alg.Valid() {
		return nil, fmt.Errorf("draft 01 signing key must include alg")
	}
	if inferred, supported := algForJWK(key); !supported || inferred != alg {
		return nil, fmt.Errorf("draft 01 signing key alg %q is inconsistent with key type", alg)
	}
	return key, nil
}

func verifyRecordSignatureWithKey(r *TXTRecord, parsed *parsedRecordSignature, key jwk.Key) bool {
	switch parsed.alg {
	case JoseAlgEdDSA:
		pub, err := exportEd25519PublicKey(key)
		return err == nil && ed25519.Verify(pub, r.CanonicalContent(), parsed.signature)
	case JoseAlgES256:
		pub, err := exportES256PublicKey(key)
		return err == nil && verifyES256(pub, r.CanonicalContent(), parsed.signature)
	default:
		return false
	}
}
