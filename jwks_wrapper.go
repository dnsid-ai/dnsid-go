package dnsid

import (
	"crypto"
	"encoding/base64"
	"errors"
	"fmt"

	"github.com/lestrrat-go/jwx/v3/jwk"
)

// JWKS is a typed wrapper over a JWK Set with SDK-level helpers.
type JWKS struct {
	set jwk.Set
}

// JWK is a typed wrapper over a single JWK with SDK-level helpers.
type JWK struct {
	key jwk.Key
}

// NewJWKS wraps a jwk.Set into the typed SDK form.
func NewJWKS(set jwk.Set) *JWKS {
	return &JWKS{set: set}
}

// ParseJWKS parses a JWKS JSON document and returns the typed wrapper.
func ParseJWKS(data []byte) (*JWKS, error) {
	set, err := ParseJWKSet(data)
	if err != nil {
		return nil, err
	}

	return NewJWKS(set), nil
}

// ParseJWKSet parses a JWKS JSON document and returns a validated raw JWK set.
func ParseJWKSet(data []byte) (jwk.Set, error) {
	set, err := parseValidatedJWKS(data)
	if err != nil {
		var validationErr *ValidationError
		if errors.As(err, &validationErr) {
			return nil, NewValidationError("jwks: parsing JWKS", err)
		}
		return nil, NewParseError("jwks: parsing JWKS", err)
	}
	return set, nil
}

// SigningKeys returns all keys eligible for signature verification.
// Keys with unset use or use=sig are eligible.
func (j *JWKS) SigningKeys() []*JWK {
	if j == nil || j.set == nil {
		return nil
	}

	keys := make([]*JWK, 0, j.set.Len())
	for i := range j.set.Len() {
		key, _ := j.set.Key(i)
		if !isSigningKey(key) {
			continue
		}
		keys = append(keys, &JWK{key: key})
	}

	return keys
}

// KeyByID returns the key with the given kid, or nil if not found.
// This is an unfiltered lookup; the returned key may have use=enc or
// any other use value. Callers that want a signing-eligible key should
// filter the result against SigningKeys() or check Use() themselves.
func (j *JWKS) KeyByID(kid string) *JWK {
	if j == nil || j.set == nil || kid == "" {
		return nil
	}

	for i := range j.set.Len() {
		key, _ := j.set.Key(i)
		if keyKid, ok := key.KeyID(); ok && keyKid == kid {
			return &JWK{key: key}
		}
	}

	return nil
}

// Validate enforces SDK invariants for signing keys.
func (j *JWKS) Validate() error {
	if j == nil || j.set == nil {
		return NewValidationError("jwks: no usable signing key", nil)
	}
	if err := validateJWKSet(j.set); err != nil {
		return NewValidationError("jwks", err)
	}

	var usable int
	signingIndex := 0
	for i := range j.set.Len() {
		key, _ := j.set.Key(i)
		if !isSigningKey(key) {
			continue
		}

		usable++
		wrapped := &JWK{key: key}
		if wrapped.Kid() == "" {
			return NewValidationError(fmt.Sprintf("jwks: signing key at index %d missing kid", signingIndex), nil)
		}
		if _, ok := algForJWK(key); !ok {
			return NewValidationError(fmt.Sprintf("jwks: signing key at index %d has unsupported key type", signingIndex), nil)
		}
		signingIndex++
	}

	if usable == 0 {
		return NewValidationError("jwks: no usable signing key", nil)
	}

	return nil
}

// CurrentRecordSigningKey returns the sole current record-signing key allowed
// by the selected identity-record profile.
func (j *JWKS) CurrentRecordSigningKey(profile string) (*JWK, error) {
	return j.currentProfileSigningKey(profile, "record-signing")
}

// CurrentOperationalSigningKey returns the sole current operational signing
// key allowed by the selected identity-record profile.
func (j *JWKS) CurrentOperationalSigningKey(profile string) (*JWK, error) {
	return j.currentProfileSigningKey(profile, "operational")
}

// ValidateRecordSigning verifies that the JWKS satisfies the selected
// identity-record profile's record-signing-key constraints. An empty profile
// selects [DefaultPublishProfile].
func (j *JWKS) ValidateRecordSigning(profile string) error {
	_, err := j.currentProfileSigningKey(profile, "record-signing")
	return err
}

// ValidateOperational verifies that the JWKS satisfies the selected
// identity-record profile's operational-key constraints. An empty profile
// selects [DefaultPublishProfile].
func (j *JWKS) ValidateOperational(profile string) error {
	_, err := j.currentProfileSigningKey(profile, "operational")
	return err
}

func (j *JWKS) currentProfileSigningKey(profile, role string) (*JWK, error) {
	if profile == "" {
		profile = DefaultPublishProfile
	}
	if _, ok := profileForVersion(profile); !ok {
		return nil, NewArgumentError(fmt.Sprintf("jwks: unsupported identity-record profile %q", profile), nil)
	}
	if j == nil || j.set == nil {
		return nil, NewValidationError(fmt.Sprintf("jwks: invalid %s key set", role), fmt.Errorf("dnsid: nil JWKS"))
	}
	if err := validateJWKSet(j.set); err != nil {
		return nil, NewValidationError(fmt.Sprintf("jwks: invalid %s key set", role), err)
	}
	key, err := singleDraft01SigningKey(j.set)
	if err != nil {
		return nil, NewValidationError(fmt.Sprintf("jwks: invalid %s key set", role), err)
	}
	return &JWK{key: key}, nil
}

// Thumbprint returns the RFC 7638 SHA-256 thumbprint of this key,
// base64url-unpadded encoded.
func (k *JWK) Thumbprint() (string, error) {
	if k == nil || k.key == nil {
		return "", fmt.Errorf("jwks: nil JWK")
	}

	thumbprint, err := k.key.Thumbprint(crypto.SHA256)
	if err != nil {
		return "", fmt.Errorf("jwks: computing JWK thumbprint: %w", err)
	}

	return base64.RawURLEncoding.EncodeToString(thumbprint), nil
}

// Kid returns the key's kid value, or empty string if unset.
func (k *JWK) Kid() string {
	if k == nil || k.key == nil {
		return ""
	}

	kid, _ := k.key.KeyID()
	return kid
}

// Alg returns the key's effective signing algorithm, deriving it from kty/crv
// when the JWK alg member is absent.
func (k *JWK) Alg() JoseAlg {
	if k == nil || k.key == nil {
		return ""
	}
	if alg, ok := jwkAlg(k.key); ok {
		return alg
	}
	if alg, ok := algForJWK(k.key); ok {
		return alg
	}
	return ""
}

// SignatureAlg returns the signing algorithm allowed by the selected
// identity-record profile. Unlike [JWK.Alg], draft profiles require an explicit
// alg member that is consistent with the key type. An empty profile selects
// [DefaultPublishProfile].
func (k *JWK) SignatureAlg(profile string) (JoseAlg, error) {
	if profile == "" {
		profile = DefaultPublishProfile
	}
	if _, ok := profileForVersion(profile); !ok {
		return "", NewArgumentError(fmt.Sprintf("jwks: unsupported identity-record profile %q", profile), nil)
	}
	if k == nil || k.key == nil {
		return "", NewValidationError("jwks: invalid signing key", fmt.Errorf("dnsid: nil JWK"))
	}
	if !signingKeyEligible(k.key) {
		return "", NewValidationError("jwks: invalid signing key", fmt.Errorf("key is not eligible for signing"))
	}
	alg, ok := jwkAlg(k.key)
	if !ok || !alg.Valid() {
		return "", NewValidationError("jwks: invalid signing key", fmt.Errorf("draft 01 signing key must include alg"))
	}
	if inferred, supported := algForJWK(k.key); !supported || inferred != alg {
		return "", NewValidationError("jwks: invalid signing key", fmt.Errorf("draft 01 signing key alg %q is inconsistent with key type", alg))
	}
	return alg, nil
}

// Use returns the key's use value, or empty string if unset.
func (k *JWK) Use() string {
	if k == nil || k.key == nil {
		return ""
	}

	use, _ := k.key.KeyUsage()
	return use
}

// Raw returns the underlying jwk.Set.
func (j *JWKS) Raw() jwk.Set {
	if j == nil {
		return nil
	}

	return j.set
}

// Raw returns the underlying jwk.Key.
func (k *JWK) Raw() jwk.Key {
	if k == nil {
		return nil
	}

	return k.key
}

func isSigningKey(key jwk.Key) bool {
	if key == nil {
		return false
	}

	use, _ := key.KeyUsage()
	return use == "" || use == string(jwk.ForSignature)
}
