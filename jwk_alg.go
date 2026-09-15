package dnsid

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
)

func parseValidatedJWKS(data []byte) (jwk.Set, error) {
	filtered, err := validateJWKSJSON(data)
	if err != nil {
		return nil, err
	}
	set, err := jwk.Parse(filtered)
	if err != nil {
		return nil, NewParseError("dnsid: parsing JWKS", err)
	}
	if err := validateJWKSet(set); err != nil {
		return nil, NewValidationError("dnsid: invalid JWKS", err)
	}
	return set, nil
}

func validateJWKSJSON(data []byte) ([]byte, error) {
	var doc struct {
		Keys []json.RawMessage `json:"keys"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, NewParseError("dnsid: parsing JWKS", err)
	}
	filtered := struct {
		Keys []json.RawMessage `json:"keys"`
	}{Keys: make([]json.RawMessage, 0, len(doc.Keys))}
	seenKids := make(map[string]struct{}, len(doc.Keys))
	for idx, raw := range doc.Keys {
		var key struct {
			Kty string `json:"kty"`
			Crv string `json:"crv"`
			X   string `json:"x"`
			Y   string `json:"y"`
			Alg string `json:"alg"`
			Use string `json:"use"`
			Kid string `json:"kid"`
		}
		if err := json.Unmarshal(raw, &key); err != nil {
			return nil, NewParseError(fmt.Sprintf("dnsid: parsing JWKS key %d", idx), err)
		}
		if key.Kid != "" {
			if _, exists := seenKids[key.Kid]; exists {
				return nil, NewValidationError(fmt.Sprintf("dnsid: duplicate kid %q in JWKS", key.Kid), nil)
			}
			seenKids[key.Kid] = struct{}{}
		}
		switch {
		case key.Kty == "OKP" && key.Crv == "Ed25519":
			if key.Alg != "" && key.Alg != JoseAlgEdDSA.String() {
				return nil, NewValidationError(fmt.Sprintf("dnsid: Ed25519 key %q has inconsistent alg %q", key.Kid, key.Alg), nil)
			}
			if key.Use != "enc" {
				if key.Use != "" && key.Use != string(jwk.ForSignature) {
					return nil, NewValidationError(fmt.Sprintf("dnsid: Ed25519 key %q has unsupported use %q", key.Kid, key.Use), nil)
				}
				if _, err := decodeFixedJWKCoordinate(key.X); err != nil {
					return nil, NewValidationError(fmt.Sprintf("dnsid: Ed25519 key %q invalid x coordinate", key.Kid), err)
				}
			}
		case key.Kty == "EC" && key.Crv == "P-256":
			if key.Use != "enc" {
				if key.Kid == "" {
					return nil, NewValidationError(fmt.Sprintf("dnsid: ES256 key at index %d missing kid", idx), nil)
				}
				if key.Alg != "" && key.Alg != JoseAlgES256.String() {
					return nil, NewValidationError(fmt.Sprintf("dnsid: ES256 key %q has inconsistent alg %q", key.Kid, key.Alg), nil)
				}
				if key.Use != "" && key.Use != string(jwk.ForSignature) {
					return nil, NewValidationError(fmt.Sprintf("dnsid: ES256 key %q has unsupported use %q", key.Kid, key.Use), nil)
				}
				if _, err := decodeFixedJWKCoordinate(key.X); err != nil {
					return nil, NewValidationError(fmt.Sprintf("dnsid: ES256 key %q invalid x coordinate", key.Kid), err)
				}
				if _, err := decodeFixedJWKCoordinate(key.Y); err != nil {
					return nil, NewValidationError(fmt.Sprintf("dnsid: ES256 key %q invalid y coordinate", key.Kid), err)
				}
			}
		default:
			continue
		}
		filtered.Keys = append(filtered.Keys, raw)
	}
	filteredData, err := json.Marshal(filtered)
	if err != nil {
		return nil, fmt.Errorf("dnsid: filtering JWKS: %w", err)
	}
	return filteredData, nil
}

func decodeFixedJWKCoordinate(value string) ([]byte, error) {
	if value == "" {
		return nil, fmt.Errorf("missing")
	}
	if strings.Contains(value, "=") {
		return nil, fmt.Errorf("must be unpadded base64url")
	}
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil {
		return nil, err
	}
	if len(decoded) != 32 {
		return nil, fmt.Errorf("length %d, want 32", len(decoded))
	}
	return decoded, nil
}

func validateJWKSet(set jwk.Set) error {
	if set == nil {
		return fmt.Errorf("dnsid: nil JWKS")
	}
	seenKids := make(map[string]struct{}, set.Len())
	for i := 0; i < set.Len(); i++ {
		key, ok := set.Key(i)
		if !ok || key == nil {
			continue
		}
		if kid, ok := key.KeyID(); ok && kid != "" {
			if _, exists := seenKids[kid]; exists {
				return fmt.Errorf("dnsid: duplicate kid %q in JWKS", kid)
			}
			seenKids[kid] = struct{}{}
		}
		if err := validateJWKUse(key); err != nil {
			return err
		}
		if err := validateJWKAlgConsistency(key); err != nil {
			return err
		}
	}
	return nil
}

func validateJWKUse(key jwk.Key) error {
	if _, supported := algForJWK(key); !supported {
		return nil
	}
	use := keyUse(key)
	if use == "" || use == string(jwk.ForSignature) || use == string(jwk.ForEncryption) {
		return nil
	}
	kid, _ := key.KeyID()
	return fmt.Errorf("dnsid: JWK %q has unsupported use %q", kid, use)
}

func validateJWKAlgConsistency(key jwk.Key) error {
	if keyUse(key) == "enc" {
		return nil
	}
	binding, supported := algForJWK(key)
	alg, hasAlg := jwkAlg(key)
	if supported {
		if hasAlg && alg != binding {
			kid, _ := key.KeyID()
			return fmt.Errorf("dnsid: JWK %q alg %q inconsistent with key type", kid, alg)
		}
		if binding == JoseAlgES256 {
			if kid, ok := key.KeyID(); !ok || kid == "" {
				return fmt.Errorf("dnsid: ES256 key missing kid")
			}
			if err := validateES256JWK(key); err != nil {
				return err
			}
		}
		return nil
	}
	if hasAlg && alg.Valid() {
		kid, _ := key.KeyID()
		return fmt.Errorf("dnsid: JWK %q alg %q inconsistent with key type", kid, alg)
	}
	return nil
}

func algForJWK(key jwk.Key) (JoseAlg, bool) {
	if key == nil {
		return "", false
	}
	switch key.KeyType() {
	case jwa.OKP():
		crv, ok := jwkCurve(key)
		if ok && crv == jwa.Ed25519() {
			return JoseAlgEdDSA, true
		}
	case jwa.EC():
		crv, ok := jwkCurve(key)
		if ok && crv == jwa.P256() {
			return JoseAlgES256, true
		}
	}
	return "", false
}

func jwkCurve(key jwk.Key) (jwa.EllipticCurveAlgorithm, bool) {
	type curveKey interface {
		Crv() (jwa.EllipticCurveAlgorithm, bool)
	}
	if k, ok := key.(curveKey); ok {
		return k.Crv()
	}
	return jwa.EmptyEllipticCurveAlgorithm(), false
}

func jwkAlg(key jwk.Key) (JoseAlg, bool) {
	alg, ok := key.Algorithm()
	if !ok || alg == nil {
		return "", false
	}
	return JoseAlg(alg.String()), true
}

func validateES256JWK(key jwk.Key) error {
	var raw ecdsa.PublicKey
	if err := jwk.Export(key, &raw); err != nil {
		return fmt.Errorf("dnsid: exporting ES256 public key: %w", err)
	}
	if raw.Curve != elliptic.P256() {
		return fmt.Errorf("dnsid: ES256 key is not P-256")
	}
	return validateP256PublicKey(&raw)
}

func signingKeyEligible(key jwk.Key) bool {
	use := keyUse(key)
	if use != "" && use != string(jwk.ForSignature) {
		return false
	}
	if key, ok := key.(interface {
		KeyOps() (jwk.KeyOperationList, bool)
	}); ok {
		ops, present := key.KeyOps()
		if present {
			for _, op := range ops {
				if op == jwk.KeyOpVerify {
					return true
				}
			}
			return false
		}
	}
	return true
}

func keyUse(key jwk.Key) string {
	if key == nil {
		return ""
	}
	use, _ := key.KeyUsage()
	return use
}

func exportEd25519PublicKey(key jwk.Key) (ed25519.PublicKey, error) {
	var raw ed25519.PublicKey
	if err := jwk.Export(key, &raw); err != nil {
		return nil, err
	}
	if len(raw) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("invalid Ed25519 public key size %d", len(raw))
	}
	return raw, nil
}

func exportES256PublicKey(key jwk.Key) (*ecdsa.PublicKey, error) {
	var raw ecdsa.PublicKey
	if err := jwk.Export(key, &raw); err != nil {
		return nil, err
	}
	if err := validateP256PublicKey(&raw); err != nil {
		return nil, err
	}
	return &raw, nil
}
