package cryptoutil

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/asn1"
	"errors"
	"math/big"
)

const ES256SignatureSize = 64

var (
	P256Order      = elliptic.P256().Params().N
	P256HalfOrder  = new(big.Int).Rsh(new(big.Int).Set(P256Order), 1)
	ErrInvalidP256 = errors.New("dnsid: invalid P-256 key")
)

func SignES256(priv *ecdsa.PrivateKey, payload []byte) ([]byte, error) {
	if err := ValidateP256PrivateKey(priv); err != nil {
		return nil, err
	}
	hash := sha256.Sum256(payload)
	// Go 1.26 documents nil-random ECDSA signing as RFC 6979
	// deterministic for the NIST curves when opts.HashFunc matches digest.
	der, err := priv.Sign(nil, hash[:], crypto.SHA256)
	if err != nil {
		return nil, err
	}
	return ES256RawFromDER(der)
}

func ES256RawFromDER(der []byte) ([]byte, error) {
	var parsed struct {
		R *big.Int
		S *big.Int
	}
	if rest, err := asn1.Unmarshal(der, &parsed); err != nil || len(rest) != 0 {
		return nil, errors.New("dnsid: invalid ES256 signer output")
	}
	if parsed.R == nil || parsed.S == nil {
		return nil, errors.New("dnsid: invalid ES256 signer output")
	}
	if parsed.R.Sign() <= 0 || parsed.S.Sign() <= 0 ||
		parsed.R.Cmp(P256Order) >= 0 || parsed.S.Cmp(P256Order) >= 0 {
		return nil, errors.New("dnsid: invalid ES256 signer output")
	}
	if parsed.S.Cmp(P256HalfOrder) > 0 {
		parsed.S.Sub(P256Order, parsed.S)
	}

	out := make([]byte, ES256SignatureSize)
	parsed.R.FillBytes(out[:32])
	parsed.S.FillBytes(out[32:])
	return out, nil
}

func VerifyES256(pub *ecdsa.PublicKey, payload, sig []byte) bool {
	if err := ValidateP256PublicKey(pub); err != nil {
		return false
	}
	if !ValidES256Signature(sig) {
		return false
	}
	r, s := ES256RawRS(sig)
	hash := sha256.Sum256(payload)
	return ecdsa.Verify(pub, hash[:], r, s)
}

func ValidES256Signature(sig []byte) bool {
	if len(sig) != ES256SignatureSize {
		return false
	}
	r, s := ES256RawRS(sig)
	if r.Sign() == 0 || s.Sign() == 0 {
		return false
	}
	if r.Cmp(P256Order) >= 0 || s.Cmp(P256Order) >= 0 {
		return false
	}
	return s.Cmp(P256HalfOrder) <= 0
}

func ES256RawRS(sig []byte) (*big.Int, *big.Int) {
	return new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:])
}

func ValidateP256PrivateKey(priv *ecdsa.PrivateKey) error {
	if priv == nil || priv.Curve != elliptic.P256() {
		return ErrInvalidP256
	}
	if _, err := priv.Bytes(); err != nil {
		return ErrInvalidP256
	}
	return ValidateP256PublicKey(&priv.PublicKey)
}

func ValidateP256PublicKey(pub *ecdsa.PublicKey) error {
	if pub == nil || pub.Curve != elliptic.P256() {
		return ErrInvalidP256
	}
	encoded, err := pub.Bytes()
	if err != nil {
		return ErrInvalidP256
	}
	if _, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), encoded); err != nil {
		return ErrInvalidP256
	}
	return nil
}
