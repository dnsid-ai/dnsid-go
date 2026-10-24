package dnsid

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"math/big"

	"github.com/dnsid-ai/dnsid-go/internal/cryptoutil"
)

var p256Order = cryptoutil.P256Order

func signES256(priv *ecdsa.PrivateKey, payload []byte) ([]byte, error) {
	return cryptoutil.SignES256(priv, payload)
}

func es256RawFromDER(der []byte) ([]byte, error) {
	return cryptoutil.ES256RawFromDER(der)
}

func verifyES256(pub *ecdsa.PublicKey, payload, sig []byte) bool {
	return cryptoutil.VerifyES256(pub, payload, sig)
}

func verifyEd25519(pub ed25519.PublicKey, payload, sig []byte) bool {
	return cryptoutil.VerifyEd25519(pub, payload, sig)
}

func validEd25519PublicKey(pub []byte) bool {
	return cryptoutil.ValidEd25519PublicKey(pub)
}

func validES256Signature(sig []byte) bool {
	return cryptoutil.ValidES256Signature(sig)
}

func es256RawRS(sig []byte) (*big.Int, *big.Int) {
	return cryptoutil.ES256RawRS(sig)
}

func validateP256PublicKey(pub *ecdsa.PublicKey) error {
	return cryptoutil.ValidateP256PublicKey(pub)
}
