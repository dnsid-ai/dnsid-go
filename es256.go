package dnsid

import (
	"crypto/ecdsa"
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

func validES256Signature(sig []byte) bool {
	return cryptoutil.ValidES256Signature(sig)
}

func es256RawRS(sig []byte) (*big.Int, *big.Int) {
	return cryptoutil.ES256RawRS(sig)
}

func validateP256PublicKey(pub *ecdsa.PublicKey) error {
	return cryptoutil.ValidateP256PublicKey(pub)
}
