package dnsid

import "github.com/lestrrat-go/jwx/v3/jwa"

// JoseAlg is the default-deny allowlist of JOSE algorithms DNSid accepts.
type JoseAlg string

// The JOSE algorithms DNSid accepts: Ed25519 (EdDSA) and ECDSA over P-256
// with SHA-256 (ES256). All other algorithms are rejected.
const (
	JoseAlgEdDSA JoseAlg = "EdDSA"
	JoseAlgES256 JoseAlg = "ES256"
)

// Valid reports whether a is in the DNSid JOSE algorithm allowlist.
func (a JoseAlg) Valid() bool {
	switch a {
	case JoseAlgEdDSA, JoseAlgES256:
		return true
	default:
		return false
	}
}

// String returns the JOSE alg identifier as a string.
func (a JoseAlg) String() string {
	return string(a)
}

func (a JoseAlg) jwa() (jwa.SignatureAlgorithm, bool) {
	switch a {
	case JoseAlgEdDSA:
		return jwa.EdDSA(), true
	case JoseAlgES256:
		return jwa.ES256(), true
	default:
		return jwa.EmptySignatureAlgorithm(), false
	}
}
