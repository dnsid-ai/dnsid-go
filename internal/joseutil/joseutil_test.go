package joseutil

import (
	"testing"

	"github.com/dnsid-ai/dnsid-go"
	"github.com/lestrrat-go/jwx/v3/jwk"
)

type algLessKeyProvider struct {
	dnsid.KeyProvider
	key jwk.Key
}

func (p algLessKeyProvider) JWK(kidOpt ...string) jwk.Key {
	return p.key
}

func TestActiveSigningMetadataDerivesMissingAlg(t *testing.T) {
	base := dnsid.GenerateEd25519KeyProvider()
	key := base.JWK()
	if err := key.Remove(jwk.AlgorithmKey); err != nil {
		t.Fatalf("remove alg: %v", err)
	}

	_, alg, err := ActiveSigningMetadata(algLessKeyProvider{KeyProvider: base, key: key})
	if err != nil {
		t.Fatalf("ActiveSigningMetadata: %v", err)
	}
	if alg != dnsid.JoseAlgEdDSA {
		t.Fatalf("ActiveSigningMetadata alg = %q, want EdDSA", alg)
	}
}
