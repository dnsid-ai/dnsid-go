// Package awskms implements the DNSid [dnsid.KeyProvider] interface on top of
// AWS KMS. An agent's operational keys are created, stored, and used for
// signing inside KMS, so private key material never leaves the service; the
// provider fetches only public keys, exposes them as JWKs, and manages the
// pending, active, and retained key lifecycle that DNSid key rotation uses.
//
// The main entry points are [Load] (and its alias [New]), which constructs a
// [Provider] from a [Client] and a [Config], and [SDKClient], which adapts a
// *kms.Client from the AWS SDK for Go v2 to the [Client] interface:
//
//	client := awskms.SDKClient{Client: kms.NewFromConfig(awsCfg)}
//	provider, err := awskms.Load(ctx, client, awskms.Config{
//		State:     awskms.State{ActiveKeyID: activeKeyARN},
//		Algorithm: types.SigningAlgorithmSpecEcdsaSha256, // JOSE ES256; the default
//	})
//	if err != nil {
//		// handle error
//	}
//	sig, err := provider.Sign(payload)
//
// A Provider signs with a single configured algorithm. Two KMS signing
// algorithms are supported: ECDSA_SHA_256 with an ECC_NIST_P256 key (JOSE
// ES256) and ED25519_SHA_512 with an ECC_NIST_EDWARDS25519 key (JOSE EdDSA).
// Rotation state is held in memory; persist it across restarts with
// [Provider.State] and restore it through [Config.State].
//
// See https://docs.dnsid.ai for DNSid guides and account setup.
package awskms
