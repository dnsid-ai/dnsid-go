// Package gcpkms implements an optional Google Cloud KMS-backed DNSid key
// provider for existing software EC_SIGN_ED25519 versions. Private keys remain
// in KMS. Signing uses RAW data, not a precomputed digest, with CRC32C integrity
// and immutable version binding checks.
//
// Supply an official *kms.KeyManagementClient to New; the caller owns and closes
// that client. Official client options can select a local gRPC endpoint for
// credential-free integration tests. The provider never creates local files.
//
// Importing this package also registers the google-kms configuration factory:
//
//	import _ "github.com/dnsid-ai/dnsid-go/key/gcp"
//
// Configuration keyRef must name an existing numeric CryptoKeyVersion. Optional
// project and location settings must match keyRef; algorithm, if set, is EdDSA.
// Credentials use Google's Application Default Credentials chain, not settings.
// Configuration opening never creates keys and never falls back to local files.
// Providers opened through configuration own their client; applications can call
// Close after all operations finish to release it.
//
// This existing-version runtime does not yet support lifecycle operations or
// managed-rotation orchestration. Merely opening a cloud key is not a migration
// of an established identity; changing its signer requires authorized rotation.
//
// Install this nested module separately; the base SDK does not depend on Google
// Cloud libraries. See https://docs.dnsid.ai for DNSid documentation.
//
// Copyright 2026 Known Systems AI, Inc.
package gcpkms
