# Google Cloud KMS initial operational-key bootstrap

The optional `github.com/dnsid-ai/dnsid-go/key/gcp` module provides
`gcpkms.CreateOrReuse(ctx, client, gcpkms.BootstrapConfig{Parent: ringName,
CryptoKeyID: keyID})`. Supply a caller-owned `BootstrapClient` (including the
official KMS client), an existing fully qualified key ring and a stable key ID.
See the [API reference](https://docs.dnsid.ai/reference/go/key-gcp/) for types
and provider operations.

Only exact named-key absence permits creation. A create-contention response
causes one winner reread; other service and context errors propagate unchanged.
Successful calls converge on the authoritative named key and its compatible,
enabled software `EC_SIGN_ED25519` immutable initial version **1**. This is not
a guarantee of immediate readiness.

If version 1 is `PENDING_GENERATION`, bootstrap returns an error and no usable
signer: that version cannot yet be used. Bootstrap does not internally retry,
poll or wait for generation. A later, separate explicit invocation with the same
project, location, key ring and key ID may succeed once the **same version 1**
is enabled and its metadata and public material pass validation. No readiness
time or eventual success is guaranteed. Missing, disabled or incompatible
versions remain errors, not permission to replace the key or create another
version. Bootstrap never creates ancestors, deletes resources or chooses
`primary` or `latest`.

## Bootstrap authorization

- **Reuse:** `GetCryptoKey` requires
  [`cloudkms.cryptoKeys.get`](https://cloud.google.com/kms/docs/reference/rest/v1/projects.locations.keyRings.cryptoKeys/get)
  on the named CryptoKey. `GetCryptoKeyVersion` requires
  [`cloudkms.cryptoKeyVersions.get`](https://cloud.google.com/kms/docs/reference/rest/v1/projects.locations.keyRings.cryptoKeys.cryptoKeyVersions/get)
  on its immutable version **1**; `GetPublicKey` requires
  [`cloudkms.cryptoKeyVersions.viewPublicKey`](https://cloud.google.com/kms/docs/reference/rest/v1/projects.locations.keyRings.cryptoKeys.cryptoKeyVersions/getPublicKey)
  on that same version.
- **Create after absence:** `CreateCryptoKey` additionally requires
  [`cloudkms.cryptoKeys.create`](https://cloud.google.com/kms/docs/reference/rest/v1/projects.locations.keyRings.cryptoKeys/create)
  on the existing **parent key ring**, not on the not-yet-created CryptoKey.
  Bootstrap requests the initial version as part of key creation; it does not
  call `CreateCryptoKeyVersion`. The read permissions above are still required
  to validate the created key and version.
- **Subsequent signing:** the returned provider's `AsymmetricSign` operation
  requires
  [`cloudkms.cryptoKeyVersions.useToSign`](https://cloud.google.com/kms/docs/reference/rest/v1/projects.locations.keyRings.cryptoKeys.cryptoKeyVersions/asymmetricSign)
  on version **1**. Bootstrap itself does not sign.

The resources above are the API authorization targets. Version permissions are
managed through IAM on the containing CryptoKey or inherited from its ancestors,
not a separate version IAM policy; see
[Cloud KMS access control and inheritance](https://cloud.google.com/kms/docs/iam).
Arrange read access for both existing winners and newly created keys without
assuming that creation alone grants it. This is operation-level authorization
guidance, not a complete policy or proof of live access. The separate
[`FIRST_SETUP` example](../../examples/deployment-identity/FIRST_SETUP.md)
creates a version under an existing key and retains its different permissions.

Obtain the operational key successfully before separately creating or reusing
an agent ID. Bootstrap performs no agent registration or rotation recovery.
Established identities must open their persisted authorized immutable version;
ordinary opening and key-source configuration remain open-only. Explicit
`GenerateKey` has its own separate pending-rotation and readiness behavior;
that behavior does not apply to `CreateOrReuse`.
