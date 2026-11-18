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

Obtain the operational key successfully before separately creating or reusing
an agent ID. Bootstrap performs no agent registration or rotation recovery.
Established identities must open their persisted authorized immutable version;
ordinary opening and key-source configuration remain open-only. Explicit
`GenerateKey` has its own separate pending-rotation and readiness behavior;
that behavior does not apply to `CreateOrReuse`.
