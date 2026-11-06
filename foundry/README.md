# Known Foundry creation

This subpackage implements the Known Foundry contract in `dnsid-sdk-compliance`
commit `89600ed`. It is not a generic DNSid registration API. Server acceptance
SR-1 through SR-7 is still a release gate; no deployed server revision is certified.
There is no sandbox fallback, replacement flow, or extra capability probe.

`Create(ctx, name)` loads SDK environment configuration and the separate
`DNSID_API_KEY` credential. File and code configuration use `New(loaded, deps)`
and its `Create` method. Both use the same workflow. Injected providers and log
registries displace loaded selection and must be supplied again on recovery.
Neither core nor configuration loading imports this package.

Create records the assigned identity without waiting for public readiness.
`Active(ctx)` completes proof and issuance, then freshly verifies DNS, signed
HTTPS resources, the current provider key, protocol ACTIVE, and lifecycle-log
evidence. Registry READY alone is insufficient. Each call uses the caller's
deadline, or a default of 30 seconds for Create and 10 minutes for Active.
Polling starts at one second and doubles to a maximum of 15 seconds. Non-cancellable provider
calls are checked before and after; the provider's own timeout bounds those calls.
Cancellation preserves progress and does not cancel the server identity.

`IdentityManager()` returns `(*dnsid.IdentityManager, error)`. It returns
`*SigningPaused` until publication configuration has been saved, then returns the
same manager instance. Policy-URL resolution is deferred until evidence is
requested; the manager still uses the configured trust for verification. Its signing provider and the handle's raw-byte `Sign`
method share a pause controller. A completed operation can reopen and sign using
its saved current binding without public network checks. `Active` refreshes that
observation. Direct access to the original provider bypasses this controller;
the pause is an application safety boundary, not a security boundary.

The existing managed issuance coordinator owns preparation and exact-byte
submission. History recovery runs only after a server rejection, or verification
of previously saved acceptance. Empty history after rejection is a resumable
error, not evidence that another issuance is safe. A recovered winner never
acknowledges the losing local bytes. Only documented issuance rejection codes enter that
recovery path; HTTP 401, 403, and 404 remain admission errors and never poison
saved issuance state. Preparations with unresolved outcomes are
not regenerated. Without durable server reclaim permission, the SDK retains the
original preparation and issuance key for recovery after server reconciliation.

## Recovery storage

`NewFileFoundryStore("")` selects `~/.dnsid/foundry/`. Named documents and lock
paths are digests of registry URL, account ID, and the exact Unicode name. The
store holds an exclusive OS lock for each workflow call, including writes, and
retains historical documents by identity ID. A competing call waits until its
deadline and receives a structured busy error.

Use a private directory. Existing paths with broader permissions are rejected;
new directories and files are owner-only (native ACLs on Windows). Writes sync
the file before atomic replacement and durable filesystem commit. This requires
a filesystem with working locking and durable rename semantics. Container-local
storage does not coordinate other containers or survive their replacement.

Back up recovery state and the provider's own key state separately. Recovery JSON
contains only public keys and non-secret provider references, never private keys
or registry credentials. `RecoveryDocument.Export` produces canonical UTF-8 JSON;
`ParseRecoveryDocument` and store `Import` reject invalid Unicode, duplicates,
unknown phases or versions, and inconsistent bindings. Unknown extension members
survive rewriting. Reopen the same provider key or a verified successor at the
destination. Checkpoint-store initialization and recovery remain application-owned.

CLI integration, hosted cross-SDK scenarios, key-provisioning internals, rotation
orchestration, and retire/revoke operations are outside this subpackage's create
workflow. Same-name terminal replacement is disabled.
