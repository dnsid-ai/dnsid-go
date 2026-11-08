# Configuration

Loaders return partial configuration; `Construct` applies defaults. Caller
dependencies win. API credentials are supplied separately and never loaded into
configuration.

```go
loaded, err := config.LoadDeploymentFile("deployment.json")
if err != nil {
    return err
}
manager, err := config.Construct(ctx, loaded, config.Dependencies{})
```

File sections are `dnsid`, `logTrust`, `registry`, and `keySource`. Unknown,
duplicate, null, and mistyped members fail. Durations use Go duration strings.
Merge is field-wise; lists replace and log trust is atomic. Operational key-source
fields replace as a group; `entityKeyPath` merges independently. Scalar zero values
cannot clear other nonzero base values; edit the merged value to clear them.

Missing provider selects file and warns that local keys are unsuitable for
production. Existing file references use `keyRef` or CLI/key-store paths.
Cloud providers require an existing stable reference and non-secret settings;
construction never generates, imports, or rotates keys.

Link the optional AWS module with
`import _ "github.com/dnsid-ai/dnsid-go/key/aws"`, then configure:

```json
{
  "keySource": {
    "provider": "aws-kms",
    "keyRef": "arn:aws:kms:us-east-1:111122223333:key/your-key-id",
    "settings": { "region": "us-east-1", "algorithm": "ES256" }
  }
}
```

Use an immutable signing-key ARN, not an alias. AWS credentials come from the
standard chain (optional `profile` names a credential source); grant
`kms:GetPublicKey` and `kms:Sign`. Installing without importing does not link a
factory. Missing providers fail before key/policy access, without file fallback.
For configuration-selected operational keys, `Construct` requires fresh, verified
local publication matching the selected key's kid, algorithm and public-key
thumbprint before returning a signing manager. Missing or invalid publication and
a different selected key fail closed. Configuration does not authorize rotation;
`Construct` has no persisted identity state.

For initial publication setup, callers can open the existing operational key with
`config.OperationalKeyProviderFrom` and inject it through
`config.Dependencies.KeyProvider`. For explicit AWS/GCP first-key creation instead,
see the separate [first-setup guide](../examples/deployment-identity/FIRST_SETUP.md).
This documented setup route does not establish
published signer binding: the caller owns binding checks and the injected
provider's lifetime, including cleanup on construction failure. Use ordinary
configuration-selected construction for subsequent established application signing.
An injected setup manager is not authenticated established-startup evidence.

For interrupted rotation recovery, reopen the **same persisted active/pending
provider and rotation journal**, not a newly generated key or the original
bootstrap key. Inject the reopened provider through
`config.Dependencies.KeyProvider` to construct the recovery publication verifier,
then pass that manager as `Publication` to
`c2sptlog.ResumeManagedOperationalKeyRotation` with the saved state and provider.
The caller still owns provider cleanup, including on construction failure, and
must keep application signing paused, block new requests, and drain in-flight
signatures. Before activation, Resume validates fresh publication and log
continuity against the saved rotation; signing resumes only after successful
activation has been durably saved. Injection does not authenticate established
startup, and a pending key is not an exception to ordinary `Construct` binding
checks. Already-activated recovery needs no new publication/network checks; do
not add network-backed construction to that path. See the
[key-rotation example](../examples/key-rotation/) for persisted recovery and the
single-process signing gate; concurrent services need their own coordination.

Link the optional GCP module with
`import _ "github.com/dnsid-ai/dnsid-go/key/gcp"`, then configure an existing version:

```json
{
  "keySource": {
    "provider": "google-kms",
    "keyRef": "projects/my-project/locations/us-east1/keyRings/agents/cryptoKeys/agent/cryptoKeyVersions/1",
    "settings": { "project": "my-project", "location": "us-east1", "algorithm": "EdDSA" }
  }
}
```

The reference must be an immutable numeric software EC_SIGN_ED25519 version.
Optional `project` and `location` must match `keyRef`; `algorithm`, if set, must
be `EdDSA`. Credentials use Application Default Credentials, not deployment
settings. Opening only reads the existing public key; it never generates a version
or substitutes a local signer. Explicit `GenerateKey` additionally requires version
creation and, for pending generation, `cloudkms.cryptoKeyVersions.get`. It waits
for that exact version within one 30-second creation/readiness/public-validation
budget, without guaranteeing readiness in that time. Failed generation leaves
local state unchanged; cloud cleanup remains operator-owned even if the remote
version becomes enabled later.

These configuration/provider and onboarding APIs work with the existing server.
Configuration-selected or automatic key creation and automatic permanent recovery
remain separate workflow changes.

See [the open-only deployment-identity executable](../examples/deployment-identity/)
for loading an existing file or AWS KMS key, checking its published binding, and
signing an HTTP request without sending it; explicit first-key creation is covered
in the separate [first-setup guide](../examples/deployment-identity/FIRST_SETUP.md).
