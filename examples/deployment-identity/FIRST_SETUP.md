# Explicit first setup (AWS)

`PrepareFirstSetup` is a small injectable composition example. It takes an AWS
client, identity configuration, and a **distinct, already available entity key
provider**. It creates the operational key inside KMS, explicitly activates it
locally, and supplies it to `NewIdentityManager`. It does not use a file keystore,
provision an entity key, run automatically from `main`, or claim protocol issuance.
Do not call it for an established identity or retry an indeterminate creation:
remote resource discovery and cleanup belong to the operator.

Before returning success, the helper validates the unsigned publication inputs,
including available public keys and distinct RFC7638 entity/operational
thumbprints, without signing a record. Validation failure after local activation
returns a nil manager, an error, and the already-created ACTIVE recovery state;
it does not delete or recreate the remote key. This does not change the general
`NewIdentityManager` constructor's validation boundary.

## Creation-specific authorization

Unlike the adjacent [README's open-only executable](README.md#provider-installation-and-aws-access),
first setup requires creation permissions as well as public-key access and signing:

- **AWS:** authorize `kms:CreateKey`, plus `kms:GetPublicKey` and `kms:Sign`
  on the created key, through applicable IAM and KMS key-policy authorization.
- **GCP:** authorize `cloudkms.cryptoKeys.get` on the existing parent,
  `cloudkms.cryptoKeyVersions.create` under it, and
  `cloudkms.cryptoKeyVersions.get` (for pending-generation readiness),
  `cloudkms.cryptoKeyVersions.viewPublicKey`, and
  `cloudkms.cryptoKeyVersions.useToSign` for its versions through applicable IAM
  policy. This path does not provision the parent or require a prior version.

## Public-reference handoff

The returned state contains only public immutable references. The application
owns its durable handoff (and must reconcile a remote create whose response is
lost). Publish `manager.GetEntityKeySet()` at `ek`, `manager.GetKeySet()` at `ku`,
and the status representation at `su`; publish the signed record from
`manager.CreateTXTRecord()` at `_dnsid.<domain>`. Complete the normal verified
publication and exact owner-signed/countersigned issuance workflow before making
status ACTIVE. Local key activation and a constructed manager are not issuance
proof. This example does not fabricate log evidence or live cloud publication.

Subsequent startup opens the recorded immutable reference, never calls Create:

```go
operational, err := awskms.Load(ctx, client, awskms.Config{
    Algorithm: types.SigningAlgorithmSpecEd25519Sha512,
    State: savedState,
})
// Handle err; then supply operational and the distinct entity provider through
// supported dependencies, and verify established publication. The main example
// demonstrates open-only config.Construct and exact published-key binding.
```

For GCP, obtain the validated pending kid and immutable version directly:

```go
operational, pendingKid, savedVersion, err := gcpkms.Create(ctx, client, existingCryptoKeyParent)
if err != nil {
    return err // A known created version is included in post-create errors for reconciliation.
}
if err := operational.Activate(pendingKid); err != nil {
    return err
}
// Retain savedVersion in application-owned state for open-only startup.
```

Before activation, the active listing is empty and the default JWK is nil;
`operational.JWK(pendingKid)` exposes the pending public key. Reopen with
`gcpkms.New(ctx, client, gcpkms.Config{KeyVersionName: savedVersion})`. A compatible
software Ed25519 signing parent must already exist; no previous version is needed.
No cloud resources are deleted implicitly on failure and injected clients remain
caller-owned.
