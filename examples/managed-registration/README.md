# Managed registration

Register one hosted **dev sandbox** identity, complete bilateral ISSUANCE, wait for registry-managed publication, and verify it independently through public DNS. No challenge server or DNS hosting is needed.

## Run

Requires Go 1.26.6+, public DNS/HTTPS access, and a dev organization API key. From the repository root:

```sh
go run ./examples/managed-registration \
  --api-key-file "$HOME/.dev-dnsid-api-key" \
  --state-dir "$HOME/.dnsid-examples/managed-registration-go"
```

Alternatively, omit `--api-key-file` and set `DNSID_API_KEY`. The credential file must contain one token; protect it with mode `600`. Credentials are not saved or printed.

**This creates a real sandbox identity and a permanent dev transparency-log entry.** It leaves the identity active. Use a dedicated directory outside the repository, and keep the private key backed up. Do not share recovery directories between SDKs.

## Common setup flow

1. Generate and persist an Ed25519 operational key through `LocalKeyProvider`.
2. Save the complete sandbox registration request and replay keys before registration. Retain the creation-time publication configuration; wait for automatic ownership verification.
3. Fetch and validate the entity JWKS from the configured dev HTTPS endpoint. `BeginManagedIssuance()` / `ResumeManagedIssuance()` validate the prepared identity/key bindings and entity signature, countersign, save exact bytes before submission, and persist the outcome.
4. Use `AwaitRegistryManagedPublication()` to confirm registry publication and verify public evidence. Do not append separately to the log.
5. Use a fresh, credential-free verifier with the configured governance ID and entity-key thumbprint. Check `ACTIVE` status, the assigned log reference, and fresh lifecycle evidence with `VerifyLogEvidence()`. Mark setup complete with `CompleteManagedIssuance()`.

This CLI serves no application. The coordinator's durable activation block gates setup completion; it does not control the registry's automatic publication.

Success prints:

```text
Registered: <assigned-domain>.sandbox.dev.dnsid.ai
Verified: <assigned-domain>.sandbox.dev.dnsid.ai status=ACTIVE DNSSEC=UNKNOWN
```

`UNKNOWN` is not authenticated DNSSEC. Configure a DNSSEC-aware resolver and the appropriate verification policy when required.

## Configuration

The example uses `config.LoadEnvironment()`, `config.Merge()`, `config.Construct()`, and `config.RegistryClientFromEnvironment()`. SDK environment settings such as `DNSID_DNS_SERVER`, `DNSID_DNSSEC_MODE`, and `DNSID_CA_BUNDLE` are read by the SDK rather than duplicated here.

The dev registry is the explicit default. A different `DNSID_REGISTRY_URL` is rejected: this example's governance ID, entity-key endpoint, and log prefix are dev-specific. Managed log trust is explicitly selected with `config.LogTrust{Managed: true}`; trust is never taken from an unverified record. Setup owns the new identity and key, so existing `DNSID_DOMAIN` and key-source settings are not used. The assigned publication snapshot is overlaid after registration.

## Recovery

Fresh runs retain only:

- `operational-key.json`: private operational key; keep secret and backed up.
- `recovery.json`: original request, replay keys, creation snapshot, trusted entity key, exact signed bytes, and issuance outcome.

The directory must be owner-only (`700`); recovery files use `600`. Writes sync the temporary file, atomically rename it, and sync the directory. Use a local filesystem that supports these operations.

Rerun with the **same directory** after interruption. Do not delete recovery state, replace the key, or edit signed bytes. Accepted issuance is not resubmitted; rejected outcomes stop. Pending or unknown outcomes retain the same bytes and idempotency key. Only transient public-read failures and publication-DNS failures are retried; integrity and policy failures stop immediately. Each run has a ten-minute deadline.

The directory lock prevents concurrent runs. After a hard crash, remove `.lock` only after confirming that no copy is still running. Original recovery files are read in place; old exact signed bytes and outcomes are imported into the SDK coordinator state before any submission.

Cleanup is explicit: retire the immutable identity through the registry before discarding its key. Production, Live challenges, and self-managed publication are outside this example.

## Offline checks

```sh
go test ./examples/managed-registration ./log/c2sptlog
```
