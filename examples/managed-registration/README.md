# Managed registration: full dev flow

Creates one sandbox identity on `https://api.dev.dnsid.ai`, completes bilateral
ISSUANCE, waits for registry-managed publication, and verifies the published
DNSid and fresh lifecycle evidence. It leaves the identity active.

Requires a dev organization API key, Go 1.26.6+, and public DNS/HTTPS access.
Run from the repository root:

```sh
go run ./examples/managed-registration \
  -api-key-file "$HOME/.dev-dnsid-api-key" \
  -state-dir "$HOME/.dnsid-examples/managed-registration"
```

Alternatively, omit `-api-key-file` and set `DNSID_API_KEY`. Credentials are
never saved in the state directory. Use a dedicated owner-only directory;
an existing directory must have mode `0700`.

## Steps

1. Generate and save an Ed25519 operational private key. Save the registration
   request and separate registration/issuance idempotency keys before sending.
2. Register with no hosting selectors, allowing the server's sandbox default.
   Preserve the immutable ID, publication configuration, and OIDC issuer;
   read publication authority using the authenticated detail endpoint.
3. Wait for `VERIFIED`. Check the prepared ISSUANCE's identity, governance,
   log reference, and both public keys. Verify the registry signature and add
   the operational countersignature with the SDK.
4. Save the exact completed bytes before submission. Check the accepted entry
   hash, index, and final reference. Wait for `READY` and DNS publication.
5. Call `VerifyDomain` and `VerifyLogEvidence` using the SDK's reviewed, embedded
   dev log/witness trust. Retry public verification while DNS propagates.

Trust does not come from the creation response. The example explicitly opts
into `NewDnsidManagedVerificationRegistry` and bootstraps the entity key from
its fixed HTTPS endpoint under `dev.dnsid.ai`. It does not accept arbitrary
registries, private hosts, or discovered trust policies. DNSSEC `UNKNOWN` is
accepted by the SDK's default policy; it does not mean DNSSEC was authenticated.

## Recovery

The run has a ten-minute deadline. On failure, keep **both**
`operational-key.json` and `recovery.json`, then rerun the same command.
Registration reuses the saved request/key. Issuance reuses the saved preparation
or exact completed bytes/key; it does not regenerate an event after submission.
An accepted submission is not sent again. Rejected outcomes stop for inspection.

One process may use the directory at a time. After a hard crash, remove `.lock`
only after confirming no copy is still running. Do not edit the recovery files
or delete them to retry: a failed run does not establish that no identity exists.
The example assumes no concurrent key rotation during this flow.

The directory contains an owner-only private key and recovery data. Keep it
outside the repository and retain it while the identity is active. A new
state directory creates another identity. Cleanup is explicit, not automatic;
retire the immutable identity through the registry before discarding its key.

Tests are offline:

```sh
go test ./examples/managed-registration
```
