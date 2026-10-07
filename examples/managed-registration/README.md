# Managed registration

Register one hosted **dev sandbox** identity and independently verify its ACTIVE
status and lifecycle evidence through public DNS. No challenge server or DNS
hosting is needed.

## Server prerequisite

**Do not run this example until server integration tests verify the revised
permanent creation-idempotency contract.** Current hosted-service support is not
established by the SDK tests. An expiring 24-hour, organization-local replay cache
is insufficient. See [the required contract](../../registration/README.md#required-server-contract).

The registry must atomically bind each registry-wide unique registration key to
its authenticated organization, complete request, and one immutable identity.
Matching retries must return that identity or a terminal error, including after
restart, long interruption, retirement, or deletion. Reuse by another organization
must fail without disclosure or another allocation. These are server guarantees,
not an SDK adapter or a client-side replay timer.

`--server-contract-verified` confirms that this deployment has passed those
integration tests. It does not probe or establish server support. Without the
flag, the example stops before key creation or network work.

## Run

After the server prerequisite is met, use Go 1.26.6+, public DNS/HTTPS access, and
a dev organization API key:

```sh
go run ./examples/managed-registration \
  --server-contract-verified \
  --api-key-file "$HOME/.dev-dnsid-api-key" \
  --state-dir "$HOME/.dnsid-examples/managed-registration-go"
```

Alternatively, omit `--api-key-file` and set `DNSID_API_KEY`. The file must
contain one token; protect it with mode `600`. Credentials are not saved or
printed.

**This creates a real sandbox identity and a permanent dev transparency-log
entry.** It leaves the identity active. Keep the private key backed up and use
a dedicated directory outside the repository.

Success prints `Verified: <assigned-domain>.sandbox.dev.dnsid.ai status=ACTIVE`.
This does not imply authenticated DNSSEC; set `DNSID_DNSSEC_MODE=required` and
use a DNSSEC-aware resolver when required.

## SDK workflow

One `registration.RegisterManagedIdentity()` call owns the registry client, key
creation, durable request replay, bilateral ISSUANCE recovery, publication polling,
and fresh credential-free public verification. `NewFileRegistrationStore()` owns
locking, owner-only permissions, atomic writes, and fsync. No organization lookup,
recovery adapter, replay deadline, or reconciliation callback is needed.

The example loads SDK environment configuration, then explicitly selects the dev
registry, managed log trust, expected governance ID, and independent entity-key
endpoint. A different `DNSID_REGISTRY_URL` is rejected. Existing identity and
key-source settings are not used. Transport settings such as `DNSID_DNS_SERVER`
and `DNSID_CA_BUNDLE` still apply.

## Recovery

Back up the **whole directory**, including `operational-key.json` (private key)
and `recovery.json` (public recovery data). Use a local filesystem that supports
POSIX permissions, atomic rename, and file/directory fsync. Rerun with the same
directory after interruption; do not replace the key or edit recovery data.
Each call has the SDK's ten-minute budget; do not add an outer retry loop.
Registration keys do not expire. Invocation deadlines do not authorize replacement
allocation.

After a hard crash, remove `.lock` only after confirming no process still uses
the directory. Earlier manual-example and expiring-replay recovery files are
**not compatible** with schema version 2. They are rejected without creating a
replacement key. Finish those operations with their original example/SDK version;
do not delete their state and register again as a recovery step.

Retire the identity through the registry before discarding its key. Production,
Live challenges, and self-managed publication are outside this example.

## Offline checks

```sh
go test ./examples/managed-registration ./registration
```
