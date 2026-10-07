# Managed registration

Register one hosted **dev sandbox** identity and independently verify its ACTIVE
status and lifecycle evidence through public DNS. No challenge server or DNS
hosting is needed.

## Run

Requires Go 1.26.6+, public DNS/HTTPS access, and a dev organization API key:

```sh
go run ./examples/managed-registration \
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

One `registration.RegisterManagedIdentity()` call owns key creation, durable
request replay, bilateral ISSUANCE recovery, publication polling, and fresh
credential-free public verification. `NewFileRegistrationStore()` owns locking,
owner-only permissions, atomic writes, and fsync. The CLI implements none of
these operations. See [the workflow documentation](../../registration/README.md).

The example loads SDK environment configuration, then explicitly selects the dev
registry, managed log trust, expected governance ID, and independent entity-key
endpoint. A different `DNSID_REGISTRY_URL` is rejected. Existing identity and
key-source settings are not used. Transport settings such as `DNSID_DNS_SERVER`
and `DNSID_CA_BUNDLE` still apply.

### Dev adapter contract

The workflow requires service-specific organization and replay capabilities.
`devAdapter` embeds the SDK registry client and resolves authenticated ownership
through `GET /api/v1/auth/me` (`user.org_id`). It rejects redirects and bounds the
response body. An organization label supplied by the user is not sufficient.

The adapter assumes the dev service retains creation replay keys for **24 hours**,
scoped to registry, organization, and request key, starting at the server's claim
(no earlier than the first request attempt). The service source at revision
`95c68f3ea8aa2532b5cd07d7a6ab43c5eb6d6dc2` defines these behaviors in
`internal/api/auth_handler.go`, `internal/api/agent_create.go`, and
`internal/db/pgstore/idempotency.go`. Confirm the deployed service honors this
contract before use. Keep the local clock within five minutes of server time,
including across restarts. The workflow subtracts that uncertainty from the
replay deadline. Expired or uncertain creation outcomes stop for authenticated
reconciliation; this adapter does not invent a reconciliation endpoint.

## Recovery

Back up the **whole directory**, including `operational-key.json` (private key)
and `recovery.json` (public recovery data). Use a local filesystem that supports
POSIX permissions, atomic rename, and file/directory fsync. Rerun with the same
directory after interruption; do not replace the key or edit recovery data.
Each call has the SDK's ten-minute budget; do not add an outer retry loop.

After a hard crash, remove `.lock` only after confirming no process still uses
the directory. Recovery files from the previous manual example are **not
compatible**. They are rejected without creating a replacement key. Finish those
operations with the previous example version; do not delete their state and
register again as a recovery step.

Retire the identity through the registry before discarding its key. Production,
Live challenges, and self-managed publication are outside this example.

## Offline checks

```sh
go test ./examples/managed-registration ./registration
```
