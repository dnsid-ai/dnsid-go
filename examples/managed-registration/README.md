# Register a named identity

The SDK handles keys, recovery, issuance, publication, and independent public
verification. The application loads configuration and makes one call:

```go
result, err := registration.RegisterManagedIdentity(ctx,
    "managed-registration-example", loaded, token,
    registration.NewFileRegistrationStore(stateDir), nil)
```

## Before running

**The dev CLI remains disabled until real server integration checks pass.**
Permanent organization-scoped replay, atomic name/key ownership, derived-key
validation, and existing-issuance recovery require server changes. SDK mocks and
acknowledgment flags do not establish support. Enable `namedRegistrationAvailable`
only after verified persistence/integration support; see the
[server contract](../../registration/README.md#required-server-contract).

Once supported, create a non-secret deployment file:

```json
{
  "logTrust": { "managed": true },
  "registry": { "registryUrl": "https://api.dev.dnsid.ai" },
  "registration": {
    "organizationId": "your-authenticated-internal-organization-id",
    "governanceId": "dev.dnsid.ai",
    "entityKeyUrl": "https://dnsid.dev.dnsid.ai/.well-known/dnsid-ek.json"
  }
}
```

```sh
export DNSID_API_KEY='your-dev-organization-api-key'
go run ./examples/managed-registration \
  --config deployment.json --state-dir "$HOME/.dnsid-examples/managed-registration-go"
```

Use Go 1.26.6+ and public DNS/HTTPS. `DNSID_API_KEY` is the sole credential input
and is not saved or printed. The fixed name is case-sensitive and account-scoped.
The dev-only example passes no allocation selectors or environment overlays.
It creates a real, permanent identity and leaves it ACTIVE; success prints the
assigned domain. Transport, DNSSEC, trust, and acceptance settings come from the file.

## Existing AWS KMS key

File keys are development-only. For KMS, add the optional provider module and
`import _ "github.com/dnsid-ai/dnsid-go/key/aws"` to the application, then add:

```json
{
  "keySource": {
    "provider": "aws-kms",
    "keyRef": "arn:aws:kms:us-east-1:123456789012:key/your-key-id",
    "settings": { "region": "us-east-1", "algorithm": "ES256" }
  }
}
```

Use an existing `SIGN_VERIFY`, `ECC_NIST_P256` key, immutable ARN (not alias),
AWS credential chain, and `kms:GetPublicKey`/`kms:Sign` permissions. The registration
call is unchanged; no private key leaves KMS. The base example does not link AWS
dependencies. Unlinked providers fail without file fallback; cloud generation
without replica convergence is rejected.

## Recovery

Back up the whole state root, including keys. Rerun with the same store/name;
never delete state, replace a key, or register again after interruption. Storage
requires POSIX permissions, atomic rename, and fsync. Clear a stale operation
lock only after confirming no process owns it. Unnamed schemas 1/2 require their
original SDK, not deletion. The SDK has a ten-minute budget and no outer retry loop.
See [SDK recovery](../../registration/README.md#recovery) for compaction, historical
proofs, rotation, and terminal replacement. Retire the identity before discarding keys.

Offline checks: `go test ./examples/managed-registration ./registration`.
