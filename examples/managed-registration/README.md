# Named managed registration

Create or resume `managed-registration-example` within one dev organization,
then independently verify public ACTIVE status and complete lifecycle evidence.
The SDK owns registry access, keys, named storage, issuance, retries, and public
verification. No recovery adapter or challenge server is needed.

## Server prerequisite

**The dev CLI is currently disabled.** The server must first pass real
persistence/integration checks for derived-key validation, atomic name/key
ownership, permanent organization-scoped replay, and existing-issuance recovery.
A 24-hour replay cache is insufficient. SDK tests simulate the required server;
they do not establish deployed support. An acknowledgment flag cannot establish
support, so there is no such flag. The repository owner can enable
`namedRegistrationAvailable` only after those server checks pass.

See [the SDK contract](../../registration/README.md#required-server-contract).
These SDK changes do not implement the required server work.

## Configuration and run

After server readiness is established, create a non-secret deployment file:

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

Organization ID is the registry account ID, not a credential hash or GI.
Fully configured account bindings need no discovery. Omitted bindings require
verified authenticated onboarding; pending governance proof/delegation fails.
The entity-key URL remains independently configured.

```sh
export DNSID_API_KEY='your-dev-organization-api-key'
go run ./examples/managed-registration \
  --config deployment.json \
  --state-dir "$HOME/.dnsid-examples/managed-registration-go"
```

`DNSID_API_KEY` is the only API credential input; it is not saved or printed.
Use Go 1.26.6+ and public DNS/HTTPS access. The CLI accepts only the dev registry
and uses the fixed, case-sensitive name `managed-registration-example`. It
passes no routing selectors: the SDK sends name/public key only, without
translating the expected GI into a root or silently selecting production.
Transport, DNSSEC, log trust, acceptance policy, and key-source settings come from
the file. No environment overlay or implicit trust preset is added.

**This creates a real identity and permanent log entry when enabled.** It leaves
the identity active. Success prints `Verified: <assigned-domain> status=ACTIVE`.
Set file `dnsid.verification.dnssecMode` to `required` and use a DNSSEC-aware
resolver when authenticated DNSSEC is required.

## AWS KMS configuration

Default file keys are for development, not production; the SDK warns when using
them. To use an existing KMS key, add the separate AWS provider module dependency
and this import to the application:

```go
import _ "github.com/dnsid-ai/dnsid-go/key/aws"
```

Then add this section to the same deployment file; the registration call does
not change:

```json
{
  "keySource": {
    "provider": "aws-kms",
    "keyRef": "arn:aws:kms:us-east-1:123456789012:key/your-key-id",
    "settings": { "region": "us-east-1", "algorithm": "ES256" }
  }
}
```

Use an existing `SIGN_VERIFY`, `ECC_NIST_P256` key and grant `kms:GetPublicKey`
and `kms:Sign`. AWS credentials come from the standard chain; the organization
API token is separate. Private key material stays in KMS. Use an immutable key
ARN, never a mutable alias. This factory rejects cloud generation because it
cannot atomically create-or-recover a key across replicas. Installing the module
without importing it does not link the factory; unavailable providers fail early
without local-file fallback. AWS dependencies are not linked in this base example.

## Recovery

Back up the **whole state root**, including each named operation's key files and
`recovery.json`. State and locks are isolated by a digest of registry/account/name;
raw names are never paths. Use a local filesystem with POSIX permissions, atomic
rename, and file/directory fsync. Rerun with the same store/configuration/name.
Do not edit state, replace a key, or start another registration after interruption.
The SDK has one ten-minute budget; no outer retry loop is needed.

After a hard crash, clear an operation's `.lock` only after confirming no process
still uses it. Unnamed schemas 1/2 are incompatible with named schema 3 and are
rejected without creating replacement keys. Recover them with the original SDK.

Creation input is discarded after validated identity facts are durable. Accepted
issuance bytes are compacted only after trusted hash/inclusion verification;
completed calls retrieve historical evidence without preparation or append.
Missing history fails instead of reissuing. Authorized completed rotation can
change key/`ku`, without the old private key or an old-URL fallback. Pending
rotation uses the existing coordinator; changing key-source settings alone is
not rotation. Retire the identity before discarding keys or requesting explicit
fresh-key replacement, and preserve its previous state/history.

## Offline checks

```sh
go test ./examples/managed-registration ./registration
```
