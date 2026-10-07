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
export DNSID_API_KEY='your-dev-organization-api-key'
go run ./examples/managed-registration \
  --server-contract-verified \
  --state-dir "$HOME/.dnsid-examples/managed-registration-go"
```

`DNSID_API_KEY` is the only credential input. Credentials are not saved or
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

## Using an AWS KMS key instead

The runnable example uses a local key. To use an existing KMS signing key, add
these imports in your own application:

```go
awsconfig "github.com/aws/aws-sdk-go-v2/config"
"github.com/aws/aws-sdk-go-v2/service/kms"
awskms "github.com/dnsid-ai/dnsid-go/key/aws"
```

After preparing `loaded`, replace the registration call with:

```go
awsCfg, err := awsconfig.LoadDefaultConfig(ctx)
if err != nil {
    return err
}
keyARN := "arn:aws:kms:us-east-1:123456789012:key/your-key-id"
provider, err := awskms.Load(ctx,
    awskms.SDKClient{Client: kms.NewFromConfig(awsCfg)},
    awskms.Config{State: awskms.State{ActiveKeyID: keyARN}})
if err != nil {
    return err
}
result, err := registration.RegisterManagedIdentity(ctx, loaded, token,
    registration.NewFileRegistrationStore(directory),
    &dnsid.AgentRegistrationInput{Environment: "sandbox"},
    registration.Options{
        Dependencies: config.Dependencies{KeyProvider: provider},
        ProviderReference: keyARN,
    })
```

Install the separate `github.com/dnsid-ai/dnsid-go/key/aws` module and AWS SDK
config package in that application. Set the AWS region and credentials through
the normal AWS credential chain; the organization API token remains separate.
Use an existing `SIGN_VERIFY`, `ECC_NIST_P256` key (ES256, the provider default)
and grant `kms:GetPublicKey` and `kms:Sign`.

Private key material stays in KMS; no local private-key file is created. Keep
`recovery.json` and reuse the same immutable key ARN and state directory on every
resume. Do not use a mutable alias or switch an existing local-key setup to KMS.
The server prerequisite still applies. If you later rotate keys, persist
`provider.State()` separately and restore it through `awskms.Config.State`.

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
