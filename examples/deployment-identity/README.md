# Published identity from deployment configuration

Load one deployment file, select an existing signing key, verify the application's
published identity, check its current operational key, and sign an RFC 9421 HTTP
request without sending it. The application code is the same for both files.

## Prerequisites and placeholders

- Use a patched Go release (Go 1.26.9 or newer), and this repository checkout.
- An identity must already be published: its `_dnsid` TXT record, entity and
  operational JWKS, active status, and lifecycle-log evidence must be available.
  Verification needs network access to DNS, HTTPS publication endpoints, and the log.
- **Replace all example domains and URLs** with the identity's persisted publication
  settings. **Replace `<persisted lifecycle-log reference>`** with its actual
  `logRef`; do not derive a new reference.
- In `deployment.aws.json`, **replace `<immutable signing-key ARN>`** with the
  existing key ARN, not an alias. For ES256 it must be an enabled asymmetric
  `ECC_NIST_P256` key with `SIGN_VERIFY` usage and `ECDSA_SHA_256` support.
  Set `region` to the ARN's region.
- In `deployment.file.json`, **`./keys.json` is a placeholder path** to an
  existing SDK local key store or flat private JWK. Paths resolve relative to the
  process working directory, not the deployment file. Protect the file (for example,
  permissions `0600`); never commit it.

These are alternative custody configurations, not two interchangeable keys.
Each configuration must point to the key already bound to the identity it names.
Copying the identity fields into a second file does not bind a new key to that
identity. A file-backed identity must already have that file's active key published;
a KMS-backed identity must already have that KMS key published.

## Log trust

The supplied files use `logTrust.managed: true` **only for an identity on a
supported DNSid-managed log**. This SDK catalog covers public
`https://log.dnsid.ai` and `https://log.dev.dnsid.ai`. It is an explicit trust
choice, not automatic trust in the log named by DNS.

For another log, replace the entire `logTrust` section with either
`{"profile": <independently trusted C2SP trust-profile object>}` or
`{"policyUrl": "<independently trusted HTTPS policy URL>"}`.
These are placeholders, not copy-ready JSON. Obtain log/witness keys, quorum policy,
and (for signed bundles) bundle verifier keys independently of the identity being
verified. Do not retain `managed` alongside another variant. See
[`config.LogTrust`](../../config/config.go) and the
[C2SP trust-profile schema](../../log/c2sptlog/trust_profile.go).
Code can instead inject an appropriately trusted `LogRegistry` through
`config.Dependencies`, including durable checkpoint storage when needed.

## Provider installation and AWS access

This example has its own Go module to keep AWS dependencies out of the core SDK.
Its `go.mod` links the root SDK and optional `key/aws` module to this checkout.
`go mod download` installs their dependencies. In another application, add the
compatible SDK and `github.com/dnsid-ai/dnsid-go/key/aws` module versions to its
`go.mod` (for example with `go get`).

The blank import in `main.go` registers the `aws-kms` factory at build time.
Installing the module alone does not link it. Both providers are linked into this
one application; selecting the file provider does not initialize AWS credentials
or call KMS. An unavailable provider fails rather than falling back to file keys.

AWS credentials use the AWS SDK's ambient chain: workload roles, shared
configuration/credential profiles (including SSO), or AWS environment variables.
For a local profile, authenticate first (for example, `aws sso login --profile
your-profile`) and set `AWS_PROFILE`. Do not put access keys, session tokens, API
credentials, or private keys in deployment JSON.

Grant `kms:GetPublicKey` and `kms:Sign` on the exact key ARN in IAM and the KMS
key policy as appropriate. No creation, import, rotation, or deletion permission
is needed. KMS access is required: signing happens through `kms:Sign`, while the
HTTP request is assembled locally and never dispatched to its target.

## Run

From this directory, after replacing the placeholders in the selected file:

```sh
go mod download

# KMS custody; use ambient workload credentials or select a local profile.
AWS_PROFILE=your-profile go run . deployment.aws.json

# Development-only file custody; ./keys.json must already exist.
go run . deployment.file.json

# Offline regression checks; no credentials or published identity needed.
go test ./...
```

`LoadDeploymentFile` parses only the chosen document. `Construct` validates
configuration, builds log trust, and opens the existing key (KMS uses
`GetPublicKey`). It can perform trust-resource network reads, but this branch
does **not** automatically verify the identity's publication or its signer binding.
The example explicitly calls `VerifyDomain` on its own domain, then compares the
selected key's RFC 7638 thumbprint, key ID, and algorithm with the verified current
operational (`ku`) key, not the entity (`ek`) key. A mismatch stops signing.

Nothing is published or changed. This example has no registration, key generation,
rotation, deletion, or automatic recovery. Changing `keyRef` does not authorize
rotation; that requires a separate authorized lifecycle operation. Local files
are for development, not production custody.
