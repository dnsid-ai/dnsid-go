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
Before returning a configuration-selected signer, `Construct` verifies local
signed publication and matches its operational key ID, algorithm, and thumbprint.
A changed key source cannot replace an established signer without explicit rotation.
This requires reachable publication and the appropriate log reader. Injected key
providers retain precedence and are the responsibility of the caller's workflow.

These configuration/provider and onboarding APIs work with the existing server.
Named creation and automatic permanent recovery are separate workflow changes.

See [the deployment-identity example](../examples/deployment-identity/) for loading
an existing file or AWS KMS key, checking its published binding, and signing an
HTTP request without sending it.
