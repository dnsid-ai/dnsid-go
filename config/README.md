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
Merge is field-wise; lists replace and log trust is atomic. Scalar zero values
cannot clear a nonzero base value; edit the merged value to clear it.

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
Changing configuration is not authorization to rotate an established identity.

These configuration/provider and onboarding APIs work with the existing server.
Named creation and automatic permanent recovery are separate workflow changes.
