# Multiple trusted log providers

Trust two independently supplied log profiles in one verification-only manager.
Each profile binds an exact scope and log prefix to its log/witness policy and
bundle-signing keys. Obtain both files through a trusted channel, not from the
identity being verified. Use profiles for two different logs.

From the repository root, with real profiles and published DNSid domains:

```sh
go run ./examples/multiple-log-providers \
  /trusted/provider-a.json /trusted/provider-b.json \
  agent-a.example agent-b.example
```

`config.LogTrust` accepts one profile. The example calls
`config.LogRegistryFromTrust` for each profile, then registers one dispatcher
that selects a provider by the authenticated reference's exact scope and prefix.
Unknown logs fail verification. `config.Construct` uses the combined registry
supplied through `config.Dependencies.LogRegistry`.

Both providers are trusted at once; a domain uses the provider named in its
`lr`. Verification does not require approval from both providers. Add ordinary
SDK settings to `settings.Dnsid`; the same transport settings reach both log
registries and the identity manager. The example does not load environment
variables or select local signing keys.

This example panics on errors, keeps checkpoints in memory, and does not configure
cross-log migration verification. It uses the config helper's 10-minute
checkpoint-age and bundle-lifetime defaults.
