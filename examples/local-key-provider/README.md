# Local Key Provider Example

Demonstrates the Go SDK `LocalKeyProvider` flow matching the TypeScript example:

- load `./keys.json`, or create it with a new Ed25519 private JWK
- inspect the active public JWK and key IDs
- generate a pending key, activate it, and inspect the provider's retained keys (draft 01 live JWKS endpoints publish only the active key)
- supersede the old retained key
- create and decode a DNSid JOSE-profile JWT

Run from this directory:

```sh
go run .
```

Delete `keys.json` to reset the persisted starting key.

Note: rotation state is persisted. This walkthrough supersedes the old retained key before exit, so the final `keys.json` contains only the current active key.
