# DNSid registry-publish example

Publishes an agent's `_dnsid` identity record through the DNSid registry. It loads the current
identity with `dnsid.NewIdentityManagerFromDnsid("", dnsid.Config{})`, reads the agent's registration, then either
signs the registry-prepared canonical identity record with the local entity key (client publication
authority) or waits for registry-managed DNS publication and verifies the published record.

```sh
export DNSID_TOKEN=...   # registry bearer token
go run ./examples/registry-publish https://registry.example.com
```

Uses the current identity selected by `~/.dnsid/config.json` — create one with `dnsid auth login` +
`dnsid init` (see [QUICKSTART.md](../../QUICKSTART.md)). Client-controlled publication also needs
the entity key on disk (`entity_key_path` in `config.json`).
