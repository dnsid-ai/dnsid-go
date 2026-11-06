# DNSid registry-publish example

Publishes an agent's `_dnsid` identity record through the DNSid registry. It loads the current
identity with `config.LoadCliDirectory` (`$DNSID_CONFIG_DIR` under `dnsid local run`, otherwise
`~/.dnsid`) merged with `config.LoadEnvironment`, reads the agent's registration, then either
signs the registry-prepared canonical identity record with the local entity key (client publication
authority) or waits for registry-managed DNS publication and verifies the published record.

The registry client comes from `config.RegistryClientFromEnvironment(nil)`: `DNSID_REGISTRY_URL` and
`DNSID_API_KEY`, defaulting to the local registry at `http://127.0.0.1:7755`.

## Local

```sh
dnsid local up
dnsid local run my-agent -- go run ./examples/registry-publish
```

## Hosted

Create the identity once with `dnsid auth login` + `dnsid init --env production --domain <fqdn>`
(see [QUICKSTART.md](../../QUICKSTART.md)), then point the example at the hosted registry with a
console-issued key:

```sh
export DNSID_REGISTRY_URL=https://api.dnsid.ai
export DNSID_API_KEY=...   # from the console
go run ./examples/registry-publish
```

Client-controlled publication also needs the entity key on disk (`entity_key_path` in `config.json`).

## Initial publication versus application signing

This example is publication setup: it explicitly opens the existing operational
key and injects it into `config.Construct`, so an unpublished identity can reach
the registry. The caller owns binding checks and the injected provider's lifetime;
cleanup runs before the process exits, including on failure. This manager is not
evidence of an authenticated established application signer. For subsequent
application signing, use ordinary configuration-selected `Construct`, which
requires fresh verified publication matching the selected key. Changing key
configuration does not authorize rotation.

Client-controlled publication validates and signs the registry-prepared canonical
record and returns the registry result; it does not independently verify DNS after
submission. The registry-managed branch waits for and verifies DNS publication.
