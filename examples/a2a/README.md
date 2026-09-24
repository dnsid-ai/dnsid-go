# DNSid A2A example (Go)

Runs Alice and Bob on the local DNSid testnet. Both expose an A2A 1.0 echo agent card and exchange `SendMessage` JSON-RPC requests authenticated with DNSid-bound RFC 9421 HTTP Message Signatures.

The Go A2A SDK has not yet published an importable A2A 1.0 module, so this example uses the A2A 1.0 JSON-RPC wire format directly. Its agent card and messages match the TypeScript and Python examples.

- `main.go` shows DNSid setup, request verification, and signed requests.
- `agent_card.go` builds and signs the A2A agent card.

## Prerequisites

Install the `dnsid` CLI ([installation guide](https://docs.dnsid.ai/cli-installation)) and start Docker. The CLI owns the local testnet.

## Run

From the `dnsid-go` repository root:

```sh
bash examples/a2a/run.sh
```

Set `DNSID_TESTNET_STATE` to use a non-default testnet state directory.

The script starts the testnet, prepares both identities and their C2SP ISSUANCE entries, starts Bob, sends one message from Alice, and stops Bob.

To run the agents separately:

```sh
CLI="${DNSID_CLI:-dnsid}"
"$CLI" testnet up
"$CLI" testnet agent ensure bob --upstream http://localhost:3002 \
  --cu https://bob.dev.dnsid.test/.well-known/agent-card.json -- \
  "$CLI" log issue --domain bob.dev.dnsid.test
"$CLI" testnet agent ensure alice --upstream http://localhost:3001 \
  --cu https://alice.dev.dnsid.test/.well-known/agent-card.json -- \
  "$CLI" log issue --domain alice.dev.dnsid.test

# Terminal 1
"$CLI" testnet run bob --port 3002 -- go run ./examples/a2a

# Terminal 2
"$CLI" testnet run alice --port 3001 -- go run ./examples/a2a bob.dev.dnsid.test
```

Expected Alice output includes:

```text
verified: alice.dev.dnsid.test -> bob.dev.dnsid.test
reply: "[from: bob.dev.dnsid.test; verified sender: alice.dev.dnsid.test] hello from alice.dev.dnsid.test"
```

`dnsid testnet run` supplies the C2SP policy location separately as
`DNSID_LOG_POLICY_URL`. `config.LoadEnvironment` treats that value as trusted
testnet configuration and never derives it from `DNSID_LOG_REF` or the log
prefix, so custom testnet proxy ports are preserved. Verification fails closed
when the value is missing.

`config.Construct` passes `DNSID_DNS_SERVER` and `DNSID_CA_BUNDLE` as a single
`dnsid.TransportConfig` to the log registry and the `IdentityManager`; the
example reuses it for the outbound HTTP client. Production applications leave it zero for the SDK's
default SSRF-safe transport and keep their official or pinned C2SP policy
independently configured.
