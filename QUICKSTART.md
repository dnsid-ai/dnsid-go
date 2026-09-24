# dnsid-go quick start

**Verify a DNSid domain, then act as an agent: mint a DNSid JWT and sign an HTTP request — all from
Go, in a few minutes.**

Step 1 needs nothing but the SDK. Steps 2–4 sign on an agent's behalf, so they need a DNSid
identity, created with the DNSid CLI — locally with `dnsid local`, or hosted with `dnsid init`.

## Prerequisites

| Tool | For |
|---|---|
| **Go 1.26.6+** — [go.dev/dl](https://go.dev/dl/) | building and running the SDK |
| **DNSid CLI** (`dnsid`) — [docs.dnsid.ai](https://docs.dnsid.ai) | Steps 2–4: `dnsid local up` (Docker) or `dnsid init` to create an agent identity |

```sh
go get github.com/dnsid-ai/dnsid-go
```

## Step 1 — Verify a domain (no identity required)

A verify-only `IdentityManager` needs no key. Give it a DNSid-enabled domain and it resolves the
`_dnsid` record, verifies the profile-selected record-signing and runtime JWKS, and queries the
status endpoint. The current SDK accepts exact `v=dnsid-draft-01` and `v=DNSid1` records. It
preserves the selector as signed; `DNSid1` is verification-only until version 1 becomes an RFC.
The default `auto` DNSSEC policy works with the built-in resolver: it preserves an `UNKNOWN`
validation state but rejects any resolver-reported validation failure. Use a DNSSEC-aware resolver
with `validated` or `required` mode when the application needs stronger DNSSEC assurance.

```go
idm, err := dnsid.NewVerifier()
if err != nil {
	log.Fatal(err)
}

ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
defer cancel()

verified, err := idm.VerifyDomain(ctx, "your-agent.example.com")
if err != nil {
	log.Fatalf("invalid: %v", err)
}
fmt.Printf("%s  governance=%s  status=%s\n",
	verified.Domain(), verified.Record().GovernanceID, verified.Status().State)
```

Runnable version: [`examples/validate-domain`](examples/validate-domain).

```sh
go run ./examples/validate-domain your-agent.example.com
```

Replace `your-agent.example.com` with a DNSid-enabled domain.

## Step 2 — Load your agent identity

**Local (default).** Start the local registry and run your program as an agent under it:

```sh
dnsid local up                          # local registry, DNS, and CA in Docker
dnsid local run my-agent -- go run .    # registers my-agent if needed, runs with DNSID_* set
```

`dnsid local run` exports `DNSID_CONFIG_DIR` (the agent's identity) plus `DNSID_REGISTRY_URL` and
`DNSID_API_KEY` for the local registry. To export the same variables into your shell instead:
`eval "$(dnsid local env my-agent)"`. Nothing talks to a hosted service; the SDK's registry client
defaults to `http://127.0.0.1:7755` and `dnsid.NewRegistryClientFromEnv()` picks up the exported
URL and key.

**Hosted.** Log in and create an identity once, then set `DNSID_REGISTRY_URL` and `DNSID_API_KEY`
from the console for any registry calls:

```sh
dnsid auth login                                   # one-time org login -> ~/.dnsid/auth.json
dnsid init --env production --domain <your-fqdn>   # agent identity     -> ~/.dnsid/<your-fqdn>/
```

Either way, `NewIdentityManagerFromDnsid("", dnsid.Config{})` reads the identity from
`$DNSID_CONFIG_DIR` (or `~/.dnsid`) and loads its operational key, giving you a manager that can
both verify *and* sign as your agent:

```go
idm, err := dnsid.NewIdentityManagerFromDnsid("", dnsid.Config{})
if err != nil {
	log.Fatal(err)
}
fmt.Println("acting as:", idm.Domain())
```

## Step 3 — Mint a DNSid JWT

The JOSE profile signs a DNSid JWT with your agent's active key:

```go
profile := jose.NewFromIdentityManagerKeyProvider(idm, jose.Config{})

token, err := profile.CreateJWT(jose.JWTOptions{
	Audience:         "bob.example.com",
	AdditionalClaims: map[string]any{"purpose": "quickstart"},
})
if err != nil {
	log.Fatal(err)
}
fmt.Println(token)
```

Verify one back with `profile.VerifyJWT(ctx, token)` — it resolves the issuer's DNSid identity and
checks the signature against the published JWKS. The
[`examples/local-key-provider`](examples/local-key-provider) walkthrough also shows key generation,
rotation, and JWKS publication without needing `~/.dnsid`.

## Step 4 — Sign an HTTP request (Web Bot Auth)

The Web Bot Auth profile adds RFC 9421 HTTP Message Signature headers, so an origin can verify the
caller is your DNSid agent. The signing key must be Ed25519.

```go
profile := webbotauth.NewFromIdentityManager(idm, webbotauth.Config{})

req, _ := http.NewRequest(http.MethodGet, "https://target.example/search?q=dnsid", nil)
signed, err := profile.CreateWebBotAuthSignedRequest(req, webbotauth.SigningOptions{})
if err != nil {
	log.Fatal(err)
}
fmt.Println("Signature-Agent:", signed.Header.Get("Signature-Agent"))
fmt.Println("Signature-Input:", signed.Header.Get("Signature-Input"))
fmt.Println("Signature:", signed.Header.Get("Signature"))
```

Runnable version: [`examples/webbotauth`](examples/webbotauth).

```sh
go run ./examples/webbotauth
```

## Where to go next

- [`examples/`](examples/) — every snippet above as a runnable program.
- [docs.dnsid.ai](https://docs.dnsid.ai) — the DNSid protocol and account setup.
- Package docs: `go doc github.com/dnsid-ai/dnsid-go`.
