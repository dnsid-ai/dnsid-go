# dnsid-go

**The Go SDK for DNSid — verify who an agent is, who governs it, and whether it's still live,
straight from DNS.**

DNSid binds an agent to a domain: a signed `_dnsid` TXT record names the agent's governing
organization (`gi`), accountable-entity record-signing key set (`ek`), and agent runtime key set
(`ku`); a status endpoint reports whether the agent is `ACTIVE` or `REVOKED`. This SDK resolves and
verifies that chain, and signs on the agent's behalf — DNSid JWTs (JOSE profile), OIDC tokens, and
[Web Bot Auth](https://datatracker.ietf.org/doc/draft-meunier-webbotauth-httpsig-protocol/) HTTP
Message Signatures (RFC 9421).

## Install

```sh
go get github.com/dnsid-ai/dnsid-go
```

Requires Go 1.26.5 or newer (matches the `go` directive in `go.mod`). See
[Compatibility](#compatibility).

## Verify a domain

```go
package main

import (
	"context"
	"fmt"
	"time"

	dnsid "github.com/dnsid-ai/dnsid-go"
)

func main() {
	idm, err := dnsid.NewVerifier()
	if err != nil {
		panic(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	verified, err := idm.VerifyDomain(ctx, "your-agent.example.com")
	if err != nil {
		panic(err)
	}

	fmt.Println("domain:", verified.Domain())
	fmt.Println("governance:", verified.Record().GovernanceID)
	fmt.Println("status:", verified.Status().State)
}
```

Replace `your-agent.example.com` with a DNSid-enabled domain. `VerifyDomain` resolves its `_dnsid`
record, verifies the record-signing and runtime JWKS selected by its profile, and queries the status
endpoint—all over SSRF-safe, DNS-rebinding-resistant transport. The default `auto` DNSSEC policy
accepts the built-in resolver's `UNKNOWN` validation state, while still rejecting a resolver-reported
`FAILED` state. Applications that require a definitive validation result must inject a DNSSEC-aware
resolver and select `validated` or `required` mode.

## TXT record versions

The `_dnsid` record's `v` tag selects its signed behavior profile; it is not the SDK release
version. This SDK:

- publishes new records with `v=dnsid-draft-01`
- verifies both `v=dnsid-draft-01` and `v=DNSid1`
- preserves the exact parsed `v` value when canonicalizing and verifying a signature
- rejects dated draft identifiers, legacy aliases, and unknown future selectors

While DNSid version 1 remains an Internet-Draft, `dnsid-draft-01` is the immutable submitted-draft
selector and the only publishable profile. Pre-RFC `DNSid1` is verification-only and selects the
latest submitted draft fully supported by that SDK release; it must not be rewritten to the
numbered selector because `v` is part of the signed content. When version 1 becomes an RFC,
`DNSid1` freezes to that RFC behavior and becomes the version 1 publish selector.

In Go, `dnsid.DefaultPublishProfile` reports the current publish selector. `dnsid.Version` reports
the Go module release; the two versions are intentionally separate.

## Packages

| Import | What it does |
|---|---|
| `github.com/dnsid-ai/dnsid-go` | Core SDK: `IdentityManager`, domain verification, TXT record parse/create, JWKS/JWK, key providers, typed errors. |
| `.../dnsid-go/jose` | DNSid JOSE profile — create and verify DNSid JWTs and compact JWS. |
| `.../dnsid-go/oidc` | Mint and verify DNSid OIDC tokens. |
| `.../dnsid-go/httpsig` · `.../webbotauth` | RFC 9421 HTTP Message Signatures and the Web Bot Auth profile. |

## Next steps

- **[QUICKSTART.md](QUICKSTART.md)** — sign as an agent, mint a JWT, and sign an HTTP request.
- **[examples/](examples/)** — runnable programs for domain verification, key rotation, and Web Bot Auth.
- **[docs.dnsid.ai](https://docs.dnsid.ai)** — protocol docs and account setup.

## Compatibility

| | Supported |
|---|---|
| **Go** | 1.26.5 (minimum, per `go.mod`) through the latest stable release. CI tests `1.26.5` and `stable`. |
| **Platforms** | linux/amd64 tested in CI; linux/arm64, darwin, and windows/amd64 supported (pure Go, no platform-specific code). |
| **Crypto/cgo** | Pure Go, builds with `CGO_ENABLED=0`. Standard-library crypto; FIPS via Go's native FIPS mode. |
| **DNSSEC** | `auto` works with the built-in resolver and rejects known validation failures. `validated` and `required` need a DNSSEC-aware resolver supplied via `WithDNSResolver`. |

Full details, including tested dependency versions and enterprise deployment notes, are in
**[COMPATIBILITY.md](COMPATIBILITY.md)**. Production runtime behavior, key rotation, revocation,
transport, cache, and error guidance are in **[OPERATIONS.md](OPERATIONS.md)**.

## License

Licensed under the [Apache License 2.0](LICENSE.txt).
