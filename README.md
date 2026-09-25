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

Requires Go 1.26.6 or newer (matches the `go` directive in `go.mod`). See
[Compatibility](#compatibility).

## Verify a domain

```go
package main

import (
	"context"
	"fmt"
	"time"

	dnsid "github.com/dnsid-ai/dnsid-go"
	"github.com/dnsid-ai/dnsid-go/config"
)

func main() {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	// Set DNSID_LOG_TRUST_PROFILE_FILE to an independently trusted profile first.
	idm, err := config.IdentityManagerFromEnvironment(ctx, nil, dnsid.Config{}, config.Dependencies{})
	if err != nil {
		panic(err)
	}

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
| **Go** | 1.26.6 (minimum, per `go.mod`) through the latest stable release. CI tests `1.26.6` and `stable`. |
| **Platforms** | linux/amd64 tested in CI; linux/arm64, darwin, and windows/amd64 supported (pure Go, no platform-specific code). |
| **Crypto/cgo** | Pure Go, builds with `CGO_ENABLED=0`. Standard-library crypto; FIPS via Go's native FIPS mode. |
| **DNSSEC** | `auto` works with the built-in resolver and rejects known validation failures. `validated` and `required` need a DNSSEC-aware resolver supplied via `WithDNSResolver`. |

Full details, including tested dependency versions and enterprise deployment notes, are in
**[COMPATIBILITY.md](COMPATIBILITY.md)**. Production runtime behavior, key rotation, revocation,
transport, cache, and error guidance are in **[OPERATIONS.md](OPERATIONS.md)**.

## Security & trust

**Official sources.** Source: `github.com/dnsid-ai/dnsid-go`. Package: `github.com/dnsid-ai/dnsid-go` on the Go module proxy (`pkg.go.dev/github.com/dnsid-ai/dnsid-go`). Releases: GitHub Releases on
this repository, each with a CycloneDX SBOM attached. Forks, mirrors, and similarly named packages
are not maintained by us. Report vulnerabilities per [SECURITY.md](SECURITY.md); never in a public issue.

**Software is not identity.** This SDK ships no private keys or credentials; its optional embedded
log trust profiles do not grant an identity. A DNSid identity is proven by control of a DNS zone,
an agent private key, and the registry's published status. Possessing, forking,
or modifying this code grants none of those: an unofficial build cannot mint or inherit anyone's identity.

**What it does on the network.** Only when you call it, and only to hosts you or the domain being verified
chose:

- DNS TXT lookup of `_dnsid.<domain>` through your system resolver (no hardcoded resolver)
- HTTPS GET to the JWKS and status URLs published in that TXT record
- Opt-in only, never contacted unless you configure them: `https://log.dnsid.ai` / `log.dev.dnsid.ai` (C2SP transparency log via `log/c2sptlog`, bundled public trust roots), cloud KMS endpoints via `key/aws`
- No telemetry, usage reporting, update checks, or crash reporting

**Logging.** The SDK has no logger; errors are returned to the caller. It warns on stderr if a
custom HTTP transport cannot be safely preserved.

**Hosted endpoints.** `api.dnsid.ai` and `log.dnsid.ai` are operated separately from this SDK under their
own terms. Nothing in this repository is an availability, uptime, or support commitment for them.

**For your privacy notice.** Using this SDK causes your system to make DNS and HTTPS requests to the domains
you verify and to the JWKS/status hosts they publish. It sends them nothing about your users. If you enable
the registry or transparency-log clients, requests also go to DNSid-operated endpoints; disclose that where
your notice requires it.

## License

Licensed under the [Apache License 2.0](LICENSE.txt).
