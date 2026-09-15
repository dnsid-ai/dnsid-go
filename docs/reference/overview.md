---
title: "Go: SDK overview"
description: "Package map for the DNSid Go SDK and where to start."
---

> Generated from the Go source by scripts/gen-docs.sh — do not edit; run it to regenerate.
> Canonical deep reference: [pkg.go.dev/github.com/dnsid-ai/dnsid-go](https://pkg.go.dev/github.com/dnsid-ai/dnsid-go).
> Guides and account setup: [https://docs.dnsid.ai](https://docs.dnsid.ai).

The Go SDK is the module `github.com/dnsid-ai/dnsid-go`, plus the separately tagged `key/aws` submodule. Install it with:

```bash
go get github.com/dnsid-ai/dnsid-go
```

Start with the root package: `IdentityManager` is the facade for verifying domains, creating and publishing identity records, and loading the agent identity your application acts as. The root package is documented across the `dnsid` pages below; the other packages are application profiles and infrastructure you pull in as needed.

| Page | What it covers |
| --- | --- |
| [Core: IdentityManager](https://docs.dnsid.ai/reference/go/dnsid) | IdentityManager, domain verification, configuration, transport, and caching for the DNSid Go SDK. |
| [Records & keys](https://docs.dnsid.ai/reference/go/dnsid-records) | TXT identity records, JWKS and JWK types, policy flags, and record parsing helpers. |
| [Profile: JOSE](https://docs.dnsid.ai/reference/go/jose) | DNSid JOSE profile: create and verify DNSid JWTs and compact JWS. |
| [Profile: HTTP signatures](https://docs.dnsid.ai/reference/go/httpsig) | RFC 9421 HTTP Message Signatures for DNSid agents. |
| [Profile: Web Bot Auth](https://docs.dnsid.ai/reference/go/webbotauth) | Web Bot Auth profile: RFC 9421-signed HTTP requests identifying a DNSid agent. |
| [Profile: OIDC](https://docs.dnsid.ai/reference/go/oidc) | Mint and verify DNSid OIDC tokens. |
| [Key providers](https://docs.dnsid.ai/reference/go/dnsid-keys) | KeyProvider implementations, key metadata, and log-event signing. |
| [Key providers: AWS KMS](https://docs.dnsid.ai/reference/go/key-aws) | AWS KMS-backed key provider for DNSid. |
| [Registry](https://docs.dnsid.ai/reference/go/dnsid-registry) | HTTPRegistryClient, publication workflows, and registry request/response types. |
| [Lifecycle log](https://docs.dnsid.ai/reference/go/log) | Agent lifecycle log abstractions for DNSid. |
| [Transparency log](https://docs.dnsid.ai/reference/go/log-c2sptlog) | C2SP transparency-log (tlog) client support for DNSid lifecycle logs. |
| [Errors & enums](https://docs.dnsid.ai/reference/go/dnsid-errors) | Typed errors and verification codes returned across the SDK. |

For a guided first verification see the [Quickstart](https://docs.dnsid.ai/quickstart); for multi-language walkthroughs of verification, OIDC tokens, and freshness see the [Libraries overview](https://docs.dnsid.ai/sdk-overview).
