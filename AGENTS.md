# Repository Guidelines

## Project Structure & Module Organization

This repository is the Go module `github.com/dnsid-ai/dnsid-go`. Core SDK code lives at the repository root in package `dnsid` and is centered on `IdentityManager`, TXT record parsing/creation/validation, JWKS/JWK wrappers, key providers, safe HTTP/DNS transport, verified-domain caching, and public error types. Application profiles live in `jose/` for JWT/JWS helpers, `httpsig/` for RFC 9421 HTTP Message Signatures, `oidc/` for OIDC federation, and `webbotauth/` for Web Bot Auth. Lifecycle-log abstractions live in `log/`; implementation-only crypto, JOSE, and network guard helpers live under `internal/`. Shared protocol fixtures live in `testdata/`, including ES256 vectors. Release notes are generated into `CHANGELOG.md` using `cliff.toml`.

## Build, Test, and Development Commands

- `go test ./...`: run the default SDK and profile package test suites.
- `go test -race ./...`: run tests with the race detector before concurrency-sensitive changes.
- `go test -run TestName ./path`: run a focused test, for example `go test -run TestParseTXTRecord_UnsupportedVersionIsParseError .`.
- `go build ./...`: compile all packages.

Use Go 1.26.6 or newer. `mise.toml` selects the current Go 1.26 patch release.

## Coding Style & Naming Conventions

Format Go code with `gofmt`; do not hand-align or introduce non-standard formatting. Package names are lowercase and short. Exported identifiers use Go-style `CamelCase`; unexported helpers use `camelCase`. Keep security-sensitive helpers explicit and narrowly scoped, especially around DNS, JWKS/JWK, JOSE/JWT/JWS, HTTP signatures, SSRF-safe HTTP, TXT canonicalization, and signature validation paths. Preserve the package dependency direction: root `dnsid` must not depend on the application profile packages. Prefer small table-driven tests and `t.Helper()` fixtures where setup is reused.

## Testing Guidelines

Tests use the standard Go `testing` package. Name tests `TestTypeOrFunction_Behavior` when possible, matching existing patterns such as `TestParseTXTRecord_UnsupportedVersionIsParseError`, `TestSafeDialerRejectsUnsafeResolvedIPWithoutDialing`, and `TestIdentityManagerPublishClientControlledRecordRejectsRegistryAuthority`. Keep deterministic fixtures in `testdata/`; generated per-test files should use `t.TempDir()`. There are currently no checked-in `integration` build-tagged tests, so do not add live DNS/HTTPS dependencies to the default suite without isolating them behind an explicit build tag or test hook.

## Commit & Pull Request Guidelines

Recent history uses concise, conventional-style prefixes such as `feat:`, `fix:`, `chore:`, `test:`, and `docs:`. Squash or merge commits should include the PR number when applicable, for example `feat: ES256 signing and verification (#35)`. Pull requests should describe behavior changes, call out protocol or security implications, link related issues, and include the exact `go test` commands run. Update `testdata/` or `CHANGELOG.md` inputs when changing wire formats, public APIs, vectors, or release-visible behavior.
