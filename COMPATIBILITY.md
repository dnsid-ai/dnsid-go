# Compatibility & Support Baseline

This is the support baseline for the `dnsid-go` SDK: which Go toolchains, dependency versions,
and platforms are tested and supported. It is the source of truth for the version numbers echoed
in `go.mod`, `.github/workflows/test.yml`, and the README. Production runtime behavior, key
rotation, revocation, transport, cache, and error guidance are documented in
[OPERATIONS.md](OPERATIONS.md).

## Supported Go versions

| | Version | Notes |
|---|---|---|
| **Minimum** | Go 1.26.6 | The `go` directive in [`go.mod`](go.mod). Building or `go get`ing with an older toolchain fails. |
| **Maximum** | Latest stable | Go's [compatibility promise](https://go.dev/doc/go1compat) covers newer releases; we test against the current stable line. |

CI tests the exact minimum toolchain and the latest stable Go release. The minimum changes only
when the module adopts a newer language or standard-library requirement.

## CI-validated Go versions

[`.github/workflows/test.yml`](.github/workflows/test.yml) runs the full test suite (root module,
including `log/c2sptlog`, plus the `key/aws` module) on a matrix of:

- **`1.26.6`** — the minimum, pinned to the `go.mod` directive.
- **`stable`** — the latest stable release resolved by `actions/setup-go` at run time.

`oldstable` is deliberately excluded because it predates the 1.26.6 minimum and cannot build the
module.

## Module dependency versions

Supported versions are the ones pinned in the module's `go.mod` files. Go's minimal version
selection means these are the *floors*; patch/minor upgrades within the same major version are
expected to work. Cross a major version (e.g. `jwx/v3` → `v4`) only after it is tested here.

Until the SDK reaches v1.0.0, breaking public API changes increment the minor version. Features
increment the minor version and backward-compatible fixes increment the patch version.

### Unreleased: breaking C2SP logical-identity correction

This SDK targets DNSid C2SP method revision
`d5a65d06f76eff4db81e50f8767a600d2ca7fc2a` of the C2SP TLog log-method specification (`log-method-extensions/c2sp-tlog-log-method.md` in the DNSid specification repository).
`SDKConformance().LogBindings` now includes that method pin. The method name,
envelope `v:1`, bundle `@v1`, and base C2SP dependency pins are unchanged.

- Replace `Chain.PreviousIndex` / `PreviousLeafHash` with `PreviousEventID`.
  Every scope now requires signed binding context and logical predecessor
  metadata. Use bound `Client` preparation/canonicalization, not the unbound
  hash primitives. `PreparedEvent.EventID()` derives identity excluding signatures.
- Deploy corrected readers, writers, monitors, and bundle producers together.
  Do not run old and corrected writers on the same stream. Inventory histories
  and reconcile outstanding exact-byte submissions before cutover.
- Preserve already-conforming streams (including public ISSUANCE-only histories)
  without re-signing. Terminal histories remain terminal. Incompatible histories
  are retained as historical evidence, not rewritten or continued: use fresh
  identity-instance streams for new histories. There is no old-format fallback.
- `ReadEvent` verifies the requested occurrence under historical signer authority,
  even when it is a later copy. Configured migration verifiers can use
  `Client.RebuildHistoryThrough` for exact-cutoff evidence and proofs. Select the
  source's trust configuration independently; untrusted `prev_lr` never grants trust.
- Application helpers no longer automatically enforce `fl=logchk`. Applications
  that require operation-level log checks must call `VerifyLogEvidence` explicitly.
  JWT/OIDC expiration no longer receives clock-skew grace; all JWT algorithms
  require a nonempty `kid`. See [OPERATIONS.md](OPERATIONS.md) for peer inputs,
  explicit duration options, cache namespaces, and resource limits.

CI uses the shared compliance default branch. The checked-in corrected bundle
is copied verbatim from `dnsid-sdk-compliance/fixtures/c2sp-stream-bundle-logical-v1.json`;
regeneration belongs there, not in this SDK. The old bundle remains only a
rejection regression. Shared selection and portable-bundle tests cover the
corrected chains; they do not establish full recursive-migration interoperability.

### Migrating from the standalone `log/c2sptlog` module

Starting with v0.18.0, `log/c2sptlog` is distributed as part of the root
`github.com/dnsid-ai/dnsid-go` module. Its Go import path is unchanged, but existing
consumers must remove the standalone module requirement before upgrading. Otherwise, both modules
provide the same package and Go reports an ambiguous import.

```sh
go mod edit -droprequire=github.com/dnsid-ai/dnsid-go/log/c2sptlog
go get github.com/dnsid-ai/dnsid-go@v0.18.0
go mod tidy
```

The standalone module's v0.17 release remains available for consumers that have not migrated, but
it will not receive releases after the package moves into the root module.

### Migrating custom `LogReader` implementations to v0.17.0+

v0.17.0 replaces `LogReader.VerifyIssuance` with two required methods so issuance
binding and operational-key continuity have separate contracts:

- Implement `VerifyBilateralBinding(ctx, input) (BilateralBinding, error)`. Verify the ISSUANCE
  event's entity and operational signatures and its correspondence with `input.Domain`,
  `input.GovernanceID`, `input.EntityKey`, and `input.OperationalKey`. Return the verified initial
  entity and operational key thumbprints and the ISSUANCE timestamp.
- Implement `VerifyOperationalContinuity(ctx, domain, initialOperationalThumbprint,
  currentOperationalThumbprint) error`. Verify the rotation chain from the ISSUANCE operational
  key to the current operational key.
- Implement the optional `LifecycleBindingVerifier` interface when both checks can be performed
  atomically over one consistent log snapshot. `IdentityManager` prefers this method when present
  and otherwise calls the two required `LogReader` methods separately.

### Migrating custom `KeyProvider` implementations to v0.18.0+

v0.18.0 adds two methods required for safe operational-key rotation:

- Implement `SignKey(kid, payload)` so only the active or a pending key can sign. Retained keys
  must not sign.
- Implement `Supersede(kid)` to remove a retained key after its replacement is active and the
  rotation transaction has completed. Keep `Purge` for explicitly deleting pending or retained
  keys.

### Root module ([`go.mod`](go.mod))

| Dependency | Tested version | Role |
|---|---|---|
| `github.com/lestrrat-go/jwx/v3` | v3.1.1 | JOSE — JWK/JWKS, JWS/JWT signing and verification. Major `v3`. |
| `github.com/forcebit/http-message-signatures-rfc9421-go` | v0.0.20 | RFC 9421 HTTP Message Signatures (Web Bot Auth). |
| `golang.org/x/net` | v0.56.0 | `publicsuffix` and `idna` for FQDN handling. |
| `github.com/transparency-dev/formats` | v0.1.1 | Transparency-log checkpoint formats (`log/c2sptlog` only). |
| `golang.org/x/mod` | v0.38.0 | Module version parsing (`log/c2sptlog` only). |

### `key/aws` submodule ([`key/aws/go.mod`](key/aws/go.mod))

| Dependency | Tested version | Role |
|---|---|---|
| `github.com/aws/aws-sdk-go-v2` | v1.43.0 | AWS SDK v2 core. |
| `github.com/aws/aws-sdk-go-v2/service/kms` | v1.55.0 | KMS-backed key provider. |

## Platform compatibility matrix

The SDK is pure Go with no build tags gating OS/arch, so it builds and runs anywhere the Go
toolchain targets. Tested and support tiers:

| OS / arch | Status | Notes |
|---|---|---|
| linux/amd64 | **Tested in CI** | `ubuntu-latest` GitHub runner. Primary support target. |
| linux/arm64 | Supported | Not in CI; no platform-specific code, expected to work. |
| darwin/amd64, darwin/arm64 | Supported | Primary development platform (arm64). |
| windows/amd64 | Supported | No platform-specific code; DNS/system-resolver behavior differs (see below). |
| wasm, other GOOS/GOARCH | Not supported | Untested; the OS stub-resolver dependency (below) makes `js/wasm` in particular unreliable. |

CI currently exercises **linux/amd64 only**. Other rows are "supported" by construction (no
platform-specific code), not by continuous testing.

File-backed `LocalKeyProvider` writes additionally require working file and parent-directory
`os.File.Sync` support. Filesystems/platforms that reject directory sync (including Windows)
return `ErrKeyStoreDurability` after publication rather than acknowledging durable storage.
Use a suitable external key provider on those platforms; in-memory keys and verification
are unaffected. See [local key-store operations](OPERATIONS.md#local-key-store-durability-and-ownership).

## Enterprise deployment notes

### cgo

No cgo is required. The SDK builds with `CGO_ENABLED=0` and produces static binaries. One caveat:
the default DNS resolver uses the OS stub resolver via `net.Resolver`, whose behavior depends on
Go's netgo/netcgo resolver selection (see DNSSEC below). Set `GODEBUG=netdns=go` for deterministic
pure-Go resolution across platforms.

### DNSSEC

The built-in resolver (`net.Resolver`) performs **no DNSSEC validation** and always reports
`DNSSECStateUnknown` — the Go standard library does not expose the AD/CD bits, so an in-transit
DNSSEC failure is invisible. The default `DNSSECModeAuto` accepts `VALID`, `UNSIGNED`, and `UNKNOWN`
but rejects `FAILED`. `DNSSECModeValidated` additionally rejects `UNKNOWN`, while
`DNSSECModeRequired` accepts only `VALID`. Integrators using either stricter mode **must** supply a
DNSSEC-aware `DNSResolver` via `WithDNSResolver` — e.g.
one backed by `miekg/dns` against a trusted validating server, or a local `unbound`. This is a
protocol/deployment requirement, not a per-platform one, but the resolver you plug in may carry its
own platform constraints.

### FIPS

The SDK uses `crypto/*` from the standard library and does not bundle its own crypto. For
FIPS 140-3 validated operation, build with the Go native FIPS mode (`GOFIPS140=v1.0.0` /
`GODEBUG=fips140=on`, Go 1.24+) or a FIPS-certified toolchain. Cryptographic algorithm choices for
DNSid JWTs/JWS are governed by the protocol profile, not by this SDK's build configuration.
