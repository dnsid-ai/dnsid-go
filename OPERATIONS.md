# DNSid Go SDK operations guide

This guide documents the production behavior of `github.com/dnsid-ai/dnsid-go` as implemented today. It is operator guidance, not a new protocol contract.

## Compatibility and API versioning

- The SDK publishes new `_dnsid` records with `v=dnsid-draft-01` and verifies both `v=dnsid-draft-01` and the pre-RFC `v=DNSid1` selector. Unknown, dated, or future TXT record selectors fail verification.
- Registry control-plane calls use `/api/v1/...` paths. Both registry constructors accept HTTPS or HTTP on loopback (the local default); non-loopback HTTP requires `WithInsecureHTTP` through `NewRegistryClientWithOptions` and is intended only for testing.
- Go, platform, dependency, DNSSEC, and FIPS support are defined in [COMPATIBILITY.md](COMPATIBILITY.md). Until the module reaches v1.0.0, breaking public API changes increment the minor version.

## HTTP transport, timeouts, redirects, and retries

Core verification (`IdentityManager.VerifyDomain`) performs HTTPS JSON fetches for entity JWKS (`ek=`), operational JWKS (`ku=`), and status (`su=`):

- SDK-managed HTTP clients use a rebinding-resistant transport: the hostname is resolved once, every returned address is checked, and the dial uses a validated concrete IP. By default, loopback and private addresses are rejected; `Config.Transport.PrivateAddressHosts` explicitly permits loopback or private-use addresses for named hosts or suffixes (for example, `.test`). Link-local, multicast, reserved, and mixed public/private resolutions remain rejected; IP-literal URLs are never exempted.
- The safe transport preserves settings from a supplied `*http.Transport`, including TLS settings and dial/handshake/idle knobs. Wrapped custom `RoundTripper` values cannot be cloned into the safe transport and are replaced with a new safe transport with a warning to stderr.
- The safe dialer has a 10 second TCP dial timeout. Core, application-profile, and C2SP identity verification share the caller's context deadline; when absent, `dnsid.DefaultVerificationTimeout` supplies a **30 second overall budget**. Child DNS/HTTPS requests, redirects, JWT retries, signature candidates, and recursive migration checks do not restart that budget. Coalesced work has a finite 30 second ceiling, preserves each waiter's cancellation/deadline, and is canceled when all waiters leave. Per-resource HTTP timeouts can shorten, not extend, the invocation budget.
- Every SDK network operation creates requests with the caller's context. Context cancellation and deadlines abort DNS lookup, connect, TLS handshake, response read, registry polling, C2SP log scans, and OIDC HTTP calls where those paths use SDK request helpers.
- `c2sptlog.NewVerificationRegistry` rejects arbitrary `RoundTripper` implementations and accepts a custom `BoundedResourceFetcher` only when it explicitly declares all required public-read guarantees. Private, loopback, proxying, or otherwise caller-owned transports remain available through lower-level `ParsePolicy`, `NewScanSource`, and `Register` composition.
- Redirects are denied by default. JWKS fetches may follow HTTPS redirects that stay on the allowed host. Status fetches may follow HTTPS redirects, still using the safe dialer. Redirect targets with non-HTTPS schemes or userinfo are rejected.
- Verification does not automatically retry failed DNS, JWKS, status, or log reads. Callers choose retry policy from the returned error type and `Transient()` flag. Registry prepared-event APIs expose `RegistryAPIError.RetrySameEntry()` and require retrying the exact same bytes and idempotency key for indeterminate submission states.
- JSON response sizes are bounded: JWKS and registry responses are limited to 1 MiB, status responses to 64 KiB, and C2SP scan resources to their configured scan limits.

Example verification client with a hard request budget (set `DNSID_LOG_TRUST_PROFILE_FILE` to an independently trusted profile first):

```go
ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
defer cancel()
client := &http.Client{Timeout: 10 * time.Second}
manager, err := config.IdentityManagerFromEnvironment(ctx, nil, dnsid.Config{}, config.Dependencies{HTTPClient: client})
if err != nil {
	return err
}
_, err = manager.VerifyDomain(ctx, "agent.example.com")
```

## DNS lookup, DNSSEC, and cache behavior

- The built-in resolver uses Go's `net.Resolver` / OS stub resolver for `_dnsid.<domain>` TXT lookups. Go does not expose DNSSEC AD/CD validation bits, so the built-in resolver always reports `DNSSECStateUnknown`.
- `DNSSECModeAuto` accepts `VALID`, `UNSIGNED`, and `UNKNOWN` and rejects `FAILED`. `DNSSECModeValidated` rejects `UNKNOWN`; `DNSSECModeRequired` accepts only `VALID`. Use `WithDNSResolver` for a resolver backed by a validating resolver such as local `unbound` when strict DNSSEC state is required.
- `Config.Transport.DNSServer` routes TXT lookups and safe-transport hostname resolution through the named DNS server, but it still uses the standard-library resolver path and does not provide DNSSEC validation.
- The built-in TXT resolver records a 5 minute TTL because `net.Resolver.LookupTXT` does not return authoritative TTLs. A custom `DNSResolver` can return real TTL metadata.
- `IdentityCache` retains at most 1024 results, with separate namespaces for every manager, including when sharing an injected backend. Cache expiry is the minimum of **DNS lookup start + returned TTL**, the `ka=` deadline, and runtime/entity TLS expiry. Verification completion and status refresh never extend DNS lifetime. Bounds are rechecked before every successful return; expiration during a status refresh fails rather than reinserting stale evidence. The legacy `NewIdentityCache(defaultTTL)` argument is ignored; unbounded or expired results are not stored.
- A returned zero DNS TTL permits only the acquiring verification operation; the next call must resolve again. There is no fallback TTL for zero. TLS validity and key age still apply to that operation. Cached custom resolvers must report remaining TTLs, never return an expired answer as a newly acquired zero-TTL answer.
- Manager policy and injected resolver, HTTPS, and log-trust configuration must remain immutable while in use. For a policy/trust change, construct a new manager (and new immutable injected infrastructure); its namespace cannot be populated by the old manager's in-flight work. Do not mutate a shared `LogRegistry` or transport's trust settings in place.
- There is no negative caching for failed DNS lookups, invalid records, JWKS failures, inactive status, or log failures.
- On a cache hit, `Config.Verification.StatusCheckInterval` controls whether the status endpoint is rechecked. The zero value means every cache hit rechecks `su=`; a positive interval serves the cached status until the interval elapses. Future-dated `lastTransitionAt` values are rejected, but old values are valid because they describe state transitions rather than response freshness.
- Use `IdentityManager.EvictDomain(domain)` to force full re-verification on the next call. The JOSE verifier also evicts and retries once, throttled to once every 30 seconds per issuer, after a JWT signature failure that may be caused by stale JWKS cache during key rotation.

For revocation demos or sensitive authorization gates, keep `StatusCheckInterval` at zero and give each verification call a deadline. That makes every cache hit re-read `su=` so a `REVOKED` status is observed as soon as the status endpoint changes.

## Counterparty acceptance

- `Config.Verification.TrustedEntities` is a verifier-local allowlist applied by `VerifyDomain` after all protocol checks, on every invocation including cache hits. Entries match the verified record's `gi=` exactly after FQDN normalization; there are no wildcard, suffix, or transitive matches. `nil` makes no acceptance decision; an empty non-nil slice denies every counterparty.
- `TrustedEntity.EntityKeyThumbprints` optionally pins the current record-signing (`ek`) key by RFC 7638 SHA-256 thumbprint. Pins never expand automatically on rotation; enroll a replacement pin through an authenticated operator channel and construct a new manager.
- Denials are permanent `VerificationCodeCounterpartyNotAccepted` errors (`errors.Is(err, dnsid.ErrCounterpartyNotAccepted)`) exposing the observed `VerifiedGovernanceID()` and `VerifiedEntityKeyThumbprint()`. Messages never echo the configured allowlist or pins.
- Verified protocol evidence is cached before acceptance runs; a denial is never cached and does not invalidate the evidence. Profile verifiers (JOSE, HTTP signatures, OIDC subject verification) inherit the policy through their `IdentityResolver`. Registry publication confirmation checks protocol evidence only and does not consult the allowlist, so a publisher need not allowlist itself.

## Application evidence and resource bounds

- Verification-only JWT callers supply `jose.VerifyJWTOptions.ExpectedAudience`; no local identity is needed. Do not derive this expected value from the token or an untrusted request.
- JWT and OIDC verification take current-peer inputs through their options' `Peer` field (`dnsid.VerifyDomainOpts`); `VerifyJWS` takes an optional `VerifyDomainOpts`. HTTP verification uses `req.TLS.VerifiedChains`. These are **already authenticated application-peer chains**, not JWKS endpoint certificates. Missing/wrong evidence fails `fl=mtls`, including cache hits. Custom resolvers should implement `VerifyDomainWithOptions`; the fallback resolver route still enforces current-peer matching.
- Compact JOSE/OIDC input is capped at 1 MiB, decoded protected headers at 16 KiB, and decoded payloads at 768 KiB. Duplicate JSON members, invalid UTF-8, nesting beyond 64 levels, noncanonical base64url, critical headers, and unencoded payloads are rejected before discovery.
- HTTP verification caps combined fields at 1 MiB, each combined signature header at 16 KiB, the request-target inputs at 64 KiB, and buffered body bytes at 8 MiB. The installed structured-field parser enforces 128 labels, 128 components, and 64 parameters. Oversized input rejects the whole invocation; candidates are never silently truncated. Body bytes within the limit are replayed unchanged.
- C2SP entries remain capped at 65,535 bytes; default bundles are 8 MiB/10,000 entries. Raw scans default to one million entries and 256 MiB aggregate entry bytes, and binding-level candidate input is also bounded before allocation. Copies consume those limits. Prefer/require bundles or lower scanner limits for predictable cost; required bundles still permit bounded `ReadEvent` discovery, not evidence fallback.
- Injected resolvers, fetchers, and log sources are trusted infrastructure: they must honor context cancellation and their response/allocation limits. Key-provider operations must have their own finite execution bounds; the synchronous signing interface cannot interrupt a blocked provider. The SDK cannot interrupt a custom implementation that ignores cancellation. HTTP hosts must also set read deadlines (including request-body reads); standalone custom body readers must be finite and interruptible. SDK byte limits are not a replacement for transport read deadlines.

## OIDC token exchange helper

The OIDC profile includes the token-exchange helper needed by demo and production agents:

- `oidc.Profile.CreateOIDCAssertion` signs a JWT-bearer assertion with the active operational key. The default assertion lifetime is 5 minutes and the default maximum is 15 minutes.
- `oidc.Profile.ExchangeOIDCToken` discovers the issuer, validates same-origin discovery endpoints, optionally mints the assertion, and performs the OAuth 2.0 JWT-bearer grant against the token endpoint.
- `oidc.Profile.GetOIDCToken` always mints a fresh assertion and exchanges it.
- OIDC HTTP calls use the caller's context, reject redirects, cap responses at 1 MiB, require HTTPS issuers by default, and allow HTTP only for loopback issuers when `AllowHTTPLoopbackIssuer` is set.

## Local key-store durability and ownership

- Use **one writing `LocalKeyProvider` instance per key file**, even within one process. Reuse that instance across goroutines. There is no cross-instance/process file locking; independent writers can overwrite each other's pending and retained keys. Serialize initial creation too: `O_EXCL` prevents clobbering an existing file, but another reader can observe an incomplete initial write.
- Initial creation syncs the key file before closing it, then syncs the parent directory. Updates write a same-directory temporary file with mode `0600`, sync and close it, rename it over the destination, then sync the parent directory. Provision the parent directory durably before use. Durability depends on the OS, filesystem and storage honoring sync; unsupported directory sync is an error, not silently ignored.
- Errors before update publication restore the previous in-memory state. `errors.Is(err, dnsid.ErrKeyStoreDurability)` instead means the new file is already visible but directory sync failed: mutations remain applied in memory. `GenerateKey` returns the new pending kid **and an error** in this case; do not publish or advance a rotation workflow on that error. Initial creation leaves the file in place and returns no provider.
- After a durability error, stop the workflow and resolve the storage problem. Inspect the current keys (reload first if creation failed or the process restarted), then call `Activate` with the **currently active kid** to re-persist the entire store without changing key states. Require success before resuming. Merely loading the file is not a durability retry; blindly repeating `GenerateKey` creates a different pending key, and repeating a completed `Purge` reports an unknown key. Reconcile any pending rotation state before proceeding.
- Keep access-controlled, encrypted backups of local private keys and test recovery. The platform database cannot reconstruct locally generated private keys. Sync is not a backup and does not protect against storage loss, deletion, or competing writers.

## Key rotation, JWT overlap, and revocation

DNSid separates accountable-entity record-signing keys (`ek=`) from operational runtime keys (`ku=`). Verification rejects records where the two keys share the same RFC 7638 JWK thumbprint.

Operational-key rotation behavior:

1. Generate a pending key with `KeyProvider.GenerateKey`.
2. Publish/record the `KEY_ROTATION` lifecycle evidence that links the previous operational key to the new key.
3. Activate the pending key with `KeyProvider.Activate`. The old active key becomes retained.
4. Publish the new `ku=` JWKS and TXT/status/log state through the registry or the caller's own publishing path.
5. Keep the old key retained until all JWTs and signed requests that could have been created with it have expired and verifier caches have had time to refresh.
6. Remove the old retained key with `Supersede` after the overlap window, or `Purge` a pending/retained key that should not remain.

Important overlap rules:

- `GetKeySet` and `GetEntityKeySet` publish only the current active key for draft 01 live endpoints. Retained keys are local verification/signing history in the key provider; they are not automatically exposed in live `ku=` JWKS.
- `Sign` uses the active key. `SignKey` can sign with an active or pending key and refuses retained keys.
- JWT creation defaults to 15 minutes. Verification allows 60 seconds of skew for `iat`/`nbf`, **never for expiration**, and rejects tokens whose lifetime exceeds `Config.MaxLifetime`. JWT/OIDC dates accept finite fractional JSON numbers, not coerced strings/booleans. Expiration is checked again after discovery. Use `Config{}.WithClockSkew(0)` for explicit zero tolerance and options' `WithExpiry` for explicit lifetime presence; zero/negative explicit lifetimes fail. Zero-valued duration struct fields mean omitted for Go compatibility.
- A JWT signed by an old key remains verifiable only while the verifier can obtain a JWKS that still contains that signing key, or until the token expires. Because draft 01 live `ku=` endpoints expose a single current key, operators should avoid rotating the live key before existing JWTs have expired unless clients can tolerate immediate invalidation.
- Recommended retained-key cleanup window: at least `max JWT lifetime + clock skew + maximum verifier cache lifetime/status interval` after the last possible signature with the old key. If you use the defaults and the manager default cache, that is at least `15m + 1m + 5m = 21m`; choose a larger window for slower DNS/TLS/cache rollout or longer configured JWT lifetimes.
- Counterparties caching the previous `ku` can reject new-key signatures until their evidence expires or is evicted. Measure that window and plan rotation around it; do not publish overlapping live keys or skip continuity verification.
- Recommended rotation interval is deployment policy, not hard-coded by the SDK. Use `ka=24h`, `7d`, `30d`, or `90d` when verifiers should enforce a maximum operational-key age from lifecycle-log evidence. Align the operational runbook so keys rotate before the selected `ka=` age expires.

Revocation behavior:

- Core verification succeeds only when `su=` returns `ACTIVE`. `PENDING`, `PROVISIONING`, `VERIFYING`, `RETIRED`, and `REVOKED` fail with `VerificationCodeStatusNotActive`; a revoked status also carries the returned revocation reason when present.
- Cached verified domains can continue to be returned until their status is rechecked. Set `StatusCheckInterval` to zero for immediate status rechecks, or call `EvictDomain` after an out-of-band revocation signal.
- `fl=logchk` is **caller-owned policy**. Core, JOSE, OIDC, and HTTP-signature verification expose `VerifiedDomain.RequiresLogCheck()` without automatically fetching operation-level evidence. Applications requiring that check call `VerifiedDomain.VerifyLogEvidence` (or `IdentityManager.VerifyLogEvidence`) at their authorization boundary and must reject its failures. Mandatory lifecycle identity binding and key continuity remain part of core verification.
- C2SP lifecycle-log non-revocation checks require a complete history source and a positive checkpoint-freshness policy. A selected-stream source that cannot prove absence of later revocation is not enough for non-revocation evidence.
- Existing JWTs are not individually recalled by the SDK. Revocation is enforced when the verifier checks the issuer's DNSid identity/status/log evidence; token verifiers should use short JWT lifetimes and force or schedule status rechecks for high-risk operations.

## Checkpoint continuity and recovery

Checkpoint rollback or inconsistent roots do not establish whether a recovery or
an attack occurred. Required continuity checks fail closed; do not clear the
checkpoint store or restart with an empty store to bypass them. Default in-memory
stores retain trust only while that store instance survives; inject durable
storage for protection across restarts.

Use `errors.As` to inspect `*c2sptlog.CheckpointAdvanceError`: `Kind` distinguishes
rollback, equal-size root conflict, failed consistency evidence and unavailable
consistency capability. The error includes the origin and both sizes/roots;
`SplitView` means an observed equal-size conflict, not proven malice. These
failures are non-transient. Fetch and storage failures retain their own causes;
outer verification wrappers can still classify them conservatively.

See [Checkpoint continuity and authorized recovery](CHECKPOINT_RECOVERY.md) for
the independently authorized exact-checkpoint replacement procedure using the
existing store CAS interface. There is no automatic reset or new reset API.

## Goroutine-safety, reuse, and resource lifecycle

- `IdentityManager`, `IdentityCache`, `LocalKeyProvider`, JOSE `Profile`, and the in-memory C2SP checkpoint store are safe for concurrent use by ordinary callers. They are intended to be reused rather than recreated per request.
- `VerifiedDomain`, `TXTRecord`, `JWKS`, and `JWK` accessors return copies where mutation could otherwise affect cached state.
- Custom `DNSResolver`, `HTTPSFetcher`, `KeyProvider`, `LogReader`, C2SP `Source`/`Appender`, and custom HTTP transports must provide their own concurrency guarantees.
- SDK-managed HTTP clients own their transports. Long-running services should reuse managers/clients so idle connections are reused. If a service creates a short-lived custom client with a custom transport, it owns calling `CloseIdleConnections` on that transport when shutting it down.
- The SDK does not start background goroutines for verification caching. Registry `WaitForStatus` polls synchronously until the target status, a terminal status, or context cancellation.

## Logging and observability

The core SDK does not use a structured logger and has no logger hook, logger name, log level, or log-disable option. It reports operational detail through returned typed errors. The only SDK-managed diagnostic write in the default transport path is a warning to stderr when a non-`*http.Transport` custom round tripper cannot be preserved safely.

Applications should log errors at their own boundaries. For verification failures, prefer `errors.As` to extract `*dnsid.VerificationError` and log its code, transient flag, agent state, and wrapped cause.

## Error reference

| Failure | Typical error type/code | Retry guidance |
|---|---|---|
| DNS lookup failure | `*VerificationError`, `dns_resolution`, transient | Retry according to caller policy; no SDK auto-retry. |
| DNSSEC validation failure or strict mode with unknown state | `*VerificationError`, `dnssec_failed`, permanent | Fix resolver/DNSSEC configuration or DNS zone state. |
| Missing, malformed, duplicated, or semantically invalid TXT record | `*VerificationError`, `record_invalid`, permanent | Fix publication. |
| Malformed JWKS/JWT/TXT input | `*ParseError` or `*VerificationError` with `malformed_token` / `record_invalid`, permanent | Fix input or publisher. |
| TLS policy/certificate failure, including expired cert | `*VerificationError`, `tls_error`, permanent | Fix certificate chain, hostname, trust roots, or URL policy. |
| JWKS/status/log transport failure | `*VerificationError`, `jwks_unavailable`, `status_unavailable`, or `log_error`; transient flag classifies retryability | Retry transient errors; fix publisher/service for permanent errors. |
| Invalid record or JWT signature | `*VerificationError`, `signature_invalid`, permanent; JOSE may evict cache and retry once after JWT signature failure | Verify key publication, token issuer, and rotation timing. |
| JWT expired/not yet valid/too long/wrong claims | `token_expired`, `token_not_yet_valid`, `lifetime_too_long`, `audience_mismatch`, `issuer_mismatch`, or `invalid_claims` | Usually permanent for that token. |
| Revoked, retired, pending, or otherwise inactive identity | `*VerificationError`, `status_not_active`, permanent for current status | Do not authorize the identity; retry only after an expected lifecycle transition. |
| Key age exceeded | `*VerificationError`, `key_age_exceeded`, permanent until rotation is published | Rotate the operational key and publish lifecycle evidence. |
| Registry HTTP/API failure | `*RegistryAPIError` | Use `RetrySameEntry`, `SubmissionState`, and `Transient` for prepared-event recovery. |

## Proxy and TLS options

- SDK-managed safe transports set `Transport.Proxy = nil`; they do not honor `HTTP_PROXY`, `HTTPS_PROXY`, `NO_PROXY`, SOCKS proxies, or authenticated proxy settings from the Go default transport. This is intentional because proxying would bypass the SDK's destination-IP validation. If a deployment must use a proxy, supply a custom `HTTPSFetcher`, custom registry HTTP client, or C2SP scan `Transport` and own the SSRF/rebinding threat model.
- `Config.Transport.CABundlePath` appends PEM certificates to the system trust pool for SDK-managed HTTPS verification. `WithHTTPClient` can carry a custom `TLSClientConfig`, including custom roots or client certificates, as long as its transport is a `*http.Transport` that can be cloned into the safe transport.
- The SDK does not provide first-class certificate pinning APIs. Implement pinning in a caller-supplied `HTTPSFetcher` or carefully configured custom transport.
- The SDK uses Go standard-library cryptography and supports Go's native FIPS mode as described in [COMPATIBILITY.md](COMPATIBILITY.md). It does not include its own FIPS module or cloud-provider HSM integration in the root package.
- AWS KMS support lives in the optional `key/aws` module. Other KMS/HSM providers should implement `KeyProvider`; concurrency, signing latency, key retention, and audit behavior are provider responsibilities.
