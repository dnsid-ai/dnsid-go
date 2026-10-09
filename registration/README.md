# Managed registration

```go
loaded, err := config.LoadDeploymentFile("deployment.json")
if err != nil {
    return err
}
result, err := registration.RegisterManagedIdentity(ctx, "billing-agent",
    loaded, organizationCredential,
    registration.NewFileRegistrationStore("/private/dnsid-state"), nil)
```

The SDK creates or resumes one named managed identity, obtains registry-owned
issuance/publication, and returns only after fresh public ACTIVE and trusted
lifecycle verification. It does not perform client-controlled or Live setup.

## Configuration

Use the [configuration package](../config/README.md) for transport, log trust,
application acceptance policy, and optional existing cloud keys. Managed setup
adds independently configured account/bootstrap expectations:

```json
{
  "logTrust": { "managed": true },
  "registry": { "registryUrl": "https://registry.example" },
  "registration": {
    "organizationId": "your-internal-account-id",
    "governanceId": "acme.example",
    "entityKeyUrl": "https://dnsid.acme.example/.well-known/dnsid-ek.json"
  }
}
```

Omitted account ID/GI requires authenticated onboarding with verified governance
proof, authorized gate, and verified entity delegation. Configured/saved bindings
must match; the entity JWKS URL is always independently configured. Expectations
do not route allocation: pass selectors explicitly through `AgentRegistrationInput`.
Omitted input sends only name/public key. Names are trimmed, case-sensitive, and
limited to 255 Unicode code points; supplied `input.Name` must match.

Default file keys are development-only. Explicit file generation requires a
stable `keySource.generation.locator` and EdDSA/ES256 `algorithm`. Cloud generation
without atomic replica convergence is rejected; use an existing immutable key
reference. Replicas need the same original key through shared storage or cloud
reference. Injected providers/log trust require stable `Options.ProviderReference`
and `Options.TrustReference`; managed setup never loads entity private keys.

## Required server contract

Verify real persistence/integration support before enabling automatic recovery.
SDK mocks and acknowledgment flags do not establish hosted compatibility.
The server must atomically bind normalized name, original key, complete request,
and immutable identity within the authenticated organization; validate derived
keys; retain replay/tombstones permanently; and let matching callers recover one
creation/ISSUANCE without losing allocations. Wrong-account/conflicting requests
fail before disclosure/allocation. Retirement/deletion never permits an old replay
to allocate again. Replacement requires confirmed terminal history, a fresh key,
preserved previous replays, and a new identity/domain/log stream. A 24-hour cache
is insufficient. These SDK changes do not implement that server work.

## Recovery

Keep the whole owner-only store, including private-key files. Operations and
locks use a digest of registry/account/name, never raw names. Use a local
filesystem with POSIX permissions, atomic rename, and file/directory fsync.
Rerun with the same operation; never replace a key or register again to recover
an unknown outcome. After a crash, clear an operation's `.lock` only after
confirming no process uses it. Other callers receive `BusyError`.

Schema 3 rejects unnamed schemas 1/2 without changing data. Recover those with
the original SDK. Replay keys derive from JCS string arrays and the retained
initial RFC 7638 thumbprint, not clocks or rotated keys. Unknown creation retains
exact input; validated identity retains publication/OIDC facts and an input
fingerprint, then discards creation extras. Conflicting explicit input still fails.

Unresolved issuance retains exact preparation/completed bytes. Accepted bytes
are compacted only after public verification and trusted inclusion of the accepted
hash/reference. Resume retrieves that historical entry; missing/conflicting history
never permits reissuance. Injected readers must implement verified `ReadEntry`.
Completed resume reads current signed `ku` and verifies authorized continuity;
old private keys and old-URL fallbacks are unnecessary. Pending rotation uses its
existing coordinator; configuration changes alone are not rotation. Terminal
identities fail. Explicit fresh-state/key replacement must preserve previous history.

The total budget defaults to ten minutes; cancellation or `Options.Timeout`
shortens it. Only classified transient failures retry within that budget. Errors
retain phase, immutable identity, status, resumability, and structured cause
without printing credentials/private material. Setup verification is isolated and
credential-free; the returned manager retains the application's acceptance policy,
including when it verifies its own domain. Registry READY alone is insufficient.
