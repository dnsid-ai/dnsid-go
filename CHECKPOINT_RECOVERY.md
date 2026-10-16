# Checkpoint continuity and authorized recovery

Design record for [#315](https://github.com/dnsid-ai/dnsid-go/issues/315).
This records the Go project's intended contract and shared vocabulary for the other
SDKs to adopt; it does not claim cross-repository approval or implementation.
Go typed diagnostics and CAS-contract tests implement [#316](https://github.com/dnsid-ai/dnsid-go/issues/316).

## Decision

A checkpoint failure describes an observation, **not its cause**. A rollback can
be a stale replica, replay, recovery, or attack. Equal-size conflicting roots are
an equivocation signal, but do not identify who caused it. A database restore
need not roll back the transparency log at all.

All continuity failures remain fail-closed. Neither an error kind, a retry, a
process restart, nor an announced recovery authorizes discarding trusted history.
An authorized re-baseline explicitly accepts a break in continuity; it does not
prove that the recovered history is an extension of the old history.

## Diagnostic contract for SDK implementations

Use these stable kind values, mapped to each language's existing error idiom:

| Kind | Observation | Response |
|---|---|---|
| `rollback` | Candidate size is smaller than the trusted size. | Retain trust; investigate with operations and security. Do not infer legitimate recovery. |
| `root_conflict` | Equal sizes have different roots. | Retain trust; escalate as potential equivocation. |
| `consistency_failed` | A supplied consistency proof fails, or a complete scan reproduces the candidate root but contradicts the trusted prefix. | `LOG_INCONSISTENT`; retain trust and investigate. This alone does not prove a fork. |
| `consistency_unavailable` | The source cannot supply consistency evidence, including required-bundle mode without a proof source. | Non-transient missing evidence; retain trust and fix source configuration. This is not evidence of equivocation. |

A network/source fetch error is not `consistency_failed`. Preserve its original
cause, including cancellation and resource-fetch classification. Store load/CAS
errors likewise remain storage failures. No automatic trust reset follows any of
these failures. Unknown kinds must not be treated as permission to continue.

Go provides `CheckpointAdvanceError` with `Kind`, `Origin`,
`OldTreeSize`, `NewTreeSize`, `OldRootHash`, `NewRootHash`, and `Cause`, with
`Error()` and `Unwrap()`. Copy both root byte slices when constructing the error;
error consumers must not be able to mutate checkpoint-store state through them.
Other SDKs should carry equivalent information without requiring message parsing.

The Go `SplitView` boolean is set only for `root_conflict`:
it means **observed equal-size root conflict**, not a proven malicious split view.
`false` is never a claim that recovery is legitimate or that the failure is safe.
Do not infer automatic retryability from this boolean. The four typed conditions
are non-transient verification failures; retrieval errors retain their underlying
classification through public verification wrappers.

Public reader and bundle errors expose `VerificationCodeLogRollback` (`LOG_ROLLBACK`),
`VerificationCodeLogFork` (`LOG_FORK`), and `VerificationCodeLogInconsistent`
(`LOG_INCONSISTENT`). `errors.As` also reaches `CheckpointAdvanceError` and its
copied diagnostics. A missing candidate leaf, invalid occurrence index, or scan
that cannot reproduce the candidate root is `INVALID_EVIDENCE`, not a continuity
contradiction. Invalid accepted checkpoints are fatal even in global candidate scans;
invalid per-entry inclusion candidates can still be omitted.

Store failures expose `VerificationCodeCheckpointStore` (`CHECKPOINT_STORE_ERROR`),
always non-transient even when the storage dependency reports itself retryable.
Fetch failures keep their own retry classification and causes. No supplied invalid
consistency proof or failed consistency retrieval permits a raw-scan fallback. `ErrConsistencyUnavailable`
lets optional sources report missing evidence without message matching.

## Re-baseline contract

**Keep `TrustedC2spCheckpointStore` unchanged. Do not add `Reset` to the required
interface and do not delete trust to return to trust-on-first-use.** Prefer an
explicit replacement checkpoint, installed by an authorized administrative path,
never by ordinary verification.

The existing Go memory store permits an exact-state replacement using
`CompareAndSwap(origin, expected, replacement)`; it does not enforce monotonicity
itself. The verifier enforces continuity before invoking CAS. A durable store may
intentionally reject a downgrade: do not bypass that policy or assume that every
injected implementation supports administrative replacement. Such deployments
must supply their own authorized replacement transaction or provision a new,
explicitly seeded store namespace and switch consumers to it while stopped.
Do not overwrite the original namespace merely to silence the alarm.

Administrative procedure:

1. Stop and drain verification and lifecycle workflows for the affected origin
   across **all processes sharing the store**. Fence writers that cannot be
   drained. An origin can cover many identity streams, not just one domain.
2. Archive the previous trusted checkpoint, observed signed checkpoint notes,
   witness evidence, failed proof/scan evidence, and relevant incident logs.
   The store's size/root/time tuple alone is not a signed evidence archive.
3. Obtain independently authenticated authorization from the deployment's
   designated recovery authority. Record the approver, incident identifier,
   exact origin, expected old checkpoint, exact replacement size/root/witnessed
   time, trust policy and witness requirements, authorization time, and reason for
   the continuity break. Retain the authorization and incident/evidence reference
   before replacement. An audit-field argument does not authenticate an operator;
   an unsigned status page or claim returned by the failing log is insufficient.
4. Verify the replacement's log signature, configured witness quorum, origin and
   freshness under independently trusted policy. Bind it to the exact checkpoint
   authorized in step 3. Ordinary valid signatures do not authorize a rollback.
   Do not weaken policy to make the replacement pass; key/policy changes require
   their own authorization. Check the recovered lifecycle state separately:
   replacing checkpoint trust cannot repair lost issuance, rotation or revocation.
5. Load the current stored tuple and compare it with the archived, authorized old
   tuple, including witness time. Only then attempt one exact-state CAS to the
   authorized replacement, including its verified witness time. An error or
   `false, nil` stops recovery: reload and re-investigate, **not** an automatic
   reload/retry loop that authorizes overwriting a different state. Require durable
   commit acknowledgment and read back the replacement before proceeding. On an
   indeterminate storage error, reconcile storage before resuming workflows.
   Append the reconciled outcome and replacement time to the retained audit record
   linking both tuples, authorization, and evidence references.
6. Rebuild affected managers, registries and log readers against the selected
   store and policy; discard old cached verification results and retained verified
   objects. Complete fresh identity/lifecycle verification before resuming service.
   Preserve the audit archive and monitor the new history for continuity failures.

This is a privileged storage operation, not a public verification endpoint or a
new recovery-token protocol. Go supports this documented CAS idiom rather than
adding an SDK reset method. Tests cover exact-state replacement and rejection
of stale expected state, without adding a reset path to verification.

## Recovery signaling and persistence

Use the deployment's independently authenticated, out-of-band incident channel
and approval process for now. A signed operator recovery statement is deferred:
its signer authority, distribution, revocation, replay protection, validity window,
and exact checkpoint binding need a separate server/client protocol decision.
A server restore notification can aid investigation but never auto-resets trust.
The server monitor work is tracked separately in the DNSid platform project.

In-memory stores protect continuity for the lifetime of that **store instance**.
Constructing a new empty store loses that memory even without restarting the
process. Both Go convenience registries default to memory storage. Durable
injected storage is required to retain observed trust across restarts; log
signatures, witness policy and freshness checks are still required in either case.
Restarting into an empty store is not an authorized recovery procedure.

The memory store validates matching nonempty origins, tree sizes in the nonnegative
`int64` range used by Go's Merkle verifier, 32-byte roots, and nonzero witnessed
instants with years 1–9999. Invalid caller tuples are `ArgumentError`; invalid
loaded records are `CHECKPOINT_STORE_ERROR`. Load and CAS copy roots. Exact CAS
includes witnessed time as an instant, not a timezone spelling.

`ContextTrustedC2spCheckpointStore` adds `LoadContext` and `CompareAndSwapContext`
without changing the existing administrative CAS idiom. The verifier uses these
operations when available. The memory store implements cancellable lock waits and
checks cancellation under its lock immediately before publication. It neither
steals locks by age nor leaves canceled writes queued. Store implementations that
wait for locks or stage data must implement these context operations, propagate the
invocation budget, and check cancellation after staging and before publication.
Context-free operations are synchronous publication boundaries; do not hide queued
or staged writes behind that interface. Decorators must forward the context
operations when the underlying store needs them.

A publication error is failure, never a successful verification or permission to
retry the write automatically. The installed tuple may have changed. Read back and
validate actual state before recovery; subsequent verification loads that actual
state again. No verifier assumes that a failed CAS left the old tuple installed.

Store injection stays code-only: construct either `NewVerificationRegistry` or
`NewDnsidManagedVerificationRegistry` with `TrustedCheckpointStore`, then inject the
registry through `config.Dependencies.LogRegistry`. Loaders do not open, initialize,
reset, or replace stores and reject checkpoint persistence/recovery file members.
Unknown environment variables remain ignored, not alternate persistence settings.

Durable adapters must provide atomic exact-state CAS, copy isolation, durable
acknowledgments and explicit ownership/backup policy. Opening existing storage must
be separate from explicit initialization. Missing, corrupt, unreadable, unsupported,
or partially lost existing state fails closed, never becoming an empty store.
Document how unseen origins differ from storage loss. Commit replacement atomically
and acknowledge only after durable commit; retain the old or new complete record
across crashes. Lock ownership must exclude paused live writers and prevent a
recovery/release operation from deleting a successor's lock. Keep checkpoint state and
its evidence archive outside the platform database's rollback boundary. Backups
must not silently restore an older verifier baseline. Shipping Go diagnostics does
not ship a durable adapter or justify advertising restart-persistent protection.
Built-in durable Go storage is separate follow-up scope; no dependency or new
storage implementation is required to settle this design.

## Validation baseline

This correction used SDK `04ec8f38cfbbd664f9e9614957256975abb5fb89` (`main`,
release version `v0.41.0`) and the checked-out compliance/design revision
`cc4605597442f6177c05c3083ef73418ef170bba` (`docs/checkpoint-trust-contract`).
The implementation changes are uncommitted on top of that SDK revision; no
older design snapshot was substituted.

Native regression coverage includes public readers, offline bundles, one
factory-to-IdentityManager storage-failure refresh, corrupt stored tuples,
exact witnessed-time CAS, conflicting writers, pre-publication cancellation,
lock cancellation/ownership, and an injected post-publication acknowledgment
failure with explicit read-back. Recovery authority authentication, signed-evidence
archive retention, fencing across processes, and audit integrity remain deployment
responsibilities. There is no built-in durable adapter; these tests do not establish
crash persistence, durable commits, file-lock recovery, or full IdentityManager
checkpoint coverage.

Validation commands passed:

```sh
go test ./...
go test -race ./...
go test -race ./log/c2sptlog -run 'TestCheckpointReader_CancellationAndConflictingWriters|TestMemoryCheckpointStore_CancelledWaitCannotPublish|TestVerifyStreamBundle_CancellationBeforePublication' -count=100
go vet ./...
```

The single-SDK entrypoint was run with `SDK_ID=go` and
`SDK_DIR=/Users/benjamin.guidarelli/dnsid-go`:

```sh
cd /Users/benjamin.guidarelli/dnsid-sdk-compliance
ci/run-one.sh "$SDK_ID" "$SDK_DIR" /tmp/checkpoint-compliance.md
```

The complete report was read: 347 PASS (including six XPASS), 11 correct
unsupported-version rejections, zero XFAIL, zero failures, and zero missing cases;
all 15 checkpoint cases matched. Harness checks also passed: 40 unit tests
(six skipped in the single-SDK setup), fixture reproducibility, and 33 focused
event-identity checks. These counts do not establish the deployment guarantees
excluded above.

The shared single-SDK report is `/tmp/checkpoint-compliance.md`. Six Go
`known_bug` markers now XPASS: `checkpoint-scan-missing-leaf`,
`checkpoint-scan-wrong-root`, `checkpoint-proof-fetch-error`,
`checkpoint-store-load-error`, `checkpoint-store-write-error`, and
`checkpoint-invalid-checkpoint-signature`. Coordinate removal in
`harness/generate_c2sp_fixtures.py` (the `bugs` map in
`generate_checkpoints`) and regenerate
`fixtures/c2sp-checkpoint-continuity.yaml` in the compliance repository. Neither
shared expectations nor generated fixtures are modified by this SDK correction.

## Delivery and acceptance

- This record resolves #315's taxonomy, authorized replacement, and signaling
  decisions. The diagnostic and storage contracts above track the current implementation.
- #316 implements the Go diagnostics and executable CAS-contract checks. Test
  rollback, root conflict, proof failure, full-scan count/root failure, missing
  capability, fetch/storage causes, copied roots, public error wrapping and CAS
  races. Each rejected candidate must leave its previously trusted checkpoint
  unchanged; this does not require rolling back earlier valid advances in a batch.
- Python adoption remains in [#218](https://github.com/dnsid-ai/dnsid-py/issues/218)
  and durable storage in [#219](https://github.com/dnsid-ai/dnsid-py/issues/219).
  TypeScript adoption remains in [#272](https://github.com/dnsid-ai/dnsid-ts/issues/272)
  and durable storage in [#273](https://github.com/dnsid-ai/dnsid-ts/issues/273).
  Their maintainers must reconcile this vocabulary with their APIs; this Go PR
  neither implements nor closes those issues.
