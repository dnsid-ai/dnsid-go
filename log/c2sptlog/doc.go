// Package c2sptlog binds DNSid lifecycle logs to C2SP transparency logs: it
// reads, verifies, and writes DNSid lifecycle events stored as entries in a
// tiled Merkle log that follows the C2SP tlog-tiles, tlog-checkpoint,
// tlog-witness, and tlog-policy specifications (see PinnedSpecificationVersions
// for the exact pinned versions).
//
// The log method is "c2sp-tlog". An identity record references a stream with
// an lr value of the form c2sp-tlog:<scope>:<log-prefix>#<stream-id>
// (Reference); individual entries are addressed by appending @<index>. Client
// implements the log package's LogReader interface on top of a Source that
// supplies inclusion-proven entries, a Policy that verifies signed checkpoints
// and witness cosignature quorums, and an optional Appender for writes.
// NewVerificationRegistry provides the standard verification setup:
//
//	registry, err := c2sptlog.NewVerificationRegistry(ctx,
//		c2sptlog.VerificationRegistryConfig{
//			PolicyURL: "https://policy.example/dnsid-policy",
//		})
//
// A parsed TrustProfile may instead bind one exact scope and log prefix to its
// policy and accepted bundle signers; profiles are independently distributed
// rather than discovered from the log. NewDnsidManagedVerificationRegistry is
// the separately named, opt-in factory for SDK-embedded Identity Digital trust
// roots; the generic factory never selects those roots implicitly. The policy
// URL is caller-selected trusted configuration and is never derived from an
// unverified log reference. The factory uses one bounded, redirect-free,
// rebinding-resistant ResourceFetcher for policy and standard log resources;
// custom fetchers must declare all public-read SecurityGuarantees. Supplying
// independently trusted BundleVerifiers and MaxBundleLifetime makes verified
// per-domain stream bundles the preferred source; RequireStreamBundle disables
// raw-scan fallback for deployment checks. Configure CheckpointMaxAge to enable
// fresh logged-state and non-revocation checks, which otherwise fail closed.
// Advanced deployments can compose ParsePolicy, NewScanSource, Register, and a
// durable checkpoint store directly.
//
// Every event is an entity- or operational-key-signed JCS-canonical JSON
// envelope. Verification replays a domain's entries in log order, checks the
// lifecycle signature chain (ISSUANCE bilateral signatures, rotation
// old-key/new-key signatures, entity signatures on later events), and logical
// predecessor metadata (Chain) in every scope. EventID excludes signatures;
// signature-only copies never advance state. Indexes and exact complete entry
// bytes remain inclusion evidence. DNSidMethodRevision pins this breaking
// pre-1.0 correction; old index/leaf chains are not accepted. A
// TrustedC2spCheckpointStore protects verified checkpoints against rollback.
//
// Multi-party signing flows use PreparedEvent: Client.PrepareEvent builds the
// unsigned envelope, Client.SignPreparedEvent collects each SignerRole
// signature, and Client.WritePreparedEvent appends the exact signed bytes.
// VerifyStreamBundle verifies an offline, producer-signed evidence bundle
// without network access. RebuildHistoryThrough supplies exact-cutoff source
// evidence for caller-configured migration verification, including valid later
// copies of the final logical event.
//
// See https://docs.dnsid.ai for protocol guides and account setup.
package c2sptlog
