package c2sptlog

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	dnsid "github.com/dnsid-ai/dnsid-go"
	dnsidlog "github.com/dnsid-ai/dnsid-go/log"
	"github.com/lestrrat-go/jwx/v3/jwk"
	formatlog "github.com/transparency-dev/formats/log"
)

// ProvenEntry is a raw log entry together with its inclusion evidence: the
// entry's index in the log, its exact canonical bytes, and a marshaled proof
// binding the entry to a signed checkpoint. The proof is untrusted until
// verified by Policy.VerifyProof.
type ProvenEntry struct {
	Index uint64
	Entry []byte
	Proof []byte
}

type verifiedEvent struct {
	event                dnsidlog.LogEvent
	chain                chainFields
	index                uint64
	signed               []byte
	parseError           error
	migration            *MigrationVerificationResult
	authorityEntity      jwk.Key
	authorityOperational jwk.Key
}

// Source supplies raw, inclusion-proven entries from a c2sp-tlog log. A
// Source is a transport: everything it returns is untrusted until the Client
// verifies proofs, signatures, and lifecycle order.
type Source interface {
	// ReadEvent returns the proven entry addressed by a final event
	// reference of the form <lr>@<index>.
	ReadEvent(ctx context.Context, ref dnsidlog.LogRef) (ProvenEntry, error)
	// RebuildHistory returns the proven entries relevant to domain in the
	// stream identified by lr, in ascending index order.
	RebuildHistory(ctx context.Context, lr Reference, domain string) ([]ProvenEntry, error)
}

// CompleteHistoryResult binds one complete history read to the exact accepted
// checkpoint and completeness mechanism that produced it. FreshnessTime is
// informational; Client independently verifies Checkpoint under its Policy.
type CompleteHistoryResult struct {
	Entries          []ProvenEntry
	Checkpoint       []byte
	CompleteThrough  uint64
	CompletenessMode string
	FreshnessTime    time.Time
}

// CompleteSource is a Source that can additionally return every entry for the
// domain together with the exact completeness boundary. Non-revocation
// verification requires a CompleteSource, since a missing REVOCATION entry
// would otherwise be undetectable.
type CompleteSource interface {
	Source
	// RebuildCompleteHistory returns one checkpoint-bound complete history.
	RebuildCompleteHistory(ctx context.Context, lr Reference, domain string) (CompleteHistoryResult, error)
}

// GlobalCandidateSource marks a Source whose RebuildHistory result is a set of
// candidates scanned from a global log. Invalid and unrelated candidates are
// ignored; failures returned by the source itself remain fatal. Sources that
// return selected-stream evidence remain strict by default.
type GlobalCandidateSource interface {
	Source
	// GlobalCandidates reports whether RebuildHistory results are unfiltered
	// candidates from a global log rather than a selected stream.
	GlobalCandidates() bool
}

// Appender appends exact canonical entry bytes to the log and returns the
// index assigned to the new entry.
type Appender interface {
	Append(ctx context.Context, entry []byte) (uint64, error)
}

// Option configures a Client constructed by New or Register.
type Option func(*Client)

const (
	defaultMaxMigrationDepth         = 8
	defaultMaxMigrationHistoryEvents = 10_000
	defaultMaxMigrationResponseBytes = 8 << 20
)

// MigrationVerificationResult is the verified state imported by an inbound
// migration. PriorHistory must be the fully verified history of PreviousLog
// through the migration event's FinalEntryRef. PriorEvidence and the aligned
// PriorHistoryReferences are required when the result is used for complete
// non-revocation evidence.
type MigrationVerificationResult struct {
	EntityKey              jwk.Key
	ActiveOperationalKey   jwk.Key
	PriorHistory           []dnsidlog.LogEvent
	PriorEvidence          *dnsidlog.LoggedStateEvidence
	PriorHistoryReferences []dnsidlog.LogRef
	// FinalOccurrence retains the exact C2SP cutoff occurrence, including a
	// later signature-valid copy, when RebuildHistoryThrough produced the result.
	FinalOccurrence *ProvenEntry
}

// MigrationVerificationLimits bound recursive migration verification. Zero
// values select finite defaults.
type MigrationVerificationLimits struct {
	// MaxDepth bounds migrations in one stitched history.
	MaxDepth int
	// MaxHistoryEvents bounds all imported and destination events.
	MaxHistoryEvents int
	// MaxResponseBytes bounds the JSON-encoded MigrationVerificationResult.
	MaxResponseBytes int64
}

// MigrationVerifier verifies the prior-log history referenced by an inbound
// migration and returns the identity keys and history established by it. It
// must propagate ctx to recursive verification so depth and cycle limits apply.
type MigrationVerifier func(context.Context, dnsidlog.LogEvent) (MigrationVerificationResult, error)

// Client binds one c2sp-tlog stream reference to a Source, Policy, and
// optional Appender. It implements the log package's LogReader,
// LifecycleBindingVerifier, and Log interfaces: reads verify inclusion
// proofs, lifecycle signatures, and logical stream-chain
// metadata before any event is returned. Methods on a nil *Client return
// errors rather than panicking.
type Client struct {
	ref              Reference
	source           Source
	appender         Appender
	policy           Policy
	checkpointStore  TrustedC2spCheckpointStore
	verifyMigration  MigrationVerifier
	migrationLimits  MigrationVerificationLimits
	trustedScope     string
	trustedLogPrefix string
}

// New constructs a Client bound to the parsed lr value. It returns an error
// if lr is not a valid c2sp-tlog reference. Missing collaborators are not an
// error here: operations that need an absent Source or Appender fail when
// called.
func New(lr string, opts ...Option) (*Client, error) {
	ref, err := ParseReference(lr)
	if err != nil {
		return nil, err
	}
	c := &Client{ref: ref, migrationLimits: defaultMigrationVerificationLimits()}
	for _, opt := range opts {
		opt(c)
	}
	if c.migrationLimits.MaxDepth < 0 || c.migrationLimits.MaxHistoryEvents < 0 || c.migrationLimits.MaxResponseBytes < 0 {
		return nil, fmt.Errorf("dnsid: c2sp-tlog migration verification limits must be non-negative")
	}
	c.migrationLimits = c.migrationLimits.withDefaults()
	if c.trustedLogPrefix != "" && (ref.Scope != c.trustedScope || ref.LogPrefix != c.trustedLogPrefix) {
		return nil, fmt.Errorf("dnsid: c2sp-tlog reference is not accepted by the trust profile")
	}
	return c, nil
}

// WithSource sets the Source the Client reads proven entries from. All read
// and verification operations require a Source.
func WithSource(source Source) Option {
	return func(c *Client) { c.source = source }
}

// WithAppender sets the Appender used to write entries. Write operations
// require an Appender.
func WithAppender(appender Appender) Option {
	return func(c *Client) { c.appender = appender }
}

// WithPolicy sets the checkpoint and proof verification policy. The zero
// Policy rejects all proofs because it has no log verifier.
func WithPolicy(policy Policy) Option {
	return func(c *Client) { c.policy = policy }
}

// WithTrustedCheckpointStore sets the store that records the largest verified
// checkpoint per origin, protecting subsequent reads against log rollback.
// Without a store, no rollback protection is applied.
func WithTrustedCheckpointStore(store TrustedC2spCheckpointStore) Option {
	return func(c *Client) { c.checkpointStore = store }
}

// WithMigrationVerifier configures verification and stitching of inbound
// migrations. Without one, inbound migration fails closed.
func WithMigrationVerifier(verifier MigrationVerifier) Option {
	return func(c *Client) { c.verifyMigration = verifier }
}

// WithMigrationVerificationLimits configures recursion and imported-history
// bounds. Zero fields use finite defaults.
func WithMigrationVerificationLimits(limits MigrationVerificationLimits) Option {
	return func(c *Client) { c.migrationLimits = limits }
}

func defaultMigrationVerificationLimits() MigrationVerificationLimits {
	return MigrationVerificationLimits{
		MaxDepth:         defaultMaxMigrationDepth,
		MaxHistoryEvents: defaultMaxMigrationHistoryEvents,
		MaxResponseBytes: defaultMaxMigrationResponseBytes,
	}
}

func (l MigrationVerificationLimits) withDefaults() MigrationVerificationLimits {
	defaults := defaultMigrationVerificationLimits()
	if l.MaxDepth == 0 {
		l.MaxDepth = defaults.MaxDepth
	}
	if l.MaxHistoryEvents == 0 {
		l.MaxHistoryEvents = defaults.MaxHistoryEvents
	}
	if l.MaxResponseBytes == 0 {
		l.MaxResponseBytes = defaults.MaxResponseBytes
	}
	return l
}

type migrationPathContextKey struct{}

type migrationPath struct {
	nextLog string
	depth   int
	seen    map[string]struct{}
	limits  MigrationVerificationLimits
}

func migrationLimitsForContext(ctx context.Context, local MigrationVerificationLimits) MigrationVerificationLimits {
	if ctx != nil {
		if path, ok := ctx.Value(migrationPathContextKey{}).(*migrationPath); ok && path != nil {
			return path.limits
		}
	}
	return local.withDefaults()
}

func enterMigration(ctx context.Context, event dnsidlog.LogEvent, currentLog string, local MigrationVerificationLimits) (context.Context, MigrationVerificationLimits, error) {
	if ctx == nil {
		return nil, MigrationVerificationLimits{}, fmt.Errorf("dnsid: c2sp-tlog migration verification context is required")
	}
	limits := migrationLimitsForContext(ctx, local)
	path, _ := ctx.Value(migrationPathContextKey{}).(*migrationPath)
	if path != nil && path.nextLog != currentLog {
		return nil, limits, fmt.Errorf("dnsid: c2sp-tlog migration history is not contiguous")
	}
	if path != nil && path.depth >= limits.MaxDepth {
		return nil, limits, fmt.Errorf("dnsid: c2sp-tlog migration recursion exceeds configured maximum %d", limits.MaxDepth)
	}
	seen := make(map[string]struct{})
	depth := 0
	if path == nil {
		seen[currentLog] = struct{}{}
	} else {
		depth = path.depth
		for logRef := range path.seen {
			seen[logRef] = struct{}{}
		}
	}
	if _, exists := seen[event.PreviousLog]; exists {
		return nil, limits, fmt.Errorf("dnsid: c2sp-tlog migration cycle contains %q", event.PreviousLog)
	}
	seen[event.PreviousLog] = struct{}{}
	next := &migrationPath{nextLog: event.PreviousLog, depth: depth + 1, seen: seen, limits: limits}
	return context.WithValue(ctx, migrationPathContextKey{}, next), limits, nil
}

func validateMigrationResources(event dnsidlog.LogEvent, result MigrationVerificationResult, limits MigrationVerificationLimits) error {
	limits = limits.withDefaults()
	if len(result.PriorHistory) > limits.MaxHistoryEvents {
		return fmt.Errorf("dnsid: c2sp-tlog migration history exceeds configured maximum %d", limits.MaxHistoryEvents)
	}
	migrations := 1
	seen := make(map[string]struct{})
	lastLog := ""
	for _, prior := range result.PriorHistory {
		if prior.Type != dnsidlog.LogEventMigration {
			continue
		}
		migrations++
		if lastLog == "" {
			seen[prior.PreviousLog] = struct{}{}
		} else if prior.PreviousLog != lastLog {
			return fmt.Errorf("dnsid: c2sp-tlog migration history is not contiguous")
		}
		if _, exists := seen[prior.NewLog]; exists {
			return fmt.Errorf("dnsid: c2sp-tlog migration history contains a cycle")
		}
		seen[prior.NewLog] = struct{}{}
		lastLog = prior.NewLog
	}
	if migrations > limits.MaxDepth {
		return fmt.Errorf("dnsid: c2sp-tlog migration recursion exceeds configured maximum %d", limits.MaxDepth)
	}
	if lastLog != "" && lastLog != event.PreviousLog {
		return fmt.Errorf("dnsid: c2sp-tlog migration history does not end at previous log")
	}
	if lastLog == "" {
		seen[event.PreviousLog] = struct{}{}
	}
	if _, exists := seen[event.NewLog]; exists {
		return fmt.Errorf("dnsid: c2sp-tlog migration history contains a cycle")
	}

	encoded, err := json.Marshal(result)
	if err != nil {
		return fmt.Errorf("dnsid: encoding c2sp-tlog migration response: %w", err)
	}
	if int64(len(encoded)) > limits.MaxResponseBytes {
		return fmt.Errorf("dnsid: c2sp-tlog migration response exceeds configured byte maximum %d", limits.MaxResponseBytes)
	}
	return nil
}

func (c *Client) verifyBoundedMigration(ctx context.Context, event dnsidlog.LogEvent) (MigrationVerificationResult, error) {
	migrationCtx, limits, err := enterMigration(ctx, event, c.ref.String(), c.migrationLimits)
	if err != nil {
		return MigrationVerificationResult{}, err
	}
	result, err := c.verifyMigration(migrationCtx, event)
	if err != nil {
		return MigrationVerificationResult{}, err
	}
	if err := validateMigrationResources(event, result, limits); err != nil {
		return MigrationVerificationResult{}, err
	}
	return result, nil
}

func withProofVerifySkipped() Option {
	return func(c *Client) { c.policy.skipProofVerify = true }
}

func withTrustProfile(scope, logPrefix string) Option {
	return func(c *Client) {
		c.trustedScope = scope
		c.trustedLogPrefix = logPrefix
	}
}

// Register installs the "c2sp-tlog" method in registry so that
// LogRegistry.NewReader builds a Client (with opts applied) for every
// c2sp-tlog lr value. It returns an error if registry is nil; an lr value
// that fails to parse yields a reader whose every method returns that parse
// error.
func Register(registry *dnsidlog.LogRegistry, opts ...Option) error {
	if registry == nil {
		return fmt.Errorf("dnsid: nil log registry")
	}
	return registry.Register(Method, func(lr string) dnsidlog.LogReader {
		client, err := New(lr, opts...)
		if err != nil {
			return errorReader{err: err}
		}
		return client
	})
}

// WriteEvent canonicalizes, validates, and appends a fully signed lifecycle
// event, returning the final event reference <lr>@<index>. In every scope,
// only ISSUANCE and inbound MIGRATION events can be written this way (they
// derive seq=0); later events must supply chain metadata via
// WriteEventWithChain.
func (c *Client) WriteEvent(ctx context.Context, event dnsidlog.LogEvent) (dnsidlog.LogRef, error) {
	if c == nil {
		return "", fmt.Errorf("dnsid: c2sp-tlog appender is required")
	}
	chain, err := c.chainForWrite(event)
	if err != nil {
		return "", err
	}
	return c.writeEvent(ctx, event, chain)
}

// EntryBytes returns the canonical, fully contextualized entry bytes without
// appending them. ISSUANCE entries receive seq=0; later events
// require EntryBytesWithChain.
func (c *Client) EntryBytes(event dnsidlog.LogEvent) ([]byte, error) {
	if c == nil {
		return nil, fmt.Errorf("dnsid: c2sp-tlog client is required")
	}
	if err := c.validateWritableStream(event); err != nil {
		return nil, err
	}
	chain, err := c.chainForWrite(event)
	if err != nil {
		return nil, err
	}
	return entryBytesWithChain(event, &c.ref, chain)
}

// EntryBytesWithChain returns canonical contextualized entry bytes with the
// caller-supplied logical stream-chain metadata, without appending them.
func (c *Client) EntryBytesWithChain(event dnsidlog.LogEvent, chain Chain) ([]byte, error) {
	if c == nil {
		return nil, fmt.Errorf("dnsid: c2sp-tlog client is required")
	}
	if err := c.validateWritableStream(event); err != nil {
		return nil, err
	}
	if err := c.validateChain(event, chain); err != nil {
		return nil, err
	}
	return entryBytesWithChain(event, &c.ref, chainFieldsFromChain(event, chain))
}

// AppendPreparedEntry parses and safely writes canonical prepared bytes.
// Deprecated: use ParsePreparedEvent and WritePreparedEvent directly.
func (c *Client) AppendPreparedEntry(ctx context.Context, entry []byte) (dnsidlog.LogRef, error) {
	prepared, err := c.ParsePreparedEvent(entry)
	if err != nil {
		return "", err
	}
	return c.WritePreparedEvent(ctx, prepared)
}

// WriteEventWithChain is WriteEvent with caller-supplied logical stream-chain
// metadata, as required for non-genesis events in every scope. The chain is validated
// against the verified history before the entry is appended.
func (c *Client) WriteEventWithChain(ctx context.Context, event dnsidlog.LogEvent, chain Chain) (dnsidlog.LogRef, error) {
	if c == nil {
		return "", fmt.Errorf("dnsid: c2sp-tlog appender is required")
	}
	if err := c.validateChain(event, chain); err != nil {
		return "", err
	}
	return c.writeEvent(ctx, event, chainFieldsFromChain(event, chain))
}

func (c *Client) writeEvent(ctx context.Context, event dnsidlog.LogEvent, chain *chainFields) (dnsidlog.LogRef, error) {
	if c == nil {
		return "", fmt.Errorf("dnsid: c2sp-tlog client is required")
	}
	prepared, err := c.prepareEvent(event, chain)
	if err != nil {
		return "", err
	}
	return c.WritePreparedEvent(ctx, prepared)
}

func (c *Client) validatePreparedChain(parsed parsedEvent) error {
	if parsed.event.Type == dnsidlog.LogEventMigration && !c.isInboundMigration(parsed.event) {
		return invalidMigration("dnsid: c2sp-tlog MIGRATION must be destination genesis", nil)
	}
	if parsed.chain.invalid {
		return fmt.Errorf("dnsid: prohibited or invalid logical chain fields")
	}
	if parsed.event.Type == dnsidlog.LogEventIssuance || c.isInboundMigration(parsed.event) {
		if parsed.chain.sequence == nil || *parsed.chain.sequence != 0 {
			return fmt.Errorf("dnsid: c2sp-tlog genesis requires seq 0")
		}
		if !validGenesisChain(parsed.chain) {
			return fmt.Errorf("dnsid: c2sp-tlog genesis must not contain previous chain fields")
		}
		return nil
	}
	if parsed.chain.sequence == nil || !validHash(parsed.chain.previousEventID) || !validHash(parsed.chain.previousStateHash) {
		return fmt.Errorf("dnsid: c2sp-tlog entry requires lifecycle chain fields")
	}
	return nil
}

func (c *Client) isInboundMigration(event dnsidlog.LogEvent) bool {
	return event.Type == dnsidlog.LogEventMigration && event.NewLog == c.ref.String()
}

// KeyTimestamp returns the signed event timestamp of the verified event that
// bound keyThumbprint for domain. Inclusion verification has already enforced
// that this timestamp does not exceed the accepted log timestamp. It returns
// an error if keyThumbprint is not the currently active operational key.
func (c *Client) KeyTimestamp(ctx context.Context, domain, keyThumbprint string) (timestamp time.Time, err error) {
	ctx, cancel := dnsid.VerificationContext(ctx)
	defer cancel()
	defer func() {
		if err == nil {
			err = ctx.Err()
		}
		err = logVerificationError(err, false)
	}()
	verified, events, err := c.rebuildVerifiedHistory(ctx, domain)
	if err != nil {
		return time.Time{}, err
	}
	snapshot, err := dnsidlog.NewDomainLog(domain, events).SnapshotAt(c.policy.now())
	if err != nil {
		return time.Time{}, err
	}
	if snapshot.HistoricalState != dnsidlog.AgentStateActive {
		return time.Time{}, dnsid.NewVerificationError(dnsid.VerificationCodeTerminalState, false, fmt.Sprintf("dnsid: c2sp-tlog identity %s has terminal logged state %s", domain, snapshot.HistoricalState), nil)
	}
	if snapshot.ActiveKeyThumbprint != keyThumbprint {
		return time.Time{}, fmt.Errorf("dnsid: no active c2sp-tlog key binding for %q", keyThumbprint)
	}
	for _, item := range verified {
		if bindsKey(item.event, keyThumbprint) {
			return item.event.Timestamp, nil
		}
	}
	return time.Time{}, fmt.Errorf("dnsid: no c2sp-tlog key binding for %q", keyThumbprint)
}

// VerifyBilateralBinding verifies the signed ISSUANCE event against the
// current DNS record material and returns its trusted continuity anchor.
func (c *Client) VerifyBilateralBinding(ctx context.Context, input dnsidlog.BilateralBindingInput) (binding dnsidlog.BilateralBinding, err error) {
	ctx, cancel := dnsid.VerificationContext(ctx)
	defer cancel()
	defer func() {
		if err == nil {
			err = ctx.Err()
		}
	}()
	_, events, err := c.rebuildVerifiedHistory(ctx, input.Domain)
	if err != nil {
		return dnsidlog.BilateralBinding{}, err
	}
	if _, err := activeHistoricalSnapshot(events, input.Domain, c.policy.now()); err != nil {
		return dnsidlog.BilateralBinding{}, logVerificationError(err, false)
	}
	binding, err = verifyBilateralBinding(events, input)
	return binding, logVerificationError(err, false)
}

func verifyBilateralBinding(events []dnsidlog.LogEvent, input dnsidlog.BilateralBindingInput) (dnsidlog.BilateralBinding, error) {
	genesis, err := issuanceEvent(events)
	if err != nil {
		return dnsidlog.BilateralBinding{}, err
	}
	if !strings.EqualFold(genesis.Domain, input.Domain) {
		return dnsidlog.BilateralBinding{}, fmt.Errorf("dnsid: c2sp-tlog ISSUANCE fqdn %q does not match %q", genesis.Domain, input.Domain)
	}
	entityThumb, err := thumbprint(genesis.InitialEntityPublicKey)
	if err != nil {
		return dnsidlog.BilateralBinding{}, fmt.Errorf("dnsid: c2sp-tlog ISSUANCE entity key thumbprint failed: %w", err)
	}
	recordEntityThumb, err := thumbprint(input.EntityKey)
	if err != nil {
		return dnsidlog.BilateralBinding{}, fmt.Errorf("dnsid: c2sp-tlog record entity key thumbprint failed: %w", err)
	}
	if entityThumb != recordEntityThumb {
		return dnsidlog.BilateralBinding{}, fmt.Errorf("dnsid: c2sp-tlog ISSUANCE entity key does not match record ek for %s", input.Domain)
	}
	if genesis.GovernanceID != input.GovernanceID {
		return dnsidlog.BilateralBinding{}, fmt.Errorf("dnsid: c2sp-tlog ISSUANCE gi %q does not match record gi %q", genesis.GovernanceID, input.GovernanceID)
	}
	operationalThumb, err := thumbprint(genesis.InitialOperationalPublicKey)
	if err != nil {
		return dnsidlog.BilateralBinding{}, fmt.Errorf("dnsid: c2sp-tlog ISSUANCE operational key thumbprint failed: %w", err)
	}
	return dnsidlog.BilateralBinding{
		InitialOperationalThumbprint: operationalThumb,
		InitialEntityThumbprint:      entityThumb,
		Timestamp:                    genesis.Timestamp,
	}, nil
}

// VerifyOperationalContinuity verifies that the current operational key is
// connected to the ISSUANCE key by the validated rotation chain.
func (c *Client) VerifyOperationalContinuity(ctx context.Context, domain, initialOperationalThumbprint, currentOperationalThumbprint string) (err error) {
	ctx, cancel := dnsid.VerificationContext(ctx)
	defer cancel()
	defer func() {
		if err == nil {
			err = ctx.Err()
		}
	}()
	_, events, err := c.rebuildVerifiedHistory(ctx, domain)
	if err != nil {
		return err
	}
	return logVerificationError(verifyOperationalContinuity(events, domain, initialOperationalThumbprint, currentOperationalThumbprint, c.policy.now()), false)
}

func verifyOperationalContinuity(events []dnsidlog.LogEvent, domain, initialOperationalThumbprint, currentOperationalThumbprint string, at time.Time) error {
	genesis, err := issuanceEvent(events)
	if err != nil {
		return err
	}
	initialThumbprint, err := thumbprint(genesis.InitialOperationalPublicKey)
	if err != nil {
		return fmt.Errorf("dnsid: c2sp-tlog ISSUANCE operational key thumbprint failed: %w", err)
	}
	if initialThumbprint != initialOperationalThumbprint {
		return fmt.Errorf("dnsid: c2sp-tlog ISSUANCE operational key does not match continuity anchor")
	}
	snapshot, err := activeHistoricalSnapshot(events, domain, at)
	if err != nil {
		return err
	}
	if snapshot.ActiveKeyThumbprint != currentOperationalThumbprint {
		return fmt.Errorf("dnsid: no active c2sp-tlog key binding for %s and key %s", domain, currentOperationalThumbprint)
	}
	return nil
}

func activeHistoricalSnapshot(events []dnsidlog.LogEvent, domain string, at time.Time) (*dnsidlog.DomainSnapshot, error) {
	snapshot, err := dnsidlog.NewDomainLog(domain, events).SnapshotAt(at)
	if err != nil {
		return nil, err
	}
	if snapshot.HistoricalState != dnsidlog.AgentStateActive {
		return nil, dnsid.NewVerificationError(dnsid.VerificationCodeTerminalState, false, fmt.Sprintf("dnsid: c2sp-tlog identity %s has terminal logged state %s", domain, snapshot.HistoricalState), nil)
	}
	return snapshot, nil
}

// VerifyLifecycleBinding verifies the bilateral ISSUANCE binding and
// operational continuity over one verified lifecycle snapshot.
func (c *Client) VerifyLifecycleBinding(ctx context.Context, input dnsidlog.BilateralBindingInput, currentOperationalThumbprint string) (binding dnsidlog.BilateralBinding, err error) {
	ctx, cancel := dnsid.VerificationContext(ctx)
	defer cancel()
	defer func() {
		if err == nil {
			err = ctx.Err()
		}
	}()
	_, events, err := c.rebuildVerifiedHistory(ctx, input.Domain)
	if err != nil {
		return dnsidlog.BilateralBinding{}, err
	}
	binding, err = verifyBilateralBinding(events, input)
	if err != nil {
		return dnsidlog.BilateralBinding{}, logVerificationError(err, false)
	}
	if err := verifyOperationalContinuity(events, input.Domain, binding.InitialOperationalThumbprint, currentOperationalThumbprint, c.policy.now()); err != nil {
		return dnsidlog.BilateralBinding{}, logVerificationError(err, false)
	}
	return binding, nil
}

func issuanceEvent(events []dnsidlog.LogEvent) (dnsidlog.LogEvent, error) {
	for _, event := range events {
		if event.Type == dnsidlog.LogEventIssuance {
			return event, nil
		}
	}
	return dnsidlog.LogEvent{}, fmt.Errorf("dnsid: c2sp-tlog history has no ISSUANCE genesis")
}

// VerifyGovernanceRelationship verifies that a verified ISSUANCE event for
// domain names governanceID as the governing organization.
func (c *Client) VerifyGovernanceRelationship(ctx context.Context, domain, governanceID string) (err error) {
	ctx, cancel := dnsid.VerificationContext(ctx)
	defer cancel()
	defer func() {
		if err == nil {
			err = ctx.Err()
		}
	}()
	events, err := c.RebuildHistory(ctx, domain)
	if err != nil {
		return err
	}
	for _, event := range events {
		if event.Type == dnsidlog.LogEventIssuance && event.GovernanceID == governanceID {
			return nil
		}
	}
	return logVerificationError(fmt.Errorf("dnsid: no c2sp-tlog governance relationship for %s and %s", domain, governanceID), false)
}

// VerifyNonRevocation verifies that domain's identity was neither revoked
// nor retired as of time at. It requires the configured Source to implement
// CompleteSource, because proving the absence of a REVOCATION entry needs a
// complete view of the stream and a positive maximum checkpoint age; without
// either it fails closed. Success returns the exact accepted proof boundaries,
// including every prior stream imported by migration.
func (c *Client) VerifyNonRevocation(ctx context.Context, domain string, at time.Time) (evidence dnsidlog.LoggedStateEvidence, err error) {
	ctx, cancel := dnsid.VerificationContext(ctx)
	defer cancel()
	defer func() {
		if err == nil {
			err = ctx.Err()
		}
		err = logVerificationError(err, false)
	}()
	complete, ok := c.source.(CompleteSource)
	if !ok {
		return dnsidlog.LoggedStateEvidence{}, dnsid.NewVerificationError(dnsid.VerificationCodeIncompleteStream, false, "dnsid: c2sp-tlog complete history source is required for non-revocation", nil)
	}
	if c.policy.MaxCheckpointAge <= 0 {
		return dnsidlog.LoggedStateEvidence{}, dnsid.NewVerificationError(dnsid.VerificationCodeInvalidEvidence, false, "dnsid: c2sp-tlog non-revocation requires a positive maximum checkpoint age", nil)
	}
	completeHistory, err := complete.RebuildCompleteHistory(ctx, c.ref, domain)
	if err != nil {
		return dnsidlog.LoggedStateEvidence{}, dnsid.NewVerificationError(dnsid.VerificationCodeIncompleteStream, resourceFailureTransient(err, true), "dnsid: c2sp-tlog history is incomplete", err)
	}
	checkpoint, err := c.verifyCompleteCheckpoint(completeHistory)
	if err != nil {
		return dnsidlog.LoggedStateEvidence{}, dnsid.NewVerificationError(dnsid.VerificationCodeInvalidEvidence, false, "dnsid: invalid complete c2sp-tlog checkpoint evidence", err)
	}
	verified, events, err := c.verifyHistoryEntries(ctx, domain, completeHistory.Entries, checkpoint)
	if err != nil {
		return dnsidlog.LoggedStateEvidence{}, err
	}
	if len(verified) == 0 {
		return dnsidlog.LoggedStateEvidence{}, dnsid.NewVerificationError(dnsid.VerificationCodeIncompleteStream, false, "dnsid: c2sp-tlog complete history contains no verified stream genesis", nil)
	}
	var priorEvidence []dnsidlog.LoggedStateEvidence
	var priorReferences []dnsidlog.LogRef
	if verified[0].event.Type == dnsidlog.LogEventMigration {
		priorEvidence, priorReferences, err = validatedPriorEvidence(verified[0].event, verified[0].migration)
		if err != nil {
			return dnsidlog.LoggedStateEvidence{}, err
		}
	} else if verified[0].event.Timestamp.After(at) {
		return dnsidlog.LoggedStateEvidence{}, dnsid.NewVerificationError(dnsid.VerificationCodeInvalidEvidence, false, "dnsid: c2sp-tlog requested time predates the bound stream genesis", nil)
	}
	snapshot, err := dnsidlog.NewDomainLog(domain, events).SnapshotAt(at)
	if err != nil {
		return dnsidlog.LoggedStateEvidence{}, err
	}
	switch snapshot.HistoricalState {
	case dnsidlog.AgentStateRevoked:
		return dnsidlog.LoggedStateEvidence{}, dnsid.NewVerificationError(dnsid.VerificationCodeTerminalState, false, fmt.Sprintf("dnsid: c2sp-tlog identity %s revoked at %s", domain, snapshot.Events[len(snapshot.Events)-1].Timestamp.Format(time.RFC3339)), nil)
	case dnsidlog.AgentStateRetired:
		return dnsidlog.LoggedStateEvidence{}, dnsid.NewVerificationError(dnsid.VerificationCodeTerminalState, false, fmt.Sprintf("dnsid: c2sp-tlog identity %s retired at %s", domain, snapshot.Events[len(snapshot.Events)-1].Timestamp.Format(time.RFC3339)), nil)
	}
	historyStart := c.ref.FinalEventRef(verified[0].index)
	historyEnd := dnsidlog.LogRef("")
	if len(priorReferences) > 0 {
		historyStart = priorReferences[0]
		if len(snapshot.Events) <= len(priorReferences) {
			historyEnd = priorReferences[len(snapshot.Events)-1]
		} else {
			historyEnd = c.ref.FinalEventRef(verified[len(snapshot.Events)-len(priorReferences)-1].index)
		}
	} else {
		for _, item := range verified {
			if item.event.Timestamp.After(at) {
				break
			}
			historyEnd = c.ref.FinalEventRef(item.index)
		}
	}
	return dnsidlog.LoggedStateEvidence{
		LogReference:     dnsidlog.LogRef(c.ref.String()),
		LoggedState:      snapshot.HistoricalState,
		HistoryStart:     historyStart,
		HistoryEnd:       historyEnd,
		CompleteThrough:  strconv.FormatUint(completeHistory.CompleteThrough, 10),
		CompletenessMode: completeHistory.CompletenessMode,
		Checkpoint:       append([]byte(nil), completeHistory.Checkpoint...),
		FreshnessTime:    checkpoint.CheckpointFreshnessTime,
		PriorEvidence:    priorEvidence,
	}, nil
}

func validatedPriorEvidence(event dnsidlog.LogEvent, migration *MigrationVerificationResult) ([]dnsidlog.LoggedStateEvidence, []dnsidlog.LogRef, error) {
	if migration == nil || migration.PriorEvidence == nil {
		return nil, nil, dnsid.NewVerificationError(dnsid.VerificationCodeInvalidEvidence, false, "dnsid: c2sp-tlog migrated history is missing prior complete evidence", nil)
	}
	if len(migration.PriorHistoryReferences) == 0 || len(migration.PriorHistoryReferences) != len(migration.PriorHistory) || migration.PriorHistoryReferences[len(migration.PriorHistoryReferences)-1] != dnsidlog.LogRef(event.FinalEntryRef) {
		return nil, nil, dnsid.NewVerificationError(dnsid.VerificationCodeInvalidEvidence, false, "dnsid: c2sp-tlog prior history references do not end at the signed migration cutoff", nil)
	}
	current := cloneLoggedStateEvidence(*migration.PriorEvidence)
	if current.LogReference != dnsidlog.LogRef(event.PreviousLog) || current.HistoryEnd != dnsidlog.LogRef(event.FinalEntryRef) {
		return nil, nil, dnsid.NewVerificationError(dnsid.VerificationCodeInvalidEvidence, false, "dnsid: c2sp-tlog prior evidence does not match the signed migration cutoff", nil)
	}
	all := append(current.PriorEvidence, current)
	if all[0].HistoryStart != migration.PriorHistoryReferences[0] {
		return nil, nil, dnsid.NewVerificationError(dnsid.VerificationCodeInvalidEvidence, false, "dnsid: c2sp-tlog prior evidence does not start at the verified history genesis", nil)
	}
	migrations := make([]dnsidlog.LogEvent, 0, len(all)-1)
	for _, prior := range migration.PriorHistory {
		if prior.Type == dnsidlog.LogEventMigration {
			migrations = append(migrations, prior)
		}
	}
	if len(all) != len(migrations)+1 {
		return nil, nil, dnsid.NewVerificationError(dnsid.VerificationCodeInvalidEvidence, false, "dnsid: c2sp-tlog prior evidence does not cover every migrated proof boundary", nil)
	}
	migrationIndex := 0
	for i, prior := range migration.PriorHistory {
		if migration.PriorHistoryReferences[i] == "" {
			return nil, nil, dnsid.NewVerificationError(dnsid.VerificationCodeInvalidEvidence, false, "dnsid: c2sp-tlog prior history contains an empty event reference", nil)
		}
		if prior.Type != dnsidlog.LogEventMigration {
			continue
		}
		if i == 0 || all[migrationIndex].LogReference != dnsidlog.LogRef(prior.PreviousLog) || all[migrationIndex].HistoryEnd != migration.PriorHistoryReferences[i-1] || migration.PriorHistoryReferences[i-1] != dnsidlog.LogRef(prior.FinalEntryRef) || all[migrationIndex+1].LogReference != dnsidlog.LogRef(prior.NewLog) || all[migrationIndex+1].HistoryStart != migration.PriorHistoryReferences[i] {
			return nil, nil, dnsid.NewVerificationError(dnsid.VerificationCodeInvalidEvidence, false, "dnsid: c2sp-tlog prior evidence does not match stitched migration history", nil)
		}
		migrationIndex++
	}
	seen := make(map[dnsidlog.LogRef]struct{}, len(all))
	for i := range all {
		item := &all[i]
		item.PriorEvidence = nil
		if item.LogReference == "" || item.HistoryStart == "" || item.HistoryEnd == "" || item.CompleteThrough == "" || item.CompletenessMode == "" || len(item.Checkpoint) == 0 || item.FreshnessTime.IsZero() || item.LoggedState != dnsidlog.AgentStateActive {
			return nil, nil, dnsid.NewVerificationError(dnsid.VerificationCodeInvalidEvidence, false, "dnsid: c2sp-tlog prior migration evidence is incomplete or terminal", nil)
		}
		if _, duplicate := seen[item.LogReference]; duplicate {
			return nil, nil, dnsid.NewVerificationError(dnsid.VerificationCodeInvalidMigration, false, "dnsid: c2sp-tlog prior evidence contains a migration cycle", nil)
		}
		seen[item.LogReference] = struct{}{}
	}
	return all, append([]dnsidlog.LogRef(nil), migration.PriorHistoryReferences...), nil
}

func cloneLoggedStateEvidence(evidence dnsidlog.LoggedStateEvidence) dnsidlog.LoggedStateEvidence {
	evidence.Checkpoint = append([]byte(nil), evidence.Checkpoint...)
	evidence.PriorEvidence = append([]dnsidlog.LoggedStateEvidence(nil), evidence.PriorEvidence...)
	for i := range evidence.PriorEvidence {
		evidence.PriorEvidence[i] = cloneLoggedStateEvidence(evidence.PriorEvidence[i])
	}
	return evidence
}

func (c *Client) verifyCompleteCheckpoint(history CompleteHistoryResult) (*VerifiedProof, error) {
	if history.CompletenessMode == "" {
		return nil, fmt.Errorf("dnsid: c2sp-tlog completeness mode is required")
	}
	if c.policy.skipProofVerify {
		if history.FreshnessTime.IsZero() {
			return nil, fmt.Errorf("dnsid: c2sp-tlog checkpoint freshness time is required")
		}
		if c.policy.now().Sub(history.FreshnessTime) > c.policy.MaxCheckpointAge {
			return nil, fmt.Errorf("dnsid: c2sp-tlog checkpoint is stale")
		}
		return &VerifiedProof{Checkpoint: &formatlog.Checkpoint{Size: history.CompleteThrough}, CheckpointFreshnessTime: history.FreshnessTime}, nil
	}
	if len(history.Checkpoint) == 0 {
		return nil, fmt.Errorf("dnsid: c2sp-tlog complete checkpoint is required")
	}
	verified, err := c.policy.verifyCheckpoint(c.ref, history.Checkpoint)
	if err != nil {
		return nil, err
	}
	if verified.Checkpoint.Size != history.CompleteThrough {
		return nil, fmt.Errorf("dnsid: c2sp-tlog completeness bound %d does not match checkpoint size %d", history.CompleteThrough, verified.Checkpoint.Size)
	}
	if verified.CheckpointFreshnessTime.IsZero() {
		return nil, fmt.Errorf("dnsid: c2sp-tlog checkpoint freshness time is required")
	}
	return verified, nil
}

// ReadEvent reads and verifies the single event addressed by a final event
// reference <lr>@<index>. The entry's inclusion proof must verify, its index
// must match the reference, and the entry must appear in the domain's
// verified lifecycle history; otherwise an error is returned.
func (c *Client) ReadEvent(ctx context.Context, ref dnsidlog.LogRef) (event dnsidlog.LogEvent, err error) {
	ctx, cancel := dnsid.VerificationContext(ctx)
	defer cancel()
	defer func() {
		if err == nil {
			err = ctx.Err()
		}
		err = logVerificationError(err, false)
	}()
	if c == nil || c.source == nil {
		return dnsidlog.LogEvent{}, dnsid.NewArgumentError("dnsid: c2sp-tlog source is required", nil)
	}
	wantRef, wantIndex, err := ParseFinalEventRef(ref)
	if err != nil {
		return dnsidlog.LogEvent{}, err
	}
	if wantRef.String() != c.ref.String() {
		return dnsidlog.LogEvent{}, dnsid.NewArgumentError("dnsid: c2sp-tlog final ref does not match client reference", nil)
	}
	proven, err := c.source.ReadEvent(ctx, ref)
	if err != nil {
		return dnsidlog.LogEvent{}, logVerificationError(err, true)
	}
	if proven.Index != wantIndex {
		return dnsidlog.LogEvent{}, fmt.Errorf("dnsid: c2sp-tlog proof index %d does not match final ref index %d", proven.Index, wantIndex)
	}
	parsed, proof, err := c.verifyProvenEntry(proven)
	if err != nil {
		return dnsidlog.LogEvent{}, err
	}
	if proof.Index != wantIndex {
		return dnsidlog.LogEvent{}, fmt.Errorf("dnsid: c2sp-tlog proof index %d does not match final ref index %d", proof.Index, wantIndex)
	}
	if !proof.LogTime.IsZero() && parsed.event.Timestamp.After(proof.LogTime) {
		return dnsidlog.LogEvent{}, fmt.Errorf("dnsid: c2sp-tlog event timestamp is after accepted log timestamp")
	}
	signed, err := CanonicalFromEntry(proven.Entry)
	if err != nil {
		return dnsidlog.LogEvent{}, err
	}
	verified, _, err := c.rebuildVerifiedHistory(ctx, parsed.event.Domain)
	if err != nil {
		return dnsidlog.LogEvent{}, err
	}
	for _, item := range verified {
		if item.index <= wantIndex && string(item.signed) == string(signed) && candidateAuthorizedByCurrentHistory(parsed.event, signed, item.authorityEntity, item.authorityOperational) {
			if err := ctx.Err(); err != nil {
				return dnsidlog.LogEvent{}, err
			}
			return parsed.event, nil
		}
	}
	return dnsidlog.LogEvent{}, fmt.Errorf("dnsid: c2sp-tlog final event is not in verified lifecycle")
}

// RebuildHistory returns domain's verified lifecycle events in log order.
// Each event's inclusion proof, signature chain, and logical
// stream-chain metadata are verified; with a GlobalCandidateSource, invalid
// or unrelated candidates are skipped rather than fatal.
func (c *Client) RebuildHistory(ctx context.Context, domain string) ([]dnsidlog.LogEvent, error) {
	_, events, err := c.rebuildVerifiedHistory(ctx, domain)
	return events, err
}

func (c *Client) rebuildVerifiedHistory(ctx context.Context, domain string) (verifiedResult []verifiedEvent, eventResult []dnsidlog.LogEvent, err error) {
	ctx, cancel := dnsid.VerificationContext(ctx)
	defer cancel()
	defer func() { err = logVerificationError(err, false) }()
	if c == nil || c.source == nil {
		return nil, nil, dnsid.NewArgumentError("dnsid: c2sp-tlog source is required", nil)
	}
	entries, err := c.source.RebuildHistory(ctx, c.ref, domain)
	if err != nil {
		return nil, nil, logVerificationError(err, true)
	}
	return c.verifyHistoryEntries(ctx, domain, entries, nil)
}

func (c *Client) verifyHistoryEntries(ctx context.Context, domain string, entries []ProvenEntry, requiredCheckpoint *VerifiedProof) (verifiedResult []verifiedEvent, eventResult []dnsidlog.LogEvent, err error) {
	if err := validateHistorySize(entries); err != nil {
		return nil, nil, err
	}
	verified := make([]verifiedEvent, 0, len(entries))
	verifiedProofs := make([]*VerifiedProof, 0, len(entries))
	globalCandidates := false
	if source, ok := c.source.(GlobalCandidateSource); ok {
		globalCandidates = source.GlobalCandidates()
	}
	for _, entry := range entries {
		if err := ctx.Err(); err != nil {
			return nil, nil, err
		}
		// Every supplied bundle proof verifies even when its lifecycle payload is noise.
		proof, err := c.policy.VerifyProof(c.ref, entry.Entry, entry.Proof)
		if err != nil {
			if !globalCandidates {
				return nil, nil, dnsid.NewVerificationError(dnsid.VerificationCodeInvalidEvidence, false, "dnsid: invalid c2sp-tlog inclusion or checkpoint evidence", err)
			}
			continue
		}
		if c.policy.skipProofVerify {
			proof.Index = entry.Index
			if requiredCheckpoint != nil {
				proof.Checkpoint = requiredCheckpoint.Checkpoint
			}
		}
		if requiredCheckpoint != nil && !sameCheckpoint(proof.Checkpoint, requiredCheckpoint.Checkpoint) {
			return nil, nil, fmt.Errorf("dnsid: c2sp-tlog entry proof is not bound to the complete checkpoint")
		}
		if proof.Index != entry.Index {
			return nil, nil, fmt.Errorf("dnsid: supplied occurrence index does not match its proof")
		}
		if err := c.validateEntryMetadata(entry.Entry); err != nil {
			if !globalCandidates {
				return nil, nil, err
			}
			continue
		}
		parsed, err := parseEventFromEntry(entry.Entry)
		if err != nil {
			continue
		} // Unparseable envelopes and malformed role signatures cannot authenticate a payload.
		if parsed.event.Domain != domain {
			if !globalCandidates {
				return nil, nil, fmt.Errorf("dnsid: supplied bundle event is for another domain")
			}
			continue
		}
		if !proof.LogTime.IsZero() && parsed.event.Timestamp.After(proof.LogTime) {
			parsed.validationError = fmt.Errorf("dnsid: event timestamp is after accepted log timestamp")
		}
		signed, err := CanonicalFromEntry(entry.Entry)
		if err != nil {
			if !globalCandidates {
				return nil, nil, err
			}
			continue
		}
		verified = append(verified, verifiedEvent{event: parsed.event, chain: parsed.chain, index: proof.Index, signed: signed, parseError: parsed.validationError})
		if proof.Checkpoint != nil {
			verifiedProofs = append(verifiedProofs, proof)
		}
	}
	sort.SliceStable(verifiedProofs, func(i, j int) bool { return verifiedProofs[i].Checkpoint.Size < verifiedProofs[j].Checkpoint.Size })
	if err := c.advanceTrustedCheckpoints(ctx, verifiedProofs); err != nil {
		return nil, nil, dnsid.NewVerificationError(dnsid.VerificationCodeInvalidEvidence, false, "dnsid: invalid trusted c2sp-tlog checkpoint evidence", err)
	}
	sort.SliceStable(verified, func(i, j int) bool { return verified[i].index < verified[j].index })
	migrationVerifier := c.verifyMigration
	if migrationVerifier != nil {
		migrationVerifier = c.verifyBoundedMigration
	}
	accepted, priorHistory, err := verifyLifecycleVerifiedWithMigration(ctx, verified, migrationVerifier, c.ref.String())
	if err != nil {
		return nil, nil, err
	}
	if len(priorHistory) > 0 {
		maximum := migrationLimitsForContext(ctx, c.migrationLimits).MaxHistoryEvents
		if len(accepted) > maximum || len(priorHistory) > maximum-len(accepted) {
			return nil, nil, invalidMigration(fmt.Sprintf("dnsid: c2sp-tlog stitched migration history exceeds configured maximum %d", maximum), nil)
		}
	}
	events := make([]dnsidlog.LogEvent, 0, len(priorHistory)+len(accepted))
	events = append(events, priorHistory...)
	for _, item := range accepted {
		events = append(events, item.event)
	}
	return accepted, events, nil
}

func validateHistorySize(entries []ProvenEntry) error {
	if len(entries) > int(defaultScanMaxTreeSize) {
		return fmt.Errorf("dnsid: history exceeds entry limit")
	}
	var total int64
	for _, entry := range entries {
		total += int64(len(entry.Entry)) + int64(len(entry.Proof))
		if total > defaultScanMaxTotalEntryBytes {
			return fmt.Errorf("dnsid: history exceeds byte limit")
		}
	}
	return nil
}

func sameCheckpoint(a, b *formatlog.Checkpoint) bool {
	return a != nil && b != nil && a.Origin == b.Origin && a.Size == b.Size && bytes.Equal(a.Hash, b.Hash)
}

func (c *Client) verifyProvenEntry(proven ProvenEntry) (parsedEvent, *VerifiedProof, error) {
	proof, err := c.policy.VerifyProof(c.ref, proven.Entry, proven.Proof)
	if err != nil {
		return parsedEvent{}, nil, err
	}
	if c.policy.skipProofVerify {
		proof.Index = proven.Index
	}
	parsed, err := c.parseCandidateEntry(proven.Entry)
	if err != nil {
		return parsedEvent{}, nil, err
	}
	return parsed, proof, nil
}

func (c *Client) parseCandidateEntry(entry []byte) (parsedEvent, error) {
	if err := c.validateEntryMetadata(entry); err != nil {
		return parsedEvent{}, err
	}
	return parseEventFromEntry(entry)
}

func (c *Client) chainForWrite(event dnsidlog.LogEvent) (*chainFields, error) {
	if event.Type == dnsidlog.LogEventIssuance || c.isInboundMigration(event) {
		seq := uint64(0)
		return &chainFields{sequence: &seq}, nil
	}
	return nil, fmt.Errorf("dnsid: c2sp-tlog write requires chain fields via WriteEventWithChain")
}

func (c *Client) validateChain(event dnsidlog.LogEvent, chain Chain) error {
	if event.Type == dnsidlog.LogEventIssuance || c.isInboundMigration(event) {
		if chain.Sequence != 0 || chain.PreviousEventID != "" || chain.PreviousStateHash != "" {
			return fmt.Errorf("dnsid: c2sp-tlog genesis requires seq 0")
		}
		return nil
	}
	if chain.Sequence == 0 || !validHash(chain.PreviousEventID) || !validHash(chain.PreviousStateHash) {
		return fmt.Errorf("dnsid: c2sp-tlog write requires lifecycle chain fields")
	}
	return nil
}

func bindsKey(event dnsidlog.LogEvent, thumbprint string) bool {
	switch event.Type {
	case dnsidlog.LogEventIssuance:
		return event.InitialOperationalThumbprint == thumbprint
	case dnsidlog.LogEventMigration:
		// A migration-in genesis re-anchors the operational key in the new log.
		return event.InitialOperationalThumbprint == thumbprint
	case dnsidlog.LogEventKeyRotation:
		return event.NewOperationalThumbprint == thumbprint
	default:
		return false
	}
}

func (c *Client) validateEntryMetadata(entry []byte) error {
	payload, err := payloadObjectFromEntry(entry)
	if err != nil {
		return err
	}
	origin, err := c.ref.Origin()
	if err != nil {
		return err
	}
	if fqdn, _ := payload["fqdn"].(string); fqdn == c.ref.StreamID {
		return fmt.Errorf("dnsid: stream ID must identify an identity instance")
	}
	checks := map[string]string{
		"method":     Method,
		"log_origin": origin,
		"stream_id":  c.ref.StreamID,
		"lr":         c.ref.String(),
	}
	for key, want := range checks {
		got, ok := payload[key].(string)
		if !ok || got == "" {
			return fmt.Errorf("dnsid: c2sp-tlog event missing %q", key)
		}
		if ok && got != want {
			return fmt.Errorf("dnsid: c2sp-tlog event %s = %q, want %q", key, got, want)
		}
	}
	return nil
}

type errorReader struct {
	err error
}

func logVerificationError(err error, transient bool) error {
	if err == nil {
		return nil
	}
	var verificationErr *dnsid.VerificationError
	if errors.As(err, &verificationErr) {
		return err
	}
	var parseErr *dnsid.ParseError
	var validationErr *dnsid.ValidationError
	var argumentErr *dnsid.ArgumentError
	if errors.As(err, &parseErr) || errors.As(err, &validationErr) || errors.As(err, &argumentErr) {
		return err
	}
	return dnsid.NewVerificationError(dnsid.VerificationCodeLogError, resourceFailureTransient(err, transient), "dnsid: c2sp-tlog verification failed", err)
}

func resourceFailureTransient(err error, fallback bool) bool {
	var classified interface{ Transient() bool }
	if errors.As(err, &classified) {
		return classified.Transient()
	}
	return fallback
}

func (r errorReader) Canonical(dnsidlog.LogEvent) ([]byte, error) { return nil, r.err }
func (r errorReader) KeyTimestamp(context.Context, string, string) (time.Time, error) {
	return time.Time{}, r.err
}
func (r errorReader) VerifyBilateralBinding(context.Context, dnsidlog.BilateralBindingInput) (dnsidlog.BilateralBinding, error) {
	return dnsidlog.BilateralBinding{}, r.err
}
func (r errorReader) VerifyOperationalContinuity(context.Context, string, string, string) error {
	return r.err
}
func (r errorReader) VerifyGovernanceRelationship(context.Context, string, string) error {
	return r.err
}
func (r errorReader) VerifyNonRevocation(context.Context, string, time.Time) (dnsidlog.LoggedStateEvidence, error) {
	return dnsidlog.LoggedStateEvidence{}, r.err
}
func (r errorReader) ReadEvent(context.Context, dnsidlog.LogRef) (dnsidlog.LogEvent, error) {
	return dnsidlog.LogEvent{}, r.err
}
func (r errorReader) RebuildHistory(context.Context, string) ([]dnsidlog.LogEvent, error) {
	return nil, r.err
}
