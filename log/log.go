package log

import (
	"context"
	"crypto"
	"encoding/base64"
	"fmt"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/dnsid-ai/dnsid-go/internal/sdkerrors"

	"github.com/lestrrat-go/jwx/v3/jwk"
)

var logMethodRE = regexp.MustCompile(`^[a-z][a-z0-9-]*$`)

// LogRef identifies an entry in a lifecycle log as {method}:{entry-ref}.
type LogRef string

// LogEventType is a lifecycle event type identifier.
type LogEventType string

// The lifecycle event types defined by DNSid draft 01.
const (
	// LogEventIssuance establishes the bilateral binding between an entity
	// key and an operational key for a domain. It is the genesis event of a
	// lifecycle stream.
	LogEventIssuance LogEventType = "ISSUANCE"
	// LogEventKeyRotation replaces the active operational key. It is signed
	// by both the outgoing and the incoming operational key.
	LogEventKeyRotation LogEventType = "KEY_ROTATION"
	// LogEventRevocation terminally revokes the identity. Its Reason must be
	// one of the codes accepted by ValidRevocationReason.
	LogEventRevocation LogEventType = "REVOCATION"
	// LogEventRetirement terminally retires the identity in good standing.
	LogEventRetirement LogEventType = "RETIREMENT"
	// LogEventMigration moves the lifecycle stream between logs; it links the
	// previous and new lr values and the final entry in the previous log.
	LogEventMigration LogEventType = "MIGRATION"
	// LogEventDelegation grants a scoped, expiring delegation to another
	// party without changing lifecycle state.
	LogEventDelegation LogEventType = "DELEGATION"
)

// ValidRevocationReason reports whether reason is a draft 01 REVOCATION reason code.
func ValidRevocationReason(reason string) bool {
	switch reason {
	case "keyCompromise", "policyViolation", "superseded", "cessationOfOperation":
		return true
	default:
		return false
	}
}

// AgentState is the canonical lifecycle state of a DNSid agent. The six
// states form the fixed protocol state machine (spec §Agent States).
// It is a defined type (not a type alias) to provide compile-time safety:
// callers must use the typed constants or ParseAgentState to construct values.
type AgentState string

// String implements fmt.Stringer.
func (s AgentState) String() string { return string(s) }

// IsValid reports whether s is one of the six canonical lifecycle states.
func (s AgentState) IsValid() bool {
	switch s {
	case AgentStatePending, AgentStateProvisioning, AgentStateVerifying, AgentStateActive, AgentStateRetired, AgentStateRevoked:
		return true
	default:
		return false
	}
}

// ParseAgentState converts a raw string (e.g. from a database column, JSON
// field, or registry response) into the typed AgentState. It returns an error
// if s is not one of the six canonical states.
func ParseAgentState(s string) (AgentState, error) {
	st := AgentState(s)
	if !st.IsValid() {
		return "", fmt.Errorf("unknown agent state: %q", s)
	}
	return st, nil
}

// The six canonical lifecycle states, in lifecycle order.
const (
	// AgentStatePending means the agent has been requested but not yet
	// provisioned.
	AgentStatePending AgentState = "PENDING"
	// AgentStateProvisioning means keys and records are being created.
	AgentStateProvisioning AgentState = "PROVISIONING"
	// AgentStateVerifying means the published identity record is awaiting
	// verification.
	AgentStateVerifying AgentState = "VERIFYING"
	// AgentStateActive means the agent identity is live and verifiable.
	AgentStateActive AgentState = "ACTIVE"
	// AgentStateRetired means the identity was terminally retired in good
	// standing.
	AgentStateRetired AgentState = "RETIRED"
	// AgentStateRevoked means the identity was terminally revoked.
	AgentStateRevoked AgentState = "REVOKED"
)

// allAgentStates lists every state in the fixed protocol state machine, in
// lifecycle order. Adding a state to AgentState means adding it here too. It is
// unexported so the fixed-six-states contract can't be mutated by callers;
// use AgentStates() to read it.
var allAgentStates = []AgentState{
	AgentStatePending,
	AgentStateProvisioning,
	AgentStateVerifying,
	AgentStateActive,
	AgentStateRetired,
	AgentStateRevoked,
}

// AgentStates returns the six canonical lifecycle states in order.
func AgentStates() []AgentState { return append([]AgentState(nil), allAgentStates...) }

// LogEvent is the SDK's method-agnostic lifecycle event carrier. Only the
// fields relevant to Type are populated; all other fields are left at their
// zero values and omitted from JSON. Signature fields hold unpadded base64url
// values. Key algorithms are read from the embedded JWKs. A log binding that
// does not independently encode initial thumbprints derives them from those
// JWKs before returning the shared event.
type LogEvent struct {
	Type LogEventType `json:"type"`

	InitialEntityKid              string  `json:"initialEntityKid,omitempty"`
	InitialEntityPublicKey        jwk.Key `json:"initialEntityPublicKey,omitempty"`
	InitialEntityThumbprint       string  `json:"initialEntityThumbprint,omitempty"`
	InitialEntitySignature        string  `json:"initialEntitySignature,omitempty"`
	InitialOperationalKid         string  `json:"initialOperationalKid,omitempty"`
	InitialOperationalPublicKey   jwk.Key `json:"initialOperationalPublicKey,omitempty"`
	InitialOperationalThumbprint  string  `json:"initialOperationalThumbprint,omitempty"`
	InitialOperationalSignature   string  `json:"initialOperationalSignature,omitempty"`
	PreviousOperationalKid        string  `json:"previousOperationalKid,omitempty"`
	PreviousOperationalThumbprint string  `json:"previousOperationalThumbprint,omitempty"`
	PreviousOperationalSignature  string  `json:"previousOperationalSignature,omitempty"`
	NewOperationalKid             string  `json:"newOperationalKid,omitempty"`
	NewOperationalPublicKey       jwk.Key `json:"newOperationalPublicKey,omitempty"`
	NewOperationalThumbprint      string  `json:"newOperationalThumbprint,omitempty"`
	NewOperationalSignature       string  `json:"newOperationalSignature,omitempty"`

	Domain       string    `json:"domain,omitempty"`
	Timestamp    time.Time `json:"timestamp,omitempty"`
	GovernanceID string    `json:"governanceId,omitempty"`

	Reason        string    `json:"reason,omitempty"`
	PreviousLog   string    `json:"previousLog,omitempty"`
	NewLog        string    `json:"newLog,omitempty"`
	FinalEntryRef string    `json:"finalEntryRef,omitempty"`
	Delegatee     string    `json:"delegatee,omitempty"`
	Scope         string    `json:"scope,omitempty"`
	Expiry        time.Time `json:"expiry,omitempty"`
}

// Log writes signed lifecycle events for a local identity.
type Log interface {
	// Canonical returns the canonical byte encoding of event that lifecycle
	// signatures are computed over.
	Canonical(event LogEvent) ([]byte, error)
	// WriteEvent appends a fully signed event to the log and returns the
	// reference of the stored entry.
	WriteEvent(ctx context.Context, event LogEvent) (LogRef, error)
}

// BilateralBindingInput is the current DNS record material checked against an
// ISSUANCE event. It is log-owned to avoid coupling log bindings to the root
// package's TXT record representation.
type BilateralBindingInput struct {
	Domain         string
	GovernanceID   string
	EntityKey      jwk.Key
	OperationalKey jwk.Key
}

// BilateralBinding is the verified key anchor established by ISSUANCE.
type BilateralBinding struct {
	InitialOperationalThumbprint string
	InitialEntityThumbprint      string
	Timestamp                    time.Time
}

// LoggedStateEvidence records the proof boundary accepted for a complete
// lifecycle-state decision. LoggedState is historical log state, not current
// protocol status. HistoryStart and HistoryEnd bound the referenced log stream.
// PriorEvidence retains the independently verified boundaries imported by
// inbound migrations, oldest first. Checkpoint and CompleteThrough are opaque
// to callers.
type LoggedStateEvidence struct {
	LogReference     LogRef
	LoggedState      AgentState
	HistoryStart     LogRef
	HistoryEnd       LogRef
	CompleteThrough  string
	CompletenessMode string
	Checkpoint       []byte
	FreshnessTime    time.Time
	PriorEvidence    []LoggedStateEvidence
}

// LogReader reads and verifies lifecycle evidence for one bound lr value.
type LogReader interface {
	// Canonical returns the canonical byte encoding of event that lifecycle
	// signatures are verified over.
	Canonical(event LogEvent) ([]byte, error)
	// KeyTimestamp returns the signed lifecycle-event time at which keyThumbprint
	// became the domain's active operational key. It returns an error if the key
	// is not currently bound.
	KeyTimestamp(ctx context.Context, domain, keyThumbprint string) (time.Time, error)
	// VerifyBilateralBinding verifies the ISSUANCE proofs, entity and operational
	// signatures, and correspondence with the current DNS record.
	VerifyBilateralBinding(ctx context.Context, input BilateralBindingInput) (BilateralBinding, error)
	// VerifyOperationalContinuity verifies a rotation chain from the ISSUANCE
	// operational key to the current operational key.
	VerifyOperationalContinuity(ctx context.Context, domain, initialOperationalThumbprint, currentOperationalThumbprint string) error
	// VerifyNonRevocation verifies that the identity was not revoked or
	// retired as of time at. It requires evidence that the observed history
	// is complete and fresh, and returns the accepted proof boundary.
	VerifyNonRevocation(ctx context.Context, domain string, at time.Time) (LoggedStateEvidence, error)
	// ReadEvent reads and verifies the single event stored at ref.
	ReadEvent(ctx context.Context, ref LogRef) (LogEvent, error)
	// RebuildHistory returns the domain's verified lifecycle events in log
	// order, dropping or rejecting entries that fail verification according
	// to the method's evidence model.
	RebuildHistory(ctx context.Context, domain string) ([]LogEvent, error)
}

// LifecycleBindingVerifier optionally combines bilateral-binding and
// operational-continuity verification over one consistent log snapshot.
// IdentityManager uses this fast path when available and otherwise calls the
// corresponding LogReader methods separately.
type LifecycleBindingVerifier interface {
	VerifyLifecycleBinding(ctx context.Context, input BilateralBindingInput, currentOperationalThumbprint string) (BilateralBinding, error)
}

// LogRegistry maps log method names to bound LogReader factories.
type LogRegistry struct {
	mu        sync.RWMutex
	factories map[string]func(lr string) LogReader
}

// NewLogRegistry returns an empty registry with no methods registered.
func NewLogRegistry() *LogRegistry {
	return &LogRegistry{factories: make(map[string]func(string) LogReader)}
}

// Register binds factory to a log method name. The method must be lowercase
// alphanumeric-with-hyphens ([a-z][a-z0-9-]*) and factory must be non-nil;
// otherwise Register returns an error. Registering an already-registered
// method replaces its factory. Register is safe for concurrent use.
func (r *LogRegistry) Register(method string, factory func(lr string) LogReader) error {
	if !logMethodRE.MatchString(method) {
		return sdkerrors.NewArgumentError(fmt.Sprintf("dnsid: invalid log method %q", method), nil)
	}
	if factory == nil {
		return sdkerrors.NewArgumentError("dnsid: nil log reader factory", nil)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.factories[method] = factory
	return nil
}

// NewReader returns a LogReader bound to the lr value. It returns an error
// only when lr is malformed; a nil registry, an unregistered method, or a
// factory that returns nil all yield a NoopLogReader, so evidence failures
// surface at verification time rather than at construction. NewReader is safe
// for concurrent use.
func (r *LogRegistry) NewReader(lr string) (LogReader, error) {
	method, _, err := ParseLogRef(lr)
	if err != nil {
		return nil, err
	}
	if r == nil {
		return NoopLogReader{Method: method}, nil
	}
	r.mu.RLock()
	factory := r.factories[method]
	r.mu.RUnlock()
	if factory == nil {
		return NoopLogReader{Method: method}, nil
	}
	reader := factory(lr)
	if reader == nil {
		return NoopLogReader{Method: method}, nil
	}
	return reader, nil
}

// ParseLogRef splits an lr value into its method and entry reference at the
// first colon. It returns an error if lr has no colon, an empty method, or a
// method that is not lowercase alphanumeric-with-hyphens.
func ParseLogRef(lr string) (method, entryRef string, err error) {
	idx := strings.IndexByte(lr, ':')
	if idx <= 0 {
		return "", "", sdkerrors.NewParseError("dnsid: malformed log reference", nil)
	}
	method, entryRef = lr[:idx], lr[idx+1:]
	if !logMethodRE.MatchString(method) {
		return "", "", sdkerrors.NewParseError("dnsid: invalid log method", nil)
	}
	return method, entryRef, nil
}

// VerificationError is a structured lifecycle-log verification failure.
type VerificationError struct {
	code      string
	transient bool
	message   string
}

// Error implements the error interface; it returns the failure message.
func (e *VerificationError) Error() string { return e.message }

// Code returns the machine-readable failure code (for example "log_error").
func (e *VerificationError) Code() string { return e.code }

// Message returns the human-readable failure message.
func (e *VerificationError) Message() string { return e.message }

// Transient reports whether retrying the operation may succeed.
func (e *VerificationError) Transient() bool { return e.transient }

// Lifecycle verification codes are shared across SDK reducer conformance tests.
const (
	VerificationCodeGenesisRequired         = "GENESIS_REQUIRED"
	VerificationCodeDuplicateIssuance       = "DUPLICATE_ISSUANCE"
	VerificationCodeInvalidIssuance         = "INVALID_ISSUANCE"
	VerificationCodeTerminalState           = "TERMINAL_STATE"
	VerificationCodeDomainMismatch          = "DOMAIN_MISMATCH"
	VerificationCodeKeyContinuity           = "KEY_CONTINUITY"
	VerificationCodeInvalidRevocationReason = "INVALID_REVOCATION_REASON"
	VerificationCodeInvalidMigration        = "INVALID_MIGRATION"
	VerificationCodeSnapshotEmpty           = "SNAPSHOT_EMPTY"
	VerificationCodeSnapshotNonPrefix       = "SNAPSHOT_NON_PREFIX"
	VerificationCodeUnsupportedEvent        = "UNSUPPORTED_EVENT"
)

// NoopLogReader fails every evidence operation for an unregistered method.
// Each method returns a *VerificationError with code "log_error" naming the
// unregistered Method; the error is not transient.
type NoopLogReader struct{ Method string }

func (n NoopLogReader) err() error {
	return &VerificationError{code: "log_error", message: fmt.Sprintf("dnsid: no LogReader registered for method %q", n.Method)}
}

// Canonical implements LogReader; it always fails.
func (n NoopLogReader) Canonical(LogEvent) ([]byte, error) { return nil, n.err() }

// KeyTimestamp implements LogReader; it always fails.
func (n NoopLogReader) KeyTimestamp(context.Context, string, string) (time.Time, error) {
	return time.Time{}, n.err()
}

// VerifyBilateralBinding implements LogReader; it always fails.
func (n NoopLogReader) VerifyBilateralBinding(context.Context, BilateralBindingInput) (BilateralBinding, error) {
	return BilateralBinding{}, n.err()
}

// VerifyOperationalContinuity implements LogReader; it always fails.
func (n NoopLogReader) VerifyOperationalContinuity(context.Context, string, string, string) error {
	return n.err()
}

// VerifyNonRevocation implements LogReader; it always fails.
func (n NoopLogReader) VerifyNonRevocation(context.Context, string, time.Time) (LoggedStateEvidence, error) {
	return LoggedStateEvidence{}, n.err()
}

// ReadEvent implements LogReader; it always fails.
func (n NoopLogReader) ReadEvent(context.Context, LogRef) (LogEvent, error) {
	return LogEvent{}, n.err()
}

// RebuildHistory implements LogReader; it always fails.
func (n NoopLogReader) RebuildHistory(context.Context, string) ([]LogEvent, error) {
	return nil, n.err()
}

// DomainLog is a verified lifecycle event history for a domain.
type DomainLog struct {
	domain string
	events []LogEvent
}

// NewDomainLog constructs a DomainLog over events already verified by a
// LogReader. It copies the events slice; events must be in log order.
func NewDomainLog(domain string, events []LogEvent) *DomainLog {
	return &DomainLog{domain: domain, events: append([]LogEvent(nil), events...)}
}

// Domain returns the domain the history belongs to. It returns "" on a nil
// receiver.
func (l *DomainLog) Domain() string {
	if l == nil {
		return ""
	}
	return l.domain
}

// Events returns a copy of the lifecycle events in log order. It returns nil
// on a nil receiver.
func (l *DomainLog) Events() []LogEvent {
	if l == nil {
		return nil
	}
	return append([]LogEvent(nil), l.events...)
}

// DomainSnapshot is the materialized lifecycle state at a point in time.
// HistoricalState holds one of the AgentState* values; ActiveKey, ActiveKeyThumbprint,
// and KeyBoundAt describe the operational key in effect at SnapshotAt; Events
// holds the lifecycle prefix the snapshot was materialized from.
type DomainSnapshot struct {
	Domain              string
	HistoricalState     AgentState
	ActiveKey           jwk.Key
	ActiveKeyThumbprint string
	KeyBoundAt          time.Time
	GovernanceID        string
	SnapshotAt          time.Time
	Events              []LogEvent
}

// SnapshotAt replays the domain's events with timestamps at or before at and
// returns the resulting lifecycle state. It enforces the lifecycle state
// machine while replaying and returns an error if the log is empty, if the
// events at or before at are not a contiguous prefix of the log, if no
// ISSUANCE event is found, or if an event sequence is invalid (for example,
// a rotation before issuance or a non-migration event after a terminal
// state). Events for other domains are ignored.
func (l *DomainLog) SnapshotAt(at time.Time) (*DomainSnapshot, error) {
	if l == nil || len(l.events) == 0 {
		return nil, lifecycleError(VerificationCodeSnapshotEmpty, -1, "no lifecycle events")
	}
	s := &DomainSnapshot{Domain: l.domain, SnapshotAt: at}
	pastSnapshotBoundary := false
	for index, event := range l.events {
		if !strings.EqualFold(event.Domain, l.domain) {
			return nil, lifecycleError(VerificationCodeDomainMismatch, index, "lifecycle event domain %q does not match %q", event.Domain, l.domain)
		}
		if event.Timestamp.After(at) {
			pastSnapshotBoundary = true
			continue
		}
		if pastSnapshotBoundary {
			return nil, lifecycleError(VerificationCodeSnapshotNonPrefix, index, "snapshot time is not a verified lifecycle prefix for %s", l.domain)
		}
		if s.HistoricalState == "" && event.Type != LogEventIssuance {
			return nil, lifecycleError(VerificationCodeGenesisRequired, index, "first lifecycle event must be ISSUANCE")
		}
		if s.HistoricalState == AgentStateRevoked || s.HistoricalState == AgentStateRetired {
			return nil, lifecycleError(VerificationCodeTerminalState, index, "lifecycle event %s after terminal state %s", event.Type, s.HistoricalState)
		}
		s.Events = append(s.Events, event)
		switch event.Type {
		case LogEventIssuance:
			if s.HistoricalState != "" {
				return nil, lifecycleError(VerificationCodeDuplicateIssuance, index, "duplicate ISSUANCE in one identity history")
			}
			operationalThumb, err := keyThumbprint(event.InitialOperationalPublicKey)
			if err != nil || event.InitialEntityPublicKey == nil || event.InitialOperationalThumbprint == "" || operationalThumb != event.InitialOperationalThumbprint {
				return nil, lifecycleError(VerificationCodeInvalidIssuance, index, "ISSUANCE key binding is invalid")
			}
			entityThumb, err := keyThumbprint(event.InitialEntityPublicKey)
			if err != nil || event.InitialEntityThumbprint == "" || entityThumb != event.InitialEntityThumbprint || entityThumb == operationalThumb {
				return nil, lifecycleError(VerificationCodeInvalidIssuance, index, "ISSUANCE entity and operational keys must be distinct")
			}
			s.HistoricalState = AgentStateActive
			s.ActiveKey = event.InitialOperationalPublicKey
			s.ActiveKeyThumbprint = event.InitialOperationalThumbprint
			s.KeyBoundAt = event.Timestamp
			s.GovernanceID = event.GovernanceID
		case LogEventKeyRotation:
			if s.HistoricalState != AgentStateActive || event.PreviousOperationalThumbprint != s.ActiveKeyThumbprint {
				return nil, lifecycleError(VerificationCodeKeyContinuity, index, "KEY_ROTATION does not continue from the active key")
			}
			newThumb, err := keyThumbprint(event.NewOperationalPublicKey)
			if err != nil || event.NewOperationalThumbprint == "" || newThumb != event.NewOperationalThumbprint || newThumb == s.ActiveKeyThumbprint {
				return nil, lifecycleError(VerificationCodeKeyContinuity, index, "KEY_ROTATION new key is invalid")
			}
			s.ActiveKey = event.NewOperationalPublicKey
			s.ActiveKeyThumbprint = event.NewOperationalThumbprint
			s.KeyBoundAt = event.Timestamp
		case LogEventRevocation:
			if !ValidRevocationReason(event.Reason) {
				return nil, lifecycleError(VerificationCodeInvalidRevocationReason, index, "invalid REVOCATION reason %q", event.Reason)
			}
			s.HistoricalState = AgentStateRevoked
		case LogEventRetirement:
			s.HistoricalState = AgentStateRetired
		case LogEventMigration:
			if event.PreviousLog == "" || event.NewLog == "" || event.FinalEntryRef == "" || event.PreviousLog == event.NewLog {
				return nil, lifecycleError(VerificationCodeInvalidMigration, index, "MIGRATION must hand off between different log references")
			}
		case LogEventDelegation:
			// Delegation does not change core identity or key state.
		default:
			return nil, lifecycleError(VerificationCodeUnsupportedEvent, index, "unsupported lifecycle event type %q", event.Type)
		}
	}
	if s.HistoricalState == "" || s.ActiveKey == nil {
		return nil, lifecycleError(VerificationCodeSnapshotEmpty, -1, "no ISSUANCE event found at snapshot time")
	}
	return s, nil
}

func keyThumbprint(key jwk.Key) (string, error) {
	if key == nil {
		return "", fmt.Errorf("missing key")
	}
	sum, err := key.Thumbprint(crypto.SHA256)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(sum), nil
}

func lifecycleError(category string, eventIndex int, format string, args ...any) error {
	message := fmt.Sprintf(format, args...)
	if eventIndex >= 0 {
		message = fmt.Sprintf("event %d: %s", eventIndex, message)
	}
	return &VerificationError{code: category, message: "dnsid: " + message}
}
