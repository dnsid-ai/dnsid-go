package dnsid

import "github.com/dnsid-ai/dnsid-go/internal/sdkerrors"

// VerificationCode is a machine-readable classifier for *VerificationError.
// Codes group failures by cause so callers can branch on type without
// pattern-matching on error strings.
type VerificationCode string

// Core verification codes defined by the language-agnostic SDK contract.
const (
	VerificationCodeDNSResolution     VerificationCode = "dns_resolution"
	VerificationCodeDNSSECFailed      VerificationCode = "dnssec_failed"
	VerificationCodeRecordInvalid     VerificationCode = "record_invalid"
	VerificationCodeSignatureInvalid  VerificationCode = "signature_invalid"
	VerificationCodeTLSError          VerificationCode = "tls_error"
	VerificationCodeKeyAgeExceeded    VerificationCode = "key_age_exceeded"
	VerificationCodeStatusUnavailable VerificationCode = "status_unavailable"
	VerificationCodeStatusNotActive   VerificationCode = "status_not_active"
	VerificationCodeLogError          VerificationCode = "log_error"
	// VerificationCodeCounterpartyNotAccepted reports that configured
	// VerificationConfig.TrustedEntities policy denied a counterparty whose
	// DNSid record verified. Always permanent.
	VerificationCodeCounterpartyNotAccepted VerificationCode = "counterparty_not_accepted"
)

// Lifecycle log verification codes emitted when strict lifecycle state-machine
// enforcement rejects an agent's log evidence. Values are the uppercase
// identifiers defined by the cross-SDK lifecycle contract.
const (
	VerificationCodeChainContinuity   VerificationCode = "CHAIN_CONTINUITY"
	VerificationCodeDuplicateIssuance VerificationCode = "DUPLICATE_ISSUANCE"
	VerificationCodeInvalidEvidence   VerificationCode = "INVALID_EVIDENCE"
	VerificationCodeIncompleteStream  VerificationCode = "INCOMPLETE_STREAM"
	VerificationCodeKeyContinuity     VerificationCode = "KEY_CONTINUITY"
	VerificationCodeInvalidMigration  VerificationCode = "INVALID_MIGRATION"
	VerificationCodeTerminalState     VerificationCode = "TERMINAL_STATE"
)

// VerificationCodeJWKSUnavailable is a Go binding extension for JWKS fetch
// failures, which the core contract does not otherwise name.
const VerificationCodeJWKSUnavailable VerificationCode = "jwks_unavailable"

// Application-profile codes retained for JOSE, HTTP-signature, and OIDC
// callers. Core VerifyDomain does not emit these codes.
//
// VerificationCodeAudienceMismatch, VerificationCodeIssuerMismatch, and
// VerificationCodeLifetimeTooLong are specific claim-validation failures.
// They are children of VerificationCodeInvalidClaims for errors.Is
// purposes: an error with one of these codes also satisfies
// errors.Is(err, ErrInvalidClaims). See VerificationError.Is.
const (
	VerificationCodeKeyNotFound        VerificationCode = "key_not_found"
	VerificationCodeAgentNotFound      VerificationCode = "agent_not_found"
	VerificationCodeTokenExpired       VerificationCode = "token_expired"
	VerificationCodeTokenNotYetValid   VerificationCode = "token_not_yet_valid"
	VerificationCodeMalformedToken     VerificationCode = "malformed_token"
	VerificationCodeInvalidClaims      VerificationCode = "invalid_claims"
	VerificationCodeAudienceMismatch   VerificationCode = "audience_mismatch"
	VerificationCodeIssuerMismatch     VerificationCode = "issuer_mismatch"
	VerificationCodeLifetimeTooLong    VerificationCode = "lifetime_too_long"
	VerificationCodePolicyNotSatisfied VerificationCode = "policy_not_satisfied"
)

// Sentinel verification errors. Defined as *VerificationError exemplars so
// callers can branch with errors.Is or errors.As. Matching is code-based: a
// freshly-constructed VerificationError with the same Code satisfies errors.Is
// against the sentinel.
var (
	ErrTokenExpired = &VerificationError{
		code:    VerificationCodeTokenExpired,
		message: "dnsid: token expired",
	}
	ErrTokenNotYetValid = &VerificationError{
		code:    VerificationCodeTokenNotYetValid,
		message: "dnsid: token not yet valid",
	}
	ErrInvalidSignature = &VerificationError{
		code:    VerificationCodeSignatureInvalid,
		message: "dnsid: invalid signature",
	}
	ErrMalformedToken = &VerificationError{
		code:    VerificationCodeMalformedToken,
		message: "dnsid: malformed token",
	}
	ErrInvalidClaims = &VerificationError{
		code:    VerificationCodeInvalidClaims,
		message: "dnsid: invalid claims",
	}
	ErrLifetimeTooLong = &VerificationError{
		code:    VerificationCodeLifetimeTooLong,
		message: "dnsid: requested lifetime exceeds maximum",
	}
	ErrCounterpartyNotAccepted = &VerificationError{
		code:    VerificationCodeCounterpartyNotAccepted,
		message: "dnsid: counterparty not accepted",
	}
)

// ParseError is the shared SDK ParseError category.
type ParseError = sdkerrors.ParseError

// NewParseError creates a parse error with an optional underlying cause.
func NewParseError(msg string, cause error) *ParseError { return sdkerrors.NewParseError(msg, cause) }

// ValidationError is returned when input parses successfully but fails a
// semantic or structural rule: required tags missing, FQDN normalization
// violations, policy-flag whitelist violations, host equality checks, etc.
// A ValidationError is always permanent.
type ValidationError struct {
	Message string
	Cause   error
}

// NewValidationError constructs a ValidationError wrapping cause with msg.
func NewValidationError(msg string, cause error) *ValidationError {
	return &ValidationError{Message: msg, Cause: cause}
}

// Error implements error.
func (e *ValidationError) Error() string {
	if e == nil {
		return "<nil>"
	}
	if e.Cause != nil {
		if e.Message == "" {
			return e.Cause.Error()
		}
		return e.Message + ": " + e.Cause.Error()
	}
	return e.Message
}

// Unwrap returns the wrapped cause, if any.
func (e *ValidationError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Cause
}

// Is matches any other *ValidationError. ValidationError is a category,
// not an identity: errors.Is(anyValidationError, anyOther) returns true.
// Use errors.As to read Message / Cause.
func (e *ValidationError) Is(target error) bool {
	_, ok := target.(*ValidationError)
	return ok
}

// ArgumentError is the shared SDK ArgumentError category.
type ArgumentError = sdkerrors.ArgumentError

// NewArgumentError creates an argument error with an optional underlying cause.
func NewArgumentError(msg string, cause error) *ArgumentError {
	return sdkerrors.NewArgumentError(msg, cause)
}

// VerificationError is returned when runtime verification fails: signature
// mismatch, JWKS fetch failure, status check failure, key not found,
// revoked agent, expired/invalid token, etc. The Code classifies the
// failure; Transient indicates whether retrying might succeed.
//
// Fields are unexported and accessed via Code(), Transient(),
// AgentState(), and Message(). This prevents accidental mutation of the
// package-level sentinel values (ErrTokenExpired, ErrTXTRecordNotFound,
// etc.) that callers may obtain via errors.As. The wrapped cause is
// exposed via Unwrap().
type VerificationError struct {
	code       VerificationCode
	transient  bool
	agentState AgentState
	message    string
	cause      error
	// Observed identity for VerificationCodeCounterpartyNotAccepted only.
	verifiedGovernanceID        string
	verifiedEntityKeyThumbprint string
}

// VerificationErrorOption configures optional fields on a VerificationError.
type VerificationErrorOption func(*VerificationError)

// WithAgentState attaches an agent state to a VerificationError.
// Used when a status check returned a specific state (e.g. "revoked").
func WithAgentState(state AgentState) VerificationErrorOption {
	return func(e *VerificationError) { e.agentState = state }
}

// WithVerifiedIdentity records the observed verified governance ID and
// record-signing key thumbprint on a counterparty acceptance denial. It never
// carries configured allowlist or pin values.
func WithVerifiedIdentity(governanceID, entityKeyThumbprint string) VerificationErrorOption {
	return func(e *VerificationError) {
		e.verifiedGovernanceID = governanceID
		e.verifiedEntityKeyThumbprint = entityKeyThumbprint
	}
}

// NewVerificationError constructs a VerificationError.
func NewVerificationError(code VerificationCode, transient bool, msg string, cause error, opts ...VerificationErrorOption) *VerificationError {
	e := &VerificationError{
		code:      code,
		transient: transient,
		message:   msg,
		cause:     cause,
	}
	for _, opt := range opts {
		opt(e)
	}
	return e
}

// Code returns the failure classifier.
func (e *VerificationError) Code() VerificationCode {
	if e == nil {
		return ""
	}
	return e.code
}

// Transient reports whether retrying might succeed.
func (e *VerificationError) Transient() bool {
	if e == nil {
		return false
	}
	return e.transient
}

// AgentState returns the agent state recorded with this error, if any
// (populated when a status check returned a specific state).
func (e *VerificationError) AgentState() AgentState {
	if e == nil {
		return ""
	}
	return e.agentState
}

// VerifiedGovernanceID returns the observed verified governance ID for a
// VerificationCodeCounterpartyNotAccepted error; empty for other codes.
func (e *VerificationError) VerifiedGovernanceID() string {
	if e == nil {
		return ""
	}
	return e.verifiedGovernanceID
}

// VerifiedEntityKeyThumbprint returns the observed verified record-signing
// key's RFC 7638 SHA-256 thumbprint for a
// VerificationCodeCounterpartyNotAccepted error; empty for other codes.
func (e *VerificationError) VerifiedEntityKeyThumbprint() string {
	if e == nil {
		return ""
	}
	return e.verifiedEntityKeyThumbprint
}

// Message returns the human-readable detail string.
func (e *VerificationError) Message() string {
	if e == nil {
		return ""
	}
	return e.message
}

// Error implements error.
func (e *VerificationError) Error() string {
	if e == nil {
		return "<nil>"
	}
	msg := e.message
	if msg == "" {
		msg = string(e.code)
	}
	if e.agentState != "" {
		msg = msg + " [agent_state=" + string(e.agentState) + "]"
	}
	if e.cause != nil {
		return msg + ": " + e.cause.Error()
	}
	return msg
}

// Unwrap returns the wrapped cause, if any.
func (e *VerificationError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.cause
}

// invalidClaimsChildren lists codes that are sub-categories of
// VerificationCodeInvalidClaims. A VerificationError carrying any of these
// codes satisfies errors.Is against ErrInvalidClaims, preserving the broader
// "invalid claims" contract while letting callers branch on the specific
// failure when they want to.
var invalidClaimsChildren = map[VerificationCode]bool{
	VerificationCodeAudienceMismatch: true,
	VerificationCodeIssuerMismatch:   true,
	VerificationCodeLifetimeTooLong:  true,
}

// Is matches another *VerificationError with the same Code. It also matches
// a sentinel exemplar whose Code is a parent category of the receiver's Code
// (see invalidClaimsChildren). This lets callers compare against a sentinel —
// e.g. errors.Is(err, ErrTXTRecordNotFound) — without holding the original
// pointer, and lets specific claim errors satisfy the broader
// errors.Is(err, ErrInvalidClaims) check.
func (e *VerificationError) Is(target error) bool {
	t, ok := target.(*VerificationError)
	if !ok {
		return false
	}
	if e.code == t.code {
		return true
	}
	if t.code == VerificationCodeInvalidClaims && invalidClaimsChildren[e.code] {
		return true
	}
	return false
}

// Compile-time interface checks.
var (
	_ error = (*ParseError)(nil)
	_ error = (*ValidationError)(nil)
	_ error = (*ArgumentError)(nil)
	_ error = (*VerificationError)(nil)
)
