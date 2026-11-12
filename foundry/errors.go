//go:build dnsid_foundry

package foundry

import (
	"errors"
	"fmt"
)

// ErrorKind classifies a Foundry workflow failure independently of server codes.
type ErrorKind string

// Workflow failure categories. Server wire codes remain unchanged in Error.Code.
const (
	KeyMissing           ErrorKind = "KEY_MISSING"
	KeyMismatch          ErrorKind = "KEY_MISMATCH"
	KeyRevoked           ErrorKind = "KEY_REVOKED"
	Busy                 ErrorKind = "busy"
	Deadline             ErrorKind = "deadline"
	UnsupportedContract  ErrorKind = "unsupported_contract"
	UnsupportedAlgorithm ErrorKind = "unsupported_algorithm"
	WorkflowOutcome      ErrorKind = "workflow_outcome"
	Terminal             ErrorKind = "terminal"
	Integrity            ErrorKind = "integrity"
	Unresolved           ErrorKind = "unresolved"
)

// Error preserves known facts and the original cause across interrupted calls.
type Error struct {
	Kind           ErrorKind
	Phase          string
	StatusCode     int
	Code           string
	IdentityID     string
	Domain         string
	RegistryStatus string
	Resumable      bool
	Cause          error
}

// Error returns the workflow facts, operator remedy, and cause.
func (e *Error) Error() string {
	text := fmt.Sprintf("foundry: %s (phase=%s, id=%q, domain=%q, code=%q)", e.Kind, e.Phase, e.IdentityID, e.Domain, e.Code)
	if e.Kind == KeyMissing {
		text += "; create the signing key first, for example through explicit KMS-first creation"
	}
	if e.Kind == KeyMismatch {
		text += "; use this identity's current provider key; run one identity per cloud provider"
	}
	if e.Cause != nil {
		text += ": " + e.Cause.Error()
	}
	return text
}

// Unwrap retains cancellation, transport, and registry error classification.
func (e *Error) Unwrap() error { return e.Cause }

// UnsupportedRegistry means onboarding or management detail lacks the required contract.
type UnsupportedRegistry struct{ Detail *Error }

// Error describes the unsupported registry contract.
func (e *UnsupportedRegistry) Error() string {
	return "foundry: unsupported registry: " + e.Detail.Error()
}

// Unwrap preserves structured workflow and HTTP facts.
func (e *UnsupportedRegistry) Unwrap() error { return e.Detail }

// SigningPaused rejects application signatures until the identity is verified.
type SigningPaused struct {
	Reason         string
	Phase          string
	IdentityID     string
	Domain         string
	RegistryStatus string
}

// Error describes why application signing is paused.
func (e *SigningPaused) Error() string { return "foundry: application signing is paused: " + e.Reason }

func failure(kind ErrorKind, doc *RecoveryDocument, cause error) *Error {
	e := &Error{Kind: kind, Cause: cause, Resumable: kind == Unresolved || kind == Busy || kind == Deadline}
	if doc != nil {
		e.Phase = doc.Phase
		e.IdentityID = doc.IdentityID
		e.Domain = doc.Domain
		e.RegistryStatus = doc.RegistryStatus
	}
	return e
}

func isKind(err error, kind ErrorKind) bool {
	var e *Error
	return errors.As(err, &e) && e.Kind == kind
}
