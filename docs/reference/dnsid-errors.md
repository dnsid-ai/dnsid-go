---
title: "Go: dnsid — errors"
description: "Typed errors and verification codes returned across the SDK."
---

> Generated from the Go source by scripts/gen-docs.sh — do not edit; run it to regenerate.
> Canonical deep reference: [pkg.go.dev/github.com/dnsid-ai/dnsid-go](https://pkg.go.dev/github.com/dnsid-ai/dnsid-go).
> Guides and account setup: [https://docs.dnsid.ai](https://docs.dnsid.ai).

Part of the root package `github.com/dnsid-ai/dnsid-go` — see [Core: IdentityManager](https://docs.dnsid.ai/reference/go/dnsid) for the package overview.

## func [MissingRequiredField](<https://github.com/dnsid-ai/dnsid-go/blob/main/identity_record.go#L139>)

```go
func MissingRequiredField(rec *TXTRecord) string
```

MissingRequiredField returns the first missing required non\-signature DNSid TXT tag name, or "" if the unsigned record has all required signing inputs.

<a name="NormalizeFQDN"></a>
## type [AgentError](<https://github.com/dnsid-ai/dnsid-go/blob/main/registry.go#L226-L231>)

AgentError matches the OpenAPI AgentError schema.

```go
type AgentError struct {
    Code        string `json:"code"`
    Title       string `json:"title"`
    Detail      string `json:"detail"`
    Remediation string `json:"remediation"`
}
```

<a name="AgentEvent"></a>
## type [ArgumentError](<https://github.com/dnsid-ai/dnsid-go/blob/main/errors.go#L151>)

ArgumentError is the shared SDK ArgumentError category.

```go
type ArgumentError = sdkerrors.ArgumentError
```

<a name="NewArgumentError"></a>
### func [NewArgumentError](<https://github.com/dnsid-ai/dnsid-go/blob/main/errors.go#L154>)

```go
func NewArgumentError(msg string, cause error) *ArgumentError
```

NewArgumentError creates an argument error with an optional underlying cause.

<a name="CanonicalRecordContentResponse"></a>
## type [ParseError](<https://github.com/dnsid-ai/dnsid-go/blob/main/errors.go#L101>)

ParseError is the shared SDK ParseError category.

```go
type ParseError = sdkerrors.ParseError
```

<a name="NewParseError"></a>
### func [NewParseError](<https://github.com/dnsid-ai/dnsid-go/blob/main/errors.go#L104>)

```go
func NewParseError(msg string, cause error) *ParseError
```

NewParseError creates a parse error with an optional underlying cause.

<a name="PolicyFlag"></a>
## type [RegistryAPIError](<https://github.com/dnsid-ai/dnsid-go/blob/main/registry.go#L1314-L1319>)

RegistryAPIError represents a registry transport failure or non\-2xx API response. The registry error schema uses fields "error" and "message".

```go
type RegistryAPIError struct {
    StatusCode int
    Code       string `json:"error,omitempty"`
    Message    string `json:"message,omitempty"`
    Cause      error  `json:"-"`
}
```

<a name="RegistryAPIError.Error"></a>
### func \(\*RegistryAPIError\) [Error](<https://github.com/dnsid-ai/dnsid-go/blob/main/registry.go#L1323>)

```go
func (e *RegistryAPIError) Error() string
```

Error implements error, formatting the HTTP status with the registry's error code and message when present.

<a name="RegistryAPIError.RetrySameEntry"></a>
### func \(\*RegistryAPIError\) [RetrySameEntry](<https://github.com/dnsid-ai/dnsid-go/blob/main/registry.go#L1354>)

```go
func (e *RegistryAPIError) RetrySameEntry() bool
```

RetrySameEntry reports whether the registry requires retrying the exact submitted bytes with the same idempotency key. An unclassified HTTP 5xx is indeterminate and therefore also requires an exact\-byte retry. Known terminal protocol errors override that transport\-level fallback.

<a name="RegistryAPIError.SubmissionState"></a>
### func \(\*RegistryAPIError\) [SubmissionState](<https://github.com/dnsid-ai/dnsid-go/blob/main/registry.go#L1372>)

```go
func (e *RegistryAPIError) SubmissionState() SubmissionState
```

SubmissionState maps a prepared\-event submission failure to the durable lifecycle state shared by managed coordinators.

<a name="RegistryAPIError.Transient"></a>
### func \(\*RegistryAPIError\) [Transient](<https://github.com/dnsid-ai/dnsid-go/blob/main/registry.go#L1396>)

```go
func (e *RegistryAPIError) Transient() bool
```

Transient reports whether retrying the registry operation may succeed. Prepared\-event callers must additionally honor RetrySameEntry so a retry never regenerates signed bytes.

<a name="RegistryAPIError.Unwrap"></a>
### func \(\*RegistryAPIError\) [Unwrap](<https://github.com/dnsid-ai/dnsid-go/blob/main/registry.go#L1343>)

```go
func (e *RegistryAPIError) Unwrap() error
```

Unwrap returns the underlying transport failure, if any.

<a name="RegistryClient"></a>
## type [RegistryWorkflowError](<https://github.com/dnsid-ai/dnsid-go/blob/main/registry.go#L1584-L1588>)

RegistryWorkflowError reports a terminal or interrupted registry workflow.

```go
type RegistryWorkflowError struct {
    Registration *AgentRegistration
    Status       string
    Cause        error
}
```

<a name="RegistryWorkflowError.Error"></a>
### func \(\*RegistryWorkflowError\) [Error](<https://github.com/dnsid-ai/dnsid-go/blob/main/registry.go#L1592>)

```go
func (e *RegistryWorkflowError) Error() string
```

Error implements error, naming the terminal workflow status when the registration is available.

<a name="RegistryWorkflowError.Unwrap"></a>
### func \(\*RegistryWorkflowError\) [Unwrap](<https://github.com/dnsid-ai/dnsid-go/blob/main/registry.go#L1610>)

```go
func (e *RegistryWorkflowError) Unwrap() error
```

Unwrap returns the cancellation or timeout that interrupted the workflow.

<a name="RetireAgentRequest"></a>
## type [ValidationError](<https://github.com/dnsid-ai/dnsid-go/blob/main/errors.go#L110-L113>)

ValidationError is returned when input parses successfully but fails a semantic or structural rule: required tags missing, FQDN normalization violations, policy\-flag whitelist violations, host equality checks, etc. A ValidationError is always permanent.

```go
type ValidationError struct {
    Message string
    Cause   error
}
```

<a name="NewValidationError"></a>
### func [NewValidationError](<https://github.com/dnsid-ai/dnsid-go/blob/main/errors.go#L116>)

```go
func NewValidationError(msg string, cause error) *ValidationError
```

NewValidationError constructs a ValidationError wrapping cause with msg.

<a name="ValidationError.Error"></a>
### func \(\*ValidationError\) [Error](<https://github.com/dnsid-ai/dnsid-go/blob/main/errors.go#L121>)

```go
func (e *ValidationError) Error() string
```

Error implements error.

<a name="ValidationError.Is"></a>
### func \(\*ValidationError\) [Is](<https://github.com/dnsid-ai/dnsid-go/blob/main/errors.go#L145>)

```go
func (e *ValidationError) Is(target error) bool
```

Is matches any other \*ValidationError. ValidationError is a category, not an identity: errors.Is\(anyValidationError, anyOther\) returns true. Use errors.As to read Message / Cause.

<a name="ValidationError.Unwrap"></a>
### func \(\*ValidationError\) [Unwrap](<https://github.com/dnsid-ai/dnsid-go/blob/main/errors.go#L135>)

```go
func (e *ValidationError) Unwrap() error
```

Unwrap returns the wrapped cause, if any.

<a name="VerificationCode"></a>
## type [VerificationCode](<https://github.com/dnsid-ai/dnsid-go/blob/main/errors.go#L8>)

VerificationCode is a machine\-readable classifier for \*VerificationError. Codes group failures by cause so callers can branch on type without pattern\-matching on error strings.

```go
type VerificationCode string
```

<a name="VerificationCodeDNSResolution"></a>Core verification codes defined by the language\-agnostic SDK contract.

```go
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
```

<a name="VerificationCodeChainContinuity"></a>Lifecycle log verification codes emitted when strict lifecycle state\-machine enforcement rejects an agent's log evidence. Values are the uppercase identifiers defined by the cross\-SDK lifecycle contract.

```go
const (
    VerificationCodeChainContinuity   VerificationCode = "CHAIN_CONTINUITY"
    VerificationCodeDuplicateIssuance VerificationCode = "DUPLICATE_ISSUANCE"
    VerificationCodeInvalidEvidence   VerificationCode = "INVALID_EVIDENCE"
    VerificationCodeIncompleteStream  VerificationCode = "INCOMPLETE_STREAM"
    VerificationCodeKeyContinuity     VerificationCode = "KEY_CONTINUITY"
    VerificationCodeInvalidMigration  VerificationCode = "INVALID_MIGRATION"
    VerificationCodeTerminalState     VerificationCode = "TERMINAL_STATE"
)
```

<a name="VerificationCodeKeyNotFound"></a>Application\-profile codes retained for JOSE, HTTP\-signature, and OIDC callers. Core VerifyDomain does not emit these codes.

VerificationCodeAudienceMismatch, VerificationCodeIssuerMismatch, and VerificationCodeLifetimeTooLong are specific claim\-validation failures. They are children of VerificationCodeInvalidClaims for errors.Is purposes: an error with one of these codes also satisfies errors.Is\(err, ErrInvalidClaims\). See VerificationError.Is.

```go
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
```

<a name="VerificationCodeJWKSUnavailable"></a>VerificationCodeJWKSUnavailable is a Go binding extension for JWKS fetch failures, which the core contract does not otherwise name.

```go
const VerificationCodeJWKSUnavailable VerificationCode = "jwks_unavailable"
```

<a name="VerificationConfig"></a>
## type [VerificationError](<https://github.com/dnsid-ai/dnsid-go/blob/main/errors.go#L168-L177>)

VerificationError is returned when runtime verification fails: signature mismatch, JWKS fetch failure, status check failure, key not found, revoked agent, expired/invalid token, etc. The Code classifies the failure; Transient indicates whether retrying might succeed.

Fields are unexported and accessed via Code\(\), Transient\(\), AgentState\(\), and Message\(\). This prevents accidental mutation of the package\-level sentinel values \(ErrTokenExpired, ErrTXTRecordNotFound, etc.\) that callers may obtain via errors.As. The wrapped cause is exposed via Unwrap\(\).

```go
type VerificationError struct {
    // contains filtered or unexported fields
}
```

<a name="NewVerificationError"></a>
### func [NewVerificationError](<https://github.com/dnsid-ai/dnsid-go/blob/main/errors.go#L199>)

```go
func NewVerificationError(code VerificationCode, transient bool, msg string, cause error, opts ...VerificationErrorOption) *VerificationError
```

NewVerificationError constructs a VerificationError.

<a name="VerificationError.AgentState"></a>
### func \(\*VerificationError\) [AgentState](<https://github.com/dnsid-ai/dnsid-go/blob/main/errors.go#L230>)

```go
func (e *VerificationError) AgentState() AgentState
```

AgentState returns the agent state recorded with this error, if any \(populated when a status check returned a specific state\).

<a name="VerificationError.Code"></a>
### func \(\*VerificationError\) [Code](<https://github.com/dnsid-ai/dnsid-go/blob/main/errors.go#L213>)

```go
func (e *VerificationError) Code() VerificationCode
```

Code returns the failure classifier.

<a name="VerificationError.Error"></a>
### func \(\*VerificationError\) [Error](<https://github.com/dnsid-ai/dnsid-go/blob/main/errors.go#L265>)

```go
func (e *VerificationError) Error() string
```

Error implements error.

<a name="VerificationError.Is"></a>
### func \(\*VerificationError\) [Is](<https://github.com/dnsid-ai/dnsid-go/blob/main/errors.go#L307>)

```go
func (e *VerificationError) Is(target error) bool
```

Is matches another \*VerificationError with the same Code. It also matches a sentinel exemplar whose Code is a parent category of the receiver's Code \(see invalidClaimsChildren\). This lets callers compare against a sentinel — e.g. errors.Is\(err, ErrTXTRecordNotFound\) — without holding the original pointer, and lets specific claim errors satisfy the broader errors.Is\(err, ErrInvalidClaims\) check.

<a name="VerificationError.Message"></a>
### func \(\*VerificationError\) [Message](<https://github.com/dnsid-ai/dnsid-go/blob/main/errors.go#L257>)

```go
func (e *VerificationError) Message() string
```

Message returns the human\-readable detail string.

<a name="VerificationError.Transient"></a>
### func \(\*VerificationError\) [Transient](<https://github.com/dnsid-ai/dnsid-go/blob/main/errors.go#L221>)

```go
func (e *VerificationError) Transient() bool
```

Transient reports whether retrying might succeed.

<a name="VerificationError.Unwrap"></a>
### func \(\*VerificationError\) [Unwrap](<https://github.com/dnsid-ai/dnsid-go/blob/main/errors.go#L283>)

```go
func (e *VerificationError) Unwrap() error
```

Unwrap returns the wrapped cause, if any.

<a name="VerificationError.VerifiedEntityKeyThumbprint"></a>
### func \(\*VerificationError\) [VerifiedEntityKeyThumbprint](<https://github.com/dnsid-ai/dnsid-go/blob/main/errors.go#L249>)

```go
func (e *VerificationError) VerifiedEntityKeyThumbprint() string
```

VerifiedEntityKeyThumbprint returns the observed verified record\-signing key's RFC 7638 SHA\-256 thumbprint for a VerificationCodeCounterpartyNotAccepted error; empty for other codes.

<a name="VerificationError.VerifiedGovernanceID"></a>
### func \(\*VerificationError\) [VerifiedGovernanceID](<https://github.com/dnsid-ai/dnsid-go/blob/main/errors.go#L239>)

```go
func (e *VerificationError) VerifiedGovernanceID() string
```

VerifiedGovernanceID returns the observed verified governance ID for a VerificationCodeCounterpartyNotAccepted error; empty for other codes.

<a name="VerificationErrorOption"></a>
## type [VerificationErrorOption](<https://github.com/dnsid-ai/dnsid-go/blob/main/errors.go#L180>)

VerificationErrorOption configures optional fields on a VerificationError.

```go
type VerificationErrorOption func(*VerificationError)
```

<a name="WithAgentState"></a>
### func [WithAgentState](<https://github.com/dnsid-ai/dnsid-go/blob/main/errors.go#L184>)

```go
func WithAgentState(state AgentState) VerificationErrorOption
```

WithAgentState attaches an agent state to a VerificationError. Used when a status check returned a specific state \(e.g. "revoked"\).

<a name="WithVerifiedIdentity"></a>
### func [WithVerifiedIdentity](<https://github.com/dnsid-ai/dnsid-go/blob/main/errors.go#L191>)

```go
func WithVerifiedIdentity(governanceID, entityKeyThumbprint string) VerificationErrorOption
```

WithVerifiedIdentity records the observed verified governance ID and record\-signing key thumbprint on a counterparty acceptance denial. It never carries configured allowlist or pin values.

<a name="VerifiedDomain"></a>
