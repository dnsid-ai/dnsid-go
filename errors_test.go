package dnsid

import (
	"errors"
	"fmt"
	"testing"
)

func TestParseError_ErrorUnwrap(t *testing.T) {
	cause := errors.New("bad bytes")
	e := NewParseError("dnsid: parse failed", cause)

	if got, want := e.Error(), "dnsid: parse failed: bad bytes"; got != want {
		t.Errorf("Error() = %q, want %q", got, want)
	}
	if !errors.Is(e, cause) {
		t.Errorf("errors.Is(e, cause) = false, want true")
	}
	//nolint:errorlint // asserts Unwrap returns the direct cause; errors.Is would not test that.
	if errors.Unwrap(e) != cause {
		t.Errorf("Unwrap() = %v, want %v", errors.Unwrap(e), cause)
	}
}

func TestValidationError_ErrorUnwrap(t *testing.T) {
	cause := errors.New("missing required tag")
	e := NewValidationError("dnsid: validation failed", cause)

	if got, want := e.Error(), "dnsid: validation failed: missing required tag"; got != want {
		t.Errorf("Error() = %q, want %q", got, want)
	}
	if !errors.Is(e, cause) {
		t.Errorf("errors.Is(e, cause) = false, want true")
	}
}

func TestArgumentError_ErrorUnwrap(t *testing.T) {
	cause := errors.New("bad argument")
	e := NewArgumentError("dnsid: invalid argument", cause)

	if got, want := e.Error(), "dnsid: invalid argument: bad argument"; got != want {
		t.Errorf("Error() = %q, want %q", got, want)
	}
	if !errors.Is(e, cause) {
		t.Errorf("errors.Is(e, cause) = false, want true")
	}
}

func TestVerificationCodes_CoreContract(t *testing.T) {
	want := map[VerificationCode]string{
		VerificationCodeDNSResolution:     "dns_resolution",
		VerificationCodeDNSSECFailed:      "dnssec_failed",
		VerificationCodeRecordInvalid:     "record_invalid",
		VerificationCodeSignatureInvalid:  "signature_invalid",
		VerificationCodeTLSError:          "tls_error",
		VerificationCodeKeyAgeExceeded:    "key_age_exceeded",
		VerificationCodeStatusUnavailable: "status_unavailable",
		VerificationCodeStatusNotActive:   "status_not_active",
		VerificationCodeLogError:          "log_error",
		VerificationCodeChainContinuity:   "CHAIN_CONTINUITY",
		VerificationCodeDuplicateIssuance: "DUPLICATE_ISSUANCE",
		VerificationCodeInvalidEvidence:   "INVALID_EVIDENCE",
		VerificationCodeIncompleteStream:  "INCOMPLETE_STREAM",
		VerificationCodeKeyContinuity:     "KEY_CONTINUITY",
		VerificationCodeInvalidMigration:  "INVALID_MIGRATION",
		VerificationCodeTerminalState:     "TERMINAL_STATE",
	}
	for code, value := range want {
		if string(code) != value {
			t.Errorf("%s = %q, want %q", code, code, value)
		}
	}
}

func TestVerificationError_ErrorUnwrap(t *testing.T) {
	cause := errors.New("network down")
	e := NewVerificationError(VerificationCodeStatusUnavailable, true, "dnsid: jwks fetch failed", cause)

	if got, want := e.Error(), "dnsid: jwks fetch failed: network down"; got != want {
		t.Errorf("Error() = %q, want %q", got, want)
	}
	if !errors.Is(e, cause) {
		t.Errorf("errors.Is(e, cause) = false, want true")
	}
	if !e.Transient() {
		t.Errorf("Transient = false, want true")
	}
}

func TestErrorsAs_AllTypes(t *testing.T) {
	t.Run("ParseError", func(t *testing.T) {
		err := fmt.Errorf("wrap: %w", NewParseError("p", nil))
		var pe *ParseError
		if !errors.As(err, &pe) {
			t.Fatalf("errors.As(*ParseError) = false")
		}
		if pe.Message != "p" {
			t.Errorf("Message = %q, want %q", pe.Message, "p")
		}
	})
	t.Run("ValidationError", func(t *testing.T) {
		err := fmt.Errorf("wrap: %w", NewValidationError("v", nil))
		var ve *ValidationError
		if !errors.As(err, &ve) {
			t.Fatalf("errors.As(*ValidationError) = false")
		}
	})
	t.Run("ArgumentError", func(t *testing.T) {
		err := fmt.Errorf("wrap: %w", NewArgumentError("a", nil))
		var ae *ArgumentError
		if !errors.As(err, &ae) {
			t.Fatalf("errors.As(*ArgumentError) = false")
		}
	})
	t.Run("VerificationError", func(t *testing.T) {
		err := fmt.Errorf("wrap: %w", NewVerificationError(VerificationCodeStatusNotActive, false, "r", nil))
		var ve *VerificationError
		if !errors.As(err, &ve) {
			t.Fatalf("errors.As(*VerificationError) = false")
		}
		if ve.Code() != VerificationCodeStatusNotActive {
			t.Errorf("Code = %q, want %q", ve.Code(), VerificationCodeStatusNotActive)
		}
	})
}

type transientLogFailure struct{}

func (transientLogFailure) Error() string   { return "log unavailable" }
func (transientLogFailure) Transient() bool { return true }

func TestJWKSVerificationError_WrapsLiveParseFailureAsRecordInvalid(t *testing.T) {
	cause := NewParseError("bad JWKS", errors.New("bad JSON"))
	err := jwksVerificationError("fetching JWKS", cause)
	var verificationErr *VerificationError
	if !errors.As(err, &verificationErr) {
		t.Fatalf("error = %T, want *VerificationError", err)
	}
	if verificationErr.Code() != VerificationCodeRecordInvalid || verificationErr.Transient() {
		t.Fatalf("code = %q, transient = %v", verificationErr.Code(), verificationErr.Transient())
	}
	if !errors.Is(err, cause) {
		t.Fatal("live parse failure cause was not preserved")
	}
}

func TestJWKSVerificationError_ClassifiesTransportFailures(t *testing.T) {
	tests := []struct {
		name      string
		err       error
		code      VerificationCode
		transient bool
	}{
		{name: "network", err: errors.New("connection refused"), code: VerificationCodeJWKSUnavailable, transient: true},
		{name: "TLS", err: errTLSPolicy, code: VerificationCodeTLSError, transient: false},
		{name: "HTTP 403", err: &httpStatusError{statusCode: 403}, code: VerificationCodeJWKSUnavailable, transient: false},
		{name: "HTTP 404", err: &httpStatusError{statusCode: 404}, code: VerificationCodeJWKSUnavailable, transient: false},
		{name: "HTTP 503", err: &httpStatusError{statusCode: 503}, code: VerificationCodeJWKSUnavailable, transient: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var verificationErr *VerificationError
			if err := jwksVerificationError("fetching JWKS", tt.err); !errors.As(err, &verificationErr) {
				t.Fatalf("error = %T, want *VerificationError", err)
			}
			if verificationErr.Code() != tt.code || verificationErr.Transient() != tt.transient {
				t.Fatalf("code = %q, transient = %v; want %q, %v", verificationErr.Code(), verificationErr.Transient(), tt.code, tt.transient)
			}
		})
	}
}

func TestLogVerificationError_PreservesTransientClassification(t *testing.T) {
	err := logVerificationError(transientLogFailure{})
	var verificationErr *VerificationError
	if !errors.As(err, &verificationErr) {
		t.Fatalf("error = %T, want *VerificationError", err)
	}
	if verificationErr.Code() != VerificationCodeLogError || !verificationErr.Transient() {
		t.Fatalf("code = %q, transient = %v", verificationErr.Code(), verificationErr.Transient())
	}
}

func TestVerificationError_TransientRoundTrip(t *testing.T) {
	transient := NewVerificationError(VerificationCodeStatusUnavailable, true, "", nil)
	permanent := NewVerificationError(VerificationCodeSignatureInvalid, false, "", nil)
	if !transient.Transient() {
		t.Errorf("transient.Transient() = false")
	}
	if permanent.Transient() {
		t.Errorf("permanent.Transient() = true")
	}
}

func TestVerificationError_WithAgentState(t *testing.T) {
	e := NewVerificationError(VerificationCodeStatusNotActive, false, "agent revoked", nil, WithAgentState(AgentStateRevoked))
	if e.AgentState() != AgentStateRevoked {
		t.Errorf("AgentState = %q, want %q", e.AgentState(), AgentStateRevoked)
	}
	if got := e.Error(); got != "agent revoked [agent_state=REVOKED]" {
		t.Errorf("Error() = %q, want it to include agent_state", got)
	}
}

// TestVerificationError_InvalidClaimsParent verifies that errors carrying
// AudienceMismatch / IssuerMismatch / LifetimeTooLong codes satisfy both the
// granular sentinel check AND the broader errors.Is(err, ErrInvalidClaims)
// check that cmd/dnsid and other consumers rely on.
func TestVerificationError_InvalidClaimsParent(t *testing.T) {
	cases := []struct {
		name string
		code VerificationCode
	}{
		{"AudienceMismatch", VerificationCodeAudienceMismatch},
		{"IssuerMismatch", VerificationCodeIssuerMismatch},
		{"LifetimeTooLong", VerificationCodeLifetimeTooLong},
		{"InvalidClaims", VerificationCodeInvalidClaims},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := NewVerificationError(tc.code, false, "x", nil)

			if !errors.Is(err, ErrInvalidClaims) {
				t.Errorf("errors.Is(%s, ErrInvalidClaims) = false; want true (parent-code match)", tc.name)
			}
			specific := NewVerificationError(tc.code, false, "", nil)
			if !errors.Is(err, specific) {
				t.Errorf("errors.Is(%s, %s sentinel) = false; want true (exact-code match)", tc.name, tc.code)
			}
		})
	}

	// Reverse direction: ErrInvalidClaims itself must not satisfy errors.Is
	// against a more-specific child (parent-code matching is one-way).
	specific := NewVerificationError(VerificationCodeAudienceMismatch, false, "", nil)
	if errors.Is(ErrInvalidClaims, specific) {
		t.Errorf("errors.Is(ErrInvalidClaims, AudienceMismatch) = true; want false (parent matches child wrongly)")
	}

	// Sibling codes must not cross-match: AudienceMismatch is not IssuerMismatch.
	aud := NewVerificationError(VerificationCodeAudienceMismatch, false, "x", nil)
	iss := NewVerificationError(VerificationCodeIssuerMismatch, false, "", nil)
	if errors.Is(aud, iss) {
		t.Errorf("errors.Is(AudienceMismatch, IssuerMismatch) = true; want false")
	}
}

func TestVerificationError_IsMatchesByCode(t *testing.T) {
	a := NewVerificationError(VerificationCodeRecordInvalid, false, "msg A", nil)
	b := NewVerificationError(VerificationCodeRecordInvalid, false, "msg B", errors.New("different cause"))
	if !errors.Is(a, b) {
		t.Errorf("errors.Is matching codes = false, want true")
	}
	c := NewVerificationError(VerificationCodeSignatureInvalid, false, "", nil)
	if errors.Is(a, c) {
		t.Errorf("errors.Is mismatching codes = true, want false")
	}
}

func TestParseError_IsCategory(t *testing.T) {
	exemplar := &ParseError{}
	if !errors.Is(NewParseError("any", nil), exemplar) {
		t.Errorf("errors.Is(ParseError, &ParseError{}) = false")
	}
	if errors.Is(NewValidationError("v", nil), exemplar) {
		t.Errorf("ValidationError matched ParseError category")
	}
}

func TestValidationError_IsCategory(t *testing.T) {
	exemplar := &ValidationError{}
	if !errors.Is(NewValidationError("any", nil), exemplar) {
		t.Errorf("errors.Is(ValidationError, &ValidationError{}) = false")
	}
	if errors.Is(NewParseError("p", nil), exemplar) {
		t.Errorf("ParseError matched ValidationError category")
	}
}

func TestArgumentError_IsCategory(t *testing.T) {
	exemplar := &ArgumentError{}
	if !errors.Is(NewArgumentError("any", nil), exemplar) {
		t.Errorf("errors.Is(ArgumentError, &ArgumentError{}) = false")
	}
	if errors.Is(NewValidationError("v", nil), exemplar) {
		t.Errorf("ValidationError matched ArgumentError category")
	}
}

// TestVerificationError_SentinelImmutability verifies that a caller who
// obtains a *VerificationError via errors.As cannot mutate the global
// sentinel, even though the caller holds a pointer. Fields are unexported,
// so direct mutation is a compile error; this test pins the invariant by
// checking that the sentinel's observable state is unchanged after a
// caller has interacted with errors.As / errors.Is.
func TestVerificationError_SentinelImmutability(t *testing.T) {
	origCode := ErrTokenExpired.Code()
	origMessage := ErrTokenExpired.Message()
	origTransient := ErrTokenExpired.Transient()

	// Simulate a caller flow: receive the sentinel, extract via errors.As,
	// run errors.Is against unrelated codes. None of this must mutate the
	// sentinel.
	var ret error = ErrTokenExpired
	var ve *VerificationError
	if !errors.As(ret, &ve) {
		t.Fatal("errors.As against sentinel failed")
	}
	_ = errors.Is(ret, ErrTokenExpired)
	_ = errors.Is(ret, ErrInvalidClaims)
	_ = ve.Code()
	_ = ve.Message()
	_ = ve.Transient()
	_ = ve.AgentState()
	_ = ve.Error()

	if ErrTokenExpired.Code() != origCode {
		t.Errorf("sentinel Code mutated: %q -> %q", origCode, ErrTokenExpired.Code())
	}
	if ErrTokenExpired.Message() != origMessage {
		t.Errorf("sentinel Message mutated: %q -> %q", origMessage, ErrTokenExpired.Message())
	}
	if ErrTokenExpired.Transient() != origTransient {
		t.Errorf("sentinel Transient mutated: %v -> %v", origTransient, ErrTokenExpired.Transient())
	}

	// errors.Is against the sentinel must still resolve correctly after
	// the above caller flow.
	fresh := NewVerificationError(VerificationCodeTokenExpired, false, "fresh", nil)
	if !errors.Is(fresh, ErrTokenExpired) {
		t.Errorf("errors.Is(fresh, ErrTokenExpired) = false after caller flow")
	}
}

// TestErrorTypes_CrossCategoryNoMatch locks down the invariant that error
// categories do not satisfy errors.Is against each other. A typed failure in
// one category must not silently match an unrelated category.
func TestErrorTypes_CrossCategoryNoMatch(t *testing.T) {
	pe := NewParseError("p", nil)
	ve := NewValidationError("v", nil)
	ae := NewArgumentError("a", nil)
	verr := NewVerificationError(VerificationCodeRecordInvalid, false, "x", nil)

	if errors.Is(pe, ErrInvalidClaims) {
		t.Errorf("ParseError matched ErrInvalidClaims")
	}
	if errors.Is(ve, ErrInvalidClaims) {
		t.Errorf("ValidationError matched ErrInvalidClaims")
	}
	if errors.Is(verr, &ParseError{}) {
		t.Errorf("VerificationError matched ParseError category")
	}
	if errors.Is(verr, &ValidationError{}) {
		t.Errorf("VerificationError matched ValidationError category")
	}
	if errors.Is(ae, &ParseError{}) || errors.Is(ae, &ValidationError{}) || errors.Is(ae, &VerificationError{}) || errors.Is(ae, ErrInvalidClaims) {
		t.Errorf("ArgumentError matched unrelated category")
	}
	if errors.Is(verr, ae) {
		t.Errorf("VerificationError matched ArgumentError category")
	}
	if errors.Is(pe, &ValidationError{}) {
		t.Errorf("ParseError matched ValidationError category")
	}
	if errors.Is(ve, &ParseError{}) {
		t.Errorf("ValidationError matched ParseError category")
	}
}

// TestTXTRecordValidate_ReturnsValidationError verifies that every semantic
// failure path in TXTRecord.Validate returns a *ValidationError, so callers
// can branch with errors.As / errors.Is instead of matching error strings.
// This mirrors dnsid-ts and dnsid-py, which raise their ValidationError
// classes from validate().
func TestPublicValidationAndArgumentErrors(t *testing.T) {
	if _, err := NormalizeFQDN("bad..example"); err == nil {
		t.Fatal("NormalizeFQDN = nil, want error")
	} else {
		var validationErr *ValidationError
		if !errors.As(err, &validationErr) {
			t.Fatalf("NormalizeFQDN error = %T, want *ValidationError", err)
		}
	}

	if err := (&AgentStatus{}).Validate(); err == nil {
		t.Fatal("AgentStatus.Validate = nil, want error")
	} else {
		var validationErr *ValidationError
		if !errors.As(err, &validationErr) {
			t.Fatalf("AgentStatus.Validate error = %T, want *ValidationError", err)
		}
	}

	if err := (IdentityConfig{}).Validate(); err == nil {
		t.Fatal("IdentityConfig.Validate = nil, want error")
	} else {
		var argumentErr *ArgumentError
		if !errors.As(err, &argumentErr) {
			t.Fatalf("IdentityConfig.Validate error = %T, want *ArgumentError", err)
		}
	}
}
