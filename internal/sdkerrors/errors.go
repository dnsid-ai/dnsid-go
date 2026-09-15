package sdkerrors

// ParseError is returned when input fails to parse: malformed TXT records,
// JWTs, or JWKS documents, ABNF rule violations, or other syntactic failures.
// A ParseError is always permanent — retrying the same input will fail again.
type ParseError struct {
	Message string
	Cause   error
}

// NewParseError constructs a ParseError wrapping cause with msg.
func NewParseError(msg string, cause error) *ParseError {
	return &ParseError{Message: msg, Cause: cause}
}

// Error implements error.
func (e *ParseError) Error() string {
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
func (e *ParseError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Cause
}

// Is matches any other *ParseError. ParseError is a category, not an
// identity: errors.Is(anyParseError, anyOtherParseError) returns true.
// Use errors.As to read Message / Cause.
func (e *ParseError) Is(target error) bool {
	_, ok := target.(*ParseError)
	return ok
}

// ArgumentError is returned when a caller supplies invalid arguments to an SDK
// API, such as a missing required option or unsupported local key identifier.
// An ArgumentError is always permanent.
type ArgumentError struct {
	Message string
	Cause   error
}

// NewArgumentError constructs an ArgumentError wrapping cause with msg.
func NewArgumentError(msg string, cause error) *ArgumentError {
	return &ArgumentError{Message: msg, Cause: cause}
}

// Error implements error.
func (e *ArgumentError) Error() string {
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
func (e *ArgumentError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Cause
}

// Is matches any other *ArgumentError. ArgumentError is a category, not an
// identity; use errors.As to read Message / Cause.
func (e *ArgumentError) Is(target error) bool {
	_, ok := target.(*ArgumentError)
	return ok
}
