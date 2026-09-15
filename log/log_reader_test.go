package log

import (
	"context"
	"errors"
	"testing"
)

func TestNoopLogReaderReturnsStructuredVerificationError(t *testing.T) {
	_, err := (NoopLogReader{Method: "missing"}).VerifyBilateralBinding(context.Background(), BilateralBindingInput{})
	var verificationErr *VerificationError
	if !errors.As(err, &verificationErr) {
		t.Fatalf("error = %T, want *VerificationError", err)
	}
	if verificationErr.Code() != "log_error" || verificationErr.Transient() {
		t.Fatalf("error code = %q, transient = %v", verificationErr.Code(), verificationErr.Transient())
	}
}
