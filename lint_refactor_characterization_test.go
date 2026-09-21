package dnsid

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// The tests in this file characterize behavior across the golangci-lint
// remediation on the chore/add-golangci-lint branch. They are written to run
// unchanged against both the pre- and post-refactor source, so any difference
// in outcome is a real behavior change rather than a test rewritten to match
// new code.
//
// Tests whose assertions only hold AFTER the refactor say so explicitly.

// --- registry.go: type assertion -> errors.As in UnregisterAgent -----------

// TestUnregisterAgentStatusHandlingUnchanged pins the contract that predates
// the refactor: 404 and 405 are swallowed as successful no-ops, every other
// failing status surfaces as an error. Passes before and after.
func TestUnregisterAgentStatusHandlingUnchanged(t *testing.T) {
	for _, tc := range []struct {
		status  int
		wantErr bool
	}{
		{http.StatusNotFound, false},
		{http.StatusMethodNotAllowed, false},
		{http.StatusNoContent, false},
		{http.StatusConflict, true},
		{http.StatusInternalServerError, true},
		{http.StatusForbidden, true},
	} {
		t.Run(http.StatusText(tc.status), func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(tc.status)
				if tc.status >= 400 {
					_, _ = w.Write([]byte(`{"error":"boom","message":"boom"}`))
				}
			}))
			defer srv.Close()

			client := &HTTPRegistryClient{baseURL: srv.URL, client: srv.Client(), allowInsecure: true}
			err := client.UnregisterAgent(context.Background(), "agent.example.com")
			if gotErr := err != nil; gotErr != tc.wantErr {
				t.Fatalf("UnregisterAgent(status %d) error = %v, wantErr %v", tc.status, err, tc.wantErr)
			}
		})
	}
}

// --- log.go: type assertion -> errors.As in logVerificationError -----------

// TestLogVerificationErrorPassesThroughDirect pins pre-existing behavior: a
// *VerificationError arriving directly is returned untouched. Before and after.
func TestLogVerificationErrorPassesThroughDirect(t *testing.T) {
	orig := NewVerificationError(VerificationCodeMalformedToken, false, "dnsid: boom", nil)
	got := logVerificationError(orig)
	if !errors.Is(got, orig) {
		t.Fatalf("logVerificationError returned %v, want the original error identity", got)
	}
	if got.Error() != orig.Error() {
		t.Fatalf("message changed: got %q, want %q", got.Error(), orig.Error())
	}
}

// TestLogVerificationErrorNilStaysNil pins behavior that must not change.
func TestLogVerificationErrorNilStaysNil(t *testing.T) {
	if err := logVerificationError(nil); err != nil {
		t.Fatalf("logVerificationError(nil) = %v, want nil", err)
	}
}

// TestLogVerificationErrorFindsWrappedVerificationError records an INTENTIONAL
// behavior change. Before the refactor the bare type assertion missed a wrapped
// *VerificationError and rebuilt it into a fresh error; after, errors.As finds
// it and passes it through untouched. This test FAILS on the pre-refactor
// source, which is exactly what it is here to document.
func TestLogVerificationErrorFindsWrappedVerificationError(t *testing.T) {
	inner := NewVerificationError(VerificationCodeMalformedToken, false, "dnsid: boom", nil)
	wrapped := fmt.Errorf("reading log: %w", inner)

	got := logVerificationError(wrapped)

	var ve *VerificationError
	if !errors.As(got, &ve) {
		t.Fatalf("logVerificationError(%v) lost the *VerificationError", wrapped)
	}
	if got.Error() != wrapped.Error() {
		t.Errorf("wrapped error was rebuilt rather than passed through:\n got  %q\n want %q",
			got.Error(), wrapped.Error())
	}
}

// --- identity_manager.go: %v -> %w in validateManagerFetchURL -------------

// TestValidateManagerFetchURLMessagesUnchanged pins the exact operator-facing
// strings and the reachability of the sentinel. A failure here means the
// %v -> %w change altered user-visible output. Passes before and after.
func TestValidateManagerFetchURLMessagesUnchanged(t *testing.T) {
	for _, tc := range []struct {
		name string
		raw  string
		want string
	}{
		{"non-https", "http://example.com/x", "URL must use https"},
		{"unparseable", "https://exa mple.example/\x7f", "invalid URL"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := validateManagerFetchURL(tc.raw, "example.com", false)
			if err == nil {
				t.Fatalf("validateManagerFetchURL(%q) = nil, want error", tc.raw)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("message = %q, want it to contain %q", err.Error(), tc.want)
			}
			if !errors.Is(err, errTLSPolicy) {
				t.Fatalf("errors.Is(err, errTLSPolicy) = false for %q", err)
			}
		})
	}
}

// TestValidateManagerFetchURLExposesParseCause records an INTENTIONAL behavior
// change: with the second verb switched from %v to %w, the underlying
// *url.Error is reachable through the chain while errTLSPolicy still is.
// FAILS on the pre-refactor source.
func TestValidateManagerFetchURLExposesParseCause(t *testing.T) {
	err := validateManagerFetchURL("https://exa mple.example/\x7f", "example.com", false)
	if err == nil {
		t.Fatal("expected an error")
	}
	if !errors.Is(err, errTLSPolicy) {
		t.Fatal("errTLSPolicy is no longer reachable")
	}
	var parseErr *url.Error
	if !errors.As(err, &parseErr) {
		t.Fatalf("underlying *url.Error not reachable from %q", err)
	}
}
