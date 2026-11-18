//go:build dnsid_foundry

package foundry

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http"
	"testing"

	dnsid "github.com/dnsid-ai/dnsid-go"
	dnsidlog "github.com/dnsid-ai/dnsid-go/log"
)

func TestIssuanceDoesNotScanBeforePreparationOrOnUnknownOutcome(t *testing.T) {
	for _, lost := range []bool{false, true} {
		t.Run(map[bool]string{false: "first issuance", true: "unknown submission"}[lost], func(t *testing.T) {
			f := newFixture(t)
			f.log.historyErr = dnsid.NewVerificationError(dnsid.VerificationCodeLogError, false, "unexpected blind history read", nil)
			if lost {
				f.registry.submitErr = &dnsid.RegistryAPIError{StatusCode: http.StatusServiceUnavailable, Code: "TLOG_SUBMISSION_INDETERMINATE"}
			}
			id, err := f.client.Create(context.Background(), "no-scan")
			if err != nil {
				t.Fatal(err)
			}
			if _, err := id.Active(context.Background()); err != nil {
				t.Fatal(err)
			}
			if f.log.historyCalls != 0 {
				t.Fatal("issuance scanned history without a server rejection")
			}
			if _, err := id.Active(context.Background()); err != nil {
				t.Fatal(err)
			}
			if f.log.historyCalls != 0 || f.registry.prepareCalls != 1 {
				t.Fatal("saved acceptance caused a blind scan or reissuance")
			}
		})
	}
}

func TestIssuanceRejectionWithEmptyOrMissingIssuanceIsResumable(t *testing.T) {
	for _, test := range []struct {
		name       string
		submission bool
		events     []dnsidlog.LogEvent
	}{
		{name: "empty history after preparation"},
		{name: "no issuance after preparation", events: []dnsidlog.LogEvent{{Type: dnsidlog.LogEventDelegation, Domain: testDomain}}},
		{name: "empty history after submission", submission: true},
		{name: "invalid entry after submission", submission: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			f := newFixture(t)
			f.log.events = test.events
			rejection := &dnsid.RegistryAPIError{StatusCode: http.StatusConflict, Code: "TLOG_PREPARATION_MISMATCH"}
			if test.name == "invalid entry after submission" {
				rejection.StatusCode, rejection.Code = http.StatusUnprocessableEntity, "TLOG_INVALID_ENTRY"
			}
			if test.submission {
				f.registry.submitErr = rejection
			} else {
				f.registry.prepareErr = rejection
			}
			id, err := f.client.Create(context.Background(), "lagging")
			if err != nil {
				t.Fatal(err)
			}
			_, err = id.Active(context.Background())
			outcome := requireKind(t, err, Unresolved)
			if !outcome.Resumable || outcome.Code != rejection.Code || outcome.StatusCode != rejection.StatusCode {
				t.Fatalf("lost rejection facts: %v", err)
			}
			if f.log.historyCalls != 1 {
				t.Fatalf("history calls=%d", f.log.historyCalls)
			}
			if f.document("lagging").Phase == "complete" {
				t.Fatal("empty history satisfied acceptance")
			}
			if test.name == "invalid entry after submission" {
				reopened, err := f.client.Create(context.Background(), "lagging")
				if err != nil {
					t.Fatal(err)
				}
				_, err = reopened.Active(context.Background())
				outcome = requireKind(t, err, Unresolved)
				if !outcome.Resumable || outcome.Code != rejection.Code || len(f.registry.submissions) != 1 || f.registry.prepareCalls != 1 {
					t.Fatalf("restart lost resumability or resubmitted rejected bytes: %v", err)
				}
			}
		})
	}
}

func TestIssuanceRejectionPreservesEvidenceFailures(t *testing.T) {
	for _, invalid := range []bool{false, true} {
		t.Run(map[bool]string{false: "unavailable", true: "invalid"}[invalid], func(t *testing.T) {
			f := newFixture(t)
			f.registry.prepareErr = &dnsid.RegistryAPIError{StatusCode: http.StatusConflict, Code: "TLOG_PREPARATION_MISMATCH"}
			f.log.historyErr = dnsid.NewVerificationError(dnsid.VerificationCodeLogError, !invalid, "evidence unavailable or invalid", nil)
			id, err := f.client.Create(context.Background(), "evidence")
			if err != nil {
				t.Fatal(err)
			}
			_, err = id.Active(context.Background())
			kind := Unresolved
			if invalid {
				kind = Integrity
			}
			requireKind(t, err, kind)
			var evidence *dnsid.VerificationError
			if !errors.As(err, &evidence) {
				t.Fatal("evidence failure was discarded")
			}
			if f.log.historyCalls != 1 {
				t.Fatal("recovery failed to read history after rejection")
			}
		})
	}
}

func TestAdmissionFailuresNeverRecordIssuanceRejection(t *testing.T) {
	for _, submission := range []bool{false, true} {
		for _, status := range []int{http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound} {
			t.Run(fmt.Sprintf("submission=%t/status=%d", submission, status), func(t *testing.T) {
				f := newFixture(t)
				// Even a conflicting wire code cannot turn 401/403/404 into byte rejection.
				admission := &dnsid.RegistryAPIError{StatusCode: status, Code: "TLOG_INVALID_ENTRY"}
				if submission {
					f.registry.submitErr = admission
				} else {
					f.registry.prepareErr = admission
				}
				id, err := f.client.Create(context.Background(), "admission")
				if err != nil {
					t.Fatal(err)
				}
				_, err = id.Active(context.Background())
				var workflow *Error
				if !errors.As(err, &workflow) || workflow.StatusCode != status || workflow.Code != admission.Code {
					t.Fatalf("admission facts lost: %v", err)
				}
				state := f.document("admission").Issuance.Operation
				if state.TerminalFailure || (state.Submission != nil && state.Submission.State == dnsid.SubmissionStateRejected) {
					t.Fatal("admission error was persisted as issuance rejection")
				}
				if f.log.historyCalls != 0 {
					t.Fatal("admission failure triggered history recovery")
				}
				f.registry.prepareErr = nil
				if _, err := id.Active(context.Background()); err != nil {
					t.Fatal(err)
				}
				if submission && !bytes.Equal(f.registry.submissions[0], f.registry.submissions[1]) {
					t.Fatal("credential recovery changed submitted bytes")
				}
			})
		}
	}
}

func TestLocalCountersignatureFailureDoesNotScanHistory(t *testing.T) {
	f := newFixture(t)
	f.client.deps.KeyProvider = &corruptingProvider{KeyProvider: f.operational, corrupt: true}
	id, err := f.client.Create(context.Background(), "invalid-local")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := id.Active(context.Background()); err == nil {
		t.Fatal("invalid signature accepted")
	}
	if f.log.historyCalls != 0 {
		t.Fatal("local validation failure triggered a history scan")
	}
}
