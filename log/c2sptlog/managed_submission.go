package c2sptlog

import (
	"errors"

	dnsid "github.com/dnsid-ai/dnsid-go"
)

// managedSubmissionFailure normalizes registry and unknown transport failures.
// An unknown error after submission begins is indeterminate and may only be
// retried with the exact persisted bytes and idempotency key.
func managedSubmissionFailure(err error) (dnsid.SubmissionState, bool, bool) {
	var apiErr *dnsid.RegistryAPIError
	if errors.As(err, &apiErr) {
		return apiErr.SubmissionState(), apiErr.Transient(), apiErr.RetrySameEntry()
	}
	return dnsid.SubmissionStateIndeterminate, true, true
}

func managedSubmissionErrorCode(err error) string {
	var apiErr *dnsid.RegistryAPIError
	if errors.As(err, &apiErr) && apiErr.Code != "" {
		return apiErr.Code
	}
	return "TLOG_SUBMISSION_INDETERMINATE"
}
