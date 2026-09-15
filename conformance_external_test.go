package dnsid_test

import (
	"fmt"
	"testing"

	"github.com/dnsid-ai/dnsid-go"
	"github.com/dnsid-ai/dnsid-go/log/c2sptlog"
)

func TestSDKConformanceC2SPBindingMatchesPackagePins(t *testing.T) {
	pins := c2sptlog.PinnedSpecificationVersions()
	want := fmt.Sprintf(
		"profile=%d;tlog-checkpoint=%s;tlog-tiles=%s;tlog-proof=%s;tlog-policy=%s;tlog-witness=%s;tlog-cosignature=%s;tlog-mirror=%s;signed-note=%s;dnsid-method=%s",
		pins.EventEnvelope,
		pins.Checkpoint,
		pins.Tiles,
		pins.Proof,
		pins.Policy,
		pins.Witness,
		pins.Cosignature,
		pins.Mirror,
		pins.SignedNote,
		c2sptlog.DNSidMethodRevision,
	)
	if got := dnsid.SDKConformance().LogBindings["c2sp-tlog"]; got != want {
		t.Fatalf("SDKConformance c2sp-tlog binding = %q, want %q", got, want)
	}
}
