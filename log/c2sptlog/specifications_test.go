package c2sptlog

import (
	"reflect"
	"testing"
)

func TestPinnedSpecificationVersions(t *testing.T) {
	want := SpecificationVersions{
		Checkpoint:    "https://c2sp.org/tlog-checkpoint@v1.1.0",
		Tiles:         "https://c2sp.org/tlog-tiles@v1.0.0",
		Proof:         "0fb2b5543ec04c7909dd58f00691c76dbebe4c6a",
		Policy:        "9787c327021255dc0c273a7d0e957e420256f5f8",
		Witness:       "https://c2sp.org/tlog-witness@v1.1.0",
		Cosignature:   "https://c2sp.org/tlog-cosignature@v1.1.0",
		Mirror:        "https://c2sp.org/tlog-mirror@v0.1.0",
		SignedNote:    "https://c2sp.org/signed-note@v1.1.0",
		EventEnvelope: 1,
	}
	if got := PinnedSpecificationVersions(); !reflect.DeepEqual(got, want) {
		t.Fatalf("PinnedSpecificationVersions() = %#v, want %#v", got, want)
	}

	changed := PinnedSpecificationVersions()
	changed.Policy = "changed"
	if got := PinnedSpecificationVersions(); !reflect.DeepEqual(got, want) {
		t.Fatalf("caller mutation changed package metadata: %#v", got)
	}
}
