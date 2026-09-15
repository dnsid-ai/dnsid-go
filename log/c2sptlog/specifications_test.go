package c2sptlog

import (
	"reflect"
	"testing"
)

func TestPinnedSpecificationVersions(t *testing.T) {
	want := SpecificationVersions{
		Checkpoint:    "https://c2sp.org/tlog-checkpoint@v1.0.0",
		Tiles:         "https://c2sp.org/tlog-tiles@v0.1.0",
		Proof:         "ab17a74116563005f908b9167e6421cc929a5c2b",
		Policy:        "1896a5aea5559b3203d275d0206d872f59348cf5",
		Witness:       "https://c2sp.org/tlog-witness@v1.0.0",
		Cosignature:   "https://c2sp.org/tlog-cosignature@v1.0.1",
		Mirror:        "d0fe789122c75b903bfc1680b0b8b8dc570f0db3",
		SignedNote:    "https://c2sp.org/signed-note@v1.0.0",
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
