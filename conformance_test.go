package dnsid

import (
	"encoding/json"
	"reflect"
	"testing"
)

func TestSDKConformance(t *testing.T) {
	want := SDKConformanceMetadata{
		PublishProfile: DefaultPublishProfile,
		VerificationProfiles: map[string]string{
			"dnsid-draft-01": "dnsid-draft-01",
			"DNSid1":         "dnsid-draft-01",
		},
		SpecificationStatus: "internet-draft",
		LogBindings: map[string]string{
			"c2sp-tlog": "profile=1;tlog-checkpoint=https://c2sp.org/tlog-checkpoint@v1.0.0;tlog-tiles=https://c2sp.org/tlog-tiles@v0.1.0;tlog-proof=ab17a74116563005f908b9167e6421cc929a5c2b;tlog-policy=1896a5aea5559b3203d275d0206d872f59348cf5;tlog-witness=https://c2sp.org/tlog-witness@v1.0.0;tlog-cosignature=https://c2sp.org/tlog-cosignature@v1.0.1;tlog-mirror=d0fe789122c75b903bfc1680b0b8b8dc570f0db3;signed-note=https://c2sp.org/signed-note@v1.0.0;dnsid-method=d5a65d06f76eff4db81e50f8767a600d2ca7fc2a",
		},
		KnownDeviations: []string{},
	}

	if got := SDKConformance(); !reflect.DeepEqual(got, want) {
		t.Fatalf("SDKConformance() = %#v, want %#v", got, want)
	}

	changed := SDKConformance()
	changed.VerificationProfiles["DNSid1"] = "changed"
	changed.LogBindings["c2sp-tlog"] = "changed"
	changed.KnownDeviations = append(changed.KnownDeviations, "changed")
	if got := SDKConformance(); !reflect.DeepEqual(got, want) {
		t.Fatalf("SDKConformance() after caller mutation = %#v, want %#v", got, want)
	}
}

func TestSDKConformanceJSONFieldNames(t *testing.T) {
	data, err := json.Marshal(SDKConformance())
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	var got map[string]json.RawMessage
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	for _, field := range []string{"publishProfile", "verificationProfiles", "specificationStatus", "logBindings", "knownDeviations"} {
		if _, ok := got[field]; !ok {
			t.Errorf("SDKConformance JSON missing %q", field)
		}
	}
}
