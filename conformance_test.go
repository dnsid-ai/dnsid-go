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
			"c2sp-tlog": "profile=1;tlog-checkpoint=https://c2sp.org/tlog-checkpoint@v1.1.0;tlog-tiles=https://c2sp.org/tlog-tiles@v1.0.0;tlog-proof=0fb2b5543ec04c7909dd58f00691c76dbebe4c6a;tlog-policy=9787c327021255dc0c273a7d0e957e420256f5f8;tlog-witness=https://c2sp.org/tlog-witness@v1.1.0;tlog-cosignature=https://c2sp.org/tlog-cosignature@v1.1.0;tlog-mirror=https://c2sp.org/tlog-mirror@v0.1.0;signed-note=https://c2sp.org/signed-note@v1.1.0;dnsid-method=972f5f19222e0a55e3ee8f8be28dd087764c144e",
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
