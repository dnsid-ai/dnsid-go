package dnsid

import (
	"encoding/json"
	"testing"
)

func TestOrganizationOnboardingResponse_ProofGatePresence(t *testing.T) {
	for _, test := range []struct {
		gate       string
		missing    bool
		authorized bool
	}{
		{gate: "", missing: true},
		{gate: `,"gate_authorized":null`, missing: true},
		{gate: `,"gate_authorized":false`},
		{gate: `,"gate_authorized":true`, authorized: true},
	} {
		var value OrganizationOnboardingResponse
		body := `{"org_id":"org","governance_domain":"governance.example","gi":{"domain":"governance.example","state":"verified"` + test.gate + `},"ek":{"status":"verified"},"future":"ignored"}`
		if err := json.Unmarshal([]byte(body), &value); err != nil {
			t.Fatal(err)
		}
		if value.MissingRequiredFields != test.missing || value.GI == nil || value.GI.GateAuthorized != test.authorized {
			t.Fatalf("gate=%q parsed=%+v", test.gate, value)
		}
	}
}
