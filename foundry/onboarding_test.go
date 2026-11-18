//go:build dnsid_foundry

package foundry

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
)

func TestCreate_OnboardingReadinessAndCompatibility(t *testing.T) {
	for _, test := range []struct {
		name   string
		change func(map[string]any)
		kind   ErrorKind
	}{
		{"governance not started", func(m map[string]any) { delete(m, "gi"); delete(m, "governance_domain") }, WorkflowOutcome},
		{"missing gi", func(m map[string]any) { delete(m, "gi") }, WorkflowOutcome},
		{"null gi", func(m map[string]any) { m["gi"] = nil }, WorkflowOutcome},
		{"missing governance domain", func(m map[string]any) { delete(m, "governance_domain") }, WorkflowOutcome},
		{"pending entity delegation", func(m map[string]any) { m["ek"].(map[string]any)["status"] = "pending" }, WorkflowOutcome},
		{"unauthorized gate", func(m map[string]any) { m["gi"].(map[string]any)["gate_authorized"] = false }, WorkflowOutcome},
		{"missing organization", func(m map[string]any) { delete(m, "org_id"); delete(m, "gi") }, UnsupportedContract},
		{"missing ek", func(m map[string]any) { delete(m, "ek") }, UnsupportedContract},
		{"missing ek status", func(m map[string]any) { delete(m["ek"].(map[string]any), "status") }, UnsupportedContract},
		{"missing gi domain", func(m map[string]any) { delete(m["gi"].(map[string]any), "domain") }, UnsupportedContract},
		{"missing gi state", func(m map[string]any) { delete(m["gi"].(map[string]any), "state") }, UnsupportedContract},
		{"missing gate", func(m map[string]any) { delete(m["gi"].(map[string]any), "gate_authorized") }, UnsupportedContract},
		{"null gate", func(m map[string]any) { m["gi"].(map[string]any)["gate_authorized"] = nil }, UnsupportedContract},
	} {
		t.Run(test.name, func(t *testing.T) {
			f := newFixture(t)
			body := map[string]any{
				"org_id":            testOrg,
				"governance_domain": "governance.example",
				"gi":                map[string]any{"domain": "governance.example", "state": "verified", "gate_authorized": true},
				"ek":                map[string]any{"status": "verified"},
			}
			test.change(body)
			wire, err := json.Marshal(body)
			if err != nil {
				t.Fatal(err)
			}
			if err := json.Unmarshal(wire, f.registry.onboarding); err != nil {
				t.Fatal(err)
			}
			// Not-ready and malformed responses must fail before expected-GI checks.
			f.client.loaded.Foundry.GovernanceID = "different.example"
			_, err = f.client.Create(context.Background(), "onboarding")
			outcome := requireKind(t, err, test.kind)
			var unsupported *UnsupportedRegistry
			if errors.As(err, &unsupported) != (test.kind == UnsupportedContract) || outcome.Resumable != (test.kind == WorkflowOutcome) {
				t.Fatalf("wrong compatibility or resumability: %v", err)
			}
			if f.registry.createCalls != 0 || f.document("onboarding") != nil {
				t.Fatal("onboarding failure mutated creation state")
			}
		})
	}
}
