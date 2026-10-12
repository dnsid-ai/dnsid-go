package dnsid

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestOnboarding_RequiresVerifiedAccountBinding(t *testing.T) {
	const valid = `{"org_id":"org-1","governance_domain":"account.example","gi":{"domain":"account.example","state":"verified","gate_authorized":true},"ek":{"status":"verified"}}`
	for _, scenario := range []string{"ready", "missing org", "invalid GI", "wrong org", "wrong expected GI", "missing proof", "wrong proof GI", "pending proof", "not authorized", "pending delegation"} {
		t.Run(scenario, func(t *testing.T) {
			var response OrganizationOnboardingResponse
			if err := json.Unmarshal([]byte(valid), &response); err != nil {
				t.Fatal(err)
			}
			expected := OrganizationBinding{OrganizationID: "org-1", GovernanceID: "account.example"}
			switch scenario {
			case "missing org":
				response.OrganizationID = ""
			case "invalid GI":
				response.GovernanceDomain = "https://account.example"
			case "wrong org":
				expected.OrganizationID = "other"
			case "wrong expected GI":
				expected.GovernanceID = "other.example"
			case "missing proof":
				response.GI = nil
			case "wrong proof GI":
				response.GI.Domain = "other.example"
			case "pending proof":
				response.GI.State = "pending"
			case "not authorized":
				response.GI.GateAuthorized = false
			case "pending delegation":
				response.EK.Status = "pending"
			}
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { json.NewEncoder(w).Encode(response) }))
			defer server.Close()
			client, err := NewRegistryClientWithOptions(server.URL, WithAuthToken("token"))
			if err != nil {
				t.Fatal(err)
			}
			_, err = client.GetOrganizationOnboarding(context.Background(), expected)
			if (err == nil) != (scenario == "ready") {
				t.Fatalf("readiness validation: %v", err)
			}
		})
	}
}

func TestOnboarding_PreservesAuthorizationAndUnavailableErrors(t *testing.T) {
	for _, status := range []int{http.StatusUnauthorized, http.StatusForbidden, http.StatusServiceUnavailable} {
		calls := 0
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			calls++
			w.WriteHeader(status)
			w.Write([]byte(`{"error":"UNAVAILABLE"}`))
		}))
		client, err := NewRegistryClientWithOptions(server.URL, WithAuthToken("token"))
		if err != nil {
			t.Fatal(err)
		}
		_, err = client.GetOrganizationOnboarding(context.Background(), OrganizationBinding{OrganizationID: "saved"})
		server.Close()
		var api *RegistryAPIError
		if !errors.As(err, &api) || api.StatusCode != status || calls != 1 {
			t.Fatalf("lost %d: %v calls=%d", status, err, calls)
		}
	}
}
