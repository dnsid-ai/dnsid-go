package dnsid

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestHTTPRegistryClient_LiveReplayDomain(t *testing.T) {
	key := GenerateEd25519KeyProvider().JWK()
	for _, test := range []struct {
		name, wireDomain       string
		invalid, includeDomain bool
	}{
		{name: "absent", invalid: true},
		{name: "null", includeDomain: true, invalid: true},
		{name: "empty", includeDomain: true, invalid: true},
		{name: "replay", wireDomain: "agent.example"},
		{name: "noncanonical", wireDomain: "Agent.Example.", invalid: true},
		{name: "invalid", wireDomain: "invalid domain", invalid: true},
		{name: "legacy nonce ignored", wireDomain: "agent.example"},
	} {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				response := map[string]any{"id": "agent-id", "status": "PROVISIONING", "publication_config": registrationTestConfig()}
				if test.name == "null" {
					response["domain"] = nil
				} else if test.includeDomain || test.wireDomain != "" {
					response["domain"] = test.wireDomain
				}
				if test.name == "legacy nonce ignored" {
					response["challenge"] = "obsolete"
					response["challenge_message"] = "not a valid transcript"
				}
				w.Header().Set("Idempotency-Key", "replay-key")
				w.WriteHeader(http.StatusCreated)
				_ = json.NewEncoder(w).Encode(response)
			}))
			defer server.Close()
			client, err := NewRegistryClient(server.URL)
			if err != nil {
				t.Fatal(err)
			}
			response, err := client.CreateLiveAgent(context.Background(), &LiveAgentRegistrationInput{Name: "exact ", PublicKey: key}, "replay-key")
			if test.invalid {
				if err == nil {
					t.Fatal("accepted invalid domain")
				}
				if response == nil || response.ID != "agent-id" {
					t.Fatalf("validation discarded creation facts: %+v", response)
				}
				return
			}
			if err != nil || response.Domain != test.wireDomain {
				t.Fatalf("response=%+v err=%v", response, err)
			}
		})
	}
}
