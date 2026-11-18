package dnsid

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestHTTPRegistryClient_LiveReplayDomain(t *testing.T) {
	provider := GenerateEd25519KeyProvider()
	key := provider.JWK()
	thumb, err := (&JWK{key: key}).Thumbprint()
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name, wireDomain, challengeDomain string
		want                              string
		invalid                           bool
		includeDomain                     bool
	}{
		{name: "absent"},
		{name: "null", includeDomain: true},
		{name: "empty", includeDomain: true, wireDomain: ""},
		{name: "replay", wireDomain: "Agent.Example.", want: "agent.example"},
		{name: "invalid", wireDomain: "invalid domain", invalid: true},
		{name: "matching transcript", wireDomain: "Agent.Example.", challengeDomain: "agent.example", want: "agent.example"},
		{name: "conflicting transcript", wireDomain: "other.example", challengeDomain: "agent.example", invalid: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				response := map[string]any{"request_id": "replay-key", "agent_id": "agent-id", "status": "provisioning", "challenge": "", "challenge_message": ""}
				if test.name == "null" {
					response["domain"] = nil
				} else if test.includeDomain || test.wireDomain != "" {
					response["domain"] = test.wireDomain
				}
				if test.challengeDomain != "" {
					message, _ := json.Marshal(LiveChallengeTranscript{Protocol: liveChallengeProtocol, OrgID: "org", AgentID: "agent-id", FQDN: test.challengeDomain, KeyID: thumb, Nonce: "nonce", ExpiresAt: time.Now().Add(time.Hour).UTC()})
					response["status"] = "challenge_pending"
					response["challenge"] = "nonce"
					response["challenge_message"] = base64.RawURLEncoding.EncodeToString(message)
				}
				w.WriteHeader(http.StatusAccepted)
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
				if response == nil || response.RequestID != "replay-key" || response.AgentID != "agent-id" {
					t.Fatalf("validation discarded creation facts: %+v", response)
				}
				return
			}
			if err != nil || response.Domain != test.want {
				t.Fatalf("response=%+v err=%v", response, err)
			}
		})
	}
}
