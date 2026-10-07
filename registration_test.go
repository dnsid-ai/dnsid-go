package dnsid

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
)

func registrationTestConfig() PublicationConfig {
	return PublicationConfig{PublishProfile: DefaultPublishProfile, GovernanceID: "example.test", KeyURL: "https://agent.example.test/keys", EntityKeyURL: "https://example.test/keys", LogRef: "testlog:1", StatusURL: "https://agent.example.test/status"}
}

func TestRegistration_SelectorsAndReplay(t *testing.T) {
	key := map[string]string{"kty": "OKP"}
	for _, req := range []CreateAgentRequest{
		{PublicKey: key},
		{Domain: "AGENT.example.test."},
		{RootDomain: "example.test", GovernanceDomain: "example.test", PublicKey: key},
		{GovernanceDomain: "example.test", PublicKey: key},
		{Managed: true, Environment: "production", PublicKey: key},
		{ZoneID: "zone-1", Environment: "sandbox", PublicKey: key},
		{Domain: "agent.example.test", Managed: true, PublicKey: key},
	} {
		t.Run(req.Domain+req.RootDomain+req.ZoneID+req.Environment, func(t *testing.T) {
			var requests []map[string]any
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Header.Get("Idempotency-Key") != "create-1" {
					t.Error("missing key")
				}
				var wire map[string]any
				if err := json.NewDecoder(r.Body).Decode(&wire); err != nil {
					t.Error(err)
				}
				requests = append(requests, wire)
				w.WriteHeader(http.StatusCreated)
				json.NewEncoder(w).Encode(CreateAgentResponse{ID: "id-1", Domain: "agent.example.test", PublicationConfig: registrationTestConfig(), OIDCIssuerURL: "https://issuer.example.test"})
			}))
			defer srv.Close()
			client, _ := NewRegistryClientWithOptions(srv.URL)
			for i := 0; i < 2; i++ {
				result, err := client.CreateAgentWithIdempotencyKey(context.Background(), &req, "create-1")
				if err != nil {
					t.Fatal(err)
				}
				if result.ID != "id-1" || result.PublicationConfig.MaxKeyAge != "" || result.OIDCIssuerURL != "https://issuer.example.test" {
					t.Fatalf("lost creation facts: %+v", result)
				}
			}
			if len(requests) != 2 || !reflect.DeepEqual(requests[0], requests[1]) {
				t.Fatalf("changed replay: %+v", requests)
			}
			if req.Environment == "" {
				if _, ok := requests[0]["environment"]; ok {
					t.Error("injected environment")
				}
			}
			if req.GovernanceDomain != "" && requests[0]["governance_domain"] != req.GovernanceDomain {
				t.Error("lost GI selector")
			}
			if req.RootDomain != "" && requests[0]["root_domain"] != req.RootDomain {
				t.Error("lost root selector")
			}
			if req.Domain != "" && requests[0]["domain"] != "agent.example.test" {
				t.Error("domain not normalized")
			}
		})
	}
}

func TestRegistration_InvalidInputDoesNotSend(t *testing.T) {
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls++ }))
	defer srv.Close()
	client, _ := NewRegistryClientWithOptions(srv.URL)
	for _, req := range []*CreateAgentRequest{
		nil, {}, {RootDomain: "example.test"}, {GovernanceDomain: "example.test"},
		{PublicKey: json.RawMessage("null")},
		{Domain: "agent.example.test", RootDomain: "bad domain"},
		{Domain: "agent.example.test", RootDomain: "example.test"},
		{Domain: "bad domain"}, {Domain: "agent.example.test", GovernanceDomain: "https://example.test"},
		{Domain: "agent.example.test", CapabilitiesURL: "http://example.test"},
		{Domain: "agent.example.test", Name: strings.Repeat("x", 256)},
		{Domain: "agent.example.test", PublicKey: map[string]any{"keys": []any{map[string]any{"keys": []any{map[string]string{"d": "secret"}}}}}},
		{PublicKey: map[string]string{"kty": "OKP"}, Tier: "live"},
	} {
		if _, err := client.CreateAgent(context.Background(), req); err == nil {
			t.Fatalf("accepted %+v", req)
		}
	}
	if calls != 0 {
		t.Fatalf("sent %d invalid requests", calls)
	}
}

func TestRegistration_ResponseAndRecovery(t *testing.T) {
	for _, scenario := range []string{"success", "detail failure", "unknown authority", "wrong instance", "wrong root", "wrong GI", "missing config", "unknown profile", "invalid URL", "invalid key age", "partial JSON", "wrong status", "AMBIGUOUS_ROOT", "GOVERNANCE_NOT_AUTHORIZED", "SERVICE_UNAVAILABLE", "MANAGED_GOVERNANCE_UNAVAILABLE", "IDEMPOTENCY_MISMATCH"} {
		t.Run(scenario, func(t *testing.T) {
			calls := 0
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls++
				if r.Header.Get("Authorization") != "Bearer token" {
					t.Error("anonymous request")
				}
				if r.Method == http.MethodGet {
					if scenario == "detail failure" {
						w.WriteHeader(http.StatusForbidden)
						return
					}
					managed := "dnsid"
					id := "id-1"
					if scenario == "unknown authority" {
						managed = "unknown"
					}
					if scenario == "wrong instance" {
						id = "id-2"
					}
					json.NewEncoder(w).Encode(AgentDetail{ID: id, Domain: "agent.example.test", Managed: managed, PublicationConfig: PublicationConfig{GovernanceID: "changed.test"}})
					return
				}
				codes := map[string]int{"AMBIGUOUS_ROOT": 409, "GOVERNANCE_NOT_AUTHORIZED": 403, "SERVICE_UNAVAILABLE": 503, "MANAGED_GOVERNANCE_UNAVAILABLE": 409, "IDEMPOTENCY_MISMATCH": 422}
				if status, ok := codes[scenario]; ok {
					w.WriteHeader(status)
					json.NewEncoder(w).Encode(map[string]string{"error": scenario})
					return
				}
				response := CreateAgentResponse{ID: "id-1", Domain: "agent.example.test", PublicationConfig: registrationTestConfig(), OIDCIssuerURL: "https://issuer.example.test"}
				switch scenario {
				case "wrong root":
					response.Domain = "agent.notexample.test"
				case "wrong GI":
					response.PublicationConfig.GovernanceID = "other.test"
				case "missing config":
					response.PublicationConfig = PublicationConfig{}
				case "unknown profile":
					response.PublicationConfig.PublishProfile = "dnsid-draft-99"
				case "invalid URL":
					response.PublicationConfig.EntityKeyURL = "http://example.test"
				case "invalid key age":
					response.PublicationConfig.MaxKeyAge = "1d"
				}
				status := http.StatusCreated
				if scenario == "wrong status" {
					status = http.StatusAccepted
				}
				w.WriteHeader(status)
				if scenario == "partial JSON" {
					w.Write([]byte(`{"id":"id-1","domain":"agent.example.test",`))
					return
				}
				json.NewEncoder(w).Encode(response)
			}))
			defer srv.Close()
			client, _ := NewRegistryClientWithOptions(srv.URL, WithAuthToken("token"))
			result, err := client.RegisterAgent(context.Background(), &AgentRegistrationInput{RootDomain: "example.test", GovernanceDomain: "example.test", PublicKeyJWK: map[string]string{"kty": "OKP"}}, "create-1")
			if scenario == "success" {
				if err != nil {
					t.Fatal(err)
				}
				if result.ID != "id-1" || result.PublicationAuthority != PublicationAuthorityRegistry || result.PublicationConfig.GovernanceID != "example.test" || result.OIDCIssuerURL != "https://issuer.example.test" {
					t.Fatalf("lost snapshot: %+v", result)
				}
				return
			}
			var recovery *RegistrationError
			if !errors.As(err, &recovery) || recovery.IdempotencyKey != "create-1" || len(recovery.Request) == 0 {
				t.Fatalf("missing recovery: %v", err)
			}
			var api *RegistryAPIError
			if strings.Contains(scenario, "_") && (!errors.As(err, &api) || api.Code != scenario) {
				t.Fatalf("lost server error: %v", err)
			}
			if scenario == "detail failure" || scenario == "unknown authority" || scenario == "wrong instance" {
				if calls != 2 || recovery.Creation.ID != "id-1" || recovery.Creation.OIDCIssuerURL == "" {
					t.Fatalf("lost creation: %+v", recovery)
				}
			} else if calls != 1 {
				t.Fatalf("fallback request: %d", calls)
			}
		})
	}
}

func TestRegistration_UnknownOutcome(t *testing.T) {
	client, _ := NewRegistryClientWithOptions("http://127.0.0.1:1")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := client.CreateAgentWithIdempotencyKey(ctx, &CreateAgentRequest{Domain: "agent.example.test"}, "create-1")
	var recovery *RegistrationError
	if !errors.As(err, &recovery) || !errors.Is(err, context.Canceled) || recovery.IdempotencyKey != "create-1" {
		t.Fatalf("lost unknown outcome: %v", err)
	}
}
