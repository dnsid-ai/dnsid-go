package dnsid

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	dnsidlog "github.com/dnsid-ai/dnsid-go/log"
)

type fakeRegistryClient struct {
	canonical     string
	signingKid    string
	published     string
	publishes     int
	revokes       int
	revokeRequest *RevokeAgentRequest
	registration  *AgentRegistration
}

func (c *fakeRegistryClient) GetRegistration(_ context.Context, domain string) (*AgentRegistration, error) {
	if c.registration != nil {
		return c.registration, nil
	}
	return &AgentRegistration{Domain: domain, PublicationAuthority: PublicationAuthorityClient, RegistryStatus: "READY"}, nil
}

func (c *fakeRegistryClient) CanonicalRecordContent(context.Context, string, string) (*CanonicalRecordContentResponse, error) {
	return &CanonicalRecordContentResponse{Canonical: c.canonical, SigningKid: c.signingKid}, nil
}

func (c *fakeRegistryClient) PublishSignature(_ context.Context, domain, sig string) (*PublishedRecord, error) {
	c.published = sig
	c.publishes++
	record, err := ParseUnsignedCanonical(c.canonical)
	if err != nil {
		return nil, err
	}
	record.Signature = sig
	return &PublishedRecord{
		Domain:            domain,
		OwnerName:         "_dnsid." + domain,
		TXTRecord:         record.Serialize(),
		TTL:               300,
		PublicationStatus: "publishing",
	}, nil
}

func (c *fakeRegistryClient) CreateAgent(_ context.Context, _ *CreateAgentRequest) (*CreateAgentResponse, error) {
	return &CreateAgentResponse{ID: "test-id", Domain: "agent.example.com", DomainDisplay: "agent.example.com", Status: "PENDING"}, nil
}

func (c *fakeRegistryClient) CreateLiveAgent(_ context.Context, _ *LiveAgentRegistrationInput, requestID string) (*LiveProvisioningResponse, error) {
	return &LiveProvisioningResponse{RequestID: requestID, AgentID: "test-id", Status: "challenge_pending"}, nil
}

func (c *fakeRegistryClient) UnregisterAgent(_ context.Context, _ string) error { return nil }

func (c *fakeRegistryClient) ListAgents(_ context.Context, _ *ListAgentsOptions) (*AgentListResponse, error) {
	return &AgentListResponse{Agents: []AgentListItem{}}, nil
}

func (c *fakeRegistryClient) GetAgentStatus(_ context.Context, _ string) (*AgentDetail, error) {
	return &AgentDetail{ID: "test-id", Domain: "agent.example.com", Status: "READY"}, nil
}

func (c *fakeRegistryClient) GetAgentEvents(_ context.Context, _ string, _ *EventListOptions) (*EventListResponse, error) {
	return &EventListResponse{Events: []AgentEvent{}}, nil
}

func (c *fakeRegistryClient) SubmitChallenge(_ context.Context, _ string, _ *ChallengeRequest) error {
	return nil
}

func (c *fakeRegistryClient) SubmitLiveProof(_ context.Context, _ string, req *LiveProofRequest) (*LiveProofResponse, error) {
	return &LiveProofResponse{RequestID: req.RequestID, AgentID: "test-id", Status: "provider_deferred"}, nil
}

func (c *fakeRegistryClient) ReissueLiveProof(_ context.Context, _ string, req *LiveProofReissueRequest) (*LiveProofReissueResponse, error) {
	return &LiveProofReissueResponse{RequestID: req.RequestID, AgentID: "test-id", Status: "challenge_pending"}, nil
}

func (c *fakeRegistryClient) RevokeAgent(_ context.Context, _ string, req *RevokeAgentRequest) (*LifecycleResponse, error) {
	c.revokes++
	c.revokeRequest = req
	return &LifecycleResponse{ID: "test-id", Status: "REVOKED"}, nil
}

func (c *fakeRegistryClient) RetireAgent(_ context.Context, _ string, _ *RetireAgentRequest) (*LifecycleResponse, error) {
	return &LifecycleResponse{ID: "test-id", Status: "RETIRED"}, nil
}

func (c *fakeRegistryClient) CancelAgent(_ context.Context, _ string) (*LifecycleResponse, error) {
	return &LifecycleResponse{ID: "test-id", Status: "CANCELLED"}, nil
}

func (c *fakeRegistryClient) RejectAgent(_ context.Context, _ string) (*LifecycleResponse, error) {
	return &LifecycleResponse{ID: "test-id", Status: "REJECTED"}, nil
}

func (c *fakeRegistryClient) VerifyAgent(_ context.Context, _ string) (*LifecycleResponse, error) {
	return &LifecycleResponse{ID: "test-id", Status: "READY"}, nil
}

func (c *fakeRegistryClient) ConfirmReady(_ context.Context, _ string) (*LifecycleResponse, error) {
	return c.VerifyAgent(context.Background(), "")
}

func (c *fakeRegistryClient) GetIdentityRecord(_ context.Context, _ string, _ *IdentityRecordRequest) (*IdentityRecordResponse, error) {
	return &IdentityRecordResponse{FQDN: "agent.example.com", CanonicalContent: c.canonical, SigningKid: c.signingKid, ExpiresAt: "2026-12-31T00:00:00Z", Tags: map[string]string{}}, nil
}

func (c *fakeRegistryClient) SubmitSignature(_ context.Context, _ string, _ *SignatureRequest) (*SignatureResponse, error) {
	return &SignatureResponse{FQDN: "agent.example.com", Status: "publishing", Records: []DNSRecord{{Name: "_dnsid.agent.example.com", Type: "TXT", Value: "test", TTL: 300}}}, nil
}

func (c *fakeRegistryClient) ListExpiringAgents(_ context.Context) (*OperationsAgentListResponse, error) {
	return &OperationsAgentListResponse{Agents: []OperationsAgent{}}, nil
}

func (c *fakeRegistryClient) ListFlaggedAgents(_ context.Context) (*OperationsAgentListResponse, error) {
	return &OperationsAgentListResponse{Agents: []OperationsAgent{}}, nil
}

func (c *fakeRegistryClient) ListPendingAgents(_ context.Context) (*OperationsAgentListResponse, error) {
	return &OperationsAgentListResponse{Agents: []OperationsAgent{}}, nil
}

func (c *fakeRegistryClient) VerifyDomainRemote(_ context.Context, _ *VerifyDomainRequest) (*VerifyDomainResponse, error) {
	return &VerifyDomainResponse{Domain: "agent.example.com", Registered: true}, nil
}

func mustBuildUnsignedTXTRecord(t *testing.T, manager *IdentityManager) *TXTRecord {
	t.Helper()
	record, err := manager.BuildUnsignedTXTRecord()
	if err != nil {
		t.Fatalf("BuildUnsignedTXTRecord: %v", err)
	}
	return record
}

func TestIdentityManagerPublishClientControlledRecordSignsRegistryCanonical(t *testing.T) {
	kp := GenerateES256KeyProvider()
	entityKP := GenerateES256KeyProvider()
	cfg := IdentityConfig{Domain: "agent.example.com", GovernanceID: "example.com", LogRef: "algorand:ADDR", StatusURL: "https://agent.example.com/status.json", KeyURL: "https://agent.example.com/ku.json", EntityKeyURL: "https://example.com/ek.json"}
	manager, err := NewIdentityManager(Config{Identity: &cfg}, kp, WithEntityKeyProvider(entityKP))
	if err != nil {
		t.Fatalf("NewIdentityManager: %v", err)
	}
	expected := mustBuildUnsignedTXTRecord(t, manager)
	canonical := string(expected.CanonicalContent())
	client := &fakeRegistryClient{canonical: canonical, signingKid: entityKP.ListKeyIds()[0]}

	published, err := manager.PublishClientControlledRecord(context.Background(), client)
	if err != nil {
		t.Fatalf("PublishClientControlledRecord: %v", err)
	}
	if client.publishes != 1 || client.published == "" {
		t.Fatalf("publish count/signature = %d/%q", client.publishes, client.published)
	}
	if published.Domain != "agent.example.com" || published.OwnerName != "_dnsid.agent.example.com" {
		t.Fatalf("published = %#v", published)
	}
	parsed, err := ParseTXTRecord(published.TXTRecord)
	if err != nil {
		t.Fatalf("ParseTXTRecord published: %v", err)
	}
	set := jwkSet(t, entityKP.JWK())
	if err := verifyRecordSignatureWithJWKS(parsed, set); err != nil {
		t.Fatalf("verifyRecordSignatureWithJWKS: %v", err)
	}
}

func TestIdentityManagerPublishClientControlledRecordSignsRegistryExtensions(t *testing.T) {
	opKP := GenerateEd25519KeyProvider()
	entityKP := GenerateEd25519KeyProvider()
	cfg := IdentityConfig{Domain: "agent.example.com", GovernanceID: "example.com", LogRef: "algorand:ADDR", StatusURL: "https://agent.example.com/status.json", KeyURL: "https://agent.example.com/ku.json", EntityKeyURL: "https://example.com/ek.json"}
	manager, err := NewIdentityManager(Config{Identity: &cfg}, opKP, WithEntityKeyProvider(entityKP))
	if err != nil {
		t.Fatalf("NewIdentityManager: %v", err)
	}
	expected := mustBuildUnsignedTXTRecord(t, manager)
	expected.UnknownTags = map[string]string{"exp": "1782864000"}
	canonical := string(expected.CanonicalContent())
	client := &fakeRegistryClient{canonical: canonical, signingKid: entityKP.ListKeyIds()[0]}

	published, err := manager.PublishClientControlledRecord(context.Background(), client)
	if err != nil {
		t.Fatalf("PublishClientControlledRecord: %v", err)
	}
	parsed, err := ParseTXTRecord(published.TXTRecord)
	if err != nil {
		t.Fatalf("ParseTXTRecord: %v", err)
	}
	if parsed.UnknownTags["exp"] != "1782864000" {
		t.Fatalf("exp extension = %q, want registry value", parsed.UnknownTags["exp"])
	}
	if err := verifyRecordSignatureWithJWKS(parsed, jwkSet(t, entityKP.JWK())); err != nil {
		t.Fatalf("registry extension was not covered by signature: %v", err)
	}
}

func TestIdentityManagerPublishClientControlledRecordRejectsRegistryAuthority(t *testing.T) {
	kp := GenerateEd25519KeyProvider()
	entityKP := GenerateEd25519KeyProvider()
	manager, err := NewIdentityManager(Config{Identity: &IdentityConfig{
		Domain: "agent.example.com", GovernanceID: "example.com", LogRef: "algorand:ADDR",
		StatusURL: "https://agent.example.com/status.json", KeyURL: "https://agent.example.com/ku.json",
		EntityKeyURL: "https://example.com/ek.json",
	}}, kp, WithEntityKeyProvider(entityKP))
	if err != nil {
		t.Fatalf("NewIdentityManager: %v", err)
	}
	client := &fakeRegistryClient{registration: &AgentRegistration{
		Domain: "agent.example.com", PublicationAuthority: PublicationAuthorityRegistry,
	}}
	if _, err := manager.PublishClientControlledRecord(context.Background(), client); err == nil {
		t.Fatal("PublishClientControlledRecord succeeded for registry authority")
	}
	if client.publishes != 0 {
		t.Fatal("signature was published")
	}
}

func TestIdentityManagerPublishClientControlledRecordPreservesAuthorityCheck(t *testing.T) {
	kp := GenerateEd25519KeyProvider()
	entityKP := GenerateEd25519KeyProvider()
	manager, err := NewIdentityManager(Config{Identity: &IdentityConfig{
		Domain: "agent.example.com", GovernanceID: "example.com", LogRef: "algorand:ADDR",
		StatusURL: "https://agent.example.com/status.json", KeyURL: "https://agent.example.com/ku.json",
		EntityKeyURL: "https://example.com/ek.json",
	}}, kp, WithEntityKeyProvider(entityKP))
	if err != nil {
		t.Fatalf("NewIdentityManager: %v", err)
	}
	client := &fakeRegistryClient{registration: &AgentRegistration{
		Domain: "agent.example.com", PublicationAuthority: PublicationAuthorityRegistry,
	}}
	if _, err := manager.PublishClientControlledRecord(context.Background(), client); err == nil {
		t.Fatal("PublishClientControlledRecord succeeded for registry authority")
	}
	if client.publishes != 0 {
		t.Fatal("signature was published")
	}
}

func TestIdentityManagerPublishClientControlledRecordRejectsMismatches(t *testing.T) {
	kp := GenerateEd25519KeyProvider()
	entityKP := GenerateEd25519KeyProvider()
	cfg := IdentityConfig{Domain: "agent.example.com", GovernanceID: "example.com", LogRef: "algorand:ADDR", StatusURL: "https://agent.example.com/status.json", KeyURL: "https://agent.example.com/ku.json", EntityKeyURL: "https://example.com/ek.json"}
	manager, err := NewIdentityManager(Config{Identity: &cfg}, kp, WithEntityKeyProvider(entityKP))
	if err != nil {
		t.Fatalf("NewIdentityManager: %v", err)
	}
	expected := string(mustBuildUnsignedTXTRecord(t, manager).CanonicalContent())

	for _, tt := range []struct {
		name       string
		canonical  string
		signingKid string
	}{
		{name: "wrong kid", canonical: expected, signingKid: "other"},
		{name: "known tag mismatch", canonical: strings.Replace(expected, "su=https://agent.example.com/status.json", "su=https://agent.example.com/other.json", 1), signingKid: entityKP.ListKeyIds()[0]},
		{name: "signature included", canonical: expected + ";sg=EdDSA:abc", signingKid: entityKP.ListKeyIds()[0]},
	} {
		t.Run(tt.name, func(t *testing.T) {
			client := &fakeRegistryClient{canonical: tt.canonical, signingKid: tt.signingKid}
			if _, err := manager.PublishClientControlledRecord(context.Background(), client); err == nil {
				t.Fatal("PublishClientControlledRecord succeeded")
			}
			if client.publishes != 0 {
				t.Fatalf("published despite mismatch")
			}
		})
	}
}

// --- HTTP client tests using httptest ---

type sequenceRegistrationReader struct {
	registrations []*AgentRegistration
	calls         int
}

func (r *sequenceRegistrationReader) GetRegistration(context.Context, string) (*AgentRegistration, error) {
	i := r.calls
	r.calls++
	if i >= len(r.registrations) {
		i = len(r.registrations) - 1
	}
	return r.registrations[i], nil
}

func TestIdentityManagerAwaitRegistryManagedPublicationRejectsWrongAuthorityAndTerminalState(t *testing.T) {
	manager, err := NewIdentityManager(Config{Identity: &IdentityConfig{
		Domain: "agent.example.com", GovernanceID: "example.com", LogRef: "algorand:ADDR", StatusURL: "https://agent.example.com/status.json",
	}}, GenerateES256KeyProvider())
	if err != nil {
		t.Fatalf("NewIdentityManager: %v", err)
	}
	for _, registration := range []*AgentRegistration{
		{Domain: "agent.example.com", PublicationAuthority: PublicationAuthorityClient, RegistryStatus: "READY", DNSPublished: true},
		{Domain: "agent.example.com", PublicationAuthority: PublicationAuthorityRegistry, RegistryStatus: "REJECTED"},
		{Domain: "agent.example.com", PublicationAuthority: PublicationAuthorityRegistry, RegistryStatus: "RETIRED"},
	} {
		reader := &sequenceRegistrationReader{registrations: []*AgentRegistration{registration}}
		if _, err := manager.AwaitRegistryManagedPublication(context.Background(), reader, nil); err == nil {
			t.Fatalf("AwaitRegistryManagedPublication succeeded for %#v", registration)
		}
	}
}

func TestIdentityManagerAwaitRegistryManagedPublicationRejectsVerificationOnlyProfile(t *testing.T) {
	operational := GenerateES256KeyProvider()
	entity := GenerateES256KeyProvider()
	config := IdentityConfig{
		Domain:       "agent.example.com",
		GovernanceID: "example.com",
		LogRef:       "testlog:agent",
		StatusURL:    "https://agent.example.com/status",
		KeyURL:       "https://agent.example.com/ku.json",
		EntityKeyURL: "https://keys.example.com/ek.json",
	}
	publisher, err := NewIdentityManager(Config{Identity: &config}, operational, WithEntityKeyProvider(entity))
	if err != nil {
		t.Fatalf("NewIdentityManager publisher: %v", err)
	}
	record := mustBuildUnsignedTXTRecord(t, publisher)
	record.Version = identityRecordDNSid1
	if _, err := signRecordWithKeyProvider(record, entity); err != nil {
		t.Fatalf("signRecordWithKeyProvider: %v", err)
	}

	ekJSON, err := json.Marshal(NewJWKS(jwkSet(t, entity.JWK())).Raw())
	if err != nil {
		t.Fatal(err)
	}
	kuJSON, err := json.Marshal(NewJWKS(jwkSet(t, operational.JWK())).Raw())
	if err != nil {
		t.Fatal(err)
	}
	dns := &testDNSResolver{records: map[string][]TXTRecordRData{
		"_dnsid.agent.example.com": {{Value: record.Serialize(), TTL: time.Minute}},
	}}
	https := testHTTPSFetcher{responses: map[string]json.RawMessage{
		record.EntityKeyURI: ekJSON,
		record.KeyURI:       kuJSON,
		record.StatusURI:    json.RawMessage(freshStatus()),
	}}
	logs := dnsidlog.NewLogRegistry()
	if err := logs.Register("testlog", func(string) dnsidlog.LogReader { return &testLogReader{} }); err != nil {
		t.Fatal(err)
	}
	manager, err := NewIdentityManager(Config{Identity: &config}, operational, WithDNSResolver(dns), WithHTTPSFetcher(&https), WithLogRegistry(logs))
	if err != nil {
		t.Fatalf("NewIdentityManager verifier: %v", err)
	}
	reader := &sequenceRegistrationReader{registrations: []*AgentRegistration{{
		Domain: "agent.example.com", PublicationAuthority: PublicationAuthorityRegistry,
		RegistryStatus: RegistryStatusReady, DNSPublished: true,
	}}}
	if _, err := manager.AwaitRegistryManagedPublication(context.Background(), reader, nil); err == nil || !strings.Contains(err.Error(), "unexpected DNSid version") {
		t.Fatalf("AwaitRegistryManagedPublication error = %v, want unexpected version", err)
	}
}

func TestCreateAgentRequestIncludesProductMetadata(t *testing.T) {
	data, err := json.Marshal(CreateAgentRequest{
		Domain:          "agent.example.com",
		Name:            "Procurement Bot",
		PublicKey:       map[string]string{"kty": "OKP"},
		CapabilitiesURL: "https://agent.example.com/AGENTS.md",
	})
	if err != nil {
		t.Fatal(err)
	}
	var body map[string]any
	if err := json.Unmarshal(data, &body); err != nil {
		t.Fatal(err)
	}
	if body["name"] != "Procurement Bot" || body["capabilities_url"] != "https://agent.example.com/AGENTS.md" {
		t.Fatalf("CreateAgentRequest JSON = %s", data)
	}
}

func TestHTTPRegistryClient_CreateAgent(t *testing.T) {
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.Method != http.MethodPost || r.URL.Path != "/api/v1/agent" {
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
		if r.Header.Get("Authorization") != "Bearer test-token" {
			t.Errorf("missing auth header")
		}
		var req CreateAgentRequest
		json.NewDecoder(r.Body).Decode(&req)
		if req.Domain != "agent.example.com" || req.Environment != "production" {
			t.Errorf("unexpected request: %+v", req)
		}
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(CreateAgentResponse{
			ID: "id-1", Domain: "agent.example.com", DomainDisplay: "agent.example.com", Status: "PENDING",
			StatusURL: "https://agent.example.com/status.json", OIDCIssuerURL: "https://issuer.example.com",
			PublicationConfig: PublicationConfig{
				PublishProfile: DefaultPublishProfile,
				GovernanceID:   "example.com",
				KeyURL:         "https://agent.example.com/ku.json",
				EntityKeyURL:   "https://example.com/ek.json",
				LogRef:         "log.example:1",
				StatusURL:      "https://agent.example.com/status.json",
			},
		})
	}))
	defer srv.Close()

	client := &HTTPRegistryClient{baseURL: srv.URL, client: srv.Client(), token: "test-token", allowInsecure: true}
	resp, err := client.CreateAgent(context.Background(), &CreateAgentRequest{Domain: "agent.example.com", Environment: "production", PublicKey: map[string]string{"kty": "OKP"}})
	if err != nil {
		t.Fatalf("CreateAgent: %v", err)
	}
	if resp.ID != "id-1" || resp.Status != "PENDING" || resp.PublicationConfig.LogRef != "log.example:1" || resp.OIDCIssuerURL != "https://issuer.example.com" {
		t.Fatalf("unexpected response: %+v", resp)
	}
	if _, err := client.CreateAgent(context.Background(), &CreateAgentRequest{PublicKey: map[string]string{"kty": "OKP", "d": "private"}}); err == nil {
		t.Fatal("CreateAgent accepted private JWK")
	}
	if calls != 1 {
		t.Fatal("CreateAgent sent private JWK")
	}
}

func TestPublicationConfigURLNamesPreserveJSONWireFields(t *testing.T) {
	raw, err := json.Marshal(PublicationConfig{
		KeyURL:       "https://agent.example.com/ku.json",
		EntityKeyURL: "https://example.com/ek.json",
	})
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	var fields map[string]any
	if err := json.Unmarshal(raw, &fields); err != nil {
		t.Fatalf("json.Unmarshal: %v", err)
	}
	if fields["ku_url"] != "https://agent.example.com/ku.json" || fields["ek_url"] != "https://example.com/ek.json" {
		t.Fatalf("URL wire fields = %#v", fields)
	}
	if _, ok := fields["KeyURL"]; ok {
		t.Fatalf("serialized Go field name KeyURL: %s", raw)
	}
	if _, ok := fields["EntityKeyURL"]; ok {
		t.Fatalf("serialized Go field name EntityKeyURL: %s", raw)
	}
}

func TestHTTPRegistryClient_CreateAgentValidatesEnvironment(t *testing.T) {
	var requests []CreateAgentRequest
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req CreateAgentRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Errorf("decode request: %v", err)
			return
		}
		requests = append(requests, req)
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(CreateAgentResponse{Domain: "assigned.zone.example"})
	}))
	defer srv.Close()

	client := &HTTPRegistryClient{baseURL: srv.URL, client: srv.Client(), allowInsecure: true}
	if _, err := client.CreateAgent(context.Background(), &CreateAgentRequest{Domain: "agent.example.com", PublicKey: map[string]string{"kty": "OKP"}}); err != nil {
		t.Fatalf("CreateAgent production default: %v", err)
	}
	if _, err := client.CreateAgent(context.Background(), &CreateAgentRequest{ZoneID: "zone-1", PublicKey: map[string]string{"kty": "OKP"}}); err != nil {
		t.Fatalf("CreateAgent zone managed: %v", err)
	}
	if len(requests) != 2 || requests[0].Environment != "production" || requests[0].Domain != "agent.example.com" || requests[1].Environment != "production" || requests[1].ZoneID != "zone-1" || requests[1].Domain != "" {
		t.Fatalf("requests = %+v", requests)
	}
	for _, req := range []*CreateAgentRequest{
		{},
		{Domain: "agent.example.com", Environment: "sandbox"},
		{Domain: "agent.example.com", Environment: "development"},
		{Domain: "agent.example.com", Environment: "staging"},
		{Domain: "agent.example.com", ZoneID: "zone-1", Environment: "production"},
		{Domain: "agent.example.com", Managed: true, Environment: "production"},
		{Managed: true},
		{Environment: "production"},
	} {
		if _, err := client.CreateAgent(context.Background(), req); err == nil {
			t.Fatalf("CreateAgent accepted invalid environment request: %+v", req)
		}
	}
	if len(requests) != 2 {
		t.Fatalf("registry calls = %d, want 2", len(requests))
	}
}

func TestHTTPRegistryClient_UnregisterAgent(t *testing.T) {
	statuses := []int{http.StatusNoContent, http.StatusNotFound, http.StatusMethodNotAllowed, http.StatusConflict}
	for _, status := range statuses {
		t.Run(http.StatusText(status), func(t *testing.T) {
			var method, path string
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				method, path = r.Method, r.URL.EscapedPath()
				w.WriteHeader(status)
			}))
			defer srv.Close()
			client := &HTTPRegistryClient{baseURL: srv.URL, client: srv.Client(), allowInsecure: true}
			err := client.UnregisterAgent(context.Background(), "agent/one.example.com")
			if method != http.MethodDelete || path != "/api/v1/agent/agent%2Fone.example.com" {
				t.Fatalf("request = %s %s", method, path)
			}
			if status == http.StatusConflict && err == nil {
				t.Fatal("UnregisterAgent accepted HTTP 409")
			}
			if status != http.StatusConflict && err != nil {
				t.Fatalf("UnregisterAgent: %v", err)
			}
		})
	}
}

func TestHTTPRegistryClient_ListAgents(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/api/v1/agent" {
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
		if r.URL.Query().Get("limit") != "10" {
			t.Errorf("unexpected limit: %s", r.URL.Query().Get("limit"))
		}
		json.NewEncoder(w).Encode(AgentListResponse{
			Agents:     []AgentListItem{{ID: "a1", Domain: "d1.example.com", Status: "READY"}},
			NextCursor: "cursor-2",
		})
	}))
	defer srv.Close()

	client := &HTTPRegistryClient{baseURL: srv.URL, client: srv.Client(), token: "tok", allowInsecure: true}
	resp, err := client.ListAgents(context.Background(), &ListAgentsOptions{Limit: 10})
	if err != nil {
		t.Fatalf("ListAgents: %v", err)
	}
	if len(resp.Agents) != 1 || resp.Agents[0].ID != "a1" {
		t.Fatalf("unexpected: %+v", resp)
	}
	if resp.NextCursor != "cursor-2" {
		t.Fatalf("unexpected cursor: %s", resp.NextCursor)
	}
}

func TestHTTPRegistryClient_GetAgentStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/api/v1/agent/agent.example.com/status" {
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
		json.NewEncoder(w).Encode(AgentDetail{
			ID: "id-1", Domain: "agent.example.com", DomainDisplay: "agent.example.com",
			Status: "READY", Managed: "dnsid", DNSPublished: true,
			Environment: "production", CreatedAt: time.Now(), UpdatedAt: time.Now(),
			StatusURL: "https://agent.example.com/status.json",
			PublicationConfig: PublicationConfig{
				PublishProfile: DefaultPublishProfile,
				GovernanceID:   "example.com",
				KeyURL:         "https://agent.example.com/ku.json",
				EntityKeyURL:   "https://example.com/ek.json",
				LogRef:         "log.example:1",
				StatusURL:      "https://agent.example.com/status.json",
			},
		})
	}))
	defer srv.Close()

	client := &HTTPRegistryClient{baseURL: srv.URL, client: srv.Client(), token: "tok", allowInsecure: true}
	resp, err := client.GetAgentStatus(context.Background(), "agent.example.com")
	if err != nil {
		t.Fatalf("GetAgentStatus: %v", err)
	}
	if resp.Status != "READY" || resp.Managed != "dnsid" || resp.PublicationConfig.LogRef != "log.example:1" {
		t.Fatalf("unexpected: %+v", resp)
	}
}

func TestHTTPRegistryClient_GetRegistration(t *testing.T) {
	for _, tt := range []struct {
		managed   string
		authority PublicationAuthority
	}{
		{managed: "self", authority: PublicationAuthorityClient},
		{managed: "dnsid", authority: PublicationAuthorityRegistry},
	} {
		t.Run(tt.managed, func(t *testing.T) {
			now := time.Now().UTC()
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				json.NewEncoder(w).Encode(AgentDetail{
					Domain: "agent.example.com", Managed: tt.managed, Status: "READY", ServerStatus: "READY",
					DNSPublished: true, ProtocolStatus: &AgentStatus{State: AgentStateActive, LastTransitionAt: now},
				})
			}))
			defer srv.Close()

			client := &HTTPRegistryClient{baseURL: srv.URL, client: srv.Client()}
			registration, err := client.GetRegistration(context.Background(), "agent.example.com")
			if err != nil {
				t.Fatalf("GetRegistration: %v", err)
			}
			if registration.PublicationAuthority != tt.authority || registration.RegistryStatus != "READY" || !registration.DNSPublished {
				t.Fatalf("registration = %#v", registration)
			}
			if registration.ProtocolStatus == nil || registration.ProtocolStatus.State != AgentStateActive {
				t.Fatalf("protocol status = %#v", registration.ProtocolStatus)
			}
		})
	}
}

func TestHTTPRegistryClient_GetRegistrationRejectsUnknownManagedMode(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(AgentDetail{Domain: "agent.example.com", Managed: "other", Status: "READY"})
	}))
	defer srv.Close()
	client := &HTTPRegistryClient{baseURL: srv.URL, client: srv.Client()}
	if _, err := client.GetRegistration(context.Background(), "agent.example.com"); err == nil {
		t.Fatal("GetRegistration succeeded")
	}
}

func TestHTTPRegistryClient_GetAgentEvents(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/api/v1/agent/agent.example.com/events" {
			t.Errorf("unexpected: %s %s", r.Method, r.URL.Path)
		}
		json.NewEncoder(w).Encode(EventListResponse{
			Events: []AgentEvent{{ID: "ev1", AgentID: "a1", EventType: "CREATED", CreatedAt: time.Now()}},
		})
	}))
	defer srv.Close()

	client := &HTTPRegistryClient{baseURL: srv.URL, client: srv.Client(), token: "tok", allowInsecure: true}
	resp, err := client.GetAgentEvents(context.Background(), "agent.example.com", nil)
	if err != nil {
		t.Fatalf("GetAgentEvents: %v", err)
	}
	if len(resp.Events) != 1 || resp.Events[0].EventType != "CREATED" {
		t.Fatalf("unexpected: %+v", resp)
	}
}

func TestHTTPRegistryClient_SubmitChallenge(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/api/v1/agent/agent.example.com/challenge" {
			t.Errorf("unexpected: %s %s", r.Method, r.URL.Path)
		}
		var req ChallengeRequest
		json.NewDecoder(r.Body).Decode(&req)
		if req.Nonce == "" || req.Signature == "" {
			t.Error("missing nonce/signature")
		}
		// Server returns 202 Accepted with no body.
		w.WriteHeader(http.StatusAccepted)
	}))
	defer srv.Close()

	client := &HTTPRegistryClient{baseURL: srv.URL, client: srv.Client(), token: "tok", allowInsecure: true}
	err := client.SubmitChallenge(context.Background(), "agent.example.com", &ChallengeRequest{Nonce: "abc", Signature: "sig123"})
	if err != nil {
		t.Fatalf("SubmitChallenge: %v", err)
	}
}

func liveChallengeMessage(t *testing.T, agentID, domain, keyID, nonce string) string {
	t.Helper()
	message, err := json.Marshal(LiveChallengeTranscript{
		Protocol: liveChallengeProtocol, OrgID: "org-1", AgentID: agentID,
		FQDN: domain, KeyID: keyID, Nonce: nonce, ExpiresAt: time.Now().Add(time.Hour).UTC(),
	})
	if err != nil {
		t.Fatal(err)
	}
	return base64.RawURLEncoding.EncodeToString(message)
}

func TestParseLiveChallenge_RejectsInvalidAndAllowsEmptyReplay(t *testing.T) {
	if domain, transcript, err := parseLiveChallenge("provider_deferred", "agent-1", "", "", "", ""); err != nil || domain != "" || transcript != nil {
		t.Fatalf("empty replay challenge = %q, %#v, %v", domain, transcript, err)
	}
	if _, _, err := parseLiveChallenge("challenge_pending", "agent-1", "challenge", "not-base64!", "key-1", ""); err == nil {
		t.Fatal("invalid challenge transcript accepted")
	}
	message := liveChallengeMessage(t, "agent-1", "live.example.com", "key-1", "challenge")
	if _, _, err := parseLiveChallenge("challenge_pending", "agent-1", "challenge", message, "other-key", ""); err == nil {
		t.Fatal("challenge transcript for another key accepted")
	}
}

func TestHTTPRegistryClient_CreateLiveAgent(t *testing.T) {
	publicKey := GenerateEd25519KeyProvider().JWK()
	keyID, _ := (&JWK{key: publicKey}).Thumbprint()
	challengeMessage := liveChallengeMessage(t, "agent-1", "live.example.com", keyID, "challenge")
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.Method != http.MethodPost || r.URL.Path != "/api/v1/agent" {
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
		requestID := r.Header.Get("Idempotency-Key")
		if requestID != "live-1" && requestID != "live-wrong-status" && requestID != "live-replay" {
			t.Errorf("Idempotency-Key = %q", requestID)
		}
		var body map[string]any
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		if body["tier"] != "live" || body["managed"] != true || body["environment"] != "production" || body["public_key"] == nil {
			t.Errorf("Live request = %+v", body)
		}
		if _, ok := body["domain"]; ok {
			t.Errorf("Live request includes domain: %+v", body)
		}
		if requestID == "live-wrong-status" {
			w.WriteHeader(http.StatusCreated)
		} else {
			w.WriteHeader(http.StatusAccepted)
		}
		if requestID == "live-replay" {
			json.NewEncoder(w).Encode(LiveProvisioningResponse{RequestID: requestID, AgentID: "agent-1", Status: "provider_deferred"})
			return
		}
		json.NewEncoder(w).Encode(LiveProvisioningResponse{
			RequestID: "live-1", AgentID: "agent-1", Status: "challenge_pending",
			Challenge: "challenge", ChallengeMessage: challengeMessage,
		})
	}))
	defer srv.Close()

	client := &HTTPRegistryClient{baseURL: srv.URL, client: srv.Client()}
	resp, err := client.CreateLiveAgent(context.Background(), &LiveAgentRegistrationInput{PublicKey: publicKey}, "live-1")
	if err != nil {
		t.Fatalf("CreateLiveAgent: %v", err)
	}
	if resp.RequestID != "live-1" || resp.AgentID != "agent-1" || resp.Domain != "live.example.com" || resp.ChallengeTranscript == nil || resp.ChallengeTranscript.KeyID != keyID {
		t.Fatalf("Live response = %+v", resp)
	}
	if _, err := client.CreateLiveAgent(context.Background(), &LiveAgentRegistrationInput{PublicKey: publicKey}, ""); err == nil || calls != 1 {
		t.Fatalf("missing idempotency key: calls=%d err=%v", calls, err)
	}
	if _, err := client.CreateLiveAgent(context.Background(), &LiveAgentRegistrationInput{PublicKey: publicKey}, "live-wrong-status"); err == nil || calls != 2 {
		t.Fatalf("CreateLiveAgent accepted HTTP 201: calls=%d err=%v", calls, err)
	}
	replay, err := client.CreateLiveAgent(context.Background(), &LiveAgentRegistrationInput{PublicKey: publicKey}, "live-replay")
	if err != nil || replay.Status != "provider_deferred" || replay.ChallengeTranscript != nil {
		t.Fatalf("CreateLiveAgent replay = %+v, %v", replay, err)
	}
	for _, invalid := range []any{
		GenerateES256KeyProvider().JWK(),
		map[string]any{"keys": []any{publicKey}},
		map[string]any{"keys": []any{map[string]any{"kty": "OKP", "crv": "Ed25519", "alg": "EdDSA", "x": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "d": "private"}}},
	} {
		if _, err := client.CreateLiveAgent(context.Background(), &LiveAgentRegistrationInput{PublicKey: invalid}, "live-invalid"); err == nil {
			t.Fatalf("CreateLiveAgent accepted invalid Live key: %#v", invalid)
		}
	}
	if calls != 3 {
		t.Fatalf("CreateLiveAgent sent invalid Live key: calls=%d", calls)
	}
}

func TestHTTPRegistryClient_LiveProofOperations(t *testing.T) {
	publicKey := GenerateEd25519KeyProvider().JWK()
	keyID, _ := (&JWK{key: publicKey}).Thumbprint()
	reissueMessage := liveChallengeMessage(t, "agent-1", "agent.example.com", keyID, "new")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.Header.Get("Idempotency-Key") != "live-1" {
			t.Errorf("unexpected request: %s %s", r.Method, r.Header.Get("Idempotency-Key"))
		}
		switch r.URL.Path {
		case "/api/v1/agent/agent.example.com/proof":
			var req LiveProofRequest
			json.NewDecoder(r.Body).Decode(&req)
			if req.RequestID != "live-1" || req.Challenge != "challenge" || req.Signature != "signature" {
				t.Errorf("proof request = %+v", req)
			}
			w.WriteHeader(http.StatusAccepted)
			json.NewEncoder(w).Encode(LiveProofResponse{RequestID: "live-1", AgentID: "agent-1", Status: "provider_deferred"})
		case "/api/v1/agent/agent.example.com/proof/reissue":
			var body map[string]any
			json.NewDecoder(r.Body).Decode(&body)
			if body["request_id"] != "live-1" || len(body) != 1 {
				t.Errorf("reissue request = %+v", body)
			}
			w.WriteHeader(http.StatusAccepted)
			json.NewEncoder(w).Encode(LiveProofReissueResponse{RequestID: "live-1", AgentID: "agent-1", Status: "challenge_pending", Challenge: "new", ChallengeMessage: reissueMessage})
		default:
			t.Errorf("unexpected path %q", r.URL.Path)
		}
	}))
	defer srv.Close()

	client := &HTTPRegistryClient{baseURL: srv.URL, client: srv.Client()}
	proof, err := client.SubmitLiveProof(context.Background(), "agent.example.com", &LiveProofRequest{
		RequestID: "live-1", Challenge: "challenge", PublicKey: publicKey, Signature: "signature",
	})
	if err != nil || proof.Status != "provider_deferred" {
		t.Fatalf("SubmitLiveProof = %+v, %v", proof, err)
	}
	reissue, err := client.ReissueLiveProof(context.Background(), "agent.example.com", &LiveProofReissueRequest{RequestID: "live-1", PublicKey: publicKey})
	if err != nil || reissue.Challenge != "new" || reissue.Domain != "agent.example.com" || reissue.ChallengeTranscript == nil || reissue.ChallengeTranscript.Nonce != "new" {
		t.Fatalf("ReissueLiveProof = %+v, %v", reissue, err)
	}
}

func TestHTTPRegistryClient_ReissueLiveProofRejectsUnboundOrInvalidKey(t *testing.T) {
	publicKey := GenerateEd25519KeyProvider().JWK()
	otherKeyID, _ := (&JWK{key: GenerateEd25519KeyProvider().JWK()}).Thumbprint()
	otherKeyMessage := liveChallengeMessage(t, "agent-1", "agent.example.com", otherKeyID, "new")
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		requestID := r.Header.Get("Idempotency-Key")
		response := LiveProofReissueResponse{RequestID: requestID, AgentID: "agent-1", Status: "challenge_pending"}
		if requestID == "wrong-key" {
			response.Challenge = "new"
			response.ChallengeMessage = otherKeyMessage
		} else {
			response.Status = "unexpected"
		}
		w.WriteHeader(http.StatusAccepted)
		json.NewEncoder(w).Encode(response)
	}))
	defer srv.Close()

	client := &HTTPRegistryClient{baseURL: srv.URL, client: srv.Client()}
	if _, err := client.ReissueLiveProof(context.Background(), "agent.example.com", &LiveProofReissueRequest{RequestID: "wrong-key", PublicKey: publicKey}); err == nil {
		t.Fatal("ReissueLiveProof accepted a challenge for another key")
	}
	if _, err := client.ReissueLiveProof(context.Background(), "agent.example.com", &LiveProofReissueRequest{RequestID: "status-bypass", PublicKey: publicKey}); err == nil {
		t.Fatal("ReissueLiveProof accepted a response without a replacement challenge")
	}
	for _, invalid := range []any{
		nil,
		GenerateES256KeyProvider().JWK(),
		map[string]any{"kty": "OKP", "crv": "Ed25519", "alg": "EdDSA", "x": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "d": "private"},
	} {
		if _, err := client.ReissueLiveProof(context.Background(), "agent.example.com", &LiveProofReissueRequest{RequestID: "invalid-key", PublicKey: invalid}); err == nil {
			t.Fatalf("ReissueLiveProof accepted invalid original key: %#v", invalid)
		}
	}
	if calls != 2 {
		t.Fatalf("ReissueLiveProof dispatched an invalid key: calls=%d", calls)
	}
}

func TestHTTPRegistryClient_RejectsInvalidLiveResponseFields(t *testing.T) {
	publicKey := GenerateEd25519KeyProvider().JWK()
	keyID, _ := (&JWK{key: publicKey}).Thumbprint()
	challengeMessage := liveChallengeMessage(t, "agent-1", "agent.example.com", keyID, "challenge")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestID := r.Header.Get("Idempotency-Key")
		body := map[string]any{
			"request_id":        requestID,
			"agent_id":          "agent-1",
			"status":            "challenge_pending",
			"challenge":         "challenge",
			"challenge_message": challengeMessage,
		}
		switch {
		case strings.HasSuffix(requestID, "-missing-request-id"):
			delete(body, "request_id")
		case strings.HasSuffix(requestID, "-missing-agent-id"):
			delete(body, "agent_id")
		case strings.HasSuffix(requestID, "-missing-status"):
			delete(body, "status")
		case strings.HasSuffix(requestID, "-mismatched-request-id"):
			body["request_id"] = "other-request"
		}
		w.WriteHeader(http.StatusAccepted)
		json.NewEncoder(w).Encode(body)
	}))
	defer srv.Close()

	client := &HTTPRegistryClient{baseURL: srv.URL, client: srv.Client()}
	operations := []struct {
		name string
		call func(string) error
	}{
		{"registration", func(requestID string) error {
			_, err := client.CreateLiveAgent(context.Background(), &LiveAgentRegistrationInput{PublicKey: publicKey}, requestID)
			return err
		}},
		{"proof", func(requestID string) error {
			_, err := client.SubmitLiveProof(context.Background(), "agent.example.com", &LiveProofRequest{RequestID: requestID, Challenge: "challenge", PublicKey: publicKey, Signature: "signature"})
			return err
		}},
		{"reissue", func(requestID string) error {
			_, err := client.ReissueLiveProof(context.Background(), "agent.example.com", &LiveProofReissueRequest{RequestID: requestID, PublicKey: publicKey})
			return err
		}},
	}
	for _, operation := range operations {
		for _, response := range []string{"missing-request-id", "missing-agent-id", "missing-status", "mismatched-request-id"} {
			t.Run(operation.name+"/"+response, func(t *testing.T) {
				if err := operation.call(operation.name + "-" + response); err == nil {
					t.Fatal("invalid Live response accepted")
				}
			})
		}
	}
}

func TestHTTPRegistryClient_RevokeAgent(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/api/v1/agent/agent.example.com/revoke" {
			t.Errorf("unexpected: %s %s", r.Method, r.URL.Path)
		}
		var req RevokeAgentRequest
		json.NewDecoder(r.Body).Decode(&req)
		if req.AgentID != "ag_123" {
			t.Errorf("unexpected agent ID: %s", req.AgentID)
		}
		if req.Reason != RegistryRevocationReasonOwnerRequest {
			t.Errorf("unexpected reason: %s", req.Reason)
		}
		json.NewEncoder(w).Encode(LifecycleResponse{ID: "id-1", Status: "REVOKED"})
	}))
	defer srv.Close()

	client := &HTTPRegistryClient{baseURL: srv.URL, client: srv.Client(), token: "tok", allowInsecure: true}
	resp, err := client.RevokeAgent(context.Background(), "agent.example.com", &RevokeAgentRequest{AgentID: "ag_123", Reason: RegistryRevocationReasonOwnerRequest})
	if err != nil {
		t.Fatalf("RevokeAgent: %v", err)
	}
	if resp.Status != "REVOKED" {
		t.Fatalf("unexpected: %+v", resp)
	}
}

func TestHTTPRegistryClient_RetireAgent(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/api/v1/agent/agent.example.com/retire" {
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
		var req RetireAgentRequest
		json.NewDecoder(r.Body).Decode(&req)
		if req.AgentID != "ag_123" {
			t.Errorf("agent_id = %q", req.AgentID)
		}
		json.NewEncoder(w).Encode(LifecycleResponse{ID: "ag_123", Status: "RETIRED"})
	}))
	defer srv.Close()

	client := &HTTPRegistryClient{baseURL: srv.URL, client: srv.Client()}
	resp, err := client.RetireAgent(context.Background(), "agent.example.com", &RetireAgentRequest{AgentID: "ag_123"})
	if err != nil || resp.Status != "RETIRED" {
		t.Fatalf("RetireAgent = %+v, %v", resp, err)
	}
}

func TestHTTPRegistryClient_RevokeAgentRejectsMissingIdentity(t *testing.T) {
	client := &HTTPRegistryClient{}
	for _, req := range []*RevokeAgentRequest{
		nil,
		{Reason: RegistryRevocationReasonOwnerRequest},
		{AgentID: "ag_123"},
		{AgentID: "ag_123", Reason: RegistryRevocationReason("keyCompromise")},
	} {
		if _, err := client.RevokeAgent(context.Background(), "agent.example.com", req); err == nil {
			t.Fatalf("RevokeAgent accepted incomplete request: %#v", req)
		}
	}
}

func TestHTTPRegistryClient_CancelAgent(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/api/v1/agent/agent.example.com/cancel" {
			t.Errorf("unexpected: %s %s", r.Method, r.URL.Path)
		}
		json.NewEncoder(w).Encode(LifecycleResponse{ID: "id-1", Status: "CANCELLED"})
	}))
	defer srv.Close()

	client := &HTTPRegistryClient{baseURL: srv.URL, client: srv.Client(), token: "tok", allowInsecure: true}
	resp, err := client.CancelAgent(context.Background(), "agent.example.com")
	if err != nil {
		t.Fatalf("CancelAgent: %v", err)
	}
	if resp.Status != "CANCELLED" {
		t.Fatalf("unexpected: %+v", resp)
	}
}

func TestHTTPRegistryClient_RejectAgent(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/api/v1/agent/agent.example.com/reject" {
			t.Errorf("unexpected: %s %s", r.Method, r.URL.Path)
		}
		json.NewEncoder(w).Encode(LifecycleResponse{ID: "id-1", Status: "REJECTED"})
	}))
	defer srv.Close()

	client := &HTTPRegistryClient{baseURL: srv.URL, client: srv.Client(), token: "tok", allowInsecure: true}
	resp, err := client.RejectAgent(context.Background(), "agent.example.com")
	if err != nil {
		t.Fatalf("RejectAgent: %v", err)
	}
	if resp.Status != "REJECTED" {
		t.Fatalf("unexpected: %+v", resp)
	}
}

func TestHTTPRegistryClient_ConfirmReady(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/api/v1/agent/agent.example.com/verify" {
			t.Errorf("unexpected: %s %s", r.Method, r.URL.Path)
		}
		json.NewEncoder(w).Encode(LifecycleResponse{ID: "id-1", Status: "READY"})
	}))
	defer srv.Close()

	client := &HTTPRegistryClient{baseURL: srv.URL, client: srv.Client(), token: "tok", allowInsecure: true}
	resp, err := client.ConfirmReady(context.Background(), "agent.example.com")
	if err != nil {
		t.Fatalf("ConfirmReady: %v", err)
	}
	if resp.Status != "READY" {
		t.Fatalf("unexpected: %+v", resp)
	}
}

func TestHTTPRegistryClient_WaitForStatus(t *testing.T) {
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/api/v1/agent/agent.example.com/status" {
			t.Errorf("unexpected: %s %s", r.Method, r.URL.Path)
		}
		calls++
		status := "VERIFYING"
		if calls >= 2 {
			status = "READY"
		}
		json.NewEncoder(w).Encode(AgentDetail{ID: "id-1", Domain: "agent.example.com", Status: status})
	}))
	defer srv.Close()

	client := &HTTPRegistryClient{baseURL: srv.URL, client: srv.Client()}
	resp, err := client.WaitForStatus(context.Background(), "agent.example.com", []string{"READY"}, &WaitForStatusOptions{PollInterval: time.Millisecond, Timeout: time.Second})
	if err != nil {
		t.Fatalf("WaitForStatus: %v", err)
	}
	if resp.Status != "READY" || calls != 2 {
		t.Fatalf("status/calls = %s/%d", resp.Status, calls)
	}
}

type staticRegistryStatusReader struct{ detail *AgentDetail }

func (r staticRegistryStatusReader) GetAgentStatus(context.Context, string) (*AgentDetail, error) {
	return r.detail, nil
}

type canceledRegistryStatusReader struct{}

func (canceledRegistryStatusReader) GetAgentStatus(ctx context.Context, _ string) (*AgentDetail, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}

type canceledRegistrationReader struct{}

func (canceledRegistrationReader) GetRegistration(ctx context.Context, _ string) (*AgentRegistration, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}

func TestWaitForRegistryStatusClassifiesTerminalAndCancellation(t *testing.T) {
	_, err := WaitForRegistryStatus(context.Background(), staticRegistryStatusReader{detail: &AgentDetail{Status: RegistryStatusRejected}}, "agent.example.com", []string{RegistryStatusReady}, nil)
	var workflowErr *RegistryWorkflowError
	if !errors.As(err, &workflowErr) || workflowErr.Status != RegistryStatusRejected {
		t.Fatalf("terminal error = %T %v, want *RegistryWorkflowError", err, err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = WaitForRegistryStatus(ctx, staticRegistryStatusReader{detail: &AgentDetail{Status: "VERIFYING"}}, "agent.example.com", []string{RegistryStatusReady}, &WaitForStatusOptions{PollInterval: time.Millisecond})
	if !errors.As(err, &workflowErr) || !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation error = %T %v, want workflow error wrapping context.Canceled", err, err)
	}

	ctx, cancel = context.WithCancel(context.Background())
	cancel()
	_, err = WaitForRegistryStatus(ctx, canceledRegistryStatusReader{}, "agent.example.com", []string{RegistryStatusReady}, nil)
	if !errors.As(err, &workflowErr) || !errors.Is(err, context.Canceled) {
		t.Fatalf("in-flight cancellation error = %T %v, want workflow error wrapping context.Canceled", err, err)
	}
}

func TestAwaitRegistryManagedPublicationClassifiesInFlightCancellation(t *testing.T) {
	manager, err := NewIdentityManager(Config{Identity: &IdentityConfig{
		Domain: "agent.example.com", GovernanceID: "example.com", LogRef: "algorand:ADDR",
		StatusURL: "https://agent.example.com/status.json",
	}}, GenerateEd25519KeyProvider())
	if err != nil {
		t.Fatalf("NewIdentityManager: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = manager.AwaitRegistryManagedPublication(ctx, canceledRegistrationReader{}, nil)
	var workflowErr *RegistryWorkflowError
	if !errors.As(err, &workflowErr) || !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation error = %T %v, want workflow error wrapping context.Canceled", err, err)
	}
}

func TestRegistryTransportFailureIsRegistryAPIError(t *testing.T) {
	cause := errors.New("connection refused")
	client := &HTTPRegistryClient{
		baseURL: "https://registry.example",
		client: &http.Client{Transport: roundTripperFunc(func(*http.Request) (*http.Response, error) {
			return nil, cause
		})},
	}
	_, err := client.GetAgentStatus(context.Background(), "agent.example.com")
	var apiErr *RegistryAPIError
	if !errors.As(err, &apiErr) || !errors.Is(err, cause) || !apiErr.Transient() || !apiErr.RetrySameEntry() {
		t.Fatalf("transport error = %T %v, want retryable *RegistryAPIError", err, err)
	}
}

func TestHTTPRegistryClient_PrepareAndSubmitKeyRotation(t *testing.T) {
	prepared := []byte(`{"domain":"agent.example.com","event":"KEY_ROTATION"}`)
	completed := []byte(`{"domain":"agent.example.com","event":"KEY_ROTATION","sigs":{"prev_op":"a","new_op":"b"}}`)
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.Header.Get("Idempotency-Key") != "rotation-1" {
			t.Errorf("Idempotency-Key = %q", r.Header.Get("Idempotency-Key"))
		}
		body, _ := io.ReadAll(r.Body)
		switch r.URL.Path {
		case "/api/v1/agent/agent.example.com/tlog/issuance/prepare":
			if len(body) != 0 {
				t.Errorf("issuance body = %q", body)
			}
			w.Header().Set("DNSID-Log-Reference", "c2sp-tlog:stream")
			w.WriteHeader(http.StatusCreated)
			w.Write(prepared)
		case "/api/v1/agent/agent.example.com/tlog/key-rotation/prepare":
			var request map[string]any
			if err := json.Unmarshal(body, &request); err != nil {
				t.Fatalf("decode preparation request: %v", err)
			}
			if request["previous_key_id"] != "old-kid" || request["public_key"] == nil {
				t.Errorf("preparation request = %s", body)
			}
			w.Header().Set("DNSID-Log-Reference", "c2sp-tlog:stream")
			w.WriteHeader(http.StatusCreated)
			w.Write(prepared)
		case "/api/v1/agent/agent.example.com/tlog/events":
			if string(body) != string(completed) {
				t.Errorf("submitted bytes changed:\n got %s\nwant %s", body, completed)
			}
			sum := sha256.Sum256(completed)
			w.WriteHeader(http.StatusCreated)
			fmt.Fprintf(w, `{"entry_hash":%q,"index":4,"key_id":"new-kid","lr":"c2sp-tlog:stream","state":"accepted"}`, hex.EncodeToString(sum[:]))
		default:
			t.Errorf("unexpected path %q", r.URL.Path)
		}
	}))
	defer srv.Close()

	client := &HTTPRegistryClient{baseURL: srv.URL, client: srv.Client()}
	issuance, err := client.PrepareIssuance(context.Background(), "agent.example.com", "rotation-1")
	if err != nil || string(issuance.EntryBytes) != string(prepared) {
		t.Fatalf("PrepareIssuance = %#v, %v", issuance, err)
	}
	response, err := client.PrepareKeyRotation(context.Background(), "agent.example.com", &KeyRotationPreparationRequest{
		PreviousKeyID: "old-kid", PublicKey: map[string]any{"kid": "new-kid"},
	}, "rotation-1")
	if err != nil {
		t.Fatalf("PrepareKeyRotation: %v", err)
	}
	if string(response.EntryBytes) != string(prepared) || response.LogReference != "c2sp-tlog:stream" {
		t.Fatalf("prepared response = %#v", response)
	}
	result, err := client.SubmitPreparedEvent(context.Background(), "agent.example.com", completed, "rotation-1")
	if err != nil {
		t.Fatalf("SubmitPreparedEvent: %v", err)
	}
	sum := sha256.Sum256(completed)
	if calls != 3 || result.EntryHash != hex.EncodeToString(sum[:]) || result.Index == nil || *result.Index != 4 || result.State != SubmissionStateAccepted {
		t.Fatalf("calls/result = %d/%#v", calls, result)
	}
	if _, err := client.PrepareKeyRotation(context.Background(), "agent.example.com", &KeyRotationPreparationRequest{
		PreviousKeyID: "old-kid", PublicKey: map[string]any{"kid": "new-kid", "d": "private"},
	}, "rotation-2"); err == nil {
		t.Fatal("PrepareKeyRotation accepted private JWK")
	}
	if calls != 3 {
		t.Fatal("private JWK was sent to registry")
	}
}

func TestHTTPRegistryClient_SubmitPreparedEventRejectsAcceptedHashMismatch(t *testing.T) {
	entry := []byte(`{"kind":"dnsid.lifecycle"}`)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/agent/agent.example.com/tlog/events" {
			t.Errorf("unexpected path %q", r.URL.Path)
		}
		json.NewEncoder(w).Encode(SubmissionResult{State: SubmissionStateAccepted, EntryHash: strings.Repeat("0", 64)})
	}))
	defer srv.Close()

	client := &HTTPRegistryClient{baseURL: srv.URL, client: srv.Client()}
	if _, err := client.SubmitPreparedEvent(context.Background(), "agent.example.com", entry, "submission-1"); err == nil || !strings.Contains(err.Error(), "exact submitted bytes") {
		t.Fatalf("SubmitPreparedEvent error = %v, want entry hash mismatch", err)
	}
}

func TestHTTPRegistryClient_SubmitPreparedEventRejectsUnknownState(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		json.NewEncoder(w).Encode(SubmissionResult{State: SubmissionState("unexpected")})
	}))
	defer srv.Close()

	client := &HTTPRegistryClient{baseURL: srv.URL, client: srv.Client()}
	_, err := client.SubmitPreparedEvent(context.Background(), "agent.example.com", []byte(`{"kind":"dnsid.lifecycle"}`), "submission-1")
	var validationErr *ValidationError
	if !errors.As(err, &validationErr) {
		t.Fatalf("SubmitPreparedEvent error = %T %v, want *ValidationError", err, err)
	}
}

func TestRegistryAPIErrorRetrySameEntry(t *testing.T) {
	for _, tt := range []struct {
		name       string
		statusCode int
		code       string
		want       bool
	}{
		{name: "busy", code: "TLOG_SUBMISSION_BUSY", want: true},
		{name: "indeterminate", code: "TLOG_SUBMISSION_INDETERMINATE", want: true},
		{name: "idempotency mismatch", code: "IDEMPOTENCY_MISMATCH", want: false},
		{name: "preparation mismatch", code: "TLOG_PREPARATION_MISMATCH", want: false},
		{name: "invalid entry", code: "TLOG_INVALID_ENTRY", want: false},
		{name: "unclassified error", code: "", want: false},
		{name: "unclassified 503", statusCode: http.StatusServiceUnavailable, want: true},
		{name: "rate limited", statusCode: http.StatusTooManyRequests, want: true},
		{name: "terminal code overrides 503", statusCode: http.StatusServiceUnavailable, code: "TLOG_INVALID_ENTRY", want: false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if got := (&RegistryAPIError{StatusCode: tt.statusCode, Code: tt.code}).RetrySameEntry(); got != tt.want {
				t.Fatalf("RetrySameEntry() = %v, want %v", got, tt.want)
			}
		})
	}
	var nilError *RegistryAPIError
	if nilError.RetrySameEntry() {
		t.Fatal("nil RegistryAPIError is retryable")
	}
}

func TestHTTPRegistryClient_GetIdentityRecord(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/api/v1/agent/agent.example.com/record" {
			t.Errorf("unexpected: %s %s", r.Method, r.URL.Path)
		}
		json.NewEncoder(w).Encode(IdentityRecordResponse{
			FQDN: "agent.example.com", CanonicalContent: "v=dnsid1;...", SigningKid: "kid-1",
			ExpiresAt: "2026-12-31T00:00:00Z", Tags: map[string]string{"su": "https://example.com/status"},
		})
	}))
	defer srv.Close()

	client := &HTTPRegistryClient{baseURL: srv.URL, client: srv.Client(), token: "tok", allowInsecure: true}
	resp, err := client.GetIdentityRecord(context.Background(), "agent.example.com", &IdentityRecordRequest{SigningKid: "kid-1"})
	if err != nil {
		t.Fatalf("GetIdentityRecord: %v", err)
	}
	if resp.SigningKid != "kid-1" || resp.FQDN != "agent.example.com" {
		t.Fatalf("unexpected: %+v", resp)
	}
}

func TestHTTPRegistryClient_SubmitSignature(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/api/v1/agent/agent.example.com/signature" {
			t.Errorf("unexpected: %s %s", r.Method, r.URL.Path)
		}
		json.NewEncoder(w).Encode(SignatureResponse{
			FQDN: "agent.example.com", Status: "publishing", Message: "DNS records being published",
			Records: []DNSRecord{{Name: "_dnsid.agent.example.com", Type: "TXT", Value: "v=dnsid1;sg=EdDSA:abc", TTL: 300}},
		})
	}))
	defer srv.Close()

	client := &HTTPRegistryClient{baseURL: srv.URL, client: srv.Client(), token: "tok", allowInsecure: true}
	resp, err := client.SubmitSignature(context.Background(), "agent.example.com", &SignatureRequest{Signature: "EdDSA:abc"})
	if err != nil {
		t.Fatalf("SubmitSignature: %v", err)
	}
	if resp.Status != "publishing" || len(resp.Records) != 1 {
		t.Fatalf("unexpected: %+v", resp)
	}
}

// TestHTTPRegistryClient_PublishSignature verifies that publication workflow
// state is not represented as protocol AgentStatus.
func TestHTTPRegistryClient_PublishSignature(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/api/v1/agent/agent.example.com/signature" {
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
		// Return a free-form status that is NOT one of the six AgentState constants.
		json.NewEncoder(w).Encode(SignatureResponse{
			FQDN:   "agent.example.com",
			Status: "pending_publication",
			Records: []DNSRecord{{
				Name:  "_dnsid.agent.example.com",
				Type:  "TXT",
				Value: "v=dnsid1;sg=EdDSA:abc",
				TTL:   300,
			}},
		})
	}))
	defer srv.Close()

	client := &HTTPRegistryClient{baseURL: srv.URL, client: srv.Client(), token: "tok", allowInsecure: true}
	record, err := client.PublishSignature(context.Background(), "agent.example.com", "EdDSA:abc")
	if err != nil {
		t.Fatalf("PublishSignature: %v", err)
	}

	if record.PublicationStatus != "pending_publication" {
		t.Errorf("PublicationStatus = %q, want %q", record.PublicationStatus, "pending_publication")
	}
	if record.ProtocolStatus != nil {
		t.Errorf("ProtocolStatus = %#v, want nil", record.ProtocolStatus)
	}

	// Verify JSON keeps publication and protocol status separate.
	data, err := json.Marshal(record)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	var m map[string]any
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatalf("json.Unmarshal: %v", err)
	}
	if m["publicationStatus"] != "pending_publication" {
		t.Errorf("JSON publicationStatus = %v, want %q", m["publicationStatus"], "pending_publication")
	}
	if _, ok := m["protocolStatus"]; ok {
		t.Error("JSON unexpectedly contains protocolStatus")
	}
	if _, ok := m["status"]; ok {
		t.Error("JSON unexpectedly contains deprecated status")
	}

	// Verify domain and record fields.
	if record.Domain != "agent.example.com" {
		t.Errorf("Domain = %q", record.Domain)
	}
	if record.OwnerName != "_dnsid.agent.example.com" {
		t.Errorf("OwnerName = %q", record.OwnerName)
	}
	if record.TXTRecord != "v=dnsid1;sg=EdDSA:abc" {
		t.Errorf("TXTRecord = %q", record.TXTRecord)
	}
	if record.TTL != 300 {
		t.Errorf("TTL = %d", record.TTL)
	}
}

// TestHTTPRegistryClient_SubmitSignature_202Accepted verifies that the legacy
// endpoint's asynchronous response remains decodable.
func TestHTTPRegistryClient_SubmitSignature_202Accepted(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/api/v1/agent/sandbox.example.com/signature" {
			t.Errorf("unexpected: %s %s", r.Method, r.URL.Path)
		}
		w.WriteHeader(http.StatusAccepted)
		json.NewEncoder(w).Encode(SignatureResponse{
			FQDN: "sandbox.example.com", Status: "pending_publication", Message: "Queued for DNS publication",
			Records: []DNSRecord{{Name: "_dnsid.sandbox.example.com", Type: "TXT", Value: "v=dnsid1;sg=EdDSA:xyz", TTL: 300}},
		})
	}))
	defer srv.Close()

	client := &HTTPRegistryClient{baseURL: srv.URL, client: srv.Client(), token: "tok", allowInsecure: true}
	resp, err := client.SubmitSignature(context.Background(), "sandbox.example.com", &SignatureRequest{Signature: "EdDSA:xyz"})
	if err != nil {
		t.Fatalf("SubmitSignature with 202: %v", err)
	}
	if resp.Status != "pending_publication" || resp.FQDN != "sandbox.example.com" {
		t.Fatalf("unexpected response: %+v", resp)
	}
}

func TestHTTPRegistryClient_ListExpiringAgents(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/api/v1/agent/expiring" {
			t.Errorf("unexpected: %s %s", r.Method, r.URL.Path)
		}
		json.NewEncoder(w).Encode(OperationsAgentListResponse{
			Agents: []OperationsAgent{{ID: "a1", Domain: "d.example.com", Status: "READY", DaysRemaining: intPtr(5)}},
		})
	}))
	defer srv.Close()

	client := &HTTPRegistryClient{baseURL: srv.URL, client: srv.Client(), token: "tok", allowInsecure: true}
	resp, err := client.ListExpiringAgents(context.Background())
	if err != nil {
		t.Fatalf("ListExpiringAgents: %v", err)
	}
	if len(resp.Agents) != 1 || *resp.Agents[0].DaysRemaining != 5 {
		t.Fatalf("unexpected: %+v", resp)
	}
}

func TestHTTPRegistryClient_ListFlaggedAgents(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/agent/flagged" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		json.NewEncoder(w).Encode(OperationsAgentListResponse{Agents: []OperationsAgent{}})
	}))
	defer srv.Close()

	client := &HTTPRegistryClient{baseURL: srv.URL, client: srv.Client(), token: "tok", allowInsecure: true}
	resp, err := client.ListFlaggedAgents(context.Background())
	if err != nil {
		t.Fatalf("ListFlaggedAgents: %v", err)
	}
	if resp.Agents == nil {
		t.Fatal("expected non-nil agents slice")
	}
}

func TestHTTPRegistryClient_ListPendingAgents(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/agent/pending" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		json.NewEncoder(w).Encode(OperationsAgentListResponse{Agents: []OperationsAgent{}})
	}))
	defer srv.Close()

	client := &HTTPRegistryClient{baseURL: srv.URL, client: srv.Client(), token: "tok", allowInsecure: true}
	resp, err := client.ListPendingAgents(context.Background())
	if err != nil {
		t.Fatalf("ListPendingAgents: %v", err)
	}
	if resp.Agents == nil {
		t.Fatal("expected non-nil agents slice")
	}
}

func TestHTTPRegistryClient_VerifyDomainRemote(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/api/v1/verify/domain" {
			t.Errorf("unexpected: %s %s", r.Method, r.URL.Path)
		}
		var req VerifyDomainRequest
		json.NewDecoder(r.Body).Decode(&req)
		json.NewEncoder(w).Encode(VerifyDomainResponse{Domain: req.Domain, Registered: true})
	}))
	defer srv.Close()

	client := &HTTPRegistryClient{baseURL: srv.URL, client: srv.Client(), token: "tok", allowInsecure: true}
	resp, err := client.VerifyDomainRemote(context.Background(), &VerifyDomainRequest{Domain: "agent.example.com"})
	if err != nil {
		t.Fatalf("VerifyDomainRemote: %v", err)
	}
	if !resp.Registered || resp.Domain != "agent.example.com" {
		t.Fatalf("unexpected: %+v", resp)
	}
}

func TestHTTPRegistryClient_ErrorResponse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusConflict)
		json.NewEncoder(w).Encode(map[string]string{"error": "conflict", "message": "agent already exists"})
	}))
	defer srv.Close()

	client := &HTTPRegistryClient{baseURL: srv.URL, client: srv.Client(), token: "tok", allowInsecure: true}
	_, err := client.CreateAgent(context.Background(), &CreateAgentRequest{Domain: "agent.example.com", Environment: "production", PublicKey: map[string]string{}})
	if err == nil {
		t.Fatal("expected error")
	}
	var apiErr *RegistryAPIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("expected *RegistryAPIError, got %T: %v", err, err)
	}
	if apiErr.StatusCode != http.StatusConflict || apiErr.Code != "conflict" {
		t.Fatalf("unexpected error: %+v", apiErr)
	}
}

func TestHTTPRegistryClient_AuthHeaderSent(t *testing.T) {
	var gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		json.NewEncoder(w).Encode(AgentListResponse{Agents: []AgentListItem{}})
	}))
	defer srv.Close()

	client := &HTTPRegistryClient{baseURL: srv.URL, client: srv.Client(), token: "my-secret-token", allowInsecure: true}
	_, _ = client.ListAgents(context.Background(), nil)
	if gotAuth != "Bearer my-secret-token" {
		t.Fatalf("expected Bearer token, got: %q", gotAuth)
	}
}

func TestHTTPRegistryClient_SetAuthToken_BlocksHTTP(t *testing.T) {
	client := &HTTPRegistryClient{baseURL: "http://example.com", client: http.DefaultClient}
	err := client.SetAuthToken("secret")
	if err == nil {
		t.Fatal("expected error setting token on HTTP client")
	}
	if client.token != "" {
		t.Fatal("token should not have been stored")
	}

	// With allowInsecure, it should succeed.
	client.allowInsecure = true
	err = client.SetAuthToken("secret")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if client.token != "secret" {
		t.Fatal("token should have been stored")
	}

	// Loopback HTTP is allowed without opting in.
	local := &HTTPRegistryClient{baseURL: "http://127.0.0.1:7755", client: http.DefaultClient}
	if err := local.SetAuthToken("testnet"); err != nil || local.token != "testnet" {
		t.Fatalf("loopback SetAuthToken: err=%v token=%q", err, local.token)
	}
}

func TestNewRegistryClient_DefaultsToLocal(t *testing.T) {
	t.Setenv("DNSID_REGISTRY_URL", "http://localhost:9999/")
	t.Setenv("DNSID_API_KEY", "testnet")

	// Plain constructors never read the environment.
	c, err := NewRegistryClient("")
	if err != nil || c.baseURL != DefaultRegistryURL || c.token != "" {
		t.Fatalf("NewRegistryClient(\"\") = %+v, %v", c, err)
	}

	c, err = NewRegistryClientFromEnv()
	if err != nil || c.baseURL != "http://localhost:9999" || c.token != "testnet" {
		t.Fatalf("env-resolved client = %+v, %v", c, err)
	}

	// Explicit options win over the environment; unset env means local, no token.
	c, err = NewRegistryClientFromEnv(WithAuthToken("k"))
	if err != nil || c.token != "k" {
		t.Fatalf("explicit option client = %+v, %v", c, err)
	}
	t.Setenv("DNSID_REGISTRY_URL", "")
	t.Setenv("DNSID_API_KEY", "")
	c, err = NewRegistryClientFromEnv()
	if err != nil || c.baseURL != DefaultRegistryURL || c.token != "" {
		t.Fatalf("unset env client = %+v, %v", c, err)
	}

	// Plaintext HTTP off loopback is rejected, token or not.
	if _, err := NewRegistryClientWithOptions("http://example.com"); err == nil {
		t.Fatal("expected rejection of non-loopback HTTP")
	}
	if _, err := NewRegistryClient("http://example.com"); err == nil {
		t.Fatal("expected rejection of non-loopback HTTP")
	}
	if _, err := NewRegistryClientWithOptions("http://example.com", WithInsecureHTTP()); err != nil {
		t.Fatalf("WithInsecureHTTP should still permit non-loopback HTTP: %v", err)
	}
}

func TestHTTPRegistryClient_ConnectionRefusedOnLoopbackHints(t *testing.T) {
	srv := httptest.NewServer(http.NotFoundHandler())
	addr := srv.URL
	srv.Close() // nothing listening now

	c, err := NewRegistryClientWithOptions(addr)
	if err != nil {
		t.Fatal(err)
	}
	_, err = c.GetAgentStatus(context.Background(), "agent.example.com")
	if err == nil || !strings.Contains(err.Error(), "run `dnsid local up`") {
		t.Fatalf("expected local-registry hint, got: %v", err)
	}
}

func TestIdentityManagerPublishClientControlledRecord_TwoKeyUsesEntityKey(t *testing.T) {
	// For the two-key profile, PublishClientControlledRecord must sign with the entity key,
	// not the operational key.
	entityKP := GenerateES256KeyProvider()
	opKP := GenerateES256KeyProvider()
	cfg := IdentityConfig{
		Domain:       "agent.example.com",
		GovernanceID: "example.com",
		LogRef:       "algorand:ADDR",
		StatusURL:    "https://agent.example.com/status.json",
		KeyURL:       "https://agent.example.com/ku.json",
		EntityKeyURL: "https://example.com/ek.json",
	}
	manager, err := NewIdentityManager(Config{Identity: &cfg}, opKP, WithEntityKeyProvider(entityKP))
	if err != nil {
		t.Fatalf("NewIdentityManager: %v", err)
	}

	// The signing kid must be the entity key's kid, not the operational key's.
	ekKid := entityKP.ListKeyIds()[0]
	opKid := opKP.ListKeyIds()[0]
	if ekKid == opKid {
		t.Fatal("test setup: entity and operational keys have the same kid")
	}

	expected := mustBuildUnsignedTXTRecord(t, manager)
	canonical := string(expected.CanonicalContent())
	client := &fakeRegistryClient{canonical: canonical, signingKid: ekKid}

	published, err := manager.PublishClientControlledRecord(context.Background(), client)
	if err != nil {
		t.Fatalf("PublishClientControlledRecord: %v", err)
	}
	if client.publishes != 1 {
		t.Fatalf("publish count = %d, want 1", client.publishes)
	}

	// Verify the signature was produced by the entity key.
	parsed, err := ParseTXTRecord(published.TXTRecord)
	if err != nil {
		t.Fatalf("ParseTXTRecord: %v", err)
	}
	ekSet := jwkSet(t, entityKP.JWK())
	if err := verifyRecordSignatureWithJWKS(parsed, ekSet); err != nil {
		t.Fatalf("signature not valid with entity key: %v", err)
	}

	// Ensure the record uses the two-key version.
	if parsed.Version != DefaultPublishProfile {
		t.Fatalf("Version = %q, want %q", parsed.Version, DefaultPublishProfile)
	}
	if parsed.EntityKeyURI == "" {
		t.Fatal("EntityKeyURI is empty for two-key record")
	}
}

func TestIdentityManagerPublishClientControlledRecord_TwoKeyDelegatedGovernance(t *testing.T) {
	// Delegated governance: gi is NOT a parent of Domain.
	// PublishClientControlledRecord must still work and produce a valid record.
	entityKP := GenerateES256KeyProvider()
	opKP := GenerateES256KeyProvider()
	cfg := IdentityConfig{
		Domain:       "agent.otherdomain.com",
		GovernanceID: "governance.example.com",
		LogRef:       "algorand:ADDR",
		StatusURL:    "https://agent.otherdomain.com/status.json",
		KeyURL:       "https://agent.otherdomain.com/ku.json",
		EntityKeyURL: "https://governance.example.com/ek.json",
	}
	manager, err := NewIdentityManager(Config{Identity: &cfg}, opKP, WithEntityKeyProvider(entityKP))
	if err != nil {
		t.Fatalf("NewIdentityManager: %v", err)
	}

	ekKid := entityKP.ListKeyIds()[0]
	expected := mustBuildUnsignedTXTRecord(t, manager)

	// The ek= must be under governance.example.com for delegated governance.
	if !strings.Contains(expected.EntityKeyURI, "governance.example.com") {
		t.Fatalf("EntityKeyURI = %q, want host under governance.example.com", expected.EntityKeyURI)
	}

	canonical := string(expected.CanonicalContent())
	client := &fakeRegistryClient{canonical: canonical, signingKid: ekKid}

	published, err := manager.PublishClientControlledRecord(context.Background(), client)
	if err != nil {
		t.Fatalf("PublishClientControlledRecord: %v", err)
	}
	if client.publishes != 1 {
		t.Fatalf("publish count = %d, want 1", client.publishes)
	}

	// Verify the published record passes validation for the agent domain.
	parsed, err := ParseTXTRecord(published.TXTRecord)
	if err != nil {
		t.Fatalf("ParseTXTRecord: %v", err)
	}
	// For 20260626 domain-governance profile, gi != parent is allowed
	// but ek= host must be at or under gi.
	if parsed.EntityKeyURI == "" {
		t.Fatal("EntityKeyURI is empty")
	}
}

func intPtr(v int) *int { return &v }

func TestRegistryAPIErrorSubmissionSemantics(t *testing.T) {
	tests := []struct {
		name      string
		status    int
		code      string
		state     SubmissionState
		transient bool
		retry     bool
	}{
		{"busy", http.StatusConflict, "TLOG_SUBMISSION_BUSY", SubmissionStatePending, true, true},
		{"indeterminate", http.StatusConflict, "TLOG_SUBMISSION_INDETERMINATE", SubmissionStateIndeterminate, true, true},
		{"idempotency mismatch", http.StatusConflict, "TLOG_IDEMPOTENCY_MISMATCH", SubmissionStateRejected, false, false},
		{"503 without code", http.StatusServiceUnavailable, "", SubmissionStateIndeterminate, true, true},
		{"429 without code", http.StatusTooManyRequests, "", SubmissionStateIndeterminate, true, true},
		{"terminal code overrides 503", http.StatusServiceUnavailable, "TLOG_INVALID_ENTRY", SubmissionStateRejected, false, false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := &RegistryAPIError{StatusCode: test.status, Code: test.code}
			if err.SubmissionState() != test.state || err.Transient() != test.transient || err.RetrySameEntry() != test.retry {
				t.Fatalf("semantics = %q/%v/%v", err.SubmissionState(), err.Transient(), err.RetrySameEntry())
			}
		})
	}
}
