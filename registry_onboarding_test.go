package dnsid

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

func TestHTTPRegistryClient_GetOrganizationOnboarding(t *testing.T) {
	var calls atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.URL.Path != "/api/v1/org/onboarding" || r.Method != http.MethodGet || (r.Header.Get("Authorization") != "Bearer token" && r.Header.Get("Authorization") != "Bearer wrong") {
			t.Errorf("unexpected onboarding request: %s %s", r.Method, r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		if r.Header.Get("Authorization") == "Bearer wrong" {
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`{"error":"FORBIDDEN"}`))
			return
		}
		_, _ = w.Write([]byte(`{"org_id":"org-1","governance_domain":"account.example","gi":{"domain":"account.example","state":"verified","gate_authorized":true},"ek":{"status":"verified"},"name":"Account"}`))
	}))
	defer server.Close()
	client, err := NewRegistryClientWithOptions(server.URL, WithRegistryHTTPClient(server.Client()), WithAuthToken("token"))
	if err != nil {
		t.Fatal(err)
	}
	view, err := client.GetOrganizationOnboarding(context.Background())
	if err != nil || view.OrganizationID != "org-1" || view.GI == nil || !view.GI.GateAuthorized || view.EK.Status != "verified" {
		t.Fatalf("onboarding: %#v %v", view, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := client.GetOrganizationOnboarding(ctx); err == nil || calls.Load() != 1 {
		t.Fatal("onboarding ignored cancellation")
	}
	if err := client.SetAuthToken("wrong"); err != nil {
		t.Fatal(err)
	}
	_, err = client.GetOrganizationOnboarding(context.Background())
	var api *RegistryAPIError
	if !errors.As(err, &api) || api.StatusCode != http.StatusForbidden || calls.Load() != 2 {
		t.Fatalf("authorization error lost or anonymous fallback: %v", err)
	}
}
