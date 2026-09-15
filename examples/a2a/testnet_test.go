package main

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"golang.org/x/mod/sumdb/note"
)

const testLogRef = "c2sp-tlog:testnet:http://log-reference.invalid:4321/log#instance_AAAAAAAAAAAAAAAAAAAAAA"

func TestCreateLogRegistryRequiresTrustedPolicyURL(t *testing.T) {
	for _, policyURL := range []string{"", " \t"} {
		_, err := createLogRegistry(context.Background(), testLogRef, policyURL, nil)
		if err == nil || !strings.Contains(err.Error(), "DNSID_LOG_POLICY_URL is required") {
			t.Fatalf("createLogRegistry error = %v, want missing DNSID_LOG_POLICY_URL error", err)
		}
	}
}

func TestCreateLogRegistryFetchesSeparatelyConfiguredPolicyURL(t *testing.T) {
	_, verifierKey, err := note.GenerateKey(nil, "log-reference.invalid:4321/log")
	if err != nil {
		t.Fatal(err)
	}
	policy := fmt.Sprintf("log %s\nquorum none\n", verifierKey)

	var requested string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		requested = req.URL.RequestURI()
		_, _ = w.Write([]byte(policy))
	}))
	t.Cleanup(server.Close)
	policyURL := server.URL + "/trusted/testnet-policy?version=1"

	registry, err := createLogRegistry(context.Background(), testLogRef, policyURL, server.Client())
	if err != nil {
		t.Fatalf("createLogRegistry: %v", err)
	}
	if registry == nil {
		t.Fatal("createLogRegistry returned a nil registry")
	}
	if requested != "/trusted/testnet-policy?version=1" {
		t.Fatalf("policy request = %q, want separately configured URL", requested)
	}
}

func TestCreateLogRegistryRejectsPolicyForDifferentLogOrigin(t *testing.T) {
	_, verifierKey, err := note.GenerateKey(nil, "different-log.example")
	if err != nil {
		t.Fatal(err)
	}
	policy := fmt.Sprintf("log %s\nquorum none\n", verifierKey)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(policy))
	}))
	t.Cleanup(server.Close)

	_, err = createLogRegistry(context.Background(), testLogRef, server.URL+"/dnsid-policy", server.Client())
	if err == nil || !strings.Contains(err.Error(), "does not match log origin") {
		t.Fatalf("createLogRegistry error = %v, want policy/log origin mismatch", err)
	}
}
