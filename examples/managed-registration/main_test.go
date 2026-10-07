package main

import (
	"context"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/dnsid-ai/dnsid-go/registration"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestDevAdapter_ResolveOrganization(t *testing.T) {
	for _, tc := range []struct {
		name   string
		status int
		body   string
		ok     bool
	}{
		{"authenticated", http.StatusOK, `{"user":{"org_id":"org-1","email":"ignored"}}`, true},
		{"unauthorized", http.StatusUnauthorized, `{"user":{"org_id":"org-1"}}`, false},
		{"redirect", http.StatusFound, "", false},
		{"missing organization", http.StatusOK, `{"user":{}}`, false},
		{"invalid JSON", http.StatusOK, `{`, false},
		{"oversized", http.StatusOK, strings.Repeat(" ", 65_537), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			adapter := &devAdapter{token: "test-token", http: &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
				if r.Method != http.MethodGet || r.URL.String() != registryURL+"/api/v1/auth/me" || r.Header.Get("Authorization") != "Bearer test-token" || r.Context() != ctx {
					t.Fatalf("unexpected organization request: %v", r)
				}
				return &http.Response{StatusCode: tc.status, Body: io.NopCloser(strings.NewReader(tc.body))}, nil
			})}}
			org, replay, err := adapter.ResolveOrganization(ctx)
			if tc.ok {
				if err != nil || org != "org-1" || replay.Retention != 24*time.Hour || replay.ClockUncertainty != 5*time.Minute || replay.Scope == "" || replay.StartConditions == "" {
					t.Fatalf("org=%q replay=%+v err=%v", org, replay, err)
				}
			} else if err == nil || org != "" || replay.Retention != 0 {
				t.Fatalf("accepted invalid organization response: org=%q err=%v", org, err)
			}
		})
	}
}

func TestRun_RejectsInvalidTokenBeforeSetup(t *testing.T) {
	for _, token := range []string{"", "two tokens", "token\n"} {
		if err := run(context.Background(), "", token); err == nil {
			t.Fatalf("accepted token %q", token)
		}
	}
}

func TestRun_RejectsDifferentRegistry(t *testing.T) {
	t.Setenv("DNSID_REGISTRY_URL", "https://other.example")
	if err := run(context.Background(), "", "test-token"); err == nil || err.Error() != "this example supports only the dev registry" {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestRun_RejectsLegacyRecoveryWithoutReplacingKey(t *testing.T) {
	t.Setenv("DNSID_REGISTRY_URL", "")
	directory := t.TempDir()
	if err := os.Chmod(directory, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "recovery.json")
	const legacy = `{"registration_key":"original-request","issuance_key":"original-issuance"}`
	if err := os.WriteFile(path, []byte(legacy), 0600); err != nil {
		t.Fatal(err)
	}
	err := run(context.Background(), directory, "test-token")
	var setup *registration.Error
	if !errors.As(err, &setup) || setup.Phase != "recovery" || setup.Code != "store" {
		t.Fatalf("unexpected error: %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil || string(data) != legacy {
		t.Fatalf("changed original recovery: %s, %v", data, err)
	}
	if _, err := os.Stat(filepath.Join(directory, "operational-key.json")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("created a replacement key: %v", err)
	}
}
