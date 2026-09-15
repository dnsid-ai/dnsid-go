package dnsid

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestNewIdentityManagerFromDnsid(t *testing.T) {
	dir := t.TempDir()
	domain := "agent.example.com"
	keyPath := filepath.Join(dir, domain, "private.jwk")
	if err := os.MkdirAll(filepath.Dir(keyPath), 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadOrCreateLocalKeyProvider(keyPath, JoseAlgES256); err != nil {
		t.Fatalf("create key: %v", err)
	}
	writeJSON(t, filepath.Join(dir, "config.json"), map[string]any{
		"server_url":    "https://api.dnsid.ai",
		"agent_id":      "ag_123",
		"domain":        domain,
		"governance_id": "example.com",
		"status_url":    "https://api.dnsid.ai/v1/status/agent.example.com",
		"environment":   "sandbox",
	})

	m, err := NewIdentityManagerFromDnsid(dir, Config{})
	if err != nil {
		t.Fatalf("NewIdentityManagerFromDnsid: %v", err)
	}
	if got := m.Domain(); got != domain {
		t.Fatalf("Domain() = %q, want %q", got, domain)
	}
	if m.KeyProvider() == nil {
		t.Fatal("KeyProvider() = nil")
	}
	if _, err := m.CreateTXTRecord(); err == nil || !strings.Contains(err.Error(), "entity KeyProvider") {
		t.Fatalf("CreateTXTRecord error = %v, want missing DNSid1 entity key", err)
	}
}

func TestNewIdentityManagerFromDnsidUsesConfigDirEnvironment(t *testing.T) {
	dir := t.TempDir()
	domain := "agent.example.com"
	keyPath := filepath.Join(dir, "private.jwk")
	if _, err := LoadOrCreateLocalKeyProvider(keyPath, JoseAlgES256); err != nil {
		t.Fatalf("create key: %v", err)
	}
	writeJSON(t, filepath.Join(dir, "config.json"), map[string]any{
		"server_url":    "https://api.dnsid.ai",
		"domain":        domain,
		"governance_id": "example.com",
	})
	t.Setenv("DNSID_CONFIG_DIR", dir)

	m, err := NewIdentityManagerFromDnsid("", Config{})
	if err != nil {
		t.Fatalf("NewIdentityManagerFromDnsid: %v", err)
	}
	if got := m.Domain(); got != domain {
		t.Fatalf("Domain() = %q, want %q", got, domain)
	}
}

func TestNewIdentityManagerFromDnsidExplicitDirOverridesEnvironment(t *testing.T) {
	dir := t.TempDir()
	domain := "explicit.example.com"
	keyPath := filepath.Join(dir, "private.jwk")
	if _, err := LoadOrCreateLocalKeyProvider(keyPath, JoseAlgES256); err != nil {
		t.Fatalf("create key: %v", err)
	}
	writeJSON(t, filepath.Join(dir, "config.json"), map[string]any{
		"server_url":    "https://api.dnsid.ai",
		"domain":        domain,
		"governance_id": "example.com",
	})
	t.Setenv("DNSID_CONFIG_DIR", filepath.Join(t.TempDir(), "missing"))

	m, err := NewIdentityManagerFromDnsid(dir, Config{})
	if err != nil {
		t.Fatalf("NewIdentityManagerFromDnsid: %v", err)
	}
	if got := m.Domain(); got != domain {
		t.Fatalf("Domain() = %q, want %q", got, domain)
	}
}

func TestNewIdentityManagerFromDnsidLoadsDNSid1PublicationConfig(t *testing.T) {
	dir := t.TempDir()
	domain := "agent.example.com"
	opKeyPath := filepath.Join(dir, domain, "private.jwk")
	if err := os.MkdirAll(filepath.Dir(opKeyPath), 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadOrCreateLocalKeyProvider(opKeyPath, JoseAlgEdDSA); err != nil {
		t.Fatalf("create operational key: %v", err)
	}
	entityKeyPath := filepath.Join(dir, domain, "entity.jwk")
	entityKey, err := LoadOrCreateLocalKeyProvider(entityKeyPath, JoseAlgEdDSA)
	if err != nil {
		t.Fatalf("create entity key: %v", err)
	}
	writeJSON(t, filepath.Join(dir, "config.json"), map[string]any{
		"server_url":       "https://api.dnsid.ai",
		"domain":           domain,
		"governance_id":    "example.com",
		"status_url":       "https://agent.example.com/status.json",
		"ku_url":           "https://agent.example.com/ku.json",
		"ek_url":           "https://example.com/ek.json",
		"entity_key_path":  filepath.Join(domain, "entity.jwk"),
		"log_ref":          "custom-log:42",
		"capabilities_url": "https://agent.example.com/AGENTS.md",
		"publish_profile":  DefaultPublishProfile,
		"max_key_age":      "90d",
	})

	m, err := NewIdentityManagerFromDnsid(dir, Config{})
	if err != nil {
		t.Fatalf("NewIdentityManagerFromDnsid: %v", err)
	}
	record, err := m.CreateTXTRecord()
	if err != nil {
		t.Fatalf("CreateTXTRecord: %v", err)
	}
	if record.Version != DefaultPublishProfile || record.KeyURI != "https://agent.example.com/ku.json" || record.EntityKeyURI != "https://example.com/ek.json" || record.LogRef != "custom-log:42" || record.Capabilities != "https://agent.example.com/AGENTS.md" || record.KeyAge != "90d" {
		t.Fatalf("unexpected DNSid1 record: %#v", record)
	}
	if err := verifyRecordSignatureWithJWKS(record, jwkSet(t, entityKey.JWK())); err != nil {
		t.Fatalf("record signature was not produced by configured entity key: %v", err)
	}
	entityKid := entityKey.ListKeyIds()[0]
	client := &fakeRegistryClient{canonical: string(record.CanonicalContent()), signingKid: entityKid}
	published, err := m.PublishClientControlledRecord(context.Background(), client)
	if err != nil {
		t.Fatalf("PublishClientControlledRecord: %v", err)
	}
	publishedRecord, err := ParseTXTRecord(published.TXTRecord)
	if err != nil {
		t.Fatalf("ParseTXTRecord: %v", err)
	}
	if err := verifyRecordSignatureWithJWKS(publishedRecord, jwkSet(t, entityKey.JWK())); err != nil {
		t.Fatalf("published record signature was not produced by configured entity key: %v", err)
	}
}

func TestNewIdentityManagerFromDnsidLoadsPerDomainExportConfig(t *testing.T) {
	root := t.TempDir()
	domain := "agent.example.com"
	dir := filepath.Join(root, domain)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadOrCreateLocalKeyProvider(filepath.Join(dir, "private.jwk"), JoseAlgEdDSA); err != nil {
		t.Fatalf("create operational key: %v", err)
	}
	entityKey, err := LoadOrCreateLocalKeyProvider(filepath.Join(dir, "entity.jwk"), JoseAlgEdDSA)
	if err != nil {
		t.Fatalf("create entity key: %v", err)
	}
	writeJSON(t, filepath.Join(dir, "config.json"), map[string]any{
		"domain":          domain,
		"governance_id":   "example.com",
		"status_url":      "https://agent.example.com/status.json",
		"ku_url":          "https://agent.example.com/ku.json",
		"ek_url":          "https://example.com/ek.json",
		"entity_key_path": "entity.jwk",
		"log_ref":         "testlog:7",
		"publish_profile": DefaultPublishProfile,
		"max_key_age":     "90d",
	})

	m, err := NewIdentityManagerFromDnsid(dir, Config{})
	if err != nil {
		t.Fatalf("NewIdentityManagerFromDnsid: %v", err)
	}
	record, err := m.CreateTXTRecord()
	if err != nil {
		t.Fatalf("CreateTXTRecord: %v", err)
	}
	if record.LogRef != "testlog:7" {
		t.Fatalf("record LogRef = %q, want registry-provided value", record.LogRef)
	}
	if err := verifyRecordSignatureWithJWKS(record, jwkSet(t, entityKey.JWK())); err != nil {
		t.Fatalf("record signature was not produced by exported entity key: %v", err)
	}
}

func TestNewIdentityManagerFromDnsidAllowsOptionalMaxKeyAge(t *testing.T) {
	dir := t.TempDir()
	domain := "agent.example.com"
	if err := os.MkdirAll(filepath.Join(dir, domain), 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadOrCreateLocalKeyProvider(filepath.Join(dir, domain, "private.jwk"), JoseAlgEdDSA); err != nil {
		t.Fatalf("create operational key: %v", err)
	}
	if _, err := LoadOrCreateLocalKeyProvider(filepath.Join(dir, domain, "entity.jwk"), JoseAlgEdDSA); err != nil {
		t.Fatalf("create entity key: %v", err)
	}
	writeJSON(t, filepath.Join(dir, "config.json"), map[string]any{
		"domain":          domain,
		"governance_id":   "example.com",
		"status_url":      "https://agent.example.com/status.json",
		"ku_url":          "https://agent.example.com/ku.json",
		"ek_url":          "https://example.com/ek.json",
		"entity_key_path": filepath.Join(domain, "entity.jwk"),
		"log_ref":         "testlog:7",
		"publish_profile": DefaultPublishProfile,
	})

	manager, err := NewIdentityManagerFromDnsid(dir, Config{})
	if err != nil {
		t.Fatalf("NewIdentityManagerFromDnsid: %v", err)
	}
	record, err := manager.CreateTXTRecord()
	if err != nil {
		t.Fatalf("CreateTXTRecord: %v", err)
	}
	if record.KeyAge != "" {
		t.Fatalf("KeyAge = %q, want empty", record.KeyAge)
	}
}

func TestNewIdentityManagerFromDnsidRequiresLogRefForEntityKey(t *testing.T) {
	dir := t.TempDir()
	writeJSON(t, filepath.Join(dir, "config.json"), map[string]any{
		"domain":          "agent.example.com",
		"entity_key_path": "entity.jwk",
	})

	_, err := NewIdentityManagerFromDnsid(dir, Config{})
	var validationErr *ValidationError
	if !errors.As(err, &validationErr) || !strings.Contains(err.Error(), "must include log_ref") {
		t.Fatalf("err = %T %v, want *ValidationError requiring log_ref", err, err)
	}
}

func TestNewIdentityManagerFromDnsidDerivesStatusURL(t *testing.T) {
	dir := t.TempDir()
	domain := "agent.example.com"
	configDomain := "Agent.Example.COM."
	keyPath := filepath.Join(dir, domain, "private.jwk")
	if err := os.MkdirAll(filepath.Dir(keyPath), 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadOrCreateLocalKeyProvider(keyPath, JoseAlgES256); err != nil {
		t.Fatalf("create key: %v", err)
	}
	writeJSON(t, filepath.Join(dir, "config.json"), map[string]any{
		"server_url":    "https://api.dnsid.ai",
		"agent_id":      "ag_123",
		"domain":        configDomain,
		"governance_id": "example.com",
		"environment":   "sandbox",
	})

	m, err := NewIdentityManagerFromDnsid(dir, Config{})
	if err != nil {
		t.Fatalf("NewIdentityManagerFromDnsid: %v", err)
	}
	if got := m.Domain(); got != domain {
		t.Fatalf("Domain() = %q, want %q", got, domain)
	}
	if !strings.Contains(m.identity.StatusURL, "/v1/status/agent.example.com") {
		t.Fatalf("derived status URI = %q", m.identity.StatusURL)
	}
}

func TestNewIdentityManagerFromDnsidRequiresStatusSource(t *testing.T) {
	dir := t.TempDir()
	writeJSON(t, filepath.Join(dir, "config.json"), map[string]any{
		"domain":        "agent.example.com",
		"governance_id": "example.com",
	})

	_, err := NewIdentityManagerFromDnsid(dir, Config{})
	if err == nil || !strings.Contains(err.Error(), "status_url or server_url") {
		t.Fatalf("err = %v, want missing status_url/server_url", err)
	}
}

func TestNewIdentityManagerFromDnsidExplicitIdentityWinsBeforeDerivation(t *testing.T) {
	dir := t.TempDir()
	// Persisted config lacks domain, status source, and governance ID; the key
	// lives under the caller-supplied domain directory.
	keyPath := filepath.Join(dir, "override.example.com", "private.jwk")
	if err := os.MkdirAll(filepath.Dir(keyPath), 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadOrCreateLocalKeyProvider(keyPath, JoseAlgES256); err != nil {
		t.Fatalf("create key: %v", err)
	}
	writeJSON(t, filepath.Join(dir, "config.json"), map[string]any{"agent_id": "ag_123"})

	m, err := NewIdentityManagerFromDnsid(dir, Config{Identity: &IdentityConfig{
		Domain: "Override.Example.com", GovernanceID: "example.com", StatusURL: "https://override.example.com/status.json",
	}})
	if err != nil {
		t.Fatalf("NewIdentityManagerFromDnsid: %v", err)
	}
	if m.Domain() != "override.example.com" || m.identity.StatusURL != "https://override.example.com/status.json" || m.identity.LogRef != "noop:0" {
		t.Fatalf("identity = %+v", m.identity)
	}
}

func TestNewIdentityManagerFromDnsidRequiresProtocolFields(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "agent.example.com", "private.jwk")
	if err := os.MkdirAll(filepath.Dir(keyPath), 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadOrCreateLocalKeyProvider(keyPath, JoseAlgES256); err != nil {
		t.Fatalf("create key: %v", err)
	}
	writeJSON(t, filepath.Join(dir, "config.json"), map[string]any{
		"server_url": "https://api.dnsid.ai",
		"domain":     "agent.example.com",
	})

	_, err := NewIdentityManagerFromDnsid(dir, Config{})
	if err == nil || !strings.Contains(err.Error(), "GovernanceID") {
		t.Fatalf("err = %v, want missing GovernanceID", err)
	}
}

func writeJSON(t *testing.T, path string, v any) {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
}
