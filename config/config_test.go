package config

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	dnsid "github.com/dnsid-ai/dnsid-go"
	dnsidlog "github.com/dnsid-ai/dnsid-go/log"
	"golang.org/x/mod/sumdb/note"
	"golang.org/x/net/dns/dnsmessage"
)

// mapEnv is a getenv over a fixed map; unset names are "".
func mapEnv(m map[string]string) func(string) string {
	return func(name string) string { return m[name] }
}

func mustLoadEnv(t *testing.T, m map[string]string) Loaded {
	t.Helper()
	l, err := LoadEnvironment(mapEnv(m))
	if err != nil {
		t.Fatalf("LoadEnvironment: %v", err)
	}
	return l
}

func wantArgumentError(t *testing.T, err error) {
	t.Helper()
	var argErr *dnsid.ArgumentError
	if !errors.As(err, &argErr) {
		t.Fatalf("error = %T %[1]v, want *dnsid.ArgumentError", err)
	}
}

func writeJSON(t *testing.T, path string, v any) {
	t.Helper()
	data, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
}

func newKey(t *testing.T, path string) *dnsid.LocalKeyProvider {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	kp, err := dnsid.LoadOrCreateLocalKeyProvider(path, dnsid.JoseAlgES256)
	if err != nil {
		t.Fatal(err)
	}
	return kp
}

func activeKid(kp dnsid.KeyProvider) string {
	if kp == nil {
		return ""
	}
	kid, _ := kp.JWK().KeyID()
	return kid
}

// fullIdentityEnv is a complete local identity minus DNSID_LOG_REF.
func fullIdentityEnv() map[string]string {
	return map[string]string{
		"DNSID_DOMAIN":        "agent.example.com",
		"DNSID_GOVERNANCE_ID": "example.com",
		"DNSID_STATUS_URL":    "https://api.example.com/status/agent.example.com",
		"DNSID_LOG_REF":       "c2sp-tlog:public:https://log.example.com#abc",
	}
}

func policyDocument(t *testing.T) []byte {
	t.Helper()
	_, key, err := note.GenerateKey(rand.Reader, "tlog.example/log")
	if err != nil {
		t.Fatal(err)
	}
	return []byte(fmt.Sprintf("log %s\nquorum none\n", key))
}

// --- Environment loader ---

func TestLoadEnvironment_TransportOnlyIsVerificationOnly(t *testing.T) {
	caPath := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(caPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: httptest.NewTLSServer(http.NotFoundHandler()).Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	l := mustLoadEnv(t, map[string]string{
		"DNSID_DNS_SERVER":    "127.0.0.1:7753",
		"DNSID_CA_BUNDLE":     caPath,
		"DNSID_PRIVATE_HOSTS": " .test, agent.example.internal ,,",
		"DNSID_DNSSEC_MODE":   "required",
	})
	if l.Dnsid.Identity != nil {
		t.Fatalf("Identity = %+v, want absent", l.Dnsid.Identity)
	}
	want := dnsid.TransportConfig{DNSServer: "127.0.0.1:7753", CABundlePath: caPath, PrivateAddressHosts: []string{".test", "agent.example.internal"}}
	if !reflect.DeepEqual(l.Dnsid.Transport, want) || l.Dnsid.Verification.DNSSECMode != dnsid.DNSSECModeRequired {
		t.Fatalf("Dnsid = %+v", l.Dnsid)
	}
	m, err := Construct(context.Background(), l, Dependencies{})
	if err != nil || m.Domain() != "" {
		t.Fatalf("Construct = %v, %v; want verification-only manager", m, err)
	}
}

func TestLoadEnvironment_NoPlaceholdersOrDerivation(t *testing.T) {
	env := fullIdentityEnv()
	delete(env, "DNSID_LOG_REF")
	delete(env, "DNSID_STATUS_URL")
	env["DNSID_REGISTRY_URL"] = "https://registry.example.com"
	l := mustLoadEnv(t, env)
	if l.Dnsid.Identity == nil || l.Dnsid.Identity.LogRef != "" || l.Dnsid.Identity.StatusURL != "" {
		t.Fatalf("Identity = %+v, want LogRef and StatusURL absent", l.Dnsid.Identity)
	}
	if l.Registry.RegistryURL != "https://registry.example.com" {
		t.Fatalf("RegistryURL = %q", l.Registry.RegistryURL)
	}
	kp := newKey(t, filepath.Join(t.TempDir(), "private.jwk"))
	_, err := Construct(context.Background(), l, Dependencies{KeyProvider: kp})
	wantArgumentError(t, err)
}

func TestLoadEnvironment_WhitespaceIsAbsent(t *testing.T) {
	l := mustLoadEnv(t, map[string]string{"DNSID_DNS_SERVER": "   ", "DNSID_PRIVATE_HOSTS": " , ", "DNSID_DOMAIN": "\t"})
	if !reflect.DeepEqual(l, Loaded{}) {
		t.Fatalf("Loaded = %+v, want zero", l)
	}
}

func TestLoadEnvironment_BogusDNSSECModeIsArgumentError(t *testing.T) {
	_, err := LoadEnvironment(mapEnv(map[string]string{"DNSID_DNSSEC_MODE": "bogus"}))
	wantArgumentError(t, err)
}

func TestLoadEnvironment_IgnoresToolingVariables(t *testing.T) {
	base := map[string]string{"DNSID_DOMAIN": "agent.example.com"}
	with := map[string]string{"DNSID_DOMAIN": "agent.example.com", "DNSID_PUBLIC_URL": "https://x", "DNSID_AGENT_PORT": "8080", "DNSID_SERVER": "https://api", "DNSID_AGENT_NAME": "a", "DNSID_AGENT_UPSTREAM": "u"}
	if !reflect.DeepEqual(mustLoadEnv(t, base), mustLoadEnv(t, with)) {
		t.Fatal("tooling variables changed the loaded configuration")
	}
}

func TestLoadEnvironment_FullSchema(t *testing.T) {
	dir := t.TempDir()
	policyPath := filepath.Join(dir, "policy")
	document := policyDocument(t)
	if err := os.WriteFile(policyPath, document, 0o600); err != nil {
		t.Fatal(err)
	}
	l := mustLoadEnv(t, map[string]string{
		"DNSID_DOMAIN": "a.example.com", "DNSID_GOVERNANCE_ID": "example.com", "DNSID_STATUS_URL": "https://s", "DNSID_LOG_REF": "m:1",
		"DNSID_EK_URL": "https://ek", "DNSID_KU_URL": "https://ku", "DNSID_PUBLISH_PROFILE": "dnsid-draft-01", "DNSID_CAPABILITIES_URL": "https://cu",
		"DNSID_LOG_POLICY_FILE": policyPath, "DNSID_REGISTRY_URL": "https://r", "DNSID_API_KEY": "secret",
		"DNSID_CONFIG_DIR": "/cfg", "DNSID_KEY_STORE": "/ks",
	})
	want := Loaded{
		Dnsid: dnsid.Config{Identity: &dnsid.IdentityConfig{
			Domain: "a.example.com", GovernanceID: "example.com", StatusURL: "https://s", LogRef: "m:1",
			EntityKeyURL: "https://ek", KeyURL: "https://ku", PublishProfile: "dnsid-draft-01", CapabilitiesURL: "https://cu",
		}},
		LogTrust:           LogTrust{PolicyDocument: document},
		Registry:           Registry{RegistryURL: "https://r"},
		RegistryCredential: "secret",
		KeySource:          KeySource{CliDirectory: "/cfg", KeyStorePath: "/ks"},
	}
	if !reflect.DeepEqual(l, want) {
		t.Fatalf("Loaded = %+v\nwant     %+v", l, want)
	}
}

// --- CLI directory loader ---

func TestLoadCliDirectory_MapsPersistedFieldsWithoutDerivation(t *testing.T) {
	dir := t.TempDir()
	writeJSON(t, filepath.Join(dir, "config.json"), map[string]any{
		"server_url": "https://api.dnsid.ai", "agent_id": "ag_1", "environment": "production",
		"domain": "agent.example.com", "governance_id": "example.com",
		"ku_url": "https://agent.example.com/jwks", "ek_url": "https://example.com/ek",
		"entity_key_path": "keys/entity.jwk", "log_ref": "c2sp-tlog:public:https://log.dnsid.ai#x",
		"publish_profile": "dnsid-draft-01", "max_key_age": "90d",
	})
	l, err := LoadCliDirectory(dir)
	if err != nil {
		t.Fatal(err)
	}
	want := Loaded{
		Dnsid: dnsid.Config{Identity: &dnsid.IdentityConfig{
			Domain: "agent.example.com", GovernanceID: "example.com", KeyURL: "https://agent.example.com/jwks", EntityKeyURL: "https://example.com/ek",
			LogRef: "c2sp-tlog:public:https://log.dnsid.ai#x", PublishProfile: "dnsid-draft-01", MaxKeyAge: "90d",
		}},
		KeySource: KeySource{CliDirectory: dir, EntityKeyPath: filepath.Join(dir, "keys/entity.jwk")},
	}
	if !reflect.DeepEqual(l, want) {
		t.Fatalf("Loaded = %+v\nwant     %+v", l, want)
	}
	if l.Dnsid.Identity.StatusURL != "" {
		t.Fatal("status_url was derived from server_url")
	}
}

func TestLoadCliDirectory_NoIdentityFieldsIsVerificationOnly(t *testing.T) {
	dir := t.TempDir()
	writeJSON(t, filepath.Join(dir, "config.json"), map[string]any{"server_url": "https://api.dnsid.ai", "domain": " "})
	l, err := LoadCliDirectory(dir)
	if err != nil || l.Dnsid.Identity != nil || l.KeySource.CliDirectory != dir {
		t.Fatalf("Loaded = %+v, %v", l, err)
	}
}

func TestIdentityManagerFromDnsid_EmptyDirReadsHomeNotEnv(t *testing.T) {
	home := t.TempDir()
	other := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("DNSID_CONFIG_DIR", other)
	for dir, domain := range map[string]string{home + "/.dnsid": "home.example.com", other: "other.example.com"} {
		newKey(t, filepath.Join(dir, "private.jwk"))
		writeJSON(t, filepath.Join(dir, "config.json"), map[string]any{
			"domain": domain, "governance_id": "example.com", "status_url": "https://api.example.com/s", "log_ref": "m:1",
		})
	}
	m, err := IdentityManagerFromDnsid(context.Background(), "", dnsid.Config{}, Dependencies{})
	if err != nil || m.Domain() != "home.example.com" {
		t.Fatalf("IdentityManagerFromDnsid = %v, %v; want ~/.dnsid identity", m, err)
	}
}

// --- Merge ---

func TestMerge_PresenceNotTruthiness(t *testing.T) {
	a := []dnsid.TrustedEntity{{GovernanceID: "a.example"}}
	base := Loaded{Dnsid: dnsid.Config{
		Verification: dnsid.VerificationConfig{TrustedEntities: a, StatusCheckInterval: 5},
		Transport:    dnsid.TransportConfig{DNSServer: "1.2.3.4:53"},
	}}

	got := Merge(base, Loaded{Dnsid: dnsid.Config{
		Verification: dnsid.VerificationConfig{TrustedEntities: []dnsid.TrustedEntity{}, StatusCheckInterval: 0},
		Transport:    dnsid.TransportConfig{DNSServer: ""},
	}})
	if got.Dnsid.Verification.StatusCheckInterval != 5 || got.Dnsid.Transport.DNSServer != "1.2.3.4:53" {
		t.Fatalf("zero-valued scalar overlay cleared a loaded value: %+v", got.Dnsid)
	}
	if got.Dnsid.Verification.TrustedEntities == nil || len(got.Dnsid.Verification.TrustedEntities) != 0 {
		t.Fatalf("explicit empty overlay: TrustedEntities = %v, want []", got.Dnsid.Verification.TrustedEntities)
	}
	got = Merge(base, Loaded{Dnsid: dnsid.Config{Transport: dnsid.TransportConfig{DNSServer: "1.2.3.4:53"}}})
	if !reflect.DeepEqual(got.Dnsid.Verification.TrustedEntities, a) || got.Dnsid.Transport.DNSServer != "1.2.3.4:53" {
		t.Fatalf("omitted overlay: %+v", got.Dnsid)
	}
}

func TestMerge_IdentityIsFieldWiseAndLogTrustIsAtomic(t *testing.T) {
	base := Loaded{
		Dnsid:    dnsid.Config{Identity: &dnsid.IdentityConfig{Domain: "a.example.com", GovernanceID: "example.com"}},
		LogTrust: LogTrust{Managed: true},
	}
	got := Merge(base, Loaded{
		Dnsid:    dnsid.Config{Identity: &dnsid.IdentityConfig{StatusURL: "https://s"}},
		LogTrust: LogTrust{PolicyURL: "https://policy.example/p"},
	})
	wantID := &dnsid.IdentityConfig{Domain: "a.example.com", GovernanceID: "example.com", StatusURL: "https://s"}
	if !reflect.DeepEqual(got.Dnsid.Identity, wantID) {
		t.Fatalf("Identity = %+v, want %+v", got.Dnsid.Identity, wantID)
	}
	if !reflect.DeepEqual(got.LogTrust, LogTrust{PolicyURL: "https://policy.example/p"}) {
		t.Fatalf("LogTrust = %+v, want policyUrl only", got.LogTrust)
	}
	if !reflect.DeepEqual(Merge(base, Loaded{}).LogTrust, base.LogTrust) {
		t.Fatal("absent overlay LogTrust replaced base")
	}
}

// --- Construct ---

func TestConstruct_TwoLogTrustVariantsIsArgumentError(t *testing.T) {
	policyPath := filepath.Join(t.TempDir(), "policy")
	if err := os.WriteFile(policyPath, policyDocument(t), 0o600); err != nil {
		t.Fatal(err)
	}
	l := mustLoadEnv(t, map[string]string{"DNSID_LOG_POLICY_FILE": policyPath, "DNSID_LOG_POLICY_URL": "https://policy.example/p"})
	_, err := Construct(context.Background(), l, Dependencies{})
	wantArgumentError(t, err)
}

func TestConstruct_InvalidConfigDoesNotFetchPolicy(t *testing.T) {
	fetched := false
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { fetched = true }))
	t.Cleanup(server.Close)
	l := Loaded{
		Dnsid:    dnsid.Config{Verification: dnsid.VerificationConfig{StatusCheckInterval: -1}},
		LogTrust: LogTrust{PolicyURL: server.URL + "/policy"},
	}
	_, err := Construct(context.Background(), l, Dependencies{})
	wantArgumentError(t, err)
	if fetched {
		t.Fatal("policy was fetched for an invalid configuration")
	}
}

func TestConstruct_CallerLogRegistryWins(t *testing.T) {
	// A policy URL this bogus would fail the factory; the caller's registry
	// means it is never consulted.
	l := Loaded{LogTrust: LogTrust{PolicyURL: "not a url", PolicyDocument: []byte("x")}}
	m, err := Construct(context.Background(), l, Dependencies{LogRegistry: dnsidlog.NewLogRegistry()})
	if err != nil || m == nil {
		t.Fatalf("Construct = %v, %v", m, err)
	}
}

func TestConstruct_ExplicitHTTPClientHasNoCABundleConsumer(t *testing.T) {
	_, err := Construct(context.Background(), Loaded{
		Dnsid: dnsid.Config{Transport: dnsid.TransportConfig{CABundlePath: "/missing-ca.pem"}},
	}, Dependencies{HTTPClient: &http.Client{}})
	wantArgumentError(t, err)
}

func TestConstruct_PolicyDocumentBuildsRegistry(t *testing.T) {
	m, err := Construct(context.Background(), Loaded{LogTrust: LogTrust{PolicyDocument: policyDocument(t)}}, Dependencies{})
	if err != nil || m == nil {
		t.Fatalf("Construct = %v, %v", m, err)
	}
}

func TestConstruct_TrustProfileFileUsesBundleLifetimeDefault(t *testing.T) {
	_, bundleKey, err := note.GenerateKey(rand.Reader, "dnsid-stream-bundle")
	if err != nil {
		t.Fatal(err)
	}
	profilePath := filepath.Join(t.TempDir(), "trust.json")
	writeJSON(t, profilePath, map[string]any{
		"version": 1, "scope": "public", "log_prefix": "https://tlog.example/log",
		"tlog_policy": string(policyDocument(t)), "bundle_verifier_keys": []string{bundleKey},
	})
	l := mustLoadEnv(t, map[string]string{"DNSID_LOG_TRUST_PROFILE_FILE": profilePath})
	if l.LogTrust.Profile == nil || l.LogTrust.Profile.LogPrefix != "https://tlog.example/log" {
		t.Fatalf("Profile = %+v", l.LogTrust.Profile)
	}
	if _, err := Construct(context.Background(), l, Dependencies{}); err != nil {
		t.Fatalf("Construct: %v", err)
	}
}

// The policy fetch honors the loaded transport: the policy URL names a host the
// configured DNS server resolves to loopback, served with a private CA.
func TestConstruct_PolicyURLFetchUsesTransport(t *testing.T) {
	document := policyDocument(t)
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(document) }))
	t.Cleanup(server.Close)
	caPath := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(caPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	serverURL, _ := url.Parse(server.URL)
	env := map[string]string{
		"DNSID_LOG_POLICY_URL": "https://example.com:" + serverURL.Port() + "/dnsid-policy",
		"DNSID_DNS_SERVER":     loopbackDNSServer(t),
		"DNSID_CA_BUNDLE":      caPath,
		"DNSID_PRIVATE_HOSTS":  ".com",
	}
	if _, err := IdentityManagerFromEnvironment(context.Background(), mapEnv(env), dnsid.Config{}, Dependencies{}); err != nil {
		t.Fatalf("with private host allowance: %v", err)
	}
	delete(env, "DNSID_PRIVATE_HOSTS")
	if _, err := IdentityManagerFromEnvironment(context.Background(), mapEnv(env), dnsid.Config{}, Dependencies{}); err == nil {
		t.Fatal("loopback policy fetch succeeded without a private host allowance")
	}
}

func TestConstruct_CliDirectoryWinsOverKeyStore(t *testing.T) {
	dir := t.TempDir()
	cliKey := newKey(t, filepath.Join(dir, "cli", "private.jwk"))
	newKey(t, filepath.Join(dir, "store.jwk"))
	env := fullIdentityEnv()
	env["DNSID_CONFIG_DIR"] = filepath.Join(dir, "cli")
	env["DNSID_KEY_STORE"] = filepath.Join(dir, "store.jwk")
	m, err := IdentityManagerFromEnvironment(context.Background(), mapEnv(env), dnsid.Config{}, Dependencies{})
	if err != nil {
		t.Fatal(err)
	}
	if got := activeKid(m.KeyProvider()); got != activeKid(cliKey) {
		t.Fatalf("active kid = %q, want CLI directory key %q", got, activeKid(cliKey))
	}
}

func TestConstruct_KeyStoreAloneSuppliesOperationalKey(t *testing.T) {
	storePath := filepath.Join(t.TempDir(), "store.jwk")
	storeKey := newKey(t, storePath)
	env := fullIdentityEnv()
	env["DNSID_KEY_STORE"] = storePath
	m, err := IdentityManagerFromEnvironment(context.Background(), mapEnv(env), dnsid.Config{}, Dependencies{})
	if err != nil || activeKid(m.KeyProvider()) != activeKid(storeKey) {
		t.Fatalf("manager = %v, %v", m, err)
	}
}

func TestConstruct_CliEntityKeyPathAndPerDomainLayout(t *testing.T) {
	dir := t.TempDir()
	domain := "Agent.Example.com"
	opKey := newKey(t, filepath.Join(dir, "agent.example.com", "private.jwk"))
	newKey(t, filepath.Join(dir, "entity.jwk"))
	writeJSON(t, filepath.Join(dir, "config.json"), map[string]any{
		"domain": domain, "governance_id": "example.com", "status_url": "https://api.example.com/s",
		"log_ref": "m:1", "ek_url": "https://example.com/ek", "entity_key_path": "entity.jwk",
	})
	m, err := IdentityManagerFromDnsid(context.Background(), dir, dnsid.Config{}, Dependencies{})
	if err != nil {
		t.Fatal(err)
	}
	if m.Domain() != "agent.example.com" || activeKid(m.KeyProvider()) != activeKid(opKey) {
		t.Fatalf("domain = %q kid = %q", m.Domain(), activeKid(m.KeyProvider()))
	}
	if m.EntityKeyURL() != "https://example.com/ek" {
		t.Fatal("entity key provider was not loaded from entity_key_path")
	}
}

func TestConstruct_CallerKeyProvidersWin(t *testing.T) {
	dir := t.TempDir()
	caller := newKey(t, filepath.Join(dir, "caller.jwk"))
	writeJSON(t, filepath.Join(dir, "config.json"), map[string]any{
		"domain": "agent.example.com", "governance_id": "example.com", "status_url": "https://api.example.com/s",
		"log_ref": "m:1", "ek_url": "https://example.com/ek", "entity_key_path": "missing.jwk",
	})
	m, err := IdentityManagerFromDnsid(context.Background(), dir, dnsid.Config{}, Dependencies{KeyProvider: caller, EntityKeyProvider: caller})
	if err != nil || activeKid(m.KeyProvider()) != activeKid(caller) || m.EntityKeyURL() != "https://example.com/ek" {
		t.Fatalf("manager = %v, %v", m, err)
	}
}

func TestConstruct_OverlayAppliesBeforeValidation(t *testing.T) {
	dir := t.TempDir()
	newKey(t, filepath.Join(dir, "private.jwk"))
	writeJSON(t, filepath.Join(dir, "config.json"), map[string]any{"domain": "agent.example.com", "governance_id": "example.com"})
	if _, err := IdentityManagerFromDnsid(context.Background(), dir, dnsid.Config{}, Dependencies{}); err == nil {
		t.Fatal("missing status_url and log_ref were accepted")
	}
	m, err := IdentityManagerFromDnsid(context.Background(), dir, dnsid.Config{Identity: &dnsid.IdentityConfig{StatusURL: "https://api.example.com/s", LogRef: "m:1"}}, Dependencies{})
	if err != nil || m.Domain() != "agent.example.com" {
		t.Fatalf("manager = %v, %v", m, err)
	}
}

func TestConvenienceEqualsManualComposition(t *testing.T) {
	dir := t.TempDir()
	newKey(t, filepath.Join(dir, "private.jwk"))
	env := fullIdentityEnv()
	env["DNSID_CONFIG_DIR"] = dir
	env["DNSID_KU_URL"] = "https://agent.example.com/jwks"
	overlay := dnsid.Config{Verification: dnsid.VerificationConfig{DNSSECMode: dnsid.DNSSECModeRequired}}

	convenient, err := IdentityManagerFromEnvironment(context.Background(), mapEnv(env), overlay, Dependencies{})
	if err != nil {
		t.Fatal(err)
	}
	loaded := mustLoadEnv(t, env)
	manual, err := Construct(context.Background(), Merge(loaded, Loaded{Dnsid: overlay}), Dependencies{})
	if err != nil {
		t.Fatal(err)
	}
	if convenient.Domain() != manual.Domain() || convenient.OperationalKeyURL() != manual.OperationalKeyURL() || activeKid(convenient.KeyProvider()) != activeKid(manual.KeyProvider()) {
		t.Fatalf("convenience %+v != manual %+v", convenient, manual)
	}
}

func TestRegistryClientFromEnvironment(t *testing.T) {
	c, err := RegistryClientFromEnvironment(mapEnv(map[string]string{}))
	if err != nil || c == nil {
		t.Fatalf("unset env: %v, %v", c, err)
	}
	c, err = RegistryClientFromEnvironment(mapEnv(map[string]string{"DNSID_REGISTRY_URL": "http://localhost:9999/", "DNSID_API_KEY": "k"}))
	if err != nil || c == nil {
		t.Fatalf("loopback env: %v, %v", c, err)
	}
	if _, err = RegistryClientFromEnvironment(mapEnv(map[string]string{"DNSID_REGISTRY_URL": "http://example.com"})); err == nil {
		t.Fatal("non-loopback HTTP accepted")
	}
}

func TestConstructorsReadNeitherEnvironmentNorFiles(t *testing.T) {
	for k, v := range fullIdentityEnv() {
		t.Setenv(k, v)
	}
	t.Setenv("DNSID_DNS_SERVER", "127.0.0.1:1")
	m, err := dnsid.NewIdentityManager(dnsid.Config{}, nil)
	if err != nil || m.Domain() != "" {
		t.Fatalf("NewIdentityManager = %v, %v; want verification-only", m, err)
	}
}

// loopbackDNSServer answers every A query with 127.0.0.1.
func loopbackDNSServer(t *testing.T) string {
	t.Helper()
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	go func() {
		buf := make([]byte, 4096)
		for {
			n, addr, err := conn.ReadFrom(buf)
			if err != nil {
				return
			}
			var p dnsmessage.Parser
			h, err := p.Start(buf[:n])
			if err != nil {
				continue
			}
			q, err := p.Question()
			if err != nil {
				continue
			}
			msg := dnsmessage.Message{Header: dnsmessage.Header{ID: h.ID, Response: true, RecursionAvailable: true}, Questions: []dnsmessage.Question{q}}
			if q.Type == dnsmessage.TypeA {
				msg.Answers = []dnsmessage.Resource{{
					Header: dnsmessage.ResourceHeader{Name: q.Name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 60},
					Body:   &dnsmessage.AResource{A: [4]byte{127, 0, 0, 1}},
				}}
			}
			if out, err := msg.Pack(); err == nil {
				_, _ = conn.WriteTo(out, addr)
			}
		}
	}()
	return conn.LocalAddr().String()
}

func TestLoadCliDirectory_RootPointerResolvesToPerIdentityConfig(t *testing.T) {
	// The CLI reads <domain>/config.json as authoritative; the root file is a pointer.
	root := t.TempDir()
	leaf := filepath.Join(root, "agent.example.com")
	writeJSON(t, filepath.Join(root, "config.json"), map[string]any{
		"domain": "Agent.Example.com.", "governance_id": "example.com", "log_ref": "stale:root", "entity_key_path": "root-entity.jwk",
	})
	writeJSON(t, filepath.Join(leaf, "config.json"), map[string]any{
		"domain": "agent.example.com", "governance_id": "example.com", "log_ref": "c2sp-tlog:public:https://log.example#leaf", "entity_key_path": "entity.jwk",
	})
	l, err := LoadCliDirectory(root)
	if err != nil {
		t.Fatal(err)
	}
	if l.Dnsid.Identity.LogRef != "c2sp-tlog:public:https://log.example#leaf" {
		t.Fatalf("LogRef = %q; root pointer was not followed", l.Dnsid.Identity.LogRef)
	}
	if l.KeySource.CliDirectory != root || l.KeySource.EntityKeyPath != filepath.Join(leaf, "entity.jwk") {
		t.Fatalf("KeySource = %+v", l.KeySource)
	}
	// A leaf directory (no <domain>/ subdirectory) is read as-is.
	ll, err := LoadCliDirectory(leaf)
	if err != nil || ll.Dnsid.Identity.LogRef != l.Dnsid.Identity.LogRef || ll.KeySource.CliDirectory != leaf {
		t.Fatalf("leaf Loaded = %+v, %v", ll, err)
	}
}
