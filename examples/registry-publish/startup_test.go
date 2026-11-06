package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	dnsid "github.com/dnsid-ai/dnsid-go"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"golang.org/x/net/dns/dnsmessage"
)

func TestRegistryPublishStartupChild(t *testing.T) {
	if os.Getenv("DNSID_TEST_PUBLISH_CHILD") != "1" {
		t.Skip("subprocess entry only")
	}
	// The Go test runner flags are not application arguments.
	os.Args = os.Args[:1]
	main()
}

func unpublishedDNS(t *testing.T) string {
	t.Helper()
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	go func() {
		buf := make([]byte, 4096)
		for {
			n, addr, err := conn.ReadFrom(buf)
			if err != nil {
				return
			}
			var parser dnsmessage.Parser
			header, err := parser.Start(buf[:n])
			if err != nil {
				continue
			}
			q, err := parser.Question()
			if err != nil {
				continue
			}
			response := dnsmessage.Message{Header: dnsmessage.Header{ID: header.ID, Response: true, RecursionAvailable: true, RCode: dnsmessage.RCodeNameError}, Questions: []dnsmessage.Question{q}}
			if wire, err := response.Pack(); err == nil {
				_, _ = conn.WriteTo(wire, addr)
			}
		}
	}()
	return conn.LocalAddr().String()
}

func publicationStartupFixture(t *testing.T) (string, *dnsid.TXTRecord, *ecdsa.PublicKey, string) {
	t.Helper()
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "agent.example.com"), 0700); err != nil {
		t.Fatal(err)
	}
	operational, err := dnsid.LoadOrCreateLocalKeyProvider(filepath.Join(dir, "agent.example.com", "private.jwk"), dnsid.JoseAlgES256)
	if err != nil {
		t.Fatal(err)
	}
	entity, err := dnsid.LoadOrCreateLocalKeyProvider(filepath.Join(dir, "entity.jwk"), dnsid.JoseAlgES256)
	if err != nil {
		t.Fatal(err)
	}
	identity := &dnsid.IdentityConfig{Domain: "agent.example.com", GovernanceID: "example.com", LogRef: "algorand:ADDR", StatusURL: "https://agent.example.com/status.json", KeyURL: "https://agent.example.com/ku.json", EntityKeyURL: "https://example.com/ek.json"}
	fixture, err := dnsid.NewIdentityManager(dnsid.Config{Identity: identity}, operational, dnsid.WithEntityKeyProvider(entity))
	if err != nil {
		t.Fatal(err)
	}
	record, err := fixture.BuildUnsignedTXTRecord()
	if err != nil {
		t.Fatal(err)
	}
	config := map[string]string{"domain": identity.Domain, "governance_id": identity.GovernanceID, "log_ref": identity.LogRef, "status_url": identity.StatusURL, "ku_url": identity.KeyURL, "ek_url": identity.EntityKeyURL, "entity_key_path": "entity.jwk"}
	encoded, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "config.json"), encoded, 0600); err != nil {
		t.Fatal(err)
	}
	var public ecdsa.PublicKey
	if err := jwk.Export(entity.JWK(), &public); err != nil {
		t.Fatal(err)
	}
	kid, _ := entity.JWK().KeyID()
	return dir, record, &public, kid
}

func runPublicationStartup(t *testing.T, dir, registry, dns string) ([]byte, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestRegistryPublishStartupChild$")
	// Strip inherited DNSid settings so proof never depends on developer custody,
	// registry credentials, transports or identity overlays.
	for _, entry := range os.Environ() {
		if !strings.HasPrefix(entry, "DNSID_") {
			cmd.Env = append(cmd.Env, entry)
		}
	}
	cmd.Env = append(cmd.Env, "DNSID_TEST_PUBLISH_CHILD=1", "DNSID_CONFIG_DIR="+dir, "DNSID_REGISTRY_URL="+registry, "DNSID_API_KEY=test-token", "DNSID_DNS_SERVER="+dns)
	output, err := cmd.CombinedOutput()
	if ctx.Err() != nil {
		t.Fatalf("startup watchdog expired: %v\n%s", ctx.Err(), output)
	}
	return output, err
}

// Mode: fake-only (local registry and NXDOMAIN DNS; real persisted ES256 keys).
// Given a genuinely unpublished configured identity, When the example's actual
// main starts, Then the registry receives the owner's valid signature over its
// independently prepared canonical record, without prior authenticated DNS.
func TestRegistryPublishStartup_UnpublishedClientSignsOwnerCanonical(t *testing.T) {
	dir, record, owner, ownerKid := publicationStartupFixture(t)
	canonical := record.CanonicalContent()
	var reads, submissions atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Header.Get("Authorization") != "Bearer test-token" {
			t.Error("registry authentication missing")
		}
		switch r.Method + " " + r.URL.Path {
		case "GET /api/v1/agent/agent.example.com/status":
			reads.Add(1)
			_ = json.NewEncoder(w).Encode(dnsid.AgentDetail{Domain: "agent.example.com", Managed: "self", Status: "READY", ServerStatus: "READY", DNSPublished: false})
		case "POST /api/v1/agent/agent.example.com/record":
			var req dnsid.IdentityRecordRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				t.Error(err)
			}
			if req.SigningKid != ownerKid {
				t.Errorf("canonical signing kid=%q want owner %q", req.SigningKid, ownerKid)
			}
			_ = json.NewEncoder(w).Encode(dnsid.IdentityRecordResponse{FQDN: "agent.example.com", CanonicalContent: string(canonical), SigningKid: ownerKid})
		case "POST /api/v1/agent/agent.example.com/signature":
			submissions.Add(1)
			var req dnsid.SignatureRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				t.Error(err)
			}
			alg, encoded, ok := strings.Cut(req.Signature, ":")
			sig, err := base64.RawURLEncoding.DecodeString(encoded)
			digest := sha256.Sum256(canonical)
			if !ok || alg != "ES256" || err != nil || len(sig) != 64 || !ecdsa.Verify(owner, digest[:], new(big.Int).SetBytes(sig[:min(32, len(sig))]), new(big.Int).SetBytes(sig[min(32, len(sig)):])) {
				t.Errorf("submitted record signature does not verify with owner key: %q", req.Signature)
			}
			signed := *record
			signed.Signature = req.Signature
			_ = json.NewEncoder(w).Encode(dnsid.SignatureResponse{FQDN: "agent.example.com", Status: "publishing", Records: []dnsid.DNSRecord{{Name: "_dnsid.agent.example.com", Type: "TXT", Value: signed.Serialize(), TTL: 300}}})
		default:
			t.Errorf("unexpected registry request %s %s", r.Method, r.URL.Path)
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	output, err := runPublicationStartup(t, dir, server.URL, unpublishedDNS(t))
	if submissions.Load() != 1 {
		t.Fatalf("unpublished startup never submitted owner-signed canonical record: submissions=%d registrationReads=%d exit=%v\n%s", submissions.Load(), reads.Load(), err, output)
	}
	if err != nil {
		t.Fatalf("client publication startup failed: %v\n%s", err, output)
	}
}

// Mode: fake-only (local registry and NXDOMAIN DNS; real persisted keys).
// Given registry-managed publication with no DNS record, When actual main
// starts, Then it reaches the wait reader before prior publication exists.
// A terminal second response bounds the wait; this is reachability, not a claim
// of successful registry DNS publication or authenticated established startup.
func TestRegistryPublishStartup_UnpublishedRegistryReachesWait(t *testing.T) {
	dir, _, _, _ := publicationStartupFixture(t)
	var reads, posts atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method != "GET" || r.URL.Path != "/api/v1/agent/agent.example.com/status" {
			posts.Add(1)
			http.Error(w, "unexpected signing request", 400)
			return
		}
		status := "PENDING"
		if reads.Add(1) > 1 {
			status = "REVOKED"
		}
		_ = json.NewEncoder(w).Encode(dnsid.AgentDetail{Domain: "agent.example.com", Managed: "dnsid", Status: status, ServerStatus: status, DNSPublished: false})
	}))
	defer server.Close()
	output, err := runPublicationStartup(t, dir, server.URL, unpublishedDNS(t))
	if reads.Load() < 2 {
		t.Fatalf("unpublished registry startup never reached wait reader: reads=%d exit=%v\n%s", reads.Load(), err, output)
	}
	if posts.Load() != 0 {
		t.Fatal("registry-managed wait attempted client signing")
	}
	if err == nil || !bytes.Contains(bytes.ToLower(output), []byte("revoked")) {
		t.Fatalf("wait did not report terminal registry response: exit=%v\n%s", err, output)
	}
}
