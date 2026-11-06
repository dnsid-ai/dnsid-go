package config_test

import (
	"context"
	"path/filepath"
	"testing"

	dnsid "github.com/dnsid-ai/dnsid-go"
	"github.com/dnsid-ai/dnsid-go/config"
)

// Mode: fake-only (missing/corrupt DNS publication, real local signing keys).
// Given a selected operational key but no authenticated publication, When
// ordinary application construction runs without explicit provider injection,
// Then it returns neither a signing manager nor successful construction.
func TestConstruct_ConfigSelectedRejectsMissingOrCorruptPublication(t *testing.T) {
	path := filepath.Join(t.TempDir(), "operational.json")
	key, err := dnsid.LoadOrCreateLocalKeyProvider(path, dnsid.JoseAlgES256)
	if err != nil {
		t.Fatal(err)
	}
	identity := &dnsid.IdentityConfig{Domain: "agent.example.com", GovernanceID: "example.com", LogRef: "algorand:ADDR", StatusURL: "https://agent.example.com/status.json", KeyURL: "https://agent.example.com/ku.json", EntityKeyURL: "https://example.com/ek.json", PolicyFlags: []dnsid.PolicyFlag{"logchk"}}
	owner := dnsid.GenerateES256KeyProvider()
	established, err := dnsid.NewIdentityManager(dnsid.Config{Identity: identity}, key, dnsid.WithEntityKeyProvider(owner))
	if err != nil {
		t.Fatal(err)
	}
	for _, provider := range []string{"", "file"} {
		for _, record := range []struct{ name, value string }{{"missing", ""}, {"corrupt", "v=dnsid1;not-an-owner-signed-record"}} {
			t.Run(provider+"/"+record.name, func(t *testing.T) {
				deps, _ := publication(t, established)
				deps.EntityKeyProvider = owner
				deps.DNSResolver = consumerDNS{record: record.value}
				loaded := config.Loaded{Dnsid: dnsid.Config{Identity: identity}, KeySource: config.KeySource{Provider: provider, KeyStorePath: path}}
				manager, err := config.Construct(context.Background(), loaded, deps)
				if err == nil || manager != nil {
					t.Fatalf("unauthenticated publication enabled signing: manager=%v err=%v", manager != nil, err)
				}
			})
		}
	}
}
