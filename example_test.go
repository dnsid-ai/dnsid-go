package dnsid_test

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"log"
	"time"

	dnsid "github.com/dnsid-ai/dnsid-go"
	dnsidlog "github.com/dnsid-ai/dnsid-go/log"
)

// exampleDNSResolver serves fixed TXT answers in place of live DNS. VerifyDomain
// requires an injected resolver that reports a definitive DNSSEC state; a
// production deployment supplies a DNSSEC-aware resolver via dnsid.WithDNSResolver.
type exampleDNSResolver map[string][]dnsid.TXTRecordRData

func (r exampleDNSResolver) FetchTXT(_ context.Context, name string) ([]dnsid.TXTRecordRData, dnsid.DNSSECState, error) {
	return r[name], dnsid.DNSSECStateUnsigned, nil
}

// exampleHTTPSFetcher serves fixed JSON documents in place of live HTTPS
// fetches of the JWKS and status endpoints.
type exampleHTTPSFetcher map[string]json.RawMessage

func (f exampleHTTPSFetcher) FetchJSON(_ context.Context, rawURL string, _ dnsid.FetchOptions) (json.RawMessage, *tls.Certificate, error) {
	body, ok := f[rawURL]
	if !ok {
		return nil, nil, fmt.Errorf("no fixture for %s", rawURL)
	}
	return body, nil, nil
}

// exampleLogReader accepts the lifecycle evidence checks that a real
// transparency-log binding would verify cryptographically.
type exampleLogReader struct{ dnsidlog.NoopLogReader }

func (exampleLogReader) VerifyBilateralBinding(context.Context, dnsidlog.BilateralBindingInput) (dnsidlog.BilateralBinding, error) {
	return dnsidlog.BilateralBinding{InitialOperationalThumbprint: "example"}, nil
}

func (exampleLogReader) VerifyOperationalContinuity(context.Context, string, string, string) error {
	return nil
}

// ExampleIdentityManager_VerifyDomain verifies a DNSid domain end to end
// against in-memory fixtures: a signed _dnsid TXT record, the entity (ek) and
// runtime (ku) JWKS documents, and an ACTIVE status document. Against live
// infrastructure only the fakes change — construct the manager with a
// DNSSEC-aware resolver and omit WithHTTPSFetcher.
func ExampleIdentityManager_VerifyDomain() {
	// The agent being verified. Its entity key signs the _dnsid record; its
	// operational key is the runtime key the agent signs with.
	entityKey := dnsid.GenerateES256KeyProvider()
	operationalKey := dnsid.GenerateEd25519KeyProvider()
	publisher, err := dnsid.NewIdentityManager(dnsid.Config{Identity: &dnsid.IdentityConfig{
		Domain:       "agent.example.com",
		GovernanceID: "example.com",
		LogRef:       "example-log:1",
		StatusURL:    "https://agent.example.com/dnsid-status.json",
		KeyURL:       "https://agent.example.com/jwks.json",
		EntityKeyURL: "https://example.com/entity-jwks.json",
	}}, operationalKey, dnsid.WithEntityKeyProvider(entityKey))
	if err != nil {
		log.Fatal(err)
	}
	record, err := publisher.CreateTXTRecord()
	if err != nil {
		log.Fatal(err)
	}
	ekJSON, _ := json.Marshal(publisher.GetEntityKeySet().Raw())
	kuJSON, _ := json.Marshal(publisher.GetKeySet().Raw())
	statusJSON := `{"state":"ACTIVE","lastTransitionAt":"` + time.Now().UTC().Format(time.RFC3339) + `"}`

	// The verifier resolves the record, checks the record signature against
	// the ek JWKS, loads the ku JWKS, consults the lifecycle log, and
	// requires an ACTIVE status.
	registry := dnsidlog.NewLogRegistry()
	if err := registry.Register("example-log", func(string) dnsidlog.LogReader { return exampleLogReader{} }); err != nil {
		log.Fatal(err)
	}
	verifier, err := dnsid.NewIdentityManager(dnsid.Config{}, nil,
		dnsid.WithDNSResolver(exampleDNSResolver{
			"_dnsid.agent.example.com": {{Value: record.Serialize(), TTL: time.Minute}},
		}),
		dnsid.WithHTTPSFetcher(exampleHTTPSFetcher{
			record.EntityKeyURI: ekJSON,
			record.KeyURI:       kuJSON,
			record.StatusURI:    json.RawMessage(statusJSON),
		}),
		dnsid.WithLogRegistry(registry),
	)
	if err != nil {
		log.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	verified, err := verifier.VerifyDomain(ctx, "agent.example.com")
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("domain:", verified.Domain())
	fmt.Println("governance:", verified.Record().GovernanceID)
	fmt.Println("status:", verified.Status().State)
	// Output:
	// domain: agent.example.com
	// governance: example.com
	// status: ACTIVE
}
