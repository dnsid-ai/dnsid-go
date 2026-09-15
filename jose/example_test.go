package jose_test

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"time"

	dnsid "github.com/dnsid-ai/dnsid-go"
	"github.com/dnsid-ai/dnsid-go/jose"
	dnsidlog "github.com/dnsid-ai/dnsid-go/log"
)

// The fakes below stand in for live DNS, HTTPS, and transparency-log lookups
// so the example runs offline. In production, omit the With... options and
// let the verifier resolve the issuer's published identity record.

type fakeDNSResolver struct {
	records map[string][]dnsid.TXTRecordRData
}

func (r fakeDNSResolver) FetchTXT(_ context.Context, name string) ([]dnsid.TXTRecordRData, dnsid.DNSSECState, error) {
	return r.records[name], dnsid.DNSSECStateUnsigned, nil
}

type fakeHTTPSFetcher struct {
	responses map[string]json.RawMessage
}

func (f fakeHTTPSFetcher) FetchJSON(_ context.Context, rawURL string, _ dnsid.FetchOptions) (json.RawMessage, *tls.Certificate, error) {
	return f.responses[rawURL], nil, nil
}

type fakeLogReader struct{}

func (fakeLogReader) Canonical(dnsidlog.LogEvent) ([]byte, error) { return nil, nil }
func (fakeLogReader) KeyTimestamp(context.Context, string, string) (time.Time, error) {
	return time.Now(), nil
}
func (fakeLogReader) VerifyBilateralBinding(context.Context, dnsidlog.BilateralBindingInput) (dnsidlog.BilateralBinding, error) {
	return dnsidlog.BilateralBinding{}, nil
}
func (fakeLogReader) VerifyOperationalContinuity(context.Context, string, string, string) error {
	return nil
}
func (fakeLogReader) VerifyGovernanceRelationship(context.Context, string, string) error { return nil }
func (fakeLogReader) VerifyNonRevocation(context.Context, string, time.Time) (dnsidlog.LoggedStateEvidence, error) {
	return dnsidlog.LoggedStateEvidence{}, nil
}
func (fakeLogReader) ReadEvent(context.Context, dnsidlog.LogRef) (dnsidlog.LogEvent, error) {
	return dnsidlog.LogEvent{}, nil
}
func (fakeLogReader) RebuildHistory(context.Context, string) ([]dnsidlog.LogEvent, error) {
	return nil, nil
}

// Example mints a DNSid JWT as agent.example.com and verifies it as
// relying-party.example.com, entirely offline.
func Example() {
	// The agent's identity: its domain, governing organization, entity
	// record-signing key, and operational key.
	agentKey := dnsid.GenerateES256KeyProvider()
	issuer, err := dnsid.NewIdentityManager(dnsid.Config{Identity: &dnsid.IdentityConfig{
		Domain:       "agent.example.com",
		GovernanceID: "example.com",
		LogRef:       "algorand:ADDR",
		StatusURL:    "https://agent.example.com/.well-known/dnsid/status.json",
		KeyURL:       "https://agent.example.com/ku.json",
		EntityKeyURL: "https://example.com/ek.json",
	}}, agentKey, dnsid.WithEntityKeyProvider(dnsid.GenerateES256KeyProvider()))
	if err != nil {
		panic(err)
	}

	// Publish the agent's identity record and key sets into the offline
	// fakes, exactly as they would appear in DNS and over HTTPS.
	record, err := issuer.CreateTXTRecord()
	if err != nil {
		panic(err)
	}
	jwksBytes, err := json.Marshal(issuer.GetKeySet().Raw())
	if err != nil {
		panic(err)
	}
	entityBytes, err := json.Marshal(issuer.GetEntityKeySet().Raw())
	if err != nil {
		panic(err)
	}
	registry := dnsidlog.NewLogRegistry()
	if err := registry.Register("algorand", func(string) dnsidlog.LogReader { return fakeLogReader{} }); err != nil {
		panic(err)
	}

	// The relying party's manager resolves the agent's identity from the
	// fakes above.
	verifier, err := dnsid.NewIdentityManager(dnsid.Config{Identity: &dnsid.IdentityConfig{
		Domain:       "relying-party.example.com",
		GovernanceID: "example.com",
		LogRef:       "algorand:ADDR",
		StatusURL:    "https://relying-party.example.com/.well-known/dnsid/status.json",
	}}, dnsid.GenerateES256KeyProvider(),
		dnsid.WithDNSResolver(fakeDNSResolver{records: map[string][]dnsid.TXTRecordRData{
			"_dnsid.agent.example.com": {{Value: record.Serialize(), TTL: time.Minute}},
		}}),
		dnsid.WithHTTPSFetcher(fakeHTTPSFetcher{responses: map[string]json.RawMessage{
			record.KeyURI:       jwksBytes,
			record.EntityKeyURI: entityBytes,
			record.StatusURI:    json.RawMessage(`{"state":"ACTIVE","lastTransitionAt":"` + time.Now().UTC().Format(time.RFC3339Nano) + `"}`),
		}}),
		dnsid.WithLogRegistry(registry),
	)
	if err != nil {
		panic(err)
	}

	// Mint a JWT as the agent.
	issuerProfile := jose.NewFromIdentityManager(issuer, agentKey, jose.Config{})
	token, err := issuerProfile.CreateJWT(jose.JWTOptions{
		Audience:         "relying-party.example.com",
		AdditionalClaims: map[string]any{"purpose": "quickstart"},
	})
	if err != nil {
		panic(err)
	}

	// Verify it as the relying party.
	verifierProfile := jose.NewFromIdentityManager(verifier, nil, jose.Config{})
	vd, claims, err := verifierProfile.VerifyJWT(context.Background(), token)
	if err != nil {
		panic(err)
	}

	fmt.Println("verified domain:", vd.Domain())
	fmt.Println("issuer:", claims.Issuer)
	fmt.Println("audience:", claims.Audiences[0])
	fmt.Println("purpose:", claims.Extra["purpose"])
	// Output:
	// verified domain: agent.example.com
	// issuer: agent.example.com
	// audience: relying-party.example.com
	// purpose: quickstart
}
