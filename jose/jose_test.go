package jose

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/dnsid-ai/dnsid-go"
	dnsidlog "github.com/dnsid-ai/dnsid-go/log"
)

type testDNSResolver struct {
	records map[string][]dnsid.TXTRecordRData
}

func (r testDNSResolver) FetchTXT(_ context.Context, name string) ([]dnsid.TXTRecordRData, dnsid.DNSSECState, error) {
	return r.records[name], dnsid.DNSSECStateUnsigned, nil
}

type testHTTPSFetcher struct {
	responses map[string]json.RawMessage
}

type emptyIdentityResolver struct{}

func (emptyIdentityResolver) VerifyDomain(context.Context, string) (*dnsid.VerifiedDomain, error) {
	return &dnsid.VerifiedDomain{}, nil
}

func (f testHTTPSFetcher) FetchJSON(_ context.Context, rawURL string, _ dnsid.FetchOptions) (json.RawMessage, *tls.Certificate, error) {
	return f.responses[rawURL], nil, nil
}

type testLogReader struct {
	nonRevocationCalls int
	nonRevocationErr   error
}

func (*testLogReader) Canonical(dnsidlog.LogEvent) ([]byte, error) { return nil, nil }
func (*testLogReader) KeyTimestamp(context.Context, string, string) (time.Time, error) {
	return time.Now(), nil
}
func (*testLogReader) VerifyBilateralBinding(context.Context, dnsidlog.BilateralBindingInput) (dnsidlog.BilateralBinding, error) {
	return dnsidlog.BilateralBinding{}, nil
}
func (*testLogReader) VerifyOperationalContinuity(context.Context, string, string, string) error {
	return nil
}
func (*testLogReader) VerifyGovernanceRelationship(context.Context, string, string) error {
	return nil
}
func (r *testLogReader) VerifyNonRevocation(context.Context, string, time.Time) (dnsidlog.LoggedStateEvidence, error) {
	r.nonRevocationCalls++
	return dnsidlog.LoggedStateEvidence{}, r.nonRevocationErr
}
func (*testLogReader) ReadEvent(context.Context, dnsidlog.LogRef) (dnsidlog.LogEvent, error) {
	return dnsidlog.LogEvent{}, nil
}
func (*testLogReader) RebuildHistory(context.Context, string) ([]dnsidlog.LogEvent, error) {
	return nil, nil
}

func testManagers(t *testing.T, flags ...dnsid.PolicyFlag) (*dnsid.IdentityManager, dnsid.KeyProvider, *dnsid.IdentityManager, *testLogReader) {
	t.Helper()
	return testManagersWithVerification(t, dnsid.VerificationConfig{}, flags...)
}

func testManagersWithVerification(t *testing.T, verification dnsid.VerificationConfig, flags ...dnsid.PolicyFlag) (*dnsid.IdentityManager, dnsid.KeyProvider, *dnsid.IdentityManager, *testLogReader) {
	t.Helper()
	kp := dnsid.GenerateES256KeyProvider()
	entityKP := dnsid.GenerateES256KeyProvider()
	if len(flags) == 0 {
		flags = []dnsid.PolicyFlag{dnsid.PolicyFlagLogCheck}
	}
	cfg := dnsid.IdentityConfig{Domain: "agent.example.com", GovernanceID: "example.com", LogRef: "algorand:ADDR", StatusURL: "https://agent.example.com/.well-known/dnsid/status.json", KeyURL: "https://agent.example.com/ku.json", EntityKeyURL: "https://example.com/ek.json", PolicyFlags: flags}
	issuer, err := dnsid.NewIdentityManager(dnsid.Config{Identity: &cfg}, kp, dnsid.WithEntityKeyProvider(entityKP))
	if err != nil {
		t.Fatalf("issuer manager: %v", err)
	}
	record, err := issuer.CreateTXTRecord()
	if err != nil {
		t.Fatalf("CreateTXTRecord: %v", err)
	}
	jwksBytes, err := json.Marshal(issuer.GetKeySet().Raw())
	if err != nil {
		t.Fatalf("marshal JWKS: %v", err)
	}
	entityBytes, err := json.Marshal(issuer.GetEntityKeySet().Raw())
	if err != nil {
		t.Fatalf("marshal entity JWKS: %v", err)
	}
	reader := &testLogReader{}
	registry := dnsidlog.NewLogRegistry()
	if err := registry.Register("algorand", func(string) dnsidlog.LogReader { return reader }); err != nil {
		t.Fatal(err)
	}
	verifier, err := dnsid.NewIdentityManager(dnsid.Config{Verification: verification, Identity: &dnsid.IdentityConfig{Domain: "relying-party.example.com", GovernanceID: "example.com", LogRef: "algorand:ADDR", StatusURL: "https://relying-party.example.com/.well-known/dnsid/status.json"}}, dnsid.GenerateES256KeyProvider(),
		dnsid.WithDNSResolver(testDNSResolver{records: map[string][]dnsid.TXTRecordRData{"_dnsid.agent.example.com": {{Value: record.Serialize(), TTL: time.Minute}}}}),
		dnsid.WithHTTPSFetcher(testHTTPSFetcher{responses: map[string]json.RawMessage{
			record.KeyURI:       jwksBytes,
			record.EntityKeyURI: entityBytes,
			record.StatusURI:    json.RawMessage(`{"state":"ACTIVE","lastTransitionAt":"` + time.Now().UTC().Format(time.RFC3339Nano) + `"}`),
		}}),
		dnsid.WithLogRegistry(registry),
	)
	if err != nil {
		t.Fatalf("verifier manager: %v", err)
	}
	return issuer, kp, verifier, reader
}

func TestProfile_VerifyInheritsCounterpartyAcceptance(t *testing.T) {
	deny := dnsid.VerificationConfig{TrustedEntities: []dnsid.TrustedEntity{{GovernanceID: "other.example"}}}
	issuer, kp, verifier, _ := testManagersWithVerification(t, deny)
	issuerProfile := NewFromIdentityManager(issuer, kp, Config{})
	verifierProfile := NewFromIdentityManager(verifier, nil, Config{})
	tok, err := issuerProfile.CreateJWT(JWTOptions{Audience: "relying-party.example.com"})
	if err != nil {
		t.Fatalf("CreateJWT: %v", err)
	}
	if _, _, err := verifierProfile.VerifyJWT(context.Background(), tok); !errors.Is(err, dnsid.ErrCounterpartyNotAccepted) {
		t.Fatalf("VerifyJWT error = %v, want CounterpartyNotAccepted", err)
	}
	jws, err := issuerProfile.CreateJWS([]byte("payload"))
	if err != nil {
		t.Fatalf("CreateJWS: %v", err)
	}
	if _, _, err := verifierProfile.VerifyJWS(context.Background(), jws); !errors.Is(err, dnsid.ErrCounterpartyNotAccepted) {
		t.Fatalf("VerifyJWS error = %v, want CounterpartyNotAccepted", err)
	}
}

func TestProfile_CreateAndVerifyJWT(t *testing.T) {
	issuer, kp, verifier, reader := testManagers(t)
	issuerProfile := NewFromIdentityManager(issuer, kp, Config{})
	verifierProfile := NewFromIdentityManager(verifier, nil, Config{})
	tok, err := issuerProfile.CreateJWT(JWTOptions{Audience: "relying-party.example.com"})
	if err != nil {
		t.Fatalf("CreateJWT: %v", err)
	}
	vd, claims, err := verifierProfile.VerifyJWT(context.Background(), tok)
	if err != nil {
		t.Fatalf("VerifyJWT: %v", err)
	}
	if vd.Domain() != "agent.example.com" || claims.Issuer != "agent.example.com" || claims.Audiences[0] != "relying-party.example.com" {
		t.Fatalf("unexpected verification result: vd=%s claims=%#v", vd.Domain(), claims)
	}
	if reader.nonRevocationCalls != 0 || !vd.RequiresLogCheck() {
		t.Fatal("logchk must remain caller-owned")
	}

	reader.nonRevocationErr = errors.New("revoked")
	if _, _, err := verifierProfile.VerifyJWT(context.Background(), tok); err != nil {
		t.Fatal(err)
	}
	_, err = vd.VerifyLogEvidence(context.Background(), time.Time{})
	var verificationErr *dnsid.VerificationError
	if !errors.As(err, &verificationErr) || verificationErr.Code() != dnsid.VerificationCodeLogError {
		t.Fatalf("VerifyJWT error = %v, want log_error", err)
	}
}

func TestProfile_VerifyJWTClassifiesMissingJWKSAsUnavailable(t *testing.T) {
	issuer, kp, _, _ := testManagers(t)
	token, err := NewFromIdentityManager(issuer, kp, Config{}).CreateJWT(JWTOptions{Audience: "relying-party.example.com"})
	if err != nil {
		t.Fatalf("CreateJWT: %v", err)
	}

	_, _, err = New(emptyIdentityResolver{}, "relying-party.example.com", nil, Config{}).VerifyJWT(context.Background(), token)
	var verificationErr *dnsid.VerificationError
	if !errors.As(err, &verificationErr) {
		t.Fatalf("VerifyJWT error = %T, want *dnsid.VerificationError", err)
	}
	if verificationErr.Code() != dnsid.VerificationCodeJWKSUnavailable || !verificationErr.Transient() {
		t.Fatalf("code = %q, transient = %v; want %q, true", verificationErr.Code(), verificationErr.Transient(), dnsid.VerificationCodeJWKSUnavailable)
	}
}

func TestProfile_CreateAndVerifyJWS(t *testing.T) {
	issuer, kp, verifier, reader := testManagers(t)
	issuerProfile := NewFromIdentityManager(issuer, kp, Config{})
	verifierProfile := NewFromIdentityManager(verifier, nil, Config{})
	compact, err := issuerProfile.CreateJWS([]byte("hello dnsid"))
	if err != nil {
		t.Fatalf("CreateJWS: %v", err)
	}
	payload, vd, err := verifierProfile.VerifyJWS(context.Background(), compact)
	if err != nil {
		t.Fatalf("VerifyJWS: %v", err)
	}
	if string(payload) != "hello dnsid" || vd.Domain() != "agent.example.com" {
		t.Fatalf("payload=%q domain=%s", payload, vd.Domain())
	}
	if reader.nonRevocationCalls != 0 || !vd.RequiresLogCheck() {
		t.Fatal("logchk must remain caller-owned")
	}
}
