package httpsig

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"io"
	"net/http"
	"strings"
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

func (f testHTTPSFetcher) FetchJSON(_ context.Context, rawURL string, _ dnsid.FetchOptions) (json.RawMessage, *tls.Certificate, error) {
	return f.responses[rawURL], nil, nil
}

type testLogReader struct{ nonRevocationCalls int }

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
	return dnsidlog.LoggedStateEvidence{}, nil
}
func (*testLogReader) ReadEvent(context.Context, dnsidlog.LogRef) (dnsidlog.LogEvent, error) {
	return dnsidlog.LogEvent{}, nil
}
func (*testLogReader) RebuildHistory(context.Context, string) ([]dnsidlog.LogEvent, error) {
	return nil, nil
}

func testManagers(t *testing.T) (*dnsid.IdentityManager, dnsid.KeyProvider, *dnsid.IdentityManager) {
	t.Helper()
	return testManagersWithKeyProvider(t, dnsid.GenerateES256KeyProvider())
}

func testManagersWithKeyProvider(t *testing.T, kp dnsid.KeyProvider) (*dnsid.IdentityManager, dnsid.KeyProvider, *dnsid.IdentityManager) {
	t.Helper()
	return testManagersWithPolicy(t, kp, nil, &testLogReader{})
}

func testManagersWithPolicy(t *testing.T, kp dnsid.KeyProvider, flags []dnsid.PolicyFlag, reader *testLogReader) (*dnsid.IdentityManager, dnsid.KeyProvider, *dnsid.IdentityManager) {
	t.Helper()
	entityKP := dnsid.GenerateES256KeyProvider()
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
	registry := dnsidlog.NewLogRegistry()
	if err := registry.Register("algorand", func(string) dnsidlog.LogReader { return reader }); err != nil {
		t.Fatal(err)
	}
	verifier, err := dnsid.NewIdentityManager(dnsid.Config{}, nil,
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
	return issuer, kp, verifier
}

func TestProfile_SignAndVerifyHTTPRequest(t *testing.T) {
	reader := &testLogReader{}
	issuer, kp, verifier := testManagersWithPolicy(t, dnsid.GenerateES256KeyProvider(), []dnsid.PolicyFlag{dnsid.PolicyFlagLogCheck}, reader)
	signer := NewFromIdentityManager(issuer, kp, Config{})
	checker := NewFromIdentityManager(verifier, nil, Config{})
	req, err := http.NewRequest(http.MethodPost, "https://api.example.com/resource", strings.NewReader("hello"))
	if err != nil {
		t.Fatal(err)
	}
	req.Host = "api.example.com"
	signed, err := signer.CreateSignedHTTPRequest(req, SigningOptions{})
	if err != nil {
		t.Fatalf("CreateSignedHTTPRequest: %v", err)
	}
	vd, err := checker.VerifyHTTPRequest(context.Background(), signed)
	if err != nil {
		t.Fatalf("VerifyHTTPRequest: %v", err)
	}
	if vd.Domain() != "agent.example.com" {
		t.Fatalf("domain = %s", vd.Domain())
	}
	if reader.nonRevocationCalls != 0 || !vd.RequiresLogCheck() {
		t.Fatal("logchk must remain caller-owned")
	}
}

func TestProfile_VerifyHTTPRequestIgnoresInvalidCoexistingSignature(t *testing.T) {
	issuer, kp, verifier := testManagers(t)
	signer := NewFromIdentityManager(issuer, kp, Config{})
	checker := NewFromIdentityManager(verifier, nil, Config{})
	req, _ := http.NewRequest(http.MethodGet, "https://api.example.com/resource", nil)
	signed, err := signer.CreateSignedHTTPRequest(req, SigningOptions{})
	if err != nil {
		t.Fatal(err)
	}
	input, sig := signed.Header.Get("Signature-Input"), signed.Header.Get("Signature")
	signed.Header.Set("Signature-Input", strings.Replace(input, "sig1=", "proxy=", 1)+", "+input)
	signed.Header.Set("Signature", `proxy=:Ym9ndXM=:, `+sig)
	if _, err := checker.VerifyHTTPRequest(context.Background(), signed); err != nil {
		t.Fatalf("VerifyHTTPRequest: %v", err)
	}
}

func TestProfile_VerifyHTTPRequestRejectsMultipleValidSignatures(t *testing.T) {
	issuer, kp, verifier := testManagers(t)
	signer := NewFromIdentityManager(issuer, kp, Config{})
	checker := NewFromIdentityManager(verifier, nil, Config{})
	req, _ := http.NewRequest(http.MethodGet, "https://api.example.com/resource", nil)
	signed, err := signer.CreateSignedHTTPRequest(req, SigningOptions{})
	if err != nil {
		t.Fatal(err)
	}
	input, sig := signed.Header.Get("Signature-Input"), signed.Header.Get("Signature")
	signed.Header.Set("Signature-Input", strings.Replace(input, "sig1=", "other=", 1)+", "+input)
	signed.Header.Set("Signature", strings.Replace(sig, "sig1=", "other=", 1)+", "+sig)
	if _, err := checker.VerifyHTTPRequest(context.Background(), signed); err == nil {
		t.Fatal("accepted multiple valid HTTP signatures")
	}
}

func TestProfile_SignAndVerifyHTTPRequestEd25519(t *testing.T) {
	issuer, kp, verifier := testManagersWithKeyProvider(t, dnsid.GenerateEd25519KeyProvider())
	signer := NewFromIdentityManager(issuer, kp, Config{})
	checker := NewFromIdentityManager(verifier, nil, Config{})
	req, err := http.NewRequest(http.MethodGet, "https://api.example.com/resource", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Host = "api.example.com"
	signed, err := signer.CreateSignedHTTPRequest(req, SigningOptions{})
	if err != nil {
		t.Fatalf("CreateSignedHTTPRequest: %v", err)
	}
	vd, err := checker.VerifyHTTPRequest(context.Background(), signed)
	if err != nil {
		t.Fatalf("VerifyHTTPRequest: %v", err)
	}
	if vd.Domain() != "agent.example.com" {
		t.Fatalf("domain = %s", vd.Domain())
	}
}

func TestProfile_VerifyHTTPRequestRejectsExcessiveExpiresLifetime(t *testing.T) {
	issuer, kp, verifier := testManagers(t)
	checker := NewFromIdentityManager(verifier, nil, Config{MaxAge: time.Minute})
	req, _ := http.NewRequest(http.MethodGet, "https://api.example.com/resource", nil)
	now := time.Now().Unix()
	if err := SignHTTPMessage(req, SignatureParams{
		Label:      "sig1",
		Components: []ComponentIdentifier{{Name: "@method"}, {Name: "@authority"}, {Name: "@target-uri"}},
		Created:    now,
		Expires:    now + int64(time.Hour/time.Second),
		KeyID:      issuer.Domain() + "#" + kp.ListKeyIds()[0],
		Alg:        "ecdsa-p256-sha256",
	}, kp); err != nil {
		t.Fatal(err)
	}
	if _, err := checker.VerifyHTTPRequest(context.Background(), req); err == nil {
		t.Fatal("accepted expires lifetime beyond max age")
	}
}

func TestProfile_CreateSignedHTTPRequestIncludesConfiguredLabelExpiryAndTag(t *testing.T) {
	manager, _, _ := testManagers(t)
	profile := NewFromIdentityManagerKeyProvider(manager, Config{})
	req, _ := http.NewRequest(http.MethodPost, "https://peer.example.com/", strings.NewReader("{}"))

	signed, err := profile.CreateSignedHTTPRequest(req, SigningOptions{Label: "a2a", ExpiresIn: 5 * time.Minute, Tag: "a2a-v1"})
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseSignatureInput(signed.Header.Get("Signature-Input"))
	if err != nil {
		t.Fatal(err)
	}
	params := parsed["a2a"]
	if params.Tag != "a2a-v1" || params.Expires-params.Created != 300 {
		t.Fatalf("signature params = %+v", params)
	}
}

func TestProfile_RejectsInvalidHTTPMessageSignatureConfig(t *testing.T) {
	req, _ := http.NewRequest(http.MethodGet, "https://api.example.com/resource", nil)
	for name, cfg := range map[string]Config{
		"negative max age":    {MaxAge: -time.Second},
		"negative clock skew": {ClockSkew: -time.Second},
	} {
		t.Run(name, func(t *testing.T) {
			profile := New(nil, "agent.example.com", dnsid.GenerateEd25519KeyProvider(), cfg)
			if _, err := profile.CreateSignedHTTPRequest(req, SigningOptions{}); err == nil {
				t.Fatal("accepted invalid HTTP Message Signatures configuration")
			}
		})
	}
}

func TestConfigWithClockSkewAllowsExplicitZero(t *testing.T) {
	profile := New(nil, "", nil, Config{}.WithClockSkew(0))
	cfg, err := profile.httpSignatureConfig()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.ClockSkew != 0 {
		t.Fatalf("ClockSkew = %v, want strict zero", cfg.ClockSkew)
	}
}

func TestProfile_SuppliedEmptyBodyRequiresCoveredDigest(t *testing.T) {
	issuer, kp, verifier := testManagers(t)
	signer := NewFromIdentityManager(issuer, kp, Config{})
	checker := NewFromIdentityManager(verifier, nil, Config{})
	req, _ := http.NewRequest(http.MethodPost, "https://api.example.com/resource", nil)
	req.Body = io.NopCloser(bytes.NewReader(nil))
	req.ContentLength = 0
	signed, err := signer.CreateSignedHTTPRequest(req, SigningOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if got := signed.Header.Get("Content-Digest"); got != "sha-256=:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=:" {
		t.Fatalf("Content-Digest = %q", got)
	}
	if !strings.Contains(signed.Header.Get("Signature-Input"), `"content-digest"`) {
		t.Fatalf("Signature-Input = %q", signed.Header.Get("Signature-Input"))
	}
	if _, err := checker.VerifyHTTPRequest(context.Background(), signed); err != nil {
		t.Fatalf("VerifyHTTPRequest supplied empty body: %v", err)
	}
}

func TestProfile_DoesNotInferBodyFromContentLength(t *testing.T) {
	issuer, kp, verifier := testManagers(t)
	signer := NewFromIdentityManager(issuer, kp, Config{})
	checker := NewFromIdentityManager(verifier, nil, Config{})
	req, _ := http.NewRequest(http.MethodPost, "https://api.example.com/resource", nil)
	req.ContentLength = 42
	signed, err := signer.CreateSignedHTTPRequest(req, SigningOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if got := signed.Header.Get("Content-Digest"); got != "" || strings.Contains(signed.Header.Get("Signature-Input"), `"content-digest"`) {
		t.Fatalf("inferred content from Content-Length: digest=%q input=%q", got, signed.Header.Get("Signature-Input"))
	}
	if _, err := checker.VerifyHTTPRequest(context.Background(), signed); err != nil {
		t.Fatalf("VerifyHTTPRequest metadata-only content length: %v", err)
	}
}

func TestProfile_VerifyHTTPRequestRejectsTamperedBody(t *testing.T) {
	issuer, kp, verifier := testManagers(t)
	signer := NewFromIdentityManager(issuer, kp, Config{})
	checker := NewFromIdentityManager(verifier, nil, Config{})
	req, err := http.NewRequest(http.MethodPost, "https://api.example.com/resource", strings.NewReader("hello"))
	if err != nil {
		t.Fatal(err)
	}
	signed, err := signer.CreateSignedHTTPRequest(req, SigningOptions{})
	if err != nil {
		t.Fatalf("CreateSignedHTTPRequest: %v", err)
	}
	signed.Body = http.NoBody
	_, err = checker.VerifyHTTPRequest(context.Background(), signed)
	if err == nil {
		t.Fatal("VerifyHTTPRequest accepted tampered body")
	}
}

func TestSignHTTPMessagePreservesOtherSignatureMembers(t *testing.T) {
	kp := dnsid.GenerateEd25519KeyProvider()
	req, _ := http.NewRequest(http.MethodGet, "https://api.example.com/resource", nil)
	req.Header.Set("Signature-Input", `old=("x-header");keyid="a,b";created=1`)
	req.Header.Set("Signature", `old=:YWJjLGRlZg==:`)
	err := SignHTTPMessage(req, SignatureParams{
		Label:      "sig1",
		Components: []ComponentIdentifier{{Name: "@method"}},
		Created:    2,
		KeyID:      "kid",
		Alg:        "ed25519",
	}, kp)
	if err != nil {
		t.Fatal(err)
	}
	if input := req.Header.Get("Signature-Input"); !strings.Contains(input, `old=("x-header");keyid="a,b"`) || !strings.Contains(input, "sig1=") {
		t.Fatalf("Signature-Input = %q", input)
	}
	if sig := req.Header.Get("Signature"); !strings.Contains(sig, "old=") || !strings.Contains(sig, "sig1=") {
		t.Fatalf("Signature = %q", sig)
	}
}

func TestParseComponentIdentifierStructuredParams(t *testing.T) {
	c := ParseComponentIdentifier(`"signature-agent";key="sig1"`)
	if c.Name != "signature-agent" || c.Params["key"] != "sig1" || c.serialize() != `"signature-agent";key="sig1"` {
		t.Fatalf("component = %#v serialized=%s", c, c.serialize())
	}
	c = ParseComponentIdentifier(`"@authority";req`)
	if c.Name != "@authority" || c.Params["req"] != true || c.serialize() != `"@authority";req` {
		t.Fatalf("component = %#v serialized=%s", c, c.serialize())
	}
}

func TestParseSignatureInputPreservesOrderedParametersAndCanonicalizes(t *testing.T) {
	parsed, err := ParseSignatureInput(`proxy=("@method");created=1, sig1=("signature-agent";key="foo bar" "@authority";req);created=2;keyid="agent.example#k";alg="ed25519"`)
	if err != nil {
		t.Fatal(err)
	}
	params := parsed["sig1"]
	if len(params.Parameters) != 3 || params.Parameters[0].Name != "created" || params.Parameters[1].Name != "keyid" || params.Parameters[2].Name != "alg" {
		t.Fatalf("parameters = %#v", params.Parameters)
	}
	if len(params.Components) != 2 || params.Components[0].Params["key"] != "foo bar" || params.Components[1].Params["req"] != true {
		t.Fatalf("components = %#v", params.Components)
	}
	if params.Components[1].serialize() != `"@authority";req` {
		t.Fatalf("component raw = %q", params.Components[1].serialize())
	}
}

func TestParseHTTPSignatureHeadersCombinesRepeatedFields(t *testing.T) {
	req, _ := http.NewRequest(http.MethodGet, "https://api.example.com/resource", nil)
	req.Header.Add("Signature-Input", `proxy=("x-test");created=1;keyid="proxy#k"`)
	req.Header.Add("Signature-Input", `sig1=("@method" "@authority" "@target-uri");created=2;keyid="agent.example#k";alg="ed25519"`)
	req.Header.Add("Signature", `other=:cHJveHk=:`)
	req.Header.Add("Signature", `sig1=:c2ln:`)
	parsed, err := parseHTTPSignatureHeaders(req)
	if err != nil {
		t.Fatal(err)
	}
	if len(parsed) != 1 || parsed[0].label != "sig1" || len(parsed[0].parameters) != 3 || string(parsed[0].signature) != "sig" {
		t.Fatalf("parsed = %#v", parsed)
	}
}

func TestHTTPQueryParamCanonicalization(t *testing.T) {
	req, _ := http.NewRequest(http.MethodGet, "https://api.example.com/?q=a+b&empty=", nil)
	got, err := httpSignatureComponentValue(req, ComponentIdentifier{Name: "@query-param", Params: map[string]any{"name": "q"}})
	if err != nil || got != "a%20b" {
		t.Fatalf("q = %q err=%v", got, err)
	}
	got, err = httpSignatureComponentValue(req, ComponentIdentifier{Name: "@query-param", Params: map[string]any{"name": "empty"}})
	if err != nil || got != "" {
		t.Fatalf("empty = %q err=%v", got, err)
	}
	if _, err := httpSignatureComponentValue(req, ComponentIdentifier{Name: "@query-param", Params: map[string]any{"name": "missing"}}); err == nil {
		t.Fatal("accepted missing query param")
	}
	req.URL.RawQuery = "q=1&q=2"
	if _, err := httpSignatureComponentValue(req, ComponentIdentifier{Name: "@query-param", Params: map[string]any{"name": "q"}}); err == nil {
		t.Fatal("accepted duplicate query param")
	}
	req.URL.RawQuery = "fa%C3%A7ade%22%3A%20=*~"
	got, err = httpSignatureComponentValue(req, ComponentIdentifier{Name: "@query-param", Params: map[string]any{"name": "fa%C3%A7ade%22%3A%20"}})
	if err != nil || got != "*%7E" {
		t.Fatalf("encoded param = %q err=%v", got, err)
	}
}

func TestBuildSignatureInputResponseRequiresReqParamForRequestComponents(t *testing.T) {
	req, _ := http.NewRequest(http.MethodGet, "https://api.example.com/resource", nil)
	res := &http.Response{Header: http.Header{}, Request: req}
	if _, err := BuildSignatureInput(res, SignatureParams{Components: []ComponentIdentifier{{Name: "@authority"}}}); err == nil {
		t.Fatal("accepted response @authority without req param")
	}
	if _, err := BuildSignatureInput(res, SignatureParams{Components: []ComponentIdentifier{{Name: "@query"}}}); err == nil {
		t.Fatal("accepted response @query without req param")
	}
	got, err := BuildSignatureInput(res, SignatureParams{Components: []ComponentIdentifier{{Name: "@authority", Params: map[string]any{"req": true}}}})
	if err != nil {
		t.Fatalf("@authority;req=true: %v", err)
	}
	if strings.Contains(got, "req=?1") || !strings.Contains(got, `"@authority";req`) {
		t.Fatalf("base = %q", got)
	}
}

func TestHTTPAuthorityCanonicalization(t *testing.T) {
	for raw, want := range map[string]string{
		"https://Example.COM:443/x":    "https://example.com/x",
		"http://Example.COM:80/x":      "http://example.com/x",
		"https://Example.COM:8443/x":   "https://example.com:8443/x",
		"https://[2001:db8::1]/x":      "https://[2001:db8::1]/x",
		"https://[2001:db8::1]:443/x":  "https://[2001:db8::1]/x",
		"https://[2001:db8::1]:8443/x": "https://[2001:db8::1]:8443/x",
	} {
		req, _ := http.NewRequest(http.MethodGet, raw, nil)
		got, err := httpSignatureComponentValue(req, ComponentIdentifier{Name: "@target-uri"})
		if err != nil || got != want {
			t.Fatalf("%s target-uri = %q err=%v", raw, got, err)
		}
	}
}

func TestBuildSignatureInputResponseStatus(t *testing.T) {
	req, _ := http.NewRequest(http.MethodGet, "https://api.example.com/resource", nil)
	res := &http.Response{StatusCode: http.StatusCreated, Header: http.Header{}, Request: req}
	got, err := BuildSignatureInput(res, SignatureParams{Components: []ComponentIdentifier{{Name: "@status"}}})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(got, `"@status": 201`) {
		t.Fatalf("base = %q", got)
	}
	if _, err := BuildSignatureInput(req, SignatureParams{Components: []ComponentIdentifier{{Name: "@status"}}}); err == nil {
		t.Fatal("accepted @status on request")
	}
}

func TestBuildSignatureInputRejectsMalformedComponents(t *testing.T) {
	req, _ := http.NewRequest(http.MethodGet, "https://api.example.com/?a=", nil)
	if _, err := BuildSignatureInput(req, SignatureParams{Components: []ComponentIdentifier{{Name: "@query-param"}}}); err == nil {
		t.Fatal("accepted @query-param without name")
	}
	if _, err := BuildSignatureInput(req, SignatureParams{Components: []ComponentIdentifier{{Name: "@method", Params: map[string]any{"unknown": true}}}}); err == nil {
		t.Fatal("accepted unsupported caller component parameter")
	}
	req.Header.Set("Signature-Agent", `other="https://bot.example/dir"`)
	if _, err := BuildSignatureInput(req, SignatureParams{Components: []ComponentIdentifier{{Name: "signature-agent", Params: map[string]any{"key": "sig1"}}}}); err == nil {
		t.Fatal("accepted missing dictionary member")
	}
	if _, err := ParseSignatureInput(`sig1=("@method";unknown="x");created=1;keyid="k";alg="ed25519"`); err == nil {
		t.Fatal("accepted unsupported component parameter")
	}
	if _, err := ParseSignatureInput(`sig1=("@method);created=1;keyid="k";alg="ed25519"`); err == nil {
		t.Fatal("accepted malformed quoted component")
	}
	if _, err := ParseSignatureInput(`sig1=("@method");created="1";keyid="k";alg="ed25519"`); err == nil {
		t.Fatal("accepted malformed created parameter")
	}
	if _, err := ParseSignatureInput(`sig1=("@authority";req="yes");created=1;keyid="k";alg="ed25519"`); err == nil {
		t.Fatal("accepted malformed req parameter")
	}
	if _, err := ParseSignatureInput(`sig1=("example-dict";sf);created=1`); err == nil {
		t.Fatal("accepted explicit sf component parameter")
	}
	if _, err := ParseSignatureInput(`sig1=("@method" "@method");created=1`); err == nil {
		t.Fatal("accepted duplicate equivalent components")
	}
}

func TestBuildSignatureInputCanonicalizesUnknownSignatureParameter(t *testing.T) {
	req, _ := http.NewRequest(http.MethodGet, "https://api.example.com/", nil)
	parsed, err := ParseSignatureInput(`sig1=("@method");created=1;extension=?1`)
	if err != nil {
		t.Fatal(err)
	}
	got, err := BuildSignatureInput(req, parsed["sig1"])
	if err != nil {
		t.Fatal(err)
	}
	want := `"@method": GET` + "\n" + `"@signature-params": ("@method");created=1;extension`
	if got != want {
		t.Fatalf("base = %q, want %q", got, want)
	}
}

func TestParseSignatureDictionariesRejectDuplicateLabels(t *testing.T) {
	if _, err := ParseSignatureInput(`sig1=("@method");created=1, sig1=("@path");created=2`); err == nil || !strings.Contains(strings.ToLower(err.Error()), "duplicate") {
		t.Fatalf("ParseSignatureInput duplicate error = %v", err)
	}
	if _, err := ParseSignature(`sig1=:b25l:, sig1=:dHdv:`); err == nil || !strings.Contains(strings.ToLower(err.Error()), "duplicate") {
		t.Fatalf("ParseSignature duplicate error = %v", err)
	}
}

func TestBuildSignatureInputPathDefaultsToSlash(t *testing.T) {
	req, _ := http.NewRequest(http.MethodGet, "https://api.example.com", nil)
	got, err := BuildSignatureInput(req, SignatureParams{Components: []ComponentIdentifier{{Name: "@path"}}})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(got, `"@path": /`) {
		t.Fatalf("base = %q", got)
	}
}

func TestBuildSignatureInputDictionaryKeyUsesRepeatedFields(t *testing.T) {
	req, _ := http.NewRequest(http.MethodGet, "https://api.example.com/resource", nil)
	req.Header.Add("Signature-Agent", `other="https://bot.example/other"`)
	req.Header.Add("Signature-Agent", `sig1="https://bot.example/dir"`)
	got, err := BuildSignatureInput(req, SignatureParams{Components: []ComponentIdentifier{{Name: "signature-agent", Params: map[string]any{"key": "sig1"}}}})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(got, `"signature-agent";key="sig1": "https://bot.example/dir"`) {
		t.Fatalf("base = %q", got)
	}
}

func TestBuildSignatureInputCombinesRepeatedFields(t *testing.T) {
	req, _ := http.NewRequest(http.MethodGet, "https://api.example.com/resource", nil)
	req.Header.Add("X-Test", "a")
	req.Header.Add("X-Test", "b")
	got, err := BuildSignatureInput(req, SignatureParams{Components: []ComponentIdentifier{{Name: "x-test"}}})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(got, `"x-test": a, b`) {
		t.Fatalf("base = %q", got)
	}
}

func TestBuildSignatureInputOriginFormTargetURI(t *testing.T) {
	req, _ := http.NewRequest(http.MethodGet, "/resource?a=1", nil)
	req.Host = "API.Example.COM:443"
	req.TLS = &tls.ConnectionState{}
	got, err := BuildSignatureInput(req, SignatureParams{Components: []ComponentIdentifier{{Name: "@target-uri"}}})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(got, `"@target-uri": https://api.example.com/resource?a=1`) {
		t.Fatalf("base = %q", got)
	}
}

func TestBuildSignatureInputReqAppliesBeforeLookup(t *testing.T) {
	req, _ := http.NewRequest(http.MethodGet, "https://api.example.com/resource", nil)
	req.Header.Set("X-Test", "ok")
	res := &http.Response{Header: http.Header{}, Request: req}
	got, err := BuildSignatureInput(res, SignatureParams{Components: []ComponentIdentifier{{Name: "@path", Params: map[string]any{"req": true}}, {Name: "x-test", Params: map[string]any{"req": true}}}})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(got, `"@path";req: /resource`) || !strings.Contains(got, `"x-test";req: ok`) {
		t.Fatalf("base = %q", got)
	}
	if _, err := BuildSignatureInput(req, SignatureParams{Components: []ComponentIdentifier{{Name: "@path", Params: map[string]any{"req": true}}}}); err == nil {
		t.Fatal("accepted req parameter on request")
	}
}

func TestBuildSignatureInputRejectsAbsentAndDuplicateFields(t *testing.T) {
	req, _ := http.NewRequest(http.MethodGet, "https://api.example.com/resource", nil)
	if _, err := BuildSignatureInput(req, SignatureParams{Components: []ComponentIdentifier{{Name: "x-missing"}}}); err == nil {
		t.Fatal("accepted absent covered field")
	}
	req.Header.Set("X-Empty", "")
	if _, err := BuildSignatureInput(req, SignatureParams{Components: []ComponentIdentifier{{Name: "x-empty"}}}); err != nil {
		t.Fatalf("rejected present empty field: %v", err)
	}
	if _, err := BuildSignatureInput(req, SignatureParams{Components: []ComponentIdentifier{{Name: "@method"}, {Name: "@method"}}}); err == nil {
		t.Fatal("accepted duplicate covered component")
	}
}

func TestContainsComponentIgnoresParamMapOrder(t *testing.T) {
	components := []ComponentIdentifier{{Name: "Foo", Params: map[string]any{"bar": true, "name": "x"}}}
	if !containsComponent(components, ComponentIdentifier{Name: "foo", Params: map[string]any{"name": "x", "bar": true}}) {
		t.Fatal("component equality used param order/case")
	}
}

func TestProfile_VerifyHTTPRequestSelectsMatchingLabel(t *testing.T) {
	issuer, kp, verifier := testManagers(t)
	checker := NewFromIdentityManager(verifier, nil, Config{})
	req, _ := http.NewRequest(http.MethodGet, "https://api.example.com/resource", nil)
	err := SignHTTPMessage(req, SignatureParams{
		Label:      "dnsid",
		Components: []ComponentIdentifier{{Name: "@method"}, {Name: "@authority"}, {Name: "@target-uri"}},
		Created:    time.Now().Unix(),
		KeyID:      issuer.Domain() + "#" + kp.ListKeyIds()[0],
		Alg:        "ecdsa-p256-sha256",
	}, kp)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := checker.VerifyHTTPRequest(context.Background(), req); err != nil {
		t.Fatalf("VerifyHTTPRequest custom label: %v", err)
	}
}
