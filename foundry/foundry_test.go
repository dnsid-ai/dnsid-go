//go:build dnsid_foundry

package foundry

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	dnsid "github.com/dnsid-ai/dnsid-go"
	"github.com/dnsid-ai/dnsid-go/config"
	"github.com/dnsid-ai/dnsid-go/internal/cryptoutil"
	"github.com/dnsid-ai/dnsid-go/jose"
	dnsidlog "github.com/dnsid-ai/dnsid-go/log"
	"github.com/dnsid-ai/dnsid-go/log/c2sptlog"
	"github.com/lestrrat-go/jwx/v3/jwk"
)

const testLR = "c2sp-tlog:testnet:https://log.example#issuance_AAAAAAAAAAAAAAAAAAAAAA"
const testOrg = "11111111-1111-4111-8111-111111111111"
const testDomain = "agent.example"

type fixture struct {
	mu          sync.Mutex
	t           *testing.T
	operational dnsid.KeyProvider
	entity      dnsid.KeyProvider
	client      *Client
	store       *FileFoundryStore
	registry    *fakeRegistry
	log         *fakeLog
	record      string
	responses   map[string]json.RawMessage
	dnsMissing  bool
	publicCalls int
	dnsCalls    int
	publicURLs  []string
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	f := &fixture{t: t, operational: dnsid.GenerateEd25519KeyProvider(), entity: dnsid.GenerateES256KeyProvider(), responses: map[string]json.RawMessage{}}
	store, err := NewFileFoundryStore(filepath.Join(t.TempDir(), "state"))
	if err != nil {
		t.Fatal(err)
	}
	f.store = store
	logClient, err := c2sptlog.New(testLR)
	if err != nil {
		t.Fatal(err)
	}
	f.log = &fakeLog{NoopLogReader: dnsidlog.NoopLogReader{Method: "fake"}, f: f}
	f.registry = &fakeRegistry{f: f, logClient: logClient, status: "PROVISIONING", responseDomain: testDomain}
	var onboarding dnsid.OrganizationOnboardingResponse
	if err := json.Unmarshal([]byte(`{"org_id":"`+testOrg+`","governance_domain":"Governance.Example.","gi":{"domain":"GOVERNANCE.EXAMPLE","state":"verified","gate_authorized":true},"ek":{"status":"verified"}}`), &onboarding); err != nil {
		t.Fatal(err)
	}
	f.registry.onboarding = &onboarding
	f.publish(f.operational, "governance.example", testLR, dnsid.AgentStateActive)
	f.client = f.newClient(f.operational, store)
	return f
}

func (f *fixture) newClient(provider dnsid.KeyProvider, store FoundryStore) *Client {
	f.t.Helper()
	logs := dnsidlog.NewLogRegistry()
	if err := logs.Register("c2sp-tlog", func(string) dnsidlog.LogReader { return f.log }); err != nil {
		f.t.Fatal(err)
	}
	client, err := New(config.Loaded{Registry: config.Registry{RegistryURL: "https://registry.example"}, Dnsid: dnsid.Config{Verification: dnsid.VerificationConfig{TrustedEntities: []dnsid.TrustedEntity{}}}}, Dependencies{Credential: "not-for-public-hosts", KeyProvider: provider, RegistryClient: f.registry, Store: store, LogRegistry: logs, DNSResolver: fakeDNS{f}, HTTPSFetcher: fakeHTTPS{f}})
	if err != nil {
		f.t.Fatal(err)
	}
	return client
}

func (f *fixture) publish(provider dnsid.KeyProvider, gi, lr string, state dnsid.AgentState) {
	f.t.Helper()
	manager, err := dnsid.NewIdentityManager(dnsid.Config{Identity: &dnsid.IdentityConfig{Domain: testDomain, GovernanceID: gi, LogRef: lr, StatusURL: "https://agent.example/status", KeyURL: "https://agent.example/ku", EntityKeyURL: "https://governance.example/ek"}}, provider, dnsid.WithEntityKeyProvider(f.entity))
	if err != nil {
		f.t.Fatal(err)
	}
	record, err := manager.CreateTXTRecord()
	if err != nil {
		f.t.Fatal(err)
	}
	f.record = record.Serialize()
	for url, provider := range map[string]dnsid.KeyProvider{"https://governance.example/ek": f.entity, "https://agent.example/ku": provider} {
		set := jwk.NewSet()
		if err := set.AddKey(provider.JWK()); err != nil {
			f.t.Fatal(err)
		}
		data, err := json.Marshal(set)
		if err != nil {
			f.t.Fatal(err)
		}
		f.responses[url] = data
	}
	f.setStatus(state)
}
func (f *fixture) setStatus(state dnsid.AgentState) {
	f.t.Helper()
	status := dnsid.AgentStatus{State: state, LastTransitionAt: time.Now().Add(-time.Minute).UTC().Truncate(time.Second)}
	if state == dnsid.AgentStateRevoked {
		status.RevocationReason = "keyCompromise"
	}
	data, err := json.Marshal(status)
	if err != nil {
		f.t.Fatal(err)
	}
	f.responses["https://agent.example/status"] = data
}

func (f *fixture) document(name string) *RecoveryDocument {
	f.t.Helper()
	key := OperationKey{f.client.loaded.Registry.RegistryURL, testOrg, name}
	doc, err := readDocument(filepath.Join(f.store.directory, key.digest()+".json"))
	if err != nil {
		f.t.Fatal(err)
	}
	return doc
}

type fakeDNS struct{ f *fixture }

func (d fakeDNS) FetchTXT(ctx context.Context, name string) ([]dnsid.TXTRecordRData, dnsid.DNSSECState, error) {
	d.f.mu.Lock()
	defer d.f.mu.Unlock()
	d.f.publicCalls++
	if err := ctx.Err(); err != nil {
		return nil, "", err
	}
	d.f.dnsCalls++
	if d.f.dnsMissing {
		return nil, dnsid.DNSSECStateUnsigned, nil
	}
	if name != "_dnsid."+testDomain {
		return nil, "", fmt.Errorf("unexpected DNS name %q", name)
	}
	return []dnsid.TXTRecordRData{{Value: d.f.record, TTL: time.Hour}}, dnsid.DNSSECStateUnsigned, nil
}

type fakeHTTPS struct{ f *fixture }

func (h fakeHTTPS) FetchJSON(ctx context.Context, url string, opts dnsid.FetchOptions) (json.RawMessage, *tls.Certificate, error) {
	h.f.mu.Lock()
	defer h.f.mu.Unlock()
	h.f.publicCalls++
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}
	h.f.publicURLs = append(h.f.publicURLs, url)
	body, ok := h.f.responses[url]
	if !ok {
		return nil, nil, fmt.Errorf("unexpected public URL %q", url)
	}
	return append(json.RawMessage(nil), body...), nil, nil
}

type fakeLog struct {
	dnsidlog.NoopLogReader
	f            *fixture
	events       []dnsidlog.LogEvent
	historyErr   error
	bindingErr   error
	historyCalls int
	currentThumb string
}

func (l *fakeLog) Canonical(event dnsidlog.LogEvent) ([]byte, error) {
	client, err := c2sptlog.New(testLR)
	if err != nil {
		return nil, err
	}
	return client.Canonical(event)
}

func (l *fakeLog) RebuildHistory(context.Context, string) ([]dnsidlog.LogEvent, error) {
	l.historyCalls++
	return append([]dnsidlog.LogEvent(nil), l.events...), l.historyErr
}
func (l *fakeLog) VerifyBilateralBinding(_ context.Context, input dnsidlog.BilateralBindingInput) (dnsidlog.BilateralBinding, error) {
	if l.bindingErr != nil {
		return dnsidlog.BilateralBinding{}, l.bindingErr
	}
	if len(l.events) == 0 {
		return dnsidlog.BilateralBinding{}, fmt.Errorf("no accepted issuance")
	}
	event := l.events[0]
	a, _ := keyThumb(input.EntityKey)
	if event.Domain != input.Domain || event.GovernanceID != input.GovernanceID || a != event.InitialEntityThumbprint {
		return dnsidlog.BilateralBinding{}, fmt.Errorf("fake verified binding mismatch")
	}
	return dnsidlog.BilateralBinding{InitialEntityThumbprint: a, InitialOperationalThumbprint: event.InitialOperationalThumbprint, Timestamp: event.Timestamp}, nil
}
func (l *fakeLog) VerifyOperationalContinuity(_ context.Context, _ string, initial, current string) error {
	if len(l.events) == 0 {
		return errors.New("no issuance")
	}
	expected := l.currentThumb
	if expected == "" {
		expected = l.events[0].InitialOperationalThumbprint
	}
	if initial != l.events[0].InitialOperationalThumbprint || current != expected {
		return dnsid.NewVerificationError(dnsid.VerificationCodeLogError, false, "no authorized operational continuity", nil)
	}
	return nil
}
func (l *fakeLog) VerifyGovernanceRelationship(context.Context, string, string) error { return nil }
func (l *fakeLog) KeyTimestamp(context.Context, string, string) (time.Time, error) {
	return time.Now().Add(-time.Minute), nil
}
func (l *fakeLog) VerifyNonRevocation(context.Context, string, time.Time) (dnsidlog.LoggedStateEvidence, error) {
	return dnsidlog.LoggedStateEvidence{LogReference: testLR, LoggedState: dnsidlog.AgentStateActive, FreshnessTime: time.Now()}, nil
}

type fakeRegistry struct {
	f                 *fixture
	logClient         *c2sptlog.Client
	onboarding        *dnsid.OrganizationOnboardingResponse
	onboardingErr     error
	status            string
	statuses          []string
	responseDomain    string
	responseID        string
	detailHook        func(*dnsid.AgentDetail) error
	oidcIssuerURL     string
	name              string
	requestID         string
	initial           json.RawMessage
	createCalls       int
	prepareCalls      int
	prepareErr        error
	submissions       [][]byte
	keys              []string
	createErr         error
	createResponseErr error
	submitErr         error
	competing         bool
	acceptedEntry     []byte
	beforeSubmit      func()
}

func (r *fakeRegistry) GetOrganizationOnboarding(context.Context) (*dnsid.OrganizationOnboardingResponse, error) {
	return r.onboarding, r.onboardingErr
}
func (r *fakeRegistry) CreateLiveAgent(_ context.Context, input *dnsid.LiveAgentRegistrationInput, key string) (*dnsid.CreateAgentResponse, error) {
	r.createCalls++
	saved := r.f.document(input.Name)
	if saved == nil || saved.Phase != "creation-pending" {
		r.f.t.Fatal("create before durable intent")
	}
	if r.initial != nil && !sameJSON(r.initial, input.PublicKey) {
		return nil, &dnsid.RegistryAPIError{StatusCode: 409, Code: "KEY_MISMATCH"}
	}
	r.name = input.Name
	r.requestID = key
	r.initial, _ = json.Marshal(input.PublicKey)
	if r.createErr != nil {
		err := r.createErr
		r.createErr = nil
		return nil, err
	}
	id := r.responseID
	if id == "" {
		id = "agent-id"
	}
	response := &dnsid.CreateAgentResponse{ID: id, Status: r.status, Domain: r.responseDomain, PublicationConfig: dnsid.PublicationConfig{PublishProfile: dnsid.DefaultPublishProfile, GovernanceID: "governance.example", LogRef: testLR, StatusURL: "https://agent.example/status", KeyURL: "https://agent.example/ku", EntityKeyURL: "https://governance.example/ek"}, OIDCIssuerURL: r.oidcIssuerURL}
	return response, r.createResponseErr
}

func (r *fakeRegistry) GetAgentStatus(context.Context, string) (*dnsid.AgentDetail, error) {
	if len(r.statuses) > 0 {
		r.status = r.statuses[0]
		r.statuses = r.statuses[1:]
	}
	detail := &dnsid.AgentDetail{ID: "agent-id", Domain: testDomain, Name: r.name, Status: r.status, Managed: "dnsid", DNSPublished: true, OIDCIssuerURL: r.oidcIssuerURL, PublicationConfig: dnsid.PublicationConfig{PublishProfile: dnsid.DefaultPublishProfile, GovernanceID: "governance.example", LogRef: testLR, StatusURL: "https://agent.example/status", KeyURL: "https://agent.example/ku", EntityKeyURL: "https://governance.example/ek"}}
	if r.detailHook != nil {
		return detail, r.detailHook(detail)
	}
	return detail, nil
}

func (r *fakeRegistry) PrepareKeyRotation(context.Context, string, *dnsid.KeyRotationPreparationRequest, string) (*dnsid.PreparedRegistryEvent, error) {
	return nil, errors.New("unexpected rotation")
}
func (r *fakeRegistry) PrepareIssuance(ctx context.Context, domain, key string) (*dnsid.PreparedRegistryEvent, error) {
	r.prepareCalls++
	r.keys = append(r.keys, key)
	if r.prepareErr != nil {
		return nil, r.prepareErr
	}
	if len(r.f.log.events) > 0 {
		return nil, &dnsid.RegistryAPIError{StatusCode: http.StatusConflict, Code: "TLOG_PREPARATION_MISMATCH"}
	}
	prepared, err := r.logClient.PrepareEvent(dnsidlog.LogEvent{Type: dnsidlog.LogEventIssuance, Domain: domain, GovernanceID: "governance.example", Timestamp: time.Now().Add(-time.Minute).UTC().Truncate(time.Second), InitialEntityPublicKey: r.f.entity.JWK(), InitialOperationalPublicKey: r.f.operational.JWK()})
	if err != nil {
		return nil, err
	}
	prepared, err = r.logClient.SignPreparedEvent(ctx, prepared, c2sptlog.SignerEntity, r.f.entity)
	if err != nil {
		return nil, err
	}
	data, err := prepared.Bytes()
	return &dnsid.PreparedRegistryEvent{EntryBytes: data}, err
}
func (r *fakeRegistry) SubmitPreparedEvent(ctx context.Context, domain string, data []byte, key string) (*dnsid.SubmissionResult, error) {
	r.submissions = append(r.submissions, append([]byte(nil), data...))
	r.keys = append(r.keys, key)
	saved := r.f.document(r.name)
	if saved.Issuance == nil || saved.Issuance.Operation == nil || !bytes.Equal(saved.Issuance.Operation.EntryBytes, data) {
		r.f.t.Fatal("exact issuance bytes not durable before submission")
	}
	if r.beforeSubmit != nil {
		r.beforeSubmit()
	}
	if r.submitErr != nil {
		err := r.submitErr
		r.submitErr = nil
		return nil, err
	}
	_, prepared, err := c2sptlog.ParsePreparedIssuance(data)
	if err != nil {
		return nil, err
	}
	if _, err := r.logClient.PreparedEntryBytes(ctx, prepared); err != nil {
		return nil, err
	}
	event, err := prepared.Event()
	if err != nil {
		return nil, err
	}
	if r.competing {
		other, err := r.PrepareIssuance(ctx, domain, key)
		if err != nil {
			return nil, err
		}
		object, err := decodeObject(other.EntryBytes)
		if err != nil {
			return nil, err
		}
		signatures := object["sigs"].(map[string]any)
		entitySignature := signatures["ae"].(map[string]any)
		signature, err := base64.RawURLEncoding.DecodeString(entitySignature["sig"].(string))
		if err != nil {
			return nil, err
		}
		s := new(big.Int).SetBytes(signature[32:])
		s.Sub(cryptoutil.P256Order, s).FillBytes(signature[32:])
		entitySignature["sig"] = base64.RawURLEncoding.EncodeToString(signature)
		other.EntryBytes, err = canonical(object)
		if err != nil {
			return nil, err
		}
		_, prepared, err := c2sptlog.ParsePreparedIssuance(other.EntryBytes)
		if err != nil {
			return nil, err
		}
		prepared, err = r.logClient.SignPreparedEvent(ctx, prepared, c2sptlog.SignerOperationalCountersignature, r.f.operational)
		if err != nil {
			return nil, err
		}
		r.acceptedEntry, err = r.logClient.PreparedEntryBytes(ctx, prepared)
		if err != nil {
			return nil, err
		}
		event, err = prepared.Event()
		if err != nil {
			return nil, err
		}
		r.f.log.events = []dnsidlog.LogEvent{event}
		r.status = "READY"
		return nil, &dnsid.RegistryAPIError{StatusCode: 422, Code: "IDEMPOTENCY_MISMATCH"}
	}
	r.f.log.events = []dnsidlog.LogEvent{event}
	r.status = "READY"
	sum := sha256.Sum256(data)
	index := uint64(0)
	ref, _ := c2sptlog.ParseReference(testLR)
	return &dnsid.SubmissionResult{State: dnsid.SubmissionStateAccepted, EntryHash: hex.EncodeToString(sum[:]), Index: &index, LogRef: string(ref.FinalEventRef(index))}, nil
}

func requireKind(t *testing.T, err error, kind ErrorKind) *Error {
	t.Helper()
	var e *Error
	if !errors.As(err, &e) || e.Kind != kind {
		t.Fatalf("error=%v, want %s", err, kind)
	}
	return e
}
func requirePaused(t *testing.T, err error) {
	t.Helper()
	var paused *SigningPaused
	if !errors.As(err, &paused) {
		t.Fatalf("error=%v, want SigningPaused", err)
	}
}

func TestNameAndHashVectors(t *testing.T) {
	data, err := os.ReadFile("../testdata/foundry/registration-vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var vectors struct {
		OrganizationID string `json:"organizationId"`
		InitialKeyID   string `json:"initialKeyId"`
		Registration   []struct {
			Name            string
			RegistrationKey string
		}
		Issuance []struct {
			RegistrationKey string
			IssuanceKey     string
		}
		RejectedNames []struct {
			Name        string
			NameUTF8Hex string `json:"nameUtf8Hex"`
		}
	}
	if err := json.Unmarshal(data, &vectors); err != nil {
		t.Fatal(err)
	}
	if len(vectors.Registration)+len(vectors.Issuance) != 17 || len(vectors.RejectedNames) != 3 {
		t.Fatal("incomplete registration, issuance, or rejected-name vectors")
	}
	for _, test := range vectors.Registration {
		t.Run(test.Name, func(t *testing.T) {
			key, err := RegistrationKey(vectors.OrganizationID, test.Name, vectors.InitialKeyID)
			if err != nil || key != test.RegistrationKey {
				t.Fatalf("registration=%s, want=%s, err=%v", key, test.RegistrationKey, err)
			}
		})
	}
	for _, test := range vectors.Issuance {
		if got := IssuanceKey(test.RegistrationKey); got != test.IssuanceKey {
			t.Fatalf("issuance=%s, want=%s", got, test.IssuanceKey)
		}
	}
	for _, test := range vectors.RejectedNames {
		name := test.Name
		if test.NameUTF8Hex != "" {
			raw, err := hex.DecodeString(test.NameUTF8Hex)
			if err != nil {
				t.Fatal(err)
			}
			name = string(raw)
		}
		if ValidateName(name) == nil {
			t.Fatalf("accepted %q", name)
		}
	}
	for _, name := range []string{"\\u2028", "\u2028", "\x00<&\n"} {
		var b bytes.Buffer
		quote(&b, name)
		var decoded string
		if err := json.Unmarshal(b.Bytes(), &decoded); err != nil || decoded != name {
			t.Fatalf("quote roundtrip %q: %s, %v", name, b.String(), err)
		}
	}
}

func TestCreateActiveAndCompletedResume(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	id, err := f.client.Create(ctx, " agent ")
	if err != nil {
		t.Fatal(err)
	}
	if id.Domain() != testDomain || id.State() != "" {
		t.Fatalf("unexpected handle %s %s", id.Domain(), id.State())
	}
	_, err = id.Sign([]byte("data"))
	requirePaused(t, err)
	manager, err := id.IdentityManager()
	if err != nil {
		t.Fatal(err)
	}
	_, err = manager.KeyProvider().Sign([]byte("data"))
	requirePaused(t, err)
	if _, err := id.Active(ctx); err != nil {
		t.Fatal(err)
	}
	activeManager, err := id.IdentityManager()
	if err != nil || activeManager != manager {
		t.Fatalf("manager changed after activation: %v", err)
	}
	if id.State() != dnsid.AgentStateActive {
		t.Fatal(id.State())
	}
	signature, err := id.Sign([]byte("data"))
	if err != nil || len(signature) != 64 {
		t.Fatalf("Sign: %v", err)
	}
	if _, err := jose.NewFromIdentityManagerKeyProvider(manager, jose.Config{}).CreateJWT(jose.JWTOptions{Audience: "recipient.example"}); err != nil {
		t.Fatal(err)
	}
	if _, err := id.Active(ctx); err != nil {
		t.Fatal(err)
	}
	second, _ := id.IdentityManager()
	if second != manager {
		t.Fatal("manager instance changed")
	}
	publicCalls := f.publicCalls
	reopened, err := f.client.Create(ctx, " agent ")
	if err != nil {
		t.Fatal(err)
	}
	if f.publicCalls != publicCalls {
		t.Fatal("completed resume made public network calls")
	}
	if _, err := reopened.Sign([]byte("data")); err != nil {
		t.Fatal(err)
	}
	if f.registry.createCalls != 1 || f.registry.prepareCalls != 1 || len(f.registry.submissions) != 1 {
		t.Fatalf("duplicate work: %+v", f.registry)
	}
	if f.document(" agent ").Phase != "complete" {
		t.Fatal("completion was not durable")
	}
	f.setStatus(dnsid.AgentStateRetired)
	_, err = id.Active(ctx)
	requireKind(t, err, Terminal)
	_, err = manager.KeyProvider().Sign([]byte("data"))
	requirePaused(t, err)
}

func TestCreateValidationAndErrors(t *testing.T) {
	for _, test := range []struct {
		name        string
		configure   func(*fixture)
		kind        ErrorKind
		unsupported bool
	}{
		{"wrong org", func(f *fixture) { f.client.loaded.Foundry.OrganizationID = "other" }, Integrity, false},
		{"wrong gi", func(f *fixture) { f.client.loaded.Foundry.GovernanceID = "wrong.example" }, Integrity, false},
		{"pending", func(f *fixture) { f.registry.onboarding.EK.Status = "pending" }, WorkflowOutcome, false},
		{"no endpoint", func(f *fixture) { f.registry.onboardingErr = &dnsid.RegistryAPIError{StatusCode: 404} }, UnsupportedContract, true},
		{"missing governance", func(f *fixture) { f.registry.onboarding.GI = nil }, WorkflowOutcome, false},
		{"unsupported algorithm", func(f *fixture) { f.client.deps.KeyProvider = dnsid.GenerateES256KeyProvider() }, UnsupportedAlgorithm, false},
		{"revoked credential", func(f *fixture) {
			f.registry.onboardingErr = &dnsid.RegistryAPIError{StatusCode: 403, Code: "KEY_REVOKED"}
		}, KeyRevoked, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			f := newFixture(t)
			test.configure(f)
			_, err := f.client.Create(context.Background(), "name")
			requireKind(t, err, test.kind)
			if test.unsupported {
				var unsupported *UnsupportedRegistry
				if !errors.As(err, &unsupported) {
					t.Fatal(err)
				}
			}
			if f.registry.createCalls != 0 {
				t.Fatal("create dispatched before validation")
			}
		})
	}
	for _, code := range []string{"KEY_MISMATCH", "IDEMPOTENCY_CONFLICT", "IDEMPOTENCY_MISMATCH", "NAME_IN_USE"} {
		t.Run(code, func(t *testing.T) {
			f := newFixture(t)
			f.registry.createErr = &dnsid.RegistryAPIError{StatusCode: 409, Code: code}
			_, err := f.client.Create(context.Background(), "name")
			var e *Error
			if !errors.As(err, &e) || e.Code != code || e.StatusCode != http.StatusConflict {
				t.Fatal(err)
			}
		})
	}
}

type emptyProvider struct{ dnsid.KeyProvider }

func (p *emptyProvider) ListKeyIds() []string { return nil }
func (p *emptyProvider) JWK(...string) jwk.Key {
	panic("empty provider must be detected through ListKeyIds")
}

func TestCreateEmptyProvider(t *testing.T) {
	f := newFixture(t)
	f.client.deps.KeyProvider = &emptyProvider{}
	_, err := f.client.Create(context.Background(), "empty")
	requireKind(t, err, KeyMissing)
	if !strings.Contains(err.Error(), "create the signing key first") || f.registry.createCalls != 0 {
		t.Fatalf("missing key remedy or unexpected mutation: %v", err)
	}
}

func TestReplayWithoutDomainAndLostCreate(t *testing.T) {
	f := newFixture(t)
	f.registry.responseDomain = ""
	_, err := f.client.Create(context.Background(), "same")
	e := requireKind(t, err, Unresolved)
	if e.IdentityID != "agent-id" || !e.Resumable {
		t.Fatal(err)
	}
	saved := f.document("same")
	if saved.IdentityID != "agent-id" || saved.Domain != "" {
		t.Fatal("lost creation facts")
	}
	key := saved.RegistrationKey
	f.registry.responseDomain = testDomain
	id, err := f.client.Create(context.Background(), "same")
	if err != nil {
		t.Fatal(err)
	}
	if id.Domain() != testDomain || f.registry.requestID != key {
		t.Fatal("replay changed request")
	}
	// A lost HTTP response reuses exactly the frozen request and idempotency key.
	f = newFixture(t)
	f.registry.createErr = &dnsid.RegistryAPIError{Cause: errors.New("lost")}
	_, err = f.client.Create(context.Background(), "lost")
	requireKind(t, err, Unresolved)
	key = f.document("lost").RegistrationKey
	if _, err := f.client.Create(context.Background(), "lost"); err != nil {
		t.Fatal(err)
	}
	if f.registry.requestID != key {
		t.Fatal("changed replay key")
	}
}

func TestRegistryStates(t *testing.T) {
	for _, state := range []string{"ERROR", "REJECTED", "CANCELLED", "REVOKED", "RETIRED", "VERIFICATION", "VERIFIED", "UNKNOWN"} {
		t.Run(state, func(t *testing.T) {
			f := newFixture(t)
			id, err := f.client.Create(context.Background(), "state")
			if err != nil {
				t.Fatal(err)
			}
			f.registry.status = state
			timeout := 2 * time.Second
			if state == "UNKNOWN" || state == "VERIFICATION" || state == "VERIFIED" {
				timeout = 300 * time.Millisecond
			}
			ctx, cancel := context.WithTimeout(context.Background(), timeout)
			defer cancel()
			_, err = id.Active(ctx)
			kind := WorkflowOutcome
			if state == "REVOKED" || state == "RETIRED" {
				kind = Terminal
			}
			if state == "UNKNOWN" || state == "VERIFICATION" || state == "VERIFIED" {
				kind = Deadline
			}
			requireKind(t, err, kind)
			if id.State() != "" || id.RegistryStatus() != state {
				t.Fatal("registry status was mapped to public state")
			}
			if f.registry.createCalls != 1 || f.registry.prepareCalls != 0 {
				t.Fatal("state triggered replacement or issuance preparation")
			}
		})
	}
}

func TestIssuanceSameBytesAndCompetingWinner(t *testing.T) {
	f := newFixture(t)
	f.registry.submitErr = &dnsid.RegistryAPIError{StatusCode: 503, Code: "TLOG_SUBMISSION_INDETERMINATE"}
	id, err := f.client.Create(context.Background(), "retry")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := id.Active(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(f.registry.submissions) != 2 || !bytes.Equal(f.registry.submissions[0], f.registry.submissions[1]) || f.registry.prepareCalls != 1 {
		t.Fatal("unknown outcome regenerated bytes")
	}
	f = newFixture(t)
	f.registry.competing = true
	id, err = f.client.Create(context.Background(), "winner")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := id.Active(context.Background()); err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(f.registry.acceptedEntry, f.registry.submissions[0]) {
		t.Fatal("fixture did not produce competing signature bytes")
	}
	saved := f.document("winner")
	if !saved.Issuance.Recovered || saved.Issuance.Operation.Submission.State != dnsid.SubmissionStateRejected {
		t.Fatal("winner receipt acknowledged losing bytes")
	}
}

func TestReplicasAndKeyMismatch(t *testing.T) {
	f := newFixture(t)
	id, err := f.client.Create(context.Background(), "replica")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := id.Active(context.Background()); err != nil {
		t.Fatal(err)
	}
	store, err := NewFileFoundryStore(filepath.Join(t.TempDir(), "state"))
	if err != nil {
		t.Fatal(err)
	}
	client := f.newClient(f.operational, store)
	f.store = store
	other, err := client.Create(context.Background(), "replica")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := other.Active(context.Background()); err != nil {
		t.Fatal(err)
	}
	if f.registry.prepareCalls != 1 || len(f.registry.submissions) != 1 {
		t.Fatal("READY replica prepared or submitted another issuance")
	}
	client = f.newClient(dnsid.GenerateEd25519KeyProvider(), f.store)
	_, err = client.Create(context.Background(), "replica")
	requireKind(t, err, KeyMismatch)
	if !strings.Contains(err.Error(), "use this identity's current provider key; run one identity per cloud provider") || strings.Contains(err.Error(), "https://") {
		t.Fatalf("key mismatch lacks self-contained guidance: %v", err)
	}
}

func TestReadinessIsPublicAndBounded(t *testing.T) {
	for _, mode := range []struct {
		name      string
		kind      ErrorKind
		message   string
		publicURL string
	}{
		{name: "missing DNS", kind: Deadline},
		{name: "not ACTIVE", kind: Deadline, publicURL: "https://agent.example/status"},
		{name: "wrong key", kind: KeyMismatch, message: "signed current ku does not serve the provider key", publicURL: "https://agent.example/ku"},
		{name: "wrong log", kind: Integrity, message: "public identity bindings differ from saved publication", publicURL: "https://agent.example/status"},
	} {
		t.Run(mode.name, func(t *testing.T) {
			f := newFixture(t)
			id, err := f.client.Create(context.Background(), "public")
			if err != nil {
				t.Fatal(err)
			}
			switch mode.name {
			case "missing DNS":
				f.dnsMissing = true
			case "not ACTIVE":
				f.setStatus(dnsid.AgentStateProvisioning)
			case "wrong key":
				successor := dnsid.GenerateEd25519KeyProvider()
				f.publish(successor, "governance.example", testLR, dnsid.AgentStateActive)
				// Isolate the provider/ku mismatch from core lifecycle-continuity checks.
				f.log.currentThumb, err = keyThumb(successor.JWK())
				if err != nil {
					t.Fatal(err)
				}
			case "wrong log":
				f.publish(f.operational, "governance.example", "c2sp-tlog:testnet:https://wrong.example#issuance_AAAAAAAAAAAAAAAAAAAAAA", dnsid.AgentStateActive)
			}
			timeout := 10 * time.Second
			if mode.kind == Deadline {
				timeout = time.Second
			}
			ctx, cancel := context.WithTimeout(context.Background(), timeout)
			defer cancel()
			_, err = id.Active(ctx)
			requireKind(t, err, mode.kind)
			if f.dnsCalls == 0 || (mode.publicURL != "" && !slices.Contains(f.publicURLs, mode.publicURL)) {
				t.Fatalf("public readiness was not checked: DNS=%d URLs=%v error=%v", f.dnsCalls, f.publicURLs, err)
			}
			if mode.kind == Deadline && !errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("expected readiness deadline: %v", err)
			}
			if mode.message != "" && !strings.Contains(err.Error(), mode.message) {
				t.Fatalf("wrong readiness failure: %v", err)
			}
			_, err = id.Sign([]byte("data"))
			requirePaused(t, err)
		})
	}
}

func TestIdentityManager_SigningPausedDuringIssuanceSubmission(t *testing.T) {
	f := newFixture(t)
	id, err := f.client.Create(context.Background(), "profile")
	if err != nil {
		t.Fatal(err)
	}
	f.registry.beforeSubmit = func() {
		manager, err := id.IdentityManager()
		if err != nil {
			t.Fatal(err)
		}
		_, err = jose.NewFromIdentityManagerKeyProvider(manager, jose.Config{}).CreateJWT(jose.JWTOptions{Audience: "recipient.example"})
		requirePaused(t, err)
	}
	if _, err := id.Active(context.Background()); err != nil {
		t.Fatal(err)
	}
}
