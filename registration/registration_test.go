package registration

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	dnsid "github.com/dnsid-ai/dnsid-go"
	"github.com/dnsid-ai/dnsid-go/config"
	dnsidlog "github.com/dnsid-ai/dnsid-go/log"
	"github.com/dnsid-ai/dnsid-go/log/c2sptlog"
	"github.com/lestrrat-go/jwx/v3/jwk"
)

type fixture struct {
	t           *testing.T
	store       *FileRegistrationStore
	loaded      config.Loaded
	options     Options
	registry    *fakeRegistry
	entity      dnsid.KeyProvider
	operational jwk.Key
	dns         *fakeDNS
	https       *fakeHTTPS
	reader      *fakeReader
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	directory := t.TempDir()
	if err := os.Chmod(directory, 0700); err != nil {
		t.Fatal(err)
	}
	f := &fixture{t: t, store: NewFileRegistrationStore(directory), entity: dnsid.GenerateEd25519KeyProvider(), dns: &fakeDNS{}, https: &fakeHTTPS{values: map[string]json.RawMessage{}}, reader: &fakeReader{}}
	f.loaded = config.Loaded{Registration: config.ManagedRegistrationConfig{OrganizationID: "11111111-1111-4111-8111-111111111111", GovernanceID: "account.example", EntityKeyURL: "https://account.example/entity.json"}, Registry: config.Registry{RegistryURL: "https://registry.example"}}
	f.loaded.Dnsid.Verification.TrustedEntities = []dnsid.TrustedEntity{} // Deny all in the application.
	logRegistry := dnsidlog.NewLogRegistry()
	if err := logRegistry.Register("c2sp-tlog", func(string) dnsidlog.LogReader { return f.reader }); err != nil {
		t.Fatal(err)
	}
	f.options = Options{Dependencies: config.Dependencies{LogRegistry: logRegistry, DNSResolver: f.dns, HTTPSFetcher: f.https}, TrustReference: "test-trust-v1", PollInterval: time.Millisecond, Timeout: 10 * time.Second}
	f.registry = &fakeRegistry{f: f}
	f.options.RegistryClient = f.registry
	f.registry.registration = &dnsid.AgentRegistration{ID: "issuance_AAAAAAAAAAAAAAAAAAAAAA", Domain: "agent.unrelated.example", PublicationAuthority: dnsid.PublicationAuthorityRegistry, RegistryStatus: "READY", DNSPublished: true, RegistryURL: f.loaded.Registry.RegistryURL, PublicationConfig: dnsid.PublicationConfig{PublishProfile: dnsid.DefaultPublishProfile, GovernanceID: f.loaded.Registration.GovernanceID, EntityKeyURL: f.loaded.Registration.EntityKeyURL, KeyURL: "https://agent.unrelated.example/keys.json", StatusURL: "https://agent.unrelated.example/status.json", LogRef: "c2sp-tlog:testnet:https://log.example#issuance_AAAAAAAAAAAAAAAAAAAAAA"}}
	f.https.set(f.loaded.Registration.EntityKeyURL, keySet(t, f.entity.JWK()))
	f.reader.evidence = dnsidlog.LoggedStateEvidence{LogReference: dnsidlog.LogRef(f.registry.registration.PublicationConfig.LogRef), LoggedState: dnsidlog.AgentStateActive, HistoryStart: "start", HistoryEnd: "end", CompleteThrough: "checkpoint", FreshnessTime: time.Now()}
	return f
}
func testScope() Scope {
	return Scope{RegistryURL: "https://registry.example", OrganizationID: "11111111-1111-4111-8111-111111111111", Name: "billing-agent"}
}
func (f *fixture) scope() Scope {
	return Scope{RegistryURL: f.loaded.Registry.RegistryURL, OrganizationID: f.loaded.Registration.OrganizationID, Name: "billing-agent"}
}
func (f *fixture) path(name string) string {
	s := f.scope()
	key, err := digestStrings(s.RegistryURL, s.OrganizationID, s.Name)
	if err != nil {
		f.t.Fatal(err)
	}
	return filepath.Join(f.store.Directory, key, name)
}
func registrationKey(t *testing.T, state *State) string {
	t.Helper()
	key, _, err := state.replayKeys()
	if err != nil {
		t.Fatal(err)
	}
	return key
}
func issuanceKey(t *testing.T, state *State) string {
	t.Helper()
	_, key, err := state.replayKeys()
	if err != nil {
		t.Fatal(err)
	}
	return key
}
func keySet(t *testing.T, key jwk.Key) json.RawMessage {
	t.Helper()
	data, err := json.Marshal(map[string]any{"keys": []jwk.Key{key}})
	if err != nil {
		t.Fatal(err)
	}
	return data
}
func (f *fixture) run(input *dnsid.AgentRegistrationInput) (*ManagedRegistrationResult, error) {
	result, err := RegisterManagedIdentity(context.Background(), "billing-agent", f.loaded, "secret-token", f.store, input, f.options)
	if err != nil {
		err = fmt.Errorf("%w: %w", err, errors.Unwrap(err))
	}
	return result, err
}
func (f *fixture) state() *State {
	f.t.Helper()
	session, err := f.store.Acquire(context.Background(), f.scope())
	if err != nil {
		f.t.Fatal(err)
	}
	defer session.Close()
	s, err := session.Load(context.Background())
	if err != nil {
		f.t.Fatal(err)
	}
	return s
}
func (f *fixture) update(change func(*State)) {
	f.t.Helper()
	session, err := f.store.Acquire(context.Background(), f.scope())
	if err != nil {
		f.t.Fatal(err)
	}
	defer session.Close()
	s, err := session.Load(context.Background())
	if err != nil {
		f.t.Fatal(err)
	}
	change(s)
	if err := session.Save(context.Background(), s); err != nil {
		f.t.Fatal(err)
	}
}
func (f *fixture) publish(operational jwk.Key) {
	f.t.Helper()
	// Record signing is independent of local operational-key possession.
	provider := dnsid.GenerateEd25519KeyProvider()
	manager, err := dnsid.NewIdentityManager(dnsid.Config{Identity: ptr(identityFrom(f.registry.registration))}, provider, dnsid.WithEntityKeyProvider(f.entity))
	if err != nil {
		f.t.Fatal(err)
	}
	record, err := manager.CreateTXTRecord()
	if err != nil {
		f.t.Fatal(err)
	}
	f.dns.setRecord(record.Serialize())
	f.https.set(f.registry.registration.PublicationConfig.KeyURL, keySet(f.t, operational))
	status, _ := json.Marshal(dnsid.AgentStatus{State: dnsid.AgentStateActive, LastTransitionAt: time.Now().Add(-time.Minute)})
	f.https.set(f.registry.registration.PublicationConfig.StatusURL, status)
}
func ptr[T any](v T) *T { return &v }

type fakeRegistry struct {
	onboarding                               *dnsid.OrganizationOnboardingResponse
	discoveryCalls                           int
	f                                        *fixture
	registration                             *dnsid.AgentRegistration
	preparation                              *dnsid.PreparedRegistryEvent
	registerCalls, prepareCalls, submitCalls int
	requests                                 []*dnsid.AgentRegistrationInput
	keys                                     []string
	entries                                  [][]byte
	createErr                                error
	submitErr                                error
	detailErr                                error
}

func (a *fakeRegistry) GetOrganizationOnboarding(context.Context) (*dnsid.OrganizationOnboardingResponse, error) {
	a.discoveryCalls++
	if a.onboarding == nil {
		return nil, errors.New("onboarding unavailable")
	}
	return clone(a.onboarding)
}
func (a *fakeRegistry) RegisterAgent(_ context.Context, input *dnsid.AgentRegistrationInput, key string) (*dnsid.AgentRegistration, error) {
	a.registerCalls++
	copy, _ := clone(input)
	a.requests = append(a.requests, copy)
	a.keys = append(a.keys, key)
	// The store is locked, so inspect its persisted file directly.
	data, err := os.ReadFile(a.f.path("recovery.json"))
	if err != nil {
		a.f.t.Fatal(err)
	}
	var state State
	if err := json.Unmarshal(data, &state); err != nil {
		a.f.t.Fatal(err)
	}
	if registrationKey(a.f.t, &state) != key || !equal(state.creationInput(), input) || len(state.OperationalKey) == 0 {
		a.f.t.Fatal("creation before durable request/key")
	}
	a.f.operational, err = parsePublic(input.PublicKeyJWK)
	if err != nil {
		a.f.t.Fatal(err)
	}
	if a.createErr != nil {
		return nil, a.createErr
	}
	return clone(a.registration)
}
func (a *fakeRegistry) GetRegistration(context.Context, string) (*dnsid.AgentRegistration, error) {
	if a.detailErr != nil {
		return nil, a.detailErr
	}
	return clone(a.registration)
}
func (a *fakeRegistry) PrepareIssuance(ctx context.Context, domain, key string) (*dnsid.PreparedRegistryEvent, error) {
	a.prepareCalls++
	client, err := c2sptlog.New(a.registration.PublicationConfig.LogRef)
	if err != nil {
		return nil, err
	}
	prepared, err := client.PrepareEvent(dnsidlog.LogEvent{Type: dnsidlog.LogEventIssuance, Domain: domain, GovernanceID: a.registration.PublicationConfig.GovernanceID, Timestamp: time.Now().Add(-time.Minute), InitialEntityPublicKey: a.f.entity.JWK(), InitialOperationalPublicKey: a.f.operational})
	if err != nil {
		return nil, err
	}
	prepared, err = client.SignPreparedEvent(ctx, prepared, c2sptlog.SignerEntity, a.f.entity)
	if err != nil {
		return nil, err
	}
	data, err := prepared.Bytes()
	a.preparation = &dnsid.PreparedRegistryEvent{EntryBytes: data, LogReference: a.registration.PublicationConfig.LogRef}
	return a.preparation, err
}
func (*fakeRegistry) PrepareKeyRotation(context.Context, string, *dnsid.KeyRotationPreparationRequest, string) (*dnsid.PreparedRegistryEvent, error) {
	return nil, errors.New("unexpected rotation")
}
func (a *fakeRegistry) SubmitPreparedEvent(_ context.Context, _ string, entry []byte, key string) (*dnsid.SubmissionResult, error) {
	a.submitCalls++
	a.entries = append(a.entries, append([]byte(nil), entry...))
	data, err := os.ReadFile(a.f.path("recovery.json"))
	if err != nil {
		a.f.t.Fatal(err)
	}
	var state State
	if err := json.Unmarshal(data, &state); err != nil {
		a.f.t.Fatal(err)
	}
	if state.Issuance == nil || !bytes.Equal(entry, state.Issuance.EntryBytes) || key != issuanceKey(a.f.t, &state) {
		a.f.t.Fatal("submission before exact bytes/key persisted")
	}
	if a.submitErr != nil {
		err := a.submitErr
		a.submitErr = nil
		return nil, err
	}
	a.f.publish(a.f.operational)
	a.f.reader.entry = append([]byte(nil), entry...)
	a.f.reader.evidence.HistoryStart = dnsidlog.LogRef(a.registration.PublicationConfig.LogRef + "@0")
	sum := sha256.Sum256(entry)
	kid, _ := a.f.operational.KeyID()
	index := uint64(0)
	return &dnsid.SubmissionResult{State: dnsid.SubmissionStateAccepted, EntryHash: hex.EncodeToString(sum[:]), Index: &index, LogRef: a.registration.PublicationConfig.LogRef + "@0", KeyID: kid}, nil
}

type fakeDNS struct {
	mu     sync.Mutex
	record string
	err    error
	calls  int
}

func (d *fakeDNS) FetchTXT(context.Context, string) ([]dnsid.TXTRecordRData, dnsid.DNSSECState, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.calls++
	if d.err != nil {
		return nil, dnsid.DNSSECStateUnsigned, d.err
	}
	return []dnsid.TXTRecordRData{{Value: d.record, TTL: time.Minute}}, dnsid.DNSSECStateUnsigned, nil
}

func (d *fakeDNS) setRecord(record string) { d.mu.Lock(); defer d.mu.Unlock(); d.record = record }
func (d *fakeDNS) setError(err error)      { d.mu.Lock(); defer d.mu.Unlock(); d.err = err }
func (d *fakeDNS) count() int              { d.mu.Lock(); defer d.mu.Unlock(); return d.calls }

type fakeHTTPS struct {
	mu     sync.Mutex
	values map[string]json.RawMessage
}

func (h *fakeHTTPS) set(url string, data json.RawMessage) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.values[url] = data
}

func (h *fakeHTTPS) FetchJSON(_ context.Context, url string, _ dnsid.FetchOptions) (json.RawMessage, *tls.Certificate, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	data, ok := h.values[url]
	if !ok {
		return nil, nil, fmt.Errorf("unexpected URL %s", url)
	}
	return data, nil, nil
}

type fakeReader struct {
	entry         []byte
	entryErr      error
	evidence      dnsidlog.LoggedStateEvidence
	continuityErr error
	evidenceErr   error
}

func (*fakeReader) Canonical(e dnsidlog.LogEvent) ([]byte, error)                      { return json.Marshal(e) }
func (*fakeReader) VerifyGovernanceRelationship(context.Context, string, string) error { return nil }
func (*fakeReader) KeyTimestamp(context.Context, string, string) (time.Time, error) {
	return time.Now().Add(-time.Minute), nil
}
func (*fakeReader) VerifyBilateralBinding(context.Context, dnsidlog.BilateralBindingInput) (dnsidlog.BilateralBinding, error) {
	return dnsidlog.BilateralBinding{InitialOperationalThumbprint: "original"}, nil
}
func (r *fakeReader) VerifyOperationalContinuity(context.Context, string, string, string) error {
	return r.continuityErr
}
func (r *fakeReader) VerifyNonRevocation(context.Context, string, time.Time) (dnsidlog.LoggedStateEvidence, error) {
	return r.evidence, r.evidenceErr
}
func (*fakeReader) ReadEvent(context.Context, dnsidlog.LogRef) (dnsidlog.LogEvent, error) {
	return dnsidlog.LogEvent{}, nil
}
func (r *fakeReader) ReadEntry(context.Context, dnsidlog.LogRef) ([]byte, error) {
	return append([]byte(nil), r.entry...), r.entryErr
}
func (r *fakeReader) RebuildHistory(context.Context, string) ([]dnsidlog.LogEvent, error) {
	if len(r.entry) == 0 {
		return nil, nil
	}
	event, err := c2sptlog.LogEventFromEntry(r.entry)
	return []dnsidlog.LogEvent{event}, err
}

func TestRegisterManagedIdentity_CompletionResumeAndAcceptance(t *testing.T) {
	f := newFixture(t)
	result, err := f.run(nil)
	if err != nil {
		t.Fatal(err)
	}
	if result.Registration.Domain != "agent.unrelated.example" || result.LoggedStateEvidence.LoggedState != dnsidlog.AgentStateActive {
		t.Fatal("missing public result")
	}
	if !f.state().Complete || f.registry.registerCalls != 1 || f.registry.prepareCalls != 1 || f.registry.submitCalls != 1 {
		t.Fatal("wrong completion ordering")
	}
	_, err = result.Manager.VerifyDomain(context.Background(), result.Registration.Domain)
	var denied *dnsid.VerificationError
	if !errors.As(err, &denied) || denied.Code() != dnsid.VerificationCodeCounterpartyNotAccepted {
		t.Fatalf("application policy changed: %v", err)
	}
	before := f.dns.count()
	if _, err := f.run(nil); err != nil {
		t.Fatal(err)
	}
	if f.registry.registerCalls != 1 || f.registry.prepareCalls != 1 || f.registry.submitCalls != 1 || f.dns.count() <= before {
		t.Fatal("resume did not use fresh evidence without mutations")
	}
	data, _ := os.ReadFile(f.path("recovery.json"))
	if bytes.Contains(data, []byte("secret-token")) || bytes.Contains(data, []byte(`"d":`)) {
		t.Fatal("secret persisted in public recovery")
	}
}

func TestRegisterManagedIdentity_UnknownSubmissionReusesBytes(t *testing.T) {
	f := newFixture(t)
	f.registry.submitErr = &dnsid.RegistryAPIError{Cause: errors.New("connection lost")}
	if _, err := f.run(nil); err != nil {
		t.Fatal(err)
	}
	if len(f.registry.entries) != 2 || !bytes.Equal(f.registry.entries[0], f.registry.entries[1]) || f.registry.prepareCalls != 1 {
		t.Fatal("unknown submission changed bytes or prepared again")
	}
}

func TestRegisterManagedIdentity_UnknownCreationRecovery(t *testing.T) {
	f := newFixture(t)
	f.registry.createErr = &dnsid.RegistryAPIError{Cause: errors.New("connection lost")}
	f.options.Timeout = 2 * time.Second
	if _, err := f.run(nil); err == nil {
		t.Fatal("expected deadline")
	}
	original := f.state()
	if registrationKey(t, original) == "" || len(original.OperationalKey) == 0 {
		t.Fatal("request/key not retained")
	}
	f.registry.createErr = nil
	f.options.Timeout = 10 * time.Second
	if _, err := f.run(nil); err != nil {
		t.Fatal(err)
	}
	current := f.state()
	if registrationKey(t, current) != registrationKey(t, original) || !equal(current.OperationalKey, original.OperationalKey) || current.Input != nil || current.CreationFingerprint != inputFingerprint(original.creationInput()) {
		t.Fatal("replay replaced original request/key")
	}
}

func TestRegisterManagedIdentity_UnknownCreationHasNoReplayExpiration(t *testing.T) {
	f := newFixture(t)
	f.registry.createErr = errors.New("unknown outcome")
	if _, err := f.run(nil); err == nil {
		t.Fatal("expected unknown outcome")
	}
	original := f.state()
	f.registry.createErr = nil
	// No creation timestamp or replay deadline is stored or consulted.
	if _, err := f.run(nil); err != nil {
		t.Fatal(err)
	}
	if f.registry.registerCalls != 2 || !equal(f.registry.requests[0], f.registry.requests[1]) || f.registry.keys[0] != f.registry.keys[1] || registrationKey(t, f.state()) != registrationKey(t, original) {
		t.Fatal("unknown outcome changed original request/key")
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestRegisterManagedIdentity_SDKClientReplaysWithReplacementCredential(t *testing.T) {
	f := newFixture(t)
	f.options.RegistryClient = nil
	var bodies [][]byte
	var keys, credentials []string
	f.options.Dependencies.HTTPSFetcher = nil
	f.options.Dependencies.HTTPClient = &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if r.Method != http.MethodPost || r.URL.String() != "https://registry.example/api/v1/agent" {
			t.Fatalf("unexpected request (organization lookup is not required): %v", r)
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatal(err)
		}
		bodies = append(bodies, body)
		keys = append(keys, r.Header.Get("Idempotency-Key"))
		credentials = append(credentials, r.Header.Get("Authorization"))
		if len(bodies) == 1 {
			return nil, errors.New("response lost after creation")
		}
		// Stand in for the server's cross-organization rejection, without any
		// identity disclosure. This is not a hosted-server integration test.
		return &http.Response{StatusCode: http.StatusForbidden, Body: io.NopCloser(strings.NewReader(`{"error":"FORBIDDEN"}`)), Header: make(http.Header)}, nil
	})}
	// Stop after the first unknown result; then resume with another credential.
	ctx, cancel := context.WithCancel(context.Background())
	transport := f.options.Dependencies.HTTPClient.Transport
	f.options.Dependencies.HTTPClient.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
		response, err := transport.RoundTrip(r)
		cancel()
		return response, err
	})
	if _, err := RegisterManagedIdentity(ctx, "billing-agent", f.loaded, "original-token", f.store, nil, f.options); err == nil {
		t.Fatal("unknown outcome succeeded")
	}
	original := f.state()
	f.options.Dependencies.HTTPClient.Transport = transport
	_, err := RegisterManagedIdentity(context.Background(), "billing-agent", f.loaded, "replacement-token", f.store, nil, f.options)
	var api *dnsid.RegistryAPIError
	if !errors.As(err, &api) || api.StatusCode != http.StatusForbidden {
		t.Fatalf("server authorization error lost: %v", err)
	}
	if len(bodies) != 2 || !bytes.Equal(bodies[0], bodies[1]) || keys[0] == "" || keys[0] != keys[1] || credentials[0] != "Bearer original-token" || credentials[1] != "Bearer replacement-token" {
		t.Fatal("credential replacement changed original request/key")
	}
	if registrationKey(t, f.state()) != registrationKey(t, original) || !equal(f.state().Input, original.Input) || f.registry.prepareCalls != 0 {
		t.Fatal("rejected replay changed recovery or started issuance")
	}
}

func TestRegisterManagedIdentity_StaticFailureBeforeEffects(t *testing.T) {
	for _, name := range []string{"gi", "url", "requested-gi", "private-key", "live"} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			var input *dnsid.AgentRegistrationInput
			switch name {
			case "gi":
				f.loaded.Registration.GovernanceID = "bad://domain"
			case "url":
				f.loaded.Registration.EntityKeyURL = "http://account.example/key"
			case "requested-gi":
				input = &dnsid.AgentRegistrationInput{GovernanceDomain: "other.example"}
			case "private-key":
				input = &dnsid.AgentRegistrationInput{PublicKeyJWK: map[string]string{"kty": "OKP", "crv": "Ed25519", "d": "secret"}}
			case "live":
				input = &dnsid.AgentRegistrationInput{Tier: "live"}
			}
			if _, err := f.run(input); err == nil {
				t.Fatal("invalid setup accepted")
			}
			if f.registry.registerCalls != 0 {
				t.Fatal("invalid input caused network work")
			}
			if entries, err := os.ReadDir(f.store.Directory); err != nil || len(entries) != 0 {
				t.Fatal("invalid input caused storage/key work")
			}
		})
	}
}

func TestRegisterManagedIdentity_BindingsAndCorruptionStopMutations(t *testing.T) {
	for _, name := range []string{"input", "provider", "missing-key", "corrupt-outcome", "corrupt-bytes", "entity-pin"} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			if _, err := f.run(nil); err != nil {
				t.Fatal(err)
			}
			before := f.registry.submitCalls
			var input *dnsid.AgentRegistrationInput
			switch name {
			case "input":
				input = &dnsid.AgentRegistrationInput{Name: "replacement"}
			case "provider":
				f.options.Dependencies.KeyProvider = dnsid.GenerateEd25519KeyProvider()
				f.options.ProviderReference = "another-provider"
			case "missing-key":
				if err := os.Remove(f.path("operational-key.json")); err != nil {
					t.Fatal(err)
				}
			case "corrupt-outcome":
				f.update(func(s *State) { s.Issuance.Submission.EntryHash = "bad" })
			case "corrupt-bytes":
				f.update(func(s *State) { s.Issuance.EntryBytes = []byte("bad") })
			case "entity-pin":
				f.update(func(s *State) { s.EntityThumbprint = "bad" })
			}
			if _, err := f.run(input); err == nil {
				t.Fatal("conflicting/corrupt recovery accepted")
			}
			if f.registry.registerCalls != 1 || f.registry.submitCalls != before {
				t.Fatal("recovery failure caused mutation")
			}
		})
	}
}

func TestRegisterManagedIdentity_RotationUsesHistoricalPublicKeys(t *testing.T) {
	f := newFixture(t)
	if _, err := f.run(nil); err != nil {
		t.Fatal(err)
	}
	keyPath := f.path("operational-key.json")
	provider, err := dnsid.NewLocalKeyProvider(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	old := provider.ListKeyIds()[0]
	next, err := provider.GenerateKey(dnsid.JoseAlgEdDSA)
	if err != nil {
		t.Fatal(err)
	}
	if err := provider.Activate(next); err != nil {
		t.Fatal(err)
	}
	if err := provider.Supersede(old); err != nil {
		t.Fatal(err)
	}
	f.registry.registration.PublicationConfig.KeyURL = "https://agent.unrelated.example/new-key.json"
	f.publish(provider.JWK())
	if provider.JWK(old) != nil {
		t.Fatal("old key remained available after superseding")
	}
	if _, err := f.run(nil); err != nil {
		t.Fatal(err)
	}
	if f.registry.registerCalls != 1 || f.registry.submitCalls != 1 {
		t.Fatal("rotation caused new setup")
	}
	f.reader.continuityErr = errors.New("no authorized rotation continuity")
	if _, err := f.run(nil); err == nil {
		t.Fatal("unexplained rotation accepted")
	}
}

func TestRegisterManagedIdentity_PropagationAndTerminalErrors(t *testing.T) {
	f := newFixture(t)
	f.dns.setError(&net.DNSError{IsNotFound: true, Name: "_dnsid.agent.unrelated.example"})
	f.options.Timeout = 2 * time.Second
	if _, err := f.run(nil); err == nil {
		t.Fatal("READY without DNS succeeded")
	}
	s := f.state()
	if s.Complete || s.Issuance.Submission.State != dnsid.SubmissionStateAccepted {
		t.Fatal("accepted state lost or premature completion")
	}
	f.dns.setError(nil)
	f.options.Timeout = 10 * time.Second
	if _, err := f.run(nil); err != nil {
		t.Fatal(err)
	}
	f.reader.evidenceErr = dnsid.NewVerificationError(dnsid.VerificationCodeTerminalState, false, "retired", nil)
	if _, err := f.run(nil); err == nil {
		t.Fatal("terminal log state accepted")
	}
	if f.registry.submitCalls != 1 {
		t.Fatal("accepted issuance was resubmitted")
	}
}

func TestFileRegistrationStore_ExclusiveAndInterruptedInitialization(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "setup")
	store := NewFileRegistrationStore(directory)
	session, err := store.Acquire(context.Background(), testScope())
	if err != nil {
		t.Fatal(err)
	}
	_, err = store.Acquire(context.Background(), testScope())
	var busy *BusyError
	if !errors.As(err, &busy) {
		t.Fatalf("expected busy: %v", err)
	}
	namedDirectory := session.(*fileSession).directory
	if err := session.Close(); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := store.Acquire(ctx, testScope()); !errors.Is(err, context.Canceled) {
		t.Fatalf("lock ignored cancellation: %v", err)
	}
	if err := os.WriteFile(filepath.Join(namedDirectory, "operational-key.json"), []byte("partial"), 0600); err != nil {
		t.Fatal(err)
	}
	session, err = store.Acquire(context.Background(), testScope())
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	if _, err := session.Load(context.Background()); err == nil {
		t.Fatal("orphan key treated as empty store")
	}
}

func TestRegisterManagedIdentity_InterruptedKeyIntentFailsClosed(t *testing.T) {
	f := newFixture(t)
	f.registry.createErr = errors.New("stop")
	if _, err := f.run(nil); err == nil {
		t.Fatal("expected failure")
	}
	f.update(func(s *State) {
		s.OperationalKey = nil
		s.Phase = "intent"
	})
	if err := os.Remove(f.path("operational-key.json")); err != nil {
		t.Fatal(err)
	}
	before := f.registry.registerCalls
	if _, err := f.run(nil); err == nil {
		t.Fatal("interrupted key creation replaced key")
	}
	if f.registry.registerCalls != before {
		t.Fatal("interrupted key creation caused creation")
	}
}

func TestRegisterManagedIdentity_DetailFailureRetainsCreation(t *testing.T) {
	f := newFixture(t)
	r := f.registry.registration
	f.registry.createErr = &dnsid.RegistrationError{Creation: &dnsid.CreateAgentResponse{ID: r.ID, Domain: r.Domain, PublicationConfig: r.PublicationConfig, OIDCIssuerURL: "https://issuer.example"}, Cause: errors.New("detail unavailable")}
	if _, err := f.run(nil); err == nil {
		t.Fatal("expected detail failure")
	}
	if f.state().Creation.ID != r.ID {
		t.Fatal("immutable creation facts lost")
	}
	f.registry.createErr = nil
	if _, err := f.run(nil); err != nil {
		t.Fatal(err)
	}
	if f.registry.registerCalls != 1 || f.state().Registration.OIDCIssuerURL != "https://issuer.example" {
		t.Fatal("known identity reallocated or issuer lost")
	}
}

func TestRegisterManagedIdentity_PreparationRecoveryDoesNotPrepareAgain(t *testing.T) {
	f := newFixture(t)
	if _, err := f.run(nil); err != nil {
		t.Fatal(err)
	}
	f.update(func(s *State) {
		s.Complete = false
		s.IssuanceCompacted = false
		s.Issuance.IdempotencyKey = issuanceKey(t, s)
		s.Issuance.Prepared = f.registry.preparation
		s.Issuance.Complete = false
		s.Issuance.ActivationBlocked = true
		s.Issuance.EntryBytes = nil
		s.Issuance.EntryHash = ""
		s.Issuance.Submission = nil
	})
	if _, err := f.run(nil); err != nil {
		t.Fatal(err)
	}
	if f.registry.prepareCalls != 1 || f.registry.submitCalls != 2 || !bytes.Equal(f.registry.entries[0], f.registry.entries[1]) {
		t.Fatal("saved preparation changed or was requested again")
	}
}

func TestRetry_NetworkTimeout(t *testing.T) {
	if !transient(fmt.Errorf("request: %w", context.DeadlineExceeded)) {
		t.Fatal("network timeout not retryable")
	}
	if transient(&net.OpError{Op: "dial", Err: errors.New("permanent failure")}) {
		t.Fatal("permanent network failure is retryable")
	}
}

func TestRetry_NarrowDNSAbsence(t *testing.T) {
	missing := dnsid.NewVerificationError(dnsid.VerificationCodeRecordInvalid, false, "missing", dnsid.ErrIdentityRecordNotFound)
	if !transient(missing) {
		t.Fatal("DNS absence not retryable")
	}
	for _, code := range []dnsid.VerificationCode{dnsid.VerificationCodeRecordInvalid, dnsid.VerificationCodeSignatureInvalid, dnsid.VerificationCodeCounterpartyNotAccepted, dnsid.VerificationCodeLogError} {
		if transient(dnsid.NewVerificationError(code, true, "bad", nil)) {
			t.Fatalf("broad retry accepted %s", code)
		}
	}
}

func TestRegisterManagedIdentity_UntrustedLogStopsCountersigning(t *testing.T) {
	f := newFixture(t)
	f.options.Dependencies.LogRegistry = nil
	f.options.TrustReference = ""
	f.loaded.LogTrust = config.LogTrust{Managed: true}
	_, err := f.run(nil)
	var failure *Error
	if !errors.As(err, &failure) || failure.Code != "log_binding" {
		t.Fatalf("untrusted assigned log accepted: %v", err)
	}
	if f.registry.prepareCalls != 0 || f.registry.submitCalls != 0 {
		t.Fatal("untrusted assigned log received operational consent")
	}
}

func TestRegisterManagedIdentity_ConfigSourcesAndCredentialReplacement(t *testing.T) {
	f := newFixture(t)
	if _, err := f.run(nil); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "deployment.json")
	document := `{"dnsid":{"verification":{"trustedEntities":[]}},"registry":{"registryUrl":"https://registry.example"},"registration":{"organizationId":"11111111-1111-4111-8111-111111111111","governanceId":"account.example","entityKeyUrl":"https://account.example/entity.json"}}`
	if err := os.WriteFile(path, []byte(document), 0600); err != nil {
		t.Fatal(err)
	}
	loaded, err := config.LoadDeploymentFile(path)
	if err != nil {
		t.Fatal(err)
	}
	f.loaded = loaded
	if _, err := f.run(nil); err != nil {
		t.Fatal(err)
	}
	environment, err := config.LoadEnvironment(func(name string) string {
		if name == "DNSID_REGISTRY_URL" {
			return loaded.Registry.RegistryURL
		}
		return ""
	})
	if err != nil {
		t.Fatal(err)
	}
	environment = config.Merge(environment, config.Loaded{Registration: loaded.Registration, Dnsid: dnsid.Config{Verification: dnsid.VerificationConfig{TrustedEntities: []dnsid.TrustedEntity{}}}})
	if _, err := RegisterManagedIdentity(context.Background(), "billing-agent", environment, "replacement-token", f.store, nil, f.options); err != nil {
		t.Fatal(err)
	}
	if f.registry.registerCalls != 1 || f.registry.submitCalls != 1 {
		t.Fatal("equivalent sources or credential replacement allocated another identity")
	}
}

func TestRegisterManagedIdentity_PrivateExtrasRejectedBeforeEffects(t *testing.T) {
	f := newFixture(t)
	raw, _ := json.Marshal(f.entity.JWK())
	var fields map[string]any
	json.Unmarshal(raw, &fields)
	fields["q"] = "private-material"
	if _, err := f.run(&dnsid.AgentRegistrationInput{PublicKeyJWK: fields}); err == nil {
		t.Fatal("private extra JWK member accepted")
	}
	if f.registry.registerCalls != 0 {
		t.Fatal("private material reached authenticated adapter")
	}
	if entries, err := os.ReadDir(f.store.Directory); err != nil || len(entries) != 0 {
		t.Fatal("private material persisted")
	}
}
