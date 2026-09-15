package dnsid

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	dnsidlog "github.com/dnsid-ai/dnsid-go/log"
)

type coalescingDNSResolver struct {
	mu        sync.Mutex
	records   map[string][]TXTRecordRData
	calls     map[string]int
	blockName string
	entered   chan struct{}
	release   chan struct{}
	failFirst bool
	once      sync.Once
}

func (r *coalescingDNSResolver) FetchTXT(ctx context.Context, name string) ([]TXTRecordRData, DNSSECState, error) {
	r.mu.Lock()
	if r.calls == nil {
		r.calls = make(map[string]int)
	}
	r.calls[name]++
	call := r.calls[name]
	records := r.records[name]
	r.mu.Unlock()

	if name == r.blockName && call == 1 {
		r.once.Do(func() { close(r.entered) })
		select {
		case <-r.release:
		case <-ctx.Done():
			return nil, DNSSECStateUnsigned, ctx.Err()
		}
	}
	if r.failFirst && call == 1 {
		return nil, DNSSECStateUnsigned, errors.New("DNS unavailable")
	}
	return records, DNSSECStateUnsigned, nil
}

func (r *coalescingDNSResolver) callCount(name string) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.calls[name]
}

type coalescingHTTPSFetcher struct {
	mu         sync.Mutex
	responses  map[string]json.RawMessage
	certs      map[string]*tls.Certificate
	calls      map[string]int
	blockURL   string
	entered    chan struct{}
	release    chan struct{}
	firstError error
	failures   map[string]error
	once       sync.Once
}

func (f *coalescingHTTPSFetcher) FetchJSON(ctx context.Context, rawURL string, _ FetchOptions) (json.RawMessage, *tls.Certificate, error) {
	f.mu.Lock()
	if f.calls == nil {
		f.calls = make(map[string]int)
	}
	f.calls[rawURL]++
	call := f.calls[rawURL]
	response := f.responses[rawURL]
	cert := f.certs[rawURL]
	failure := f.failures[rawURL]
	f.mu.Unlock()

	if rawURL == f.blockURL && call == 1 {
		f.once.Do(func() { close(f.entered) })
		select {
		case <-f.release:
		case <-ctx.Done():
			return nil, nil, ctx.Err()
		}
	}
	if call == 1 && f.firstError != nil && rawURL == f.blockURL {
		return nil, nil, f.firstError
	}
	return response, cert, failure
}

func (f *coalescingHTTPSFetcher) callCount(rawURL string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls[rawURL]
}

type controlledHTTPSFetcher struct {
	base      HTTPSFetcher
	gates     map[string]<-chan struct{}
	entered   map[string]chan struct{}
	cancelled map[string]chan struct{}
}

func (f *controlledHTTPSFetcher) FetchJSON(ctx context.Context, rawURL string, opts FetchOptions) (json.RawMessage, *tls.Certificate, error) {
	if entered := f.entered[rawURL]; entered != nil {
		close(entered)
	}
	if gate := f.gates[rawURL]; gate != nil {
		select {
		case <-gate:
		case <-ctx.Done():
			if cancelled := f.cancelled[rawURL]; cancelled != nil {
				close(cancelled)
			}
			return nil, nil, ctx.Err()
		}
	}
	return f.base.FetchJSON(ctx, rawURL, opts)
}

type coalescingLogReader struct {
	bindings       atomic.Int32
	continuities   atomic.Int32
	nonRevocations atomic.Int32
}

func (r *coalescingLogReader) Canonical(event dnsidlog.LogEvent) ([]byte, error) {
	return []byte(event.Type), nil
}
func (r *coalescingLogReader) KeyTimestamp(context.Context, string, string) (time.Time, error) {
	return time.Now(), nil
}
func (r *coalescingLogReader) VerifyBilateralBinding(context.Context, dnsidlog.BilateralBindingInput) (dnsidlog.BilateralBinding, error) {
	r.bindings.Add(1)
	return dnsidlog.BilateralBinding{InitialOperationalThumbprint: "initial"}, nil
}
func (r *coalescingLogReader) VerifyOperationalContinuity(context.Context, string, string, string) error {
	r.continuities.Add(1)
	return nil
}
func (r *coalescingLogReader) VerifyNonRevocation(context.Context, string, time.Time) (dnsidlog.LoggedStateEvidence, error) {
	r.nonRevocations.Add(1)
	return dnsidlog.LoggedStateEvidence{}, nil
}
func (r *coalescingLogReader) ReadEvent(context.Context, dnsidlog.LogRef) (dnsidlog.LogEvent, error) {
	return dnsidlog.LogEvent{}, nil
}
func (r *coalescingLogReader) RebuildHistory(context.Context, string) ([]dnsidlog.LogEvent, error) {
	return nil, nil
}

type coalescingFixture struct {
	manager *IdentityManager
	dns     *coalescingDNSResolver
	https   *coalescingHTTPSFetcher
	reader  *coalescingLogReader
	records map[string]*TXTRecord
}

func newCoalescingFixture(t *testing.T, domains []string, flags []PolicyFlag) *coalescingFixture {
	t.Helper()
	dns := &coalescingDNSResolver{records: make(map[string][]TXTRecordRData), calls: make(map[string]int)}
	https := &coalescingHTTPSFetcher{responses: make(map[string]json.RawMessage), calls: make(map[string]int)}
	records := make(map[string]*TXTRecord)
	for _, domain := range domains {
		operational := GenerateES256KeyProvider()
		entity := GenerateES256KeyProvider()
		publisher, err := NewIdentityManager(Config{Identity: &IdentityConfig{
			Domain: domain, GovernanceID: domain, LogRef: "testlog:agent",
			StatusURL: "https://" + domain + "/status", KeyURL: "https://" + domain + "/ku.json",
			EntityKeyURL: "https://" + domain + "/ek.json", PolicyFlags: flags,
		}}, operational, WithEntityKeyProvider(entity))
		if err != nil {
			t.Fatalf("NewIdentityManager publisher: %v", err)
		}
		record, err := publisher.CreateTXTRecord()
		if err != nil {
			t.Fatalf("CreateTXTRecord: %v", err)
		}
		ek, err := json.Marshal(mustJWKSet(t, entity.JWK()))
		if err != nil {
			t.Fatal(err)
		}
		ku, err := json.Marshal(mustJWKSet(t, operational.JWK()))
		if err != nil {
			t.Fatal(err)
		}
		dns.records["_dnsid."+domain] = []TXTRecordRData{{Value: record.Serialize(), TTL: time.Hour}}
		https.responses[record.EntityKeyURI] = ek
		https.responses[record.KeyURI] = ku
		https.responses[record.StatusURI] = json.RawMessage(freshStatus())
		records[domain] = record
	}
	reader := &coalescingLogReader{}
	registry := dnsidlog.NewLogRegistry()
	if err := registry.Register("testlog", func(string) dnsidlog.LogReader { return reader }); err != nil {
		t.Fatal(err)
	}
	manager, err := NewVerifier(WithDNSResolver(dns), WithHTTPSFetcher(https), WithLogRegistry(registry))
	if err != nil {
		t.Fatal(err)
	}
	return &coalescingFixture{manager: manager, dns: dns, https: https, reader: reader, records: records}
}

func waitForJoins(manager *IdentityManager, count int, refresh bool) chan struct{} {
	joined := make(chan struct{}, count)
	manager.inFlightHook = func(_ string, gotRefresh bool) {
		if gotRefresh == refresh {
			joined <- struct{}{}
		}
	}
	return joined
}

func awaitN(ch <-chan struct{}, count int) {
	for range count {
		<-ch
	}
}

func TestCoalesceVerification_PreservesInitiatingContextValues(t *testing.T) {
	type contextKey struct{}
	ctx := context.WithValue(context.Background(), contextKey{}, "value")
	manager, err := NewVerifier()
	if err != nil {
		t.Fatal(err)
	}
	_, err = manager.coalesceVerification(ctx, "agent.example.com", false, func(sharedCtx context.Context) (*VerifiedDomain, error) {
		if sharedCtx.Value(contextKey{}) != "value" {
			return nil, errors.New("shared context lost initiating value")
		}
		return &VerifiedDomain{}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestCoalesceVerification_CoalescesDifferentContextValues(t *testing.T) {
	type contextKey struct{}
	manager, err := NewVerifier()
	if err != nil {
		t.Fatal(err)
	}
	joined := waitForJoins(manager, 2, false)
	started, release := make(chan struct{}), make(chan struct{})
	results := make(chan *VerifiedDomain, 2)
	errs := make(chan error, 2)
	go func() {
		vd, err := manager.coalesceVerification(context.WithValue(context.Background(), contextKey{}, "first"), "agent.example.com", false, func(sharedCtx context.Context) (*VerifiedDomain, error) {
			close(started)
			<-release
			return &VerifiedDomain{domain: sharedCtx.Value(contextKey{}).(string)}, nil
		})
		results <- vd
		errs <- err
	}()
	<-started
	go func() {
		vd, err := manager.coalesceVerification(context.WithValue(context.Background(), contextKey{}, "second"), "agent.example.com", false, func(context.Context) (*VerifiedDomain, error) {
			return nil, errors.New("duplicate work")
		})
		results <- vd
		errs <- err
	}()
	awaitN(joined, 2)
	close(release)

	for range 2 {
		vd, err := <-results, <-errs
		if err != nil || vd.domain != "first" {
			t.Fatalf("result = %#v, %v; want shared first caller result", vd, err)
		}
	}
}

func TestVerifyDomain_CoalescesConcurrentColdCalls(t *testing.T) {
	const domain = "agent.example.com"
	fixture := newCoalescingFixture(t, []string{domain}, []PolicyFlag{PolicyFlagLogCheck})
	fixture.dns.blockName = "_dnsid." + domain
	fixture.dns.entered = make(chan struct{})
	fixture.dns.release = make(chan struct{})
	joined := waitForJoins(fixture.manager, 32, false)

	start := make(chan struct{})
	errs := make(chan error, 32)
	for range 32 {
		go func() {
			<-start
			_, err := fixture.manager.VerifyDomain(context.Background(), "AGENT.EXAMPLE.COM.")
			errs <- err
		}()
	}
	close(start)
	<-fixture.dns.entered
	awaitN(joined, 32)
	close(fixture.dns.release)
	for range 32 {
		if err := <-errs; err != nil {
			t.Fatalf("VerifyDomain: %v", err)
		}
	}

	if got := fixture.dns.callCount("_dnsid." + domain); got != 1 {
		t.Fatalf("DNS calls = %d, want 1", got)
	}
	record := fixture.records[domain]
	for _, endpoint := range []string{record.EntityKeyURI, record.KeyURI, record.StatusURI} {
		if got := fixture.https.callCount(endpoint); got != 1 {
			t.Fatalf("%s calls = %d, want 1", endpoint, got)
		}
	}
	if got := fixture.reader.bindings.Load(); got != 1 {
		t.Fatalf("lifecycle binding calls = %d, want 1", got)
	}
	if got := fixture.reader.continuities.Load(); got != 1 {
		t.Fatalf("lifecycle continuity calls = %d, want 1", got)
	}
	if got := fixture.reader.nonRevocations.Load(); got != 0 {
		t.Fatalf("VerifyDomain performed %d operation-level log checks", got)
	}
}

func TestVerifyDomain_PostSignatureWorkOverlapsWithoutFollowingBeforeAuthentication(t *testing.T) {
	const domain = "agent.example.com"
	fixture := newCoalescingFixture(t, []string{domain}, nil)
	record := fixture.records[domain]
	ekRelease, kuRelease, statusRelease := make(chan struct{}), make(chan struct{}), make(chan struct{})
	ekEntered, kuEntered, statusEntered := make(chan struct{}), make(chan struct{}), make(chan struct{})
	fixture.manager.https = &controlledHTTPSFetcher{
		base: fixture.https,
		gates: map[string]<-chan struct{}{
			record.EntityKeyURI: ekRelease,
			record.KeyURI:       kuRelease,
			record.StatusURI:    statusRelease,
		},
		entered: map[string]chan struct{}{
			record.EntityKeyURI: ekEntered,
			record.KeyURI:       kuEntered,
			record.StatusURI:    statusEntered,
		},
	}

	result := make(chan error, 1)
	go func() {
		_, err := fixture.manager.VerifyDomain(context.Background(), domain)
		result <- err
	}()
	<-ekEntered
	select {
	case <-kuEntered:
		t.Fatal("ku was fetched before sg authentication completed")
	case <-statusEntered:
		t.Fatal("su was fetched before sg authentication completed")
	default:
	}
	close(ekRelease)
	<-kuEntered
	<-statusEntered
	close(kuRelease)
	close(statusRelease)
	if err := <-result; err != nil {
		t.Fatalf("VerifyDomain: %v", err)
	}
}

func TestVerifyDomain_PostSignatureFailureCancelsSiblingWork(t *testing.T) {
	const domain = "agent.example.com"
	fixture := newCoalescingFixture(t, []string{domain}, nil)
	record := fixture.records[domain]
	kuRelease, statusRelease := make(chan struct{}), make(chan struct{})
	kuEntered, statusEntered, kuCancelled := make(chan struct{}), make(chan struct{}), make(chan struct{})
	fixture.https.responses[record.StatusURI] = json.RawMessage(fmt.Sprintf(`{"state":"RETIRED","lastTransitionAt":%q}`, time.Now().Add(-time.Minute).UTC().Format(time.RFC3339Nano)))
	fixture.manager.https = &controlledHTTPSFetcher{
		base: fixture.https,
		gates: map[string]<-chan struct{}{
			record.KeyURI:    kuRelease,
			record.StatusURI: statusRelease,
		},
		entered: map[string]chan struct{}{
			record.KeyURI:    kuEntered,
			record.StatusURI: statusEntered,
		},
		cancelled: map[string]chan struct{}{record.KeyURI: kuCancelled},
	}

	result := make(chan error, 1)
	go func() {
		_, err := fixture.manager.VerifyDomain(context.Background(), domain)
		result <- err
	}()
	<-kuEntered
	<-statusEntered
	close(statusRelease)
	<-kuCancelled
	var verificationErr *VerificationError
	if err := <-result; !errors.As(err, &verificationErr) || verificationErr.Code() != VerificationCodeStatusNotActive {
		t.Fatalf("VerifyDomain error = %v, want status_not_active", err)
	}
}

func TestVerifyDomain_ConcurrentFailuresPreferIdentityError(t *testing.T) {
	const domain = "agent.example.com"
	fixture := newCoalescingFixture(t, []string{domain}, nil)
	record := fixture.records[domain]
	fixture.https.failures = map[string]error{
		record.KeyURI:    NewValidationError("invalid ku", nil),
		record.StatusURI: errors.New("status unavailable"),
	}

	_, err := fixture.manager.VerifyDomain(context.Background(), domain)
	var verificationErr *VerificationError
	if !errors.As(err, &verificationErr) || verificationErr.Code() != VerificationCodeRecordInvalid {
		t.Fatalf("VerifyDomain error = %v, want record_invalid", err)
	}
}

func TestVerifyDomain_StatusCertificateDoesNotBoundExpiry(t *testing.T) {
	const domain = "agent.example.com"
	fixture := newCoalescingFixture(t, []string{domain}, nil)
	record := fixture.records[domain]
	fixture.https.certs = map[string]*tls.Certificate{
		record.StatusURI: {Leaf: &x509.Certificate{NotAfter: time.Now().Add(time.Minute)}},
	}

	for range 2 { // initial verification, then status refresh
		vd, err := fixture.manager.VerifyDomain(context.Background(), domain)
		if err != nil {
			t.Fatal(err)
		}
		if want := vd.dnsExpiresAt; !vd.Expiry().Equal(want) || want.After(vd.verifiedAt.Add(time.Hour)) {
			t.Fatalf("Expiry = %v, want DNS TTL deadline %v", vd.Expiry(), want)
		}
	}
}

func cachedManagerForStatus(t *testing.T, domains ...string) (*IdentityManager, *coalescingHTTPSFetcher, map[string]string) {
	t.Helper()
	fetcher := &coalescingHTTPSFetcher{responses: make(map[string]json.RawMessage), calls: make(map[string]int)}
	manager, err := NewIdentityManager(Config{}, nil, WithHTTPSFetcher(fetcher))
	if err != nil {
		t.Fatal(err)
	}
	urls := make(map[string]string)
	for _, domain := range domains {
		statusURL := "https://" + domain + "/status"
		urls[domain] = statusURL
		fetcher.responses[statusURL] = json.RawMessage(freshStatus())
		manager.cache.put(&VerifiedDomain{
			domain: domain, record: &TXTRecord{StatusURI: statusURL},
			status:     &AgentStatus{State: AgentStateActive, LastTransitionAt: time.Now().Add(-time.Hour)},
			verifiedAt: time.Now(), lastStatusCheckAt: time.Now().Add(-time.Hour),
			dnsTTL: time.Hour, expiry: time.Now().Add(time.Hour),
			dnsExpiresAt: time.Now().Add(time.Hour),
		}, manager)
	}
	return manager, fetcher, urls
}

func TestVerifyDomain_CoalescesStatusRefreshAndIntervalZeroRefetches(t *testing.T) {
	const domain = "agent.example.com"
	manager, fetcher, urls := cachedManagerForStatus(t, domain)
	fetcher.blockURL = urls[domain]
	fetcher.entered = make(chan struct{})
	fetcher.release = make(chan struct{})
	joined := waitForJoins(manager, 32, true)

	errs := make(chan error, 32)
	for range 32 {
		go func() {
			_, err := manager.VerifyDomain(context.Background(), domain)
			errs <- err
		}()
	}
	<-fetcher.entered
	awaitN(joined, 32)
	close(fetcher.release)
	for range 32 {
		if err := <-errs; err != nil {
			t.Fatalf("VerifyDomain refresh: %v", err)
		}
	}
	if got := fetcher.callCount(urls[domain]); got != 1 {
		t.Fatalf("status calls = %d, want 1", got)
	}

	if _, err := manager.VerifyDomain(context.Background(), domain); err != nil {
		t.Fatalf("sequential VerifyDomain: %v", err)
	}
	if got := fetcher.callCount(urls[domain]); got != 2 {
		t.Fatalf("status calls after sequential interval-zero call = %d, want 2", got)
	}
}

func TestVerifyDomain_SharedRefreshFailureRetriesWithoutStaleSuccess(t *testing.T) {
	const domain = "agent.example.com"
	manager, fetcher, urls := cachedManagerForStatus(t, domain)
	fetcher.blockURL = urls[domain]
	fetcher.entered = make(chan struct{})
	fetcher.release = make(chan struct{})
	fetcher.firstError = errors.New("status unavailable")
	joined := waitForJoins(manager, 32, true)

	errs := make(chan error, 32)
	for range 32 {
		go func() {
			_, err := manager.VerifyDomain(context.Background(), domain)
			errs <- err
		}()
	}
	<-fetcher.entered
	awaitN(joined, 32)
	close(fetcher.release)
	for range 32 {
		var verificationErr *VerificationError
		if err := <-errs; !errors.As(err, &verificationErr) || verificationErr.Code() != VerificationCodeStatusUnavailable {
			t.Fatalf("shared refresh error = %v, want status_unavailable", err)
		}
	}
	if _, err := manager.VerifyDomain(context.Background(), domain); err != nil {
		t.Fatalf("retry VerifyDomain: %v", err)
	}
	if got := fetcher.callCount(urls[domain]); got != 2 {
		t.Fatalf("status calls after retry = %d, want 2", got)
	}
}

func TestVerifyDomain_SharedColdFailureRetries(t *testing.T) {
	const domain = "agent.example.com"
	fixture := newCoalescingFixture(t, []string{domain}, nil)
	fixture.dns.blockName = "_dnsid." + domain
	fixture.dns.entered = make(chan struct{})
	fixture.dns.release = make(chan struct{})
	fixture.dns.failFirst = true
	joined := waitForJoins(fixture.manager, 32, false)

	errs := make(chan error, 32)
	for range 32 {
		go func() {
			_, err := fixture.manager.VerifyDomain(context.Background(), domain)
			errs <- err
		}()
	}
	<-fixture.dns.entered
	awaitN(joined, 32)
	close(fixture.dns.release)
	for range 32 {
		var verificationErr *VerificationError
		if err := <-errs; !errors.As(err, &verificationErr) || verificationErr.Code() != VerificationCodeDNSResolution {
			t.Fatalf("shared cold error = %v, want dns_resolution", err)
		}
	}
	if _, err := fixture.manager.VerifyDomain(context.Background(), domain); err != nil {
		t.Fatalf("retry VerifyDomain: %v", err)
	}
	if got := fixture.dns.callCount("_dnsid." + domain); got != 2 {
		t.Fatalf("DNS calls after retry = %d, want 2", got)
	}
}

func TestVerifyDomain_MixedMTLSCallersShareReusableWork(t *testing.T) {
	const domain = "agent.example.com"
	fixture := newCoalescingFixture(t, []string{domain}, []PolicyFlag{PolicyFlagMTLS})
	fixture.dns.blockName = "_dnsid." + domain
	fixture.dns.entered = make(chan struct{})
	fixture.dns.release = make(chan struct{})
	joined := waitForJoins(fixture.manager, 2, false)

	validResult := make(chan error, 1)
	invalidResult := make(chan error, 1)
	go func() {
		_, err := fixture.manager.VerifyDomainWithOptions(context.Background(), domain, VerifyDomainOpts{
			VerifiedPeerCertificateChains: [][]*x509.Certificate{{{DNSNames: []string{domain}}}},
		})
		validResult <- err
	}()
	<-fixture.dns.entered
	go func() {
		_, err := fixture.manager.VerifyDomainWithOptions(context.Background(), domain, VerifyDomainOpts{})
		invalidResult <- err
	}()
	awaitN(joined, 2)
	close(fixture.dns.release)

	if err := <-validResult; err != nil {
		t.Fatalf("valid mTLS caller: %v", err)
	}
	var verificationErr *VerificationError
	if err := <-invalidResult; !errors.As(err, &verificationErr) || verificationErr.Code() != VerificationCodeTLSError {
		t.Fatalf("invalid mTLS caller error = %v, want tls_error", err)
	}
	if got := fixture.dns.callCount("_dnsid." + domain); got != 1 {
		t.Fatalf("DNS calls = %d, want 1", got)
	}
}

func TestVerifyDomain_IndependentContextCancellationDoesNotCancelSharedWork(t *testing.T) {
	const domain = "agent.example.com"
	fixture := newCoalescingFixture(t, []string{domain}, nil)
	fixture.dns.blockName = "_dnsid." + domain
	fixture.dns.entered = make(chan struct{})
	fixture.dns.release = make(chan struct{})
	joined := waitForJoins(fixture.manager, 2, false)

	ctx, cancel := context.WithCancel(context.Background())
	cancelledResult := make(chan error, 1)
	successResult := make(chan error, 1)
	go func() {
		_, err := fixture.manager.VerifyDomain(ctx, domain)
		cancelledResult <- err
	}()
	<-fixture.dns.entered
	go func() {
		_, err := fixture.manager.VerifyDomain(context.Background(), domain)
		successResult <- err
	}()
	awaitN(joined, 2)
	cancel()
	select {
	case err := <-cancelledResult:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("cancelled caller error = %v, want context.Canceled", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("cancelled caller did not return promptly")
	}
	close(fixture.dns.release)
	if err := <-successResult; err != nil {
		t.Fatalf("independent caller: %v", err)
	}
	if got := fixture.dns.callCount("_dnsid." + domain); got != 1 {
		t.Fatalf("DNS calls = %d, want 1 shared call", got)
	}
}

func TestVerifyDomain_DifferentDomainsProgressIndependently(t *testing.T) {
	const blockedDomain = "blocked.example.com"
	const freeDomain = "free.example.com"
	fixture := newCoalescingFixture(t, []string{blockedDomain, freeDomain}, nil)
	fixture.dns.blockName = "_dnsid." + blockedDomain
	fixture.dns.entered = make(chan struct{})
	fixture.dns.release = make(chan struct{})

	blockedResult := make(chan error, 1)
	go func() {
		_, err := fixture.manager.VerifyDomain(context.Background(), blockedDomain)
		blockedResult <- err
	}()
	<-fixture.dns.entered

	freeResult := make(chan error, 1)
	go func() {
		_, err := fixture.manager.VerifyDomain(context.Background(), freeDomain)
		freeResult <- err
	}()
	select {
	case err := <-freeResult:
		if err != nil {
			t.Fatalf("free domain: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("free domain blocked behind another domain")
	}
	close(fixture.dns.release)
	if err := <-blockedResult; err != nil {
		t.Fatalf("blocked domain: %v", err)
	}
}

func TestVerifyDomain_NonActiveRefreshEvictsCache(t *testing.T) {
	const domain = "agent.example.com"
	manager, fetcher, urls := cachedManagerForStatus(t, domain)
	fetcher.responses[urls[domain]] = json.RawMessage(fmt.Sprintf(`{"state":"RETIRED","lastTransitionAt":%q}`, time.Now().UTC().Format(time.RFC3339Nano)))

	_, err := manager.VerifyDomain(context.Background(), domain)
	var verificationErr *VerificationError
	if !errors.As(err, &verificationErr) || verificationErr.Code() != VerificationCodeStatusNotActive {
		t.Fatalf("VerifyDomain error = %v, want status_not_active", err)
	}
	if got := manager.cachedDomain(domain); got != nil {
		t.Fatal("non-ACTIVE status left a positive cache entry")
	}
}
