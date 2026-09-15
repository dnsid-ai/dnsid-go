package dnsid

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"testing"
	"time"

	dnsidlog "github.com/dnsid-ai/dnsid-go/log"
)

func TestIdentityCache_SeparatesVerificationContexts(t *testing.T) {
	const domain = "agent.example"
	f := newCoalescingFixture(t, []string{domain}, nil)
	if _, err := f.manager.VerifyDomain(context.Background(), domain); err != nil {
		t.Fatal(err)
	}
	strict, err := NewIdentityManager(Config{Verification: VerificationConfig{DNSSECMode: DNSSECModeRequired}}, nil, WithIdentityCache(f.manager.cache), WithDNSResolver(f.dns), WithHTTPSFetcher(f.https), WithLogRegistry(f.manager.logRegistry))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := strict.VerifyDomain(context.Background(), domain); err == nil {
		t.Fatal("strict manager consumed another context's cache")
	}
	if got := f.dns.callCount("_dnsid." + domain); got != 2 {
		t.Fatalf("DNS calls = %d", got)
	}
	vd := f.manager.cachedDomain(domain)
	if vd == nil {
		t.Fatal("other namespace lost its evidence")
	}
	// Public cache operations use one standalone namespace, even for manager results.
	cache := f.manager.cache
	cache.Put(vd)
	if cache.Get(domain) == nil {
		t.Fatal("public Put/Get did not round-trip")
	}
	cache.Evict(domain)
	if cache.Get(domain) != nil || f.manager.cachedDomain(domain) == nil {
		t.Fatal("public eviction crossed namespaces")
	}
}

func TestVerifyDomain_DNSExpiryStartsAtAcquisition(t *testing.T) {
	const domain = "agent.example"
	f := newCoalescingFixture(t, []string{domain}, nil)
	f.dns.records["_dnsid."+domain][0].TTL = 10 * time.Millisecond
	f.https.blockURL = f.records[domain].EntityKeyURI
	f.https.entered, f.https.release = make(chan struct{}), make(chan struct{})
	result := make(chan error, 1)
	go func() { _, err := f.manager.VerifyDomain(context.Background(), domain); result <- err }()
	<-f.https.entered
	time.Sleep(20 * time.Millisecond)
	close(f.https.release)
	var ve *VerificationError
	if err := <-result; !errors.As(err, &ve) || ve.Code() != VerificationCodeDNSResolution {
		t.Fatalf("expired lookup = %v", err)
	}
	if f.manager.cachedDomain(domain) != nil {
		t.Fatal("expired DNS evidence cached")
	}
}

func TestVerifyDomain_StatusRefreshCannotReviveExpiredEvidence(t *testing.T) {
	const domain = "agent.example"
	m, f, urls := cachedManagerForStatus(t, domain)
	vd := m.cachedDomain(domain)
	vd.dnsExpiresAt, vd.expiry = time.Now().Add(10*time.Millisecond), time.Now().Add(10*time.Millisecond)
	m.cache.put(vd, m)
	f.blockURL = urls[domain]
	f.entered, f.release = make(chan struct{}), make(chan struct{})
	result := make(chan error, 1)
	go func() { _, err := m.VerifyDomain(context.Background(), domain); result <- err }()
	<-f.entered
	time.Sleep(20 * time.Millisecond)
	close(f.release)
	if err := <-result; err == nil {
		t.Fatal("expired refresh succeeded")
	}
	if m.cachedDomain(domain) != nil {
		t.Fatal("expired evidence reinserted")
	}
}

func TestVerifyDomain_ZeroTTLIsSingleUseAndStillChecksTLS(t *testing.T) {
	const domain = "agent.example"
	f := newCoalescingFixture(t, []string{domain}, nil)
	f.dns.records["_dnsid."+domain][0].TTL = 0
	for range 2 {
		if _, err := f.manager.VerifyDomain(context.Background(), domain); err != nil {
			t.Fatal(err)
		}
	}
	if got := f.dns.callCount("_dnsid." + domain); got != 2 {
		t.Fatalf("zero TTL reused: %d lookups", got)
	}
	f.https.certs = map[string]*tls.Certificate{f.records[domain].KeyURI: {Leaf: &x509.Certificate{NotAfter: time.Now().Add(-time.Second)}}}
	var ve *VerificationError
	if _, err := f.manager.VerifyDomain(context.Background(), domain); !errors.As(err, &ve) || ve.Code() != VerificationCodeTLSError {
		t.Fatalf("expired TLS with zero TTL: %v", err)
	}
	vd := &VerifiedDomain{domain: domain, record: &TXTRecord{KeyAge: "1s"}, keyBoundAt: time.Now().Add(-time.Hour)}
	if err := f.manager.requireFreshIdentityEvidence(vd, true); !errors.As(err, &ve) || ve.Code() != VerificationCodeKeyAgeExceeded {
		t.Fatalf("zero TTL key age: %v", err)
	}
}

func TestVerificationContext_DefaultAndCallerDeadlines(t *testing.T) {
	ctx, cancel := VerificationContext(context.Background())
	defer cancel()
	deadline, ok := ctx.Deadline()
	if !ok || time.Until(deadline) > DefaultVerificationTimeout {
		t.Fatal("no finite default")
	}
	parent, stop := context.WithTimeout(context.Background(), time.Millisecond)
	defer stop()
	child, done := VerificationContext(parent)
	defer done()
	want, _ := parent.Deadline()
	got, _ := child.Deadline()
	if !got.Equal(want) {
		t.Fatal("child restarted deadline")
	}
	stop()
	m := newCoalescingFixture(t, []string{"agent.example"}, nil).manager
	if vd, err := m.VerifyDomain(parent, "agent.example"); err == nil || vd != nil {
		t.Fatal("canceled verification succeeded")
	}
}

func TestLogRegistry_ArgumentAndParseCategories(t *testing.T) {
	r := dnsidlog.NewLogRegistry()
	var parse *ParseError
	if _, err := r.NewReader("invalid"); !errors.As(err, &parse) {
		t.Fatalf("NewReader: %v", err)
	}
	var argument *ArgumentError
	if err := r.Register("BAD", nil); !errors.As(err, &argument) {
		t.Fatalf("Register: %v", err)
	}
}
