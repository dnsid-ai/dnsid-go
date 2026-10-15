package dnsid

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"
)

type revalidatingHTTPS struct {
	HTTPSFetcher
	t *testing.T
}

func (f revalidatingHTTPS) FetchJSON(ctx context.Context, uri string, opts FetchOptions) (json.RawMessage, *tls.Certificate, error) {
	if !opts.Revalidate {
		f.t.Error("refresh did not require HTTP revalidation: " + uri)
	}
	return f.HTTPSFetcher.FetchJSON(ctx, uri, opts)
}

func TestRefreshDomain_ReplacesCachedKeyAndFailsWithoutFallback(t *testing.T) {
	const domain = "agent.example.com"
	f := newCoalescingFixture(t, []string{domain}, nil)
	before, err := f.manager.VerifyDomain(context.Background(), domain)
	if err != nil {
		t.Fatal(err)
	}
	key := GenerateEd25519KeyProvider()
	body, _ := json.Marshal(mustJWKSet(t, key.JWK()))
	f.https.responses[f.records[domain].KeyURI] = body
	f.manager.https = revalidatingHTTPS{f.https, t}
	after, err := f.manager.RefreshDomain(context.Background(), "AGENT.EXAMPLE.COM.", VerifyDomainOpts{})
	if err != nil || after.operationalKeyThumbprint == before.operationalKeyThumbprint || after.CachedState() != "fresh" {
		t.Fatalf("refresh did not replace cached evidence: %v", err)
	}
	f.https.failures = map[string]error{f.records[domain].KeyURI: errors.New("unavailable")}
	if vd, err := f.manager.RefreshDomain(context.Background(), domain, VerifyDomainOpts{}); vd != nil || err == nil {
		t.Fatal("failed refresh returned stale evidence")
	}
	if cached := f.manager.cachedDomain(domain); cached == nil || cached.VerifiedAt() != after.VerifiedAt() {
		t.Fatal("failed refresh changed retained evidence")
	}
}

func TestRefreshDomain_CoalescesAndChecksEachPeer(t *testing.T) {
	const domain = "agent.example.com"
	f := newCoalescingFixture(t, []string{domain}, []PolicyFlag{PolicyFlagMTLS})
	f.dns.blockName, f.dns.entered, f.dns.release = "_dnsid."+domain, make(chan struct{}), make(chan struct{})
	joined := waitForJoins(f.manager, 2, true)
	errs := make(chan error, 2)
	go func() {
		_, err := f.manager.RefreshDomain(context.Background(), domain, VerifyDomainOpts{})
		errs <- err
	}()
	<-f.dns.entered
	go func() {
		_, err := f.manager.RefreshDomain(context.Background(), domain, VerifyDomainOpts{
			VerifiedPeerCertificateChains: [][]*x509.Certificate{{{DNSNames: []string{domain}}}},
		})
		errs <- err
	}()
	awaitN(joined, 2)
	close(f.dns.release)
	failures := 0
	for range 2 {
		if <-errs != nil {
			failures++
		}
	}
	if failures != 1 || f.dns.callCount("_dnsid."+domain) != 1 {
		t.Fatalf("per-peer failures=%d, DNS calls=%d", failures, f.dns.callCount("_dnsid."+domain))
	}
}

func TestRefreshDomain_OlderLookupCannotOverwriteRefresh(t *testing.T) {
	for _, ttl := range []time.Duration{0, time.Minute} {
		const domain = "agent.example.com"
		f := newCoalescingFixture(t, []string{domain}, nil)
		uri := f.records[domain].KeyURI
		f.https.blockURL, f.https.entered, f.https.release = uri, make(chan struct{}), make(chan struct{})
		var wg sync.WaitGroup
		wg.Go(func() {
			if _, err := f.manager.VerifyDomain(context.Background(), domain); err != nil {
				t.Error(err)
			}
		})
		<-f.https.entered
		body, _ := json.Marshal(mustJWKSet(t, GenerateEd25519KeyProvider().JWK()))
		f.https.mu.Lock()
		f.https.responses[uri] = body
		f.https.mu.Unlock()
		f.dns.mu.Lock()
		f.dns.records["_dnsid."+domain] = []TXTRecordRData{{Value: f.records[domain].Serialize(), TTL: ttl}}
		f.dns.mu.Unlock()
		refreshed, err := f.manager.RefreshDomain(context.Background(), domain, VerifyDomainOpts{})
		if err != nil {
			t.Fatal(err)
		}
		close(f.https.release)
		wg.Wait()
		cached := f.manager.cachedDomain(domain)
		if ttl == 0 && cached != nil || ttl > 0 && (cached == nil || cached.operationalKeyThumbprint != refreshed.operationalKeyThumbprint) {
			t.Fatal("older lookup restored superseded cache state")
		}
	}
}

func TestDefaultHTTPSFetcher_Revalidates(t *testing.T) {
	fetcher := defaultHTTPSFetcher{client: &http.Client{Transport: roundTripperFunc(func(req *http.Request) (*http.Response, error) {
		if req.Header.Get("Cache-Control") != "no-cache" || req.Header.Get("If-None-Match") != "" {
			t.Error("expected unconditional HTTP revalidation")
		}
		return &http.Response{StatusCode: 200, Header: http.Header{}, Body: io.NopCloser(strings.NewReader(`{}`))}, nil
	})}}
	if _, _, err := fetcher.FetchJSON(context.Background(), "https://agent.example.com/ku", FetchOptions{AllowedHost: "agent.example.com", Revalidate: true}); err != nil {
		t.Fatal(err)
	}
}
