package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	dnsid "github.com/dnsid-ai/dnsid-go"
	dnsidlog "github.com/dnsid-ai/dnsid-go/log"
	"github.com/dnsid-ai/dnsid-go/log/c2sptlog"
)

// testnetHTTPClient deliberately permits private addresses. This policy lives
// in the example—not the SDK—because production SDK transports reject them.
func testnetHTTPClient(config dnsid.TransportConfig) (*http.Client, error) {
	client, err := dnsid.CreateDnsidHTTPClient(config)
	if err != nil {
		return nil, err
	}

	base, ok := client.Transport.(*http.Transport)
	if !ok {
		return nil, fmt.Errorf("dnsid testnet: expected *http.Transport, got %T", client.Transport)
	}
	transport := base.Clone()
	resolver := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, config.DNSServer)
		},
	}
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	transport.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, err
		}
		if net.ParseIP(host) != nil {
			return dialer.DialContext(ctx, network, addr)
		}

		ips, err := resolver.LookupIPAddr(ctx, host)
		if err != nil {
			return nil, err
		}
		for _, ip := range ips {
			conn, err := dialer.DialContext(ctx, network, net.JoinHostPort(ip.IP.String(), port))
			if err == nil {
				return conn, nil
			}
		}
		return nil, fmt.Errorf("dial %s: no reachable address", host)
	}
	transport.DialTLSContext = nil
	client.Transport = transport
	return client, nil
}

// testnetFetcher adapts the local client to the SDK's HTTPSFetcher interface.
// It keeps the SDK's HTTPS, host-boundary, and response-size checks.
type testnetFetcher struct{ client *http.Client }

func (f testnetFetcher) FetchJSON(ctx context.Context, rawURL string, opts dnsid.FetchOptions) (json.RawMessage, *tls.Certificate, error) {
	u, err := url.Parse(rawURL)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil {
		return nil, nil, fmt.Errorf("invalid testnet HTTPS URL %q", rawURL)
	}
	if opts.AllowedHost != "" {
		host := strings.ToLower(u.Hostname())
		allowed := strings.ToLower(opts.AllowedHost)
		if host != allowed && (!opts.DomainBoundary || !strings.HasSuffix(host, "."+allowed)) {
			return nil, nil, fmt.Errorf("testnet HTTPS host %q does not match %q", host, allowed)
		}
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, nil, err
	}
	resp, err := f.client.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return nil, nil, fmt.Errorf("testnet HTTPS fetch returned HTTP %s", resp.Status)
	}

	limit := opts.MaxResponseBytes
	if limit <= 0 {
		limit = 1 << 20
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return nil, nil, err
	}
	if int64(len(data)) > limit {
		return nil, nil, fmt.Errorf("testnet HTTPS response exceeds %d bytes", limit)
	}

	// The local registry currently wraps su= responses in its agent-detail
	// document; production serves the protocol status directly.
	var envelope struct {
		ProtocolStatus json.RawMessage `json:"protocolStatus"`
	}
	if json.Unmarshal(data, &envelope) == nil && len(envelope.ProtocolStatus) != 0 {
		data = envelope.ProtocolStatus
	}

	var cert *tls.Certificate
	if resp.TLS != nil && len(resp.TLS.PeerCertificates) > 0 {
		leaf := resp.TLS.PeerCertificates[0]
		cert = &tls.Certificate{Certificate: [][]byte{leaf.Raw}, Leaf: leaf}
	}
	return data, cert, nil
}

func createLogRegistry(ctx context.Context, logRef, policyURL string, client *http.Client) (*dnsidlog.LogRegistry, error) {
	policyURL = strings.TrimSpace(policyURL)
	if policyURL == "" {
		return nil, fmt.Errorf("DNSID_LOG_POLICY_URL is required; run with `dnsid testnet run`")
	}
	ref, err := c2sptlog.ParseReference(logRef)
	if err != nil {
		return nil, fmt.Errorf("parse DNSID_LOG_REF: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, policyURL, nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch C2SP policy: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return nil, fmt.Errorf("fetch C2SP policy: HTTP %s", resp.Status)
	}

	document, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	policy, err := c2sptlog.ParsePolicy(document)
	if err != nil {
		return nil, err
	}
	origin, err := ref.Origin()
	if err != nil {
		return nil, err
	}
	policyOrigin := ""
	if policy.LogVerifier != nil {
		policyOrigin = policy.LogVerifier.Name()
	}
	if policyOrigin != origin {
		return nil, fmt.Errorf("trusted C2SP policy log key %q does not match log origin %q", policyOrigin, origin)
	}
	source, err := c2sptlog.NewScanSource(policy, c2sptlog.ScanSourceConfig{
		HTTPClient: client,
		Transport:  client.Transport,
	})
	if err != nil {
		return nil, err
	}

	registry := dnsidlog.NewLogRegistry()
	err = c2sptlog.Register(
		registry,
		c2sptlog.WithPolicy(policy),
		c2sptlog.WithSource(source),
		c2sptlog.WithTrustedCheckpointStore(c2sptlog.NewMemoryTrustedC2spCheckpointStore()),
	)
	return registry, err
}
