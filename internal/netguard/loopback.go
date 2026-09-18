package netguard

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"time"
)

// LoopbackOnlyTransport returns a transport that dials loopback addresses only.
// It is the escape hatch for operator-configured local services (the local
// registry, an http:// loopback OIDC issuer) that the SSRF-safe transport
// would otherwise refuse.
func LoopbackOnlyTransport() *http.Transport {
	var tr *http.Transport
	if base, ok := http.DefaultTransport.(*http.Transport); ok {
		tr = base.Clone()
	} else {
		tr = &http.Transport{}
	}
	tr.Proxy = nil
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	resolver := &net.Resolver{}
	tr.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, err
		}
		if ip := net.ParseIP(host); ip != nil {
			if !ip.IsLoopback() {
				return nil, fmt.Errorf("dial blocked: %s is not loopback", ip)
			}
			return dialer.DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
		}
		ips, err := resolver.LookupIPAddr(ctx, host)
		if err != nil {
			return nil, err
		}
		for _, ip := range ips {
			if ip.IP == nil || !ip.IP.IsLoopback() {
				return nil, fmt.Errorf("dial blocked: %s resolves outside loopback", host)
			}
		}
		if len(ips) == 0 {
			return nil, fmt.Errorf("dial blocked: %s resolved to no addresses", host)
		}
		var lastErr error
		for _, ip := range ips {
			conn, err := dialer.DialContext(ctx, network, net.JoinHostPort(ip.IP.String(), port))
			if err == nil {
				return conn, nil
			}
			lastErr = err
		}
		return nil, lastErr
	}
	return tr
}
