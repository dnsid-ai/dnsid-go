package dnsid

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"time"

	"github.com/dnsid-ai/dnsid-go/internal/netguard"
)

type ipResolverFunc = netguard.IPResolverFunc
type contextDialFunc = netguard.ContextDialFunc

const defaultHTTPClientTimeout = 30 * time.Second

func newSafeHTTPClientFrom(base *http.Client) *http.Client {
	return safeHTTPClientWithDefaultTimeout(netguard.NewSafeHTTPClientFrom(base))
}

func newSafeHTTPClientFromWithResolver(base *http.Client, resolve ipResolverFunc, privateAddressHosts []string) *http.Client {
	return safeHTTPClientWithDefaultTimeout(netguard.NewSafeHTTPClientFromWithResolver(base, resolve, netguard.Policy{PrivateAddressHosts: privateAddressHosts}))
}

func safeHTTPClientWithDefaultTimeout(client *http.Client) *http.Client {
	if client.Timeout == 0 {
		client.Timeout = defaultHTTPClientTimeout
	}
	return client
}

// SafeDialerTransport returns an HTTP transport that resolves a hostname once,
// validates every returned IP address, and dials a concrete validated IP.
func SafeDialerTransport() *http.Transport {
	return netguard.SafeDialerTransport()
}

func safeDialerTransportWith(resolve ipResolverFunc, dial contextDialFunc) *http.Transport {
	return netguard.SafeDialerTransportWith(resolve, dial)
}

func dialValidatedIP(ctx context.Context, network string, addr string, resolve ipResolverFunc, dial contextDialFunc) (net.Conn, string, error) {
	return netguard.DialValidatedIP(ctx, network, addr, resolve, dial, netguard.Policy{})
}

func cloneTLSConfig(cfg *tls.Config) *tls.Config {
	return netguard.CloneTLSConfig(cfg)
}
