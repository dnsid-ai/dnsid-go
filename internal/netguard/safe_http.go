package netguard

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"os"
	"strings"
	"time"
)

type IPResolverFunc func(context.Context, string) ([]net.IPAddr, error)
type ContextDialFunc func(context.Context, string, string) (net.Conn, error)

// UnsafeDestinationError reports that destination validation rejected a dial
// before any connection was attempted.
type UnsafeDestinationError struct {
	Message string
}

func (e *UnsafeDestinationError) Error() string {
	if e == nil {
		return "<nil>"
	}
	return e.Message
}

// Policy relaxes destination validation. The zero value is the default: only
// publicly routable addresses are dialed. There is no built-in exemption for
// any name or TLD.
type Policy struct {
	// PrivateAddressHosts lists hostnames (exact) or leading-dot suffixes
	// (".test") whose resolved addresses may be loopback or private-use
	// (RFC 1918, RFC 4193). Other non-public classes stay rejected.
	PrivateAddressHosts []string
}

// AllowsPrivateAddresses reports whether host matches a PrivateAddressHosts
// entry: an exact hostname, or a leading-dot suffix on a DNS-label boundary
// (".test" matches "test" and "a.test", not "evil-test" or "a.test.example").
// Matching is case-insensitive and ignores a trailing dot. IP literals never
// match.
func (p Policy) AllowsPrivateAddresses(host string) bool {
	host = strings.TrimSuffix(strings.ToLower(host), ".")
	if host == "" || net.ParseIP(host) != nil {
		return false
	}
	for _, entry := range p.PrivateAddressHosts {
		entry = strings.TrimSuffix(strings.ToLower(entry), ".")
		if entry == "" || entry == "." {
			continue
		}
		if suffix, ok := strings.CutPrefix(entry, "."); ok {
			if host == suffix || strings.HasSuffix(host, entry) {
				return true
			}
		} else if host == entry {
			return true
		}
	}
	return false
}

func NewSafeHTTPClientFrom(base *http.Client) *http.Client {
	return NewSafeHTTPClientFromWithResolver(base, nil, Policy{})
}

func NewSafeHTTPClientFromWithResolver(base *http.Client, resolve IPResolverFunc, policy Policy) *http.Client {
	if base == nil {
		base = &http.Client{}
	}
	client := *base
	client.Transport = SafeDialerTransportFromRoundTripperWithResolver(base.Transport, resolve, policy)
	client.CheckRedirect = func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}
	return &client
}

// SafeDialerTransport returns an HTTP transport that resolves a hostname once,
// validates every returned IP address, and dials a concrete validated IP.
func SafeDialerTransport() *http.Transport {
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	resolver := &net.Resolver{}
	return SafeDialerTransportWith(resolver.LookupIPAddr, dialer.DialContext)
}

// SafeDialerTransportFromRoundTripper preserves TLS and transport settings
// only when rt is a *http.Transport. Wrapped or custom RoundTrippers cannot be
// safely cloned into a rebinding-safe Transport, so they are replaced with a
// new empty *http.Transport and a warning is written to stderr.
func SafeDialerTransportFromRoundTripper(rt http.RoundTripper) *http.Transport {
	return SafeDialerTransportFromRoundTripperWithResolver(rt, nil, Policy{})
}

func SafeDialerTransportFromRoundTripperWithResolver(rt http.RoundTripper, resolve IPResolverFunc, policy Policy) *http.Transport {
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	if resolve == nil {
		resolver := &net.Resolver{}
		resolve = resolver.LookupIPAddr
	}

	var base *http.Transport
	if rt != nil {
		var ok bool
		base, ok = rt.(*http.Transport)
		if !ok {
			fmt.Fprintf(os.Stderr, "dnsid: HTTPS client cannot preserve non-*http.Transport %T; using a new safe transport\n", rt)
			base = &http.Transport{}
		}
	}
	return SafeDialerTransportFrom(base, resolve, dialer.DialContext, policy)
}

func SafeDialerTransportWith(resolve IPResolverFunc, dial ContextDialFunc) *http.Transport {
	return SafeDialerTransportFrom(nil, resolve, dial, Policy{})
}

func SafeDialerTransportFrom(base *http.Transport, resolve IPResolverFunc, dial ContextDialFunc, policy Policy) *http.Transport {
	if base == nil {
		if t, ok := http.DefaultTransport.(*http.Transport); ok {
			base = t
		} else {
			base = &http.Transport{}
		}
	}
	tr := base.Clone()
	tr.Proxy = nil

	safeDial := func(ctx context.Context, network, addr string) (net.Conn, string, error) {
		return DialValidatedIP(ctx, network, addr, resolve, dial, policy)
	}
	tr.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		conn, _, err := safeDial(ctx, network, addr)
		return conn, err
	}
	tr.DialTLSContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		conn, serverName, err := safeDial(ctx, network, addr)
		if err != nil {
			return nil, err
		}

		cfg := CloneTLSConfig(tr.TLSClientConfig)
		if cfg.ServerName == "" {
			cfg.ServerName = serverName
		}

		tlsConn := tls.Client(conn, cfg)
		handshakeCtx := ctx
		var cancel context.CancelFunc
		if tr.TLSHandshakeTimeout > 0 {
			handshakeCtx, cancel = context.WithTimeout(ctx, tr.TLSHandshakeTimeout)
			defer cancel()
		}
		if err := tlsConn.HandshakeContext(handshakeCtx); err != nil {
			_ = conn.Close()
			return nil, err
		}
		return tlsConn, nil
	}
	return tr
}

var (
	globallyRoutableSpecialPrefixes = []netip.Prefix{
		netip.MustParsePrefix("192.0.0.9/32"),
		netip.MustParsePrefix("192.0.0.10/32"),
		netip.MustParsePrefix("2001:1::1/128"),
		netip.MustParsePrefix("2001:1::2/128"),
		netip.MustParsePrefix("2001:1::3/128"),
		netip.MustParsePrefix("2001:3::/32"),
		netip.MustParsePrefix("2001:4:112::/48"),
		netip.MustParsePrefix("2001:20::/28"),
		netip.MustParsePrefix("2001:30::/28"),
	}
	nonRoutableSpecialPrefixes = []netip.Prefix{
		netip.MustParsePrefix("0.0.0.0/8"),
		netip.MustParsePrefix("100.64.0.0/10"),
		netip.MustParsePrefix("192.0.0.0/24"),
		netip.MustParsePrefix("192.0.2.0/24"),
		netip.MustParsePrefix("192.88.99.0/24"),
		netip.MustParsePrefix("198.18.0.0/15"),
		netip.MustParsePrefix("198.51.100.0/24"),
		netip.MustParsePrefix("203.0.113.0/24"),
		netip.MustParsePrefix("240.0.0.0/4"),
		netip.MustParsePrefix("2001::/23"),
		netip.MustParsePrefix("2001:db8::/32"),
		netip.MustParsePrefix("2002::/16"),
		netip.MustParsePrefix("3fff::/20"),
	}
	allocatedIPv6GlobalUnicast = netip.MustParsePrefix("2000::/3")
)

// IsPrivateOrLoopbackIP reports whether ip is loopback (127.0.0.0/8, ::1) or
// private-use (RFC 1918, RFC 4193). These are the only non-public classes a
// PrivateAddressHosts match may resolve to.
func IsPrivateOrLoopbackIP(ip net.IP) bool {
	addr, ok := netip.AddrFromSlice(ip)
	if !ok {
		return false
	}
	addr = addr.Unmap()
	return addr.IsLoopback() || addr.IsPrivate()
}

// IsNonPublicIP reports whether ip is not publicly routable. In addition to
// the address classes recognized by net.IP, it rejects IANA special-purpose
// ranges and unallocated IPv6 space.
func IsNonPublicIP(ip net.IP) bool {
	addr, ok := netip.AddrFromSlice(ip)
	if !ok {
		return true
	}
	addr = addr.Unmap()
	for _, prefix := range globallyRoutableSpecialPrefixes {
		if prefix.Contains(addr) {
			return false
		}
	}
	if addr.Is6() && !allocatedIPv6GlobalUnicast.Contains(addr) {
		return true
	}
	for _, prefix := range nonRoutableSpecialPrefixes {
		if prefix.Contains(addr) {
			return true
		}
	}
	return !addr.IsGlobalUnicast() || addr.IsPrivate()
}

func DialValidatedIP(
	ctx context.Context,
	network string,
	addr string,
	resolve IPResolverFunc,
	dial ContextDialFunc,
	policy Policy,
) (net.Conn, string, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, "", err
	}

	if ip := net.ParseIP(host); ip != nil {
		if IsNonPublicIP(ip) {
			return nil, "", &UnsafeDestinationError{Message: fmt.Sprintf("dial blocked: %s is non-public", ip)}
		}
		conn, err := dial(ctx, network, net.JoinHostPort(ip.String(), port))
		return conn, host, err
	}

	ips, err := resolve(ctx, host)
	if err != nil {
		return nil, "", err
	}
	if len(ips) == 0 {
		return nil, "", &UnsafeDestinationError{Message: fmt.Sprintf("dial blocked: %s resolved to no addresses", host)}
	}
	allowPrivate := policy.AllowsPrivateAddresses(host)
	sawPublic, sawPrivate := false, false
	for _, ip := range ips {
		if ip.IP == nil {
			return nil, "", &UnsafeDestinationError{Message: fmt.Sprintf("dial blocked: %s resolved to invalid address", host)}
		}
		if !IsNonPublicIP(ip.IP) {
			sawPublic = true
			continue
		}
		if !allowPrivate || !IsPrivateOrLoopbackIP(ip.IP) {
			return nil, "", &UnsafeDestinationError{Message: fmt.Sprintf("dial blocked: %s resolves to non-public %s", host, ip.IP)}
		}
		sawPrivate = true
	}
	if sawPublic && sawPrivate {
		return nil, "", &UnsafeDestinationError{Message: fmt.Sprintf("dial blocked: %s resolves to both public and private addresses", host)}
	}

	var lastErr error
	for _, ip := range ips {
		conn, dialErr := dial(ctx, network, net.JoinHostPort(ip.IP.String(), port))
		if dialErr == nil {
			return conn, host, nil
		}
		lastErr = dialErr
		if ctx.Err() != nil {
			return nil, "", ctx.Err()
		}
	}
	return nil, "", lastErr
}

func CloneTLSConfig(cfg *tls.Config) *tls.Config {
	if cfg == nil {
		return &tls.Config{}
	}
	return cfg.Clone()
}
