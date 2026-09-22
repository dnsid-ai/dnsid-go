package dnsid

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"
)

// TestSafeJWKSHTTPClientRejectsLoopbackResolutionAtDial proves the hardened
// replacement path (the safe JWKS/HTTPS client) blocks a public-looking
// hostname that resolves to loopback at dial time — closing the TOCTOU gap
// the removed legacy fetchJWKSSet had between URL validation and the dial.
func TestSafeJWKSHTTPClientRejectsLoopbackResolutionAtDial(t *testing.T) {
	client := newSafeHTTPClientFromWithResolver(nil, func(context.Context, string) ([]net.IPAddr, error) {
		return []net.IPAddr{{IP: net.ParseIP("127.0.0.1")}}, nil
	}, false)

	req, err := http.NewRequest(http.MethodGet, "https://origin.example.com/jwks", nil)
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.Do(req)
	if err == nil || !strings.Contains(err.Error(), "non-public") {
		t.Fatalf("expected dial-time non-public rejection, got %v", err)
	}
}

// Names under the reserved .test TLD, or any name with AllowPrivateNetwork,
// may resolve to loopback: that is how dnsid local answers.
func TestSafeJWKSHTTPClientAllowsLoopbackForTestTLDOrPrivatePolicy(t *testing.T) {
	loopback := func(context.Context, string) ([]net.IPAddr, error) {
		return []net.IPAddr{{IP: net.ParseIP("127.0.0.1")}}, nil
	}
	for _, tc := range []struct {
		name, host   string
		allowPrivate bool
	}{
		{"test tld", "alice.dev.dnsid.test", false},
		{"allow private", "alice.dev.example.internal", true},
	} {
		client := newSafeHTTPClientFromWithResolver(nil, loopback, tc.allowPrivate)
		req, err := http.NewRequest(http.MethodGet, "https://"+tc.host+":1/jwks", nil)
		if err != nil {
			t.Fatal(err)
		}
		_, err = client.Do(req)
		// Nothing listens on port 1; the dial must get past the guard and fail on connect.
		if err == nil || strings.Contains(err.Error(), "non-public") {
			t.Fatalf("%s: expected the guard to pass and the dial to fail, got %v", tc.name, err)
		}
	}
}

func TestSafeJWKSHTTPClientDisablesRedirects(t *testing.T) {
	client := newSafeHTTPClientFrom(nil)
	req, err := http.NewRequest(http.MethodGet, "https://example.com/jwks", nil)
	if err != nil {
		t.Fatal(err)
	}
	err = client.CheckRedirect(req, []*http.Request{req})
	if !errors.Is(err, http.ErrUseLastResponse) {
		t.Fatalf("CheckRedirect error = %v, want %v", err, http.ErrUseLastResponse)
	}
}

func TestValidateManagerFetchURLRejectsFragments(t *testing.T) {
	if err := validateManagerFetchURL("https://example.com/jwks#fragment", "example.com", false); err == nil || !strings.Contains(err.Error(), "fragment") {
		t.Fatalf("initial fragment error = %v, want fragment rejection", err)
	}

	client := clientWithRedirectPolicy(&http.Client{}, "https://example.com/jwks", FetchOptions{RedirectPolicy: RedirectPolicyHTTPS})
	req, err := http.NewRequest(http.MethodGet, "https://example.com/next#fragment", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := client.CheckRedirect(req, nil); err == nil || !strings.Contains(err.Error(), "fragment") {
		t.Fatalf("redirect fragment error = %v, want fragment rejection", err)
	}
}

func TestNewSafeJWKSHTTPClientFromCopiesBaseAndInstallsSafeTransport(t *testing.T) {
	base := &http.Client{Timeout: 42 * time.Second}
	client := newSafeHTTPClientFrom(base)
	if client == base {
		t.Fatal("expected a copy of the base client")
	}
	if client.Timeout != base.Timeout {
		t.Fatalf("Timeout = %v, want %v", client.Timeout, base.Timeout)
	}
	tr, ok := client.Transport.(*http.Transport)
	if !ok || tr.DialContext == nil || tr.DialTLSContext == nil {
		t.Fatalf("expected safe transport, got %#v", client.Transport)
	}
	if client.CheckRedirect == nil {
		t.Fatal("expected redirect policy")
	}
	req, err := http.NewRequest(http.MethodGet, "https://example.com/jwks", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := client.CheckRedirect(req, []*http.Request{req}); !errors.Is(err, http.ErrUseLastResponse) {
		t.Fatalf("CheckRedirect error = %v, want %v", err, http.ErrUseLastResponse)
	}

	nilBase := newSafeHTTPClientFrom(nil)
	if nilBase.Transport == nil || nilBase.CheckRedirect == nil {
		t.Fatalf("nil base client did not get safe defaults: %#v", nilBase)
	}
}

func TestNewSafeJWKSHTTPClientFromWarnsForCustomRoundTripper(t *testing.T) {
	stderr := captureStderr(t, func() {
		client := newSafeHTTPClientFrom(&http.Client{Transport: roundTripperFunc(func(*http.Request) (*http.Response, error) {
			t.Fatal("custom round tripper should be replaced for JWKS safety")
			return nil, nil
		})})
		tr, ok := client.Transport.(*http.Transport)
		if !ok || tr.DialContext == nil || tr.DialTLSContext == nil {
			t.Fatalf("expected replacement safe transport, got %#v", client.Transport)
		}
	})
	if !strings.Contains(stderr, "cannot preserve non-*http.Transport") {
		t.Fatalf("stderr = %q, want non-*http.Transport warning", stderr)
	}
}

func TestSafeDialerTransportHandlesCustomDefaultTransport(t *testing.T) {
	orig := http.DefaultTransport
	http.DefaultTransport = roundTripperFunc(func(*http.Request) (*http.Response, error) {
		t.Fatal("custom default transport should not be used")
		return nil, nil
	})
	t.Cleanup(func() { http.DefaultTransport = orig })

	tr := safeDialerTransportWith(
		func(context.Context, string) ([]net.IPAddr, error) {
			return []net.IPAddr{{IP: net.ParseIP("8.8.8.8")}}, nil
		},
		func(context.Context, string, string) (net.Conn, error) {
			return nil, errors.New("dial stopped")
		},
	)
	if tr == nil || tr.DialContext == nil || tr.DialTLSContext == nil {
		t.Fatalf("expected safe transport, got %#v", tr)
	}
}

func TestSafeDialerTransportDisablesProxyFromEnvironment(t *testing.T) {
	t.Setenv("HTTPS_PROXY", "http://127.0.0.1:8080")
	tr := SafeDialerTransport()
	if tr.Proxy != nil {
		t.Fatal("safe transport must not use environment proxies")
	}
}

func TestSafeDialerDialContextResolvesOnceAndDialsValidatedIP(t *testing.T) {
	dialErr := errors.New("stop after address capture")
	var dialed string
	resolveCalls := 0
	tr := safeDialerTransportWith(
		func(context.Context, string) ([]net.IPAddr, error) {
			resolveCalls++
			if resolveCalls > 1 {
				return []net.IPAddr{{IP: net.ParseIP("192.168.1.1")}}, nil
			}
			return []net.IPAddr{{IP: net.ParseIP("8.8.8.8")}}, nil
		},
		func(_ context.Context, _ string, addr string) (net.Conn, error) {
			dialed = addr
			return nil, dialErr
		},
	)

	_, err := tr.DialContext(context.Background(), "tcp", "origin.example.com:443")
	if !errors.Is(err, dialErr) {
		t.Fatalf("DialContext error = %v, want %v", err, dialErr)
	}
	if dialed != "8.8.8.8:443" {
		t.Fatalf("dialed %q, want validated IP", dialed)
	}
	if resolveCalls != 1 {
		t.Fatalf("resolver called %d times, want 1", resolveCalls)
	}
}

func TestSafeDialerRejectsMixedSafeAndUnsafeResolvedIPsWithoutDialing(t *testing.T) {
	for _, tt := range []struct {
		name string
		dial func(*http.Transport) error
	}{
		{
			name: "tcp",
			dial: func(tr *http.Transport) error {
				_, err := tr.DialContext(context.Background(), "tcp", "origin.example.com:443")
				return err
			},
		},
		{
			name: "tls",
			dial: func(tr *http.Transport) error {
				_, err := tr.DialTLSContext(context.Background(), "tcp", "origin.example.com:443")
				return err
			},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			calledDial := false
			tr := safeDialerTransportWith(
				func(context.Context, string) ([]net.IPAddr, error) {
					return []net.IPAddr{
						{IP: net.ParseIP("8.8.8.8")},
						{IP: net.ParseIP("192.168.1.1")},
					}, nil
				},
				func(context.Context, string, string) (net.Conn, error) {
					calledDial = true
					return nil, nil
				},
			)

			err := tt.dial(tr)
			if err == nil || !strings.Contains(err.Error(), "non-public 192.168.1.1") {
				t.Fatalf("expected mixed-resolution rejection, got %v", err)
			}
			if calledDial {
				t.Fatal("mixed safe and unsafe addresses should not be dialed")
			}
		})
	}
}

func TestSafeDialerRejectsUnsafeResolvedIPWithoutDialing(t *testing.T) {
	for _, tt := range []struct {
		name string
		dial func(*http.Transport) error
	}{
		{
			name: "tcp",
			dial: func(tr *http.Transport) error {
				_, err := tr.DialContext(context.Background(), "tcp", "origin.example.com:443")
				return err
			},
		},
		{
			name: "tls",
			dial: func(tr *http.Transport) error {
				_, err := tr.DialTLSContext(context.Background(), "tcp", "origin.example.com:443")
				return err
			},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			calledDial := false
			tr := safeDialerTransportWith(
				func(context.Context, string) ([]net.IPAddr, error) {
					return []net.IPAddr{{IP: net.ParseIP("127.0.0.1")}}, nil
				},
				func(context.Context, string, string) (net.Conn, error) {
					calledDial = true
					return nil, nil
				},
			)

			err := tt.dial(tr)
			if err == nil || !strings.Contains(err.Error(), "non-public") {
				t.Fatalf("expected non-public rejection, got %v", err)
			}
			if calledDial {
				t.Fatal("unsafe resolved address should not be dialed")
			}
		})
	}
}

func TestDialValidatedIPLiteralUsesIPWithoutResolving(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer func() { _ = serverConn.Close() }()

	calledResolve := false
	var dialed string
	conn, serverName, err := dialValidatedIP(
		context.Background(),
		"tcp",
		"8.8.8.8:443",
		func(context.Context, string) ([]net.IPAddr, error) {
			calledResolve = true
			return nil, nil
		},
		func(_ context.Context, _ string, addr string) (net.Conn, error) {
			dialed = addr
			return clientConn, nil
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	if calledResolve {
		t.Fatal("IP literal should not be resolved")
	}
	if serverName != "8.8.8.8" {
		t.Fatalf("serverName = %q, want IP literal", serverName)
	}
	if dialed != "8.8.8.8:443" {
		t.Fatalf("dialed %q, want IP literal", dialed)
	}
}

func TestDialValidatedIPRejectsSpecialUseAddresses(t *testing.T) {
	tests := []struct {
		ip       string
		wantDial bool
	}{
		{ip: "0.0.0.1"},
		{ip: "100.64.0.1"},
		{ip: "192.0.0.1"},
		{ip: "192.0.2.1"},
		{ip: "192.88.99.1"},
		{ip: "198.18.0.1"},
		{ip: "198.51.100.1"},
		{ip: "203.0.113.1"},
		{ip: "240.0.0.1"},
		{ip: "64:ff9b::1"},
		{ip: "100::1"},
		{ip: "2001::1"},
		{ip: "2001:db8::1"},
		{ip: "2002::1"},
		{ip: "3fff::1"},
		{ip: "4000::1"},
		{ip: "8.8.8.8", wantDial: true},
		{ip: "192.0.0.9", wantDial: true},
		{ip: "2001:3::1", wantDial: true},
		{ip: "2606:4700:4700::1111", wantDial: true},
	}
	for _, test := range tests {
		t.Run(test.ip, func(t *testing.T) {
			calledDial := false
			_, _, _ = dialValidatedIP(
				context.Background(),
				"tcp",
				net.JoinHostPort(test.ip, "443"),
				func(context.Context, string) ([]net.IPAddr, error) {
					t.Fatal("IP literal should not be resolved")
					return nil, nil
				},
				func(context.Context, string, string) (net.Conn, error) {
					calledDial = true
					return nil, errors.New("dial stopped")
				},
			)
			if calledDial != test.wantDial {
				t.Fatalf("dialed = %v, want %v", calledDial, test.wantDial)
			}
		})
	}
}

func TestDialValidatedIPRejectsUnsafeIPLiteralWithoutDialing(t *testing.T) {
	calledDial := false
	_, _, err := dialValidatedIP(
		context.Background(),
		"tcp",
		"127.0.0.1:443",
		func(context.Context, string) ([]net.IPAddr, error) {
			t.Fatal("IP literal should not be resolved")
			return nil, nil
		},
		func(context.Context, string, string) (net.Conn, error) {
			calledDial = true
			return nil, nil
		},
	)
	if err == nil || !strings.Contains(err.Error(), "non-public") {
		t.Fatalf("expected non-public rejection, got %v", err)
	}
	if calledDial {
		t.Fatal("unsafe IP literal should not be dialed")
	}
}

func TestDialValidatedIPRejectsInvalidAddress(t *testing.T) {
	_, _, err := dialValidatedIP(
		context.Background(),
		"tcp",
		"missing-port",
		func(context.Context, string) ([]net.IPAddr, error) {
			t.Fatal("invalid address should not be resolved")
			return nil, nil
		},
		func(context.Context, string, string) (net.Conn, error) {
			t.Fatal("invalid address should not be dialed")
			return nil, nil
		},
	)
	if err == nil {
		t.Fatal("expected invalid address error")
	}
}

func TestDialValidatedIPReturnsResolverAndEmptyResultsErrors(t *testing.T) {
	resolveErr := errors.New("resolver unavailable")
	_, _, err := dialValidatedIP(
		context.Background(),
		"tcp",
		"origin.example.com:443",
		func(context.Context, string) ([]net.IPAddr, error) {
			return nil, resolveErr
		},
		func(context.Context, string, string) (net.Conn, error) {
			t.Fatal("resolver error should not be dialed")
			return nil, nil
		},
	)
	if !errors.Is(err, resolveErr) {
		t.Fatalf("error = %v, want %v", err, resolveErr)
	}

	_, _, err = dialValidatedIP(
		context.Background(),
		"tcp",
		"origin.example.com:443",
		func(context.Context, string) ([]net.IPAddr, error) {
			return nil, nil
		},
		func(context.Context, string, string) (net.Conn, error) {
			t.Fatal("empty resolver result should not be dialed")
			return nil, nil
		},
	)
	if err == nil || !strings.Contains(err.Error(), "resolved to no addresses") {
		t.Fatalf("expected empty resolution error, got %v", err)
	}
}

func TestDialValidatedIPRejectsNilResolvedIPWithoutDialing(t *testing.T) {
	calledDial := false
	_, _, err := dialValidatedIP(
		context.Background(),
		"tcp",
		"origin.example.com:443",
		func(context.Context, string) ([]net.IPAddr, error) {
			return []net.IPAddr{{}}, nil
		},
		func(context.Context, string, string) (net.Conn, error) {
			calledDial = true
			return nil, nil
		},
	)
	if err == nil || !strings.Contains(err.Error(), "invalid address") {
		t.Fatalf("expected invalid address rejection, got %v", err)
	}
	if calledDial {
		t.Fatal("nil resolved address should not be dialed")
	}
}

func TestDialValidatedIPTriesNextValidatedIPAfterDialError(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer func() { _ = serverConn.Close() }()

	firstErr := errors.New("first address refused")
	var dialed []string
	conn, serverName, err := dialValidatedIP(
		context.Background(),
		"tcp",
		"origin.example.com:443",
		func(context.Context, string) ([]net.IPAddr, error) {
			return []net.IPAddr{
				{IP: net.ParseIP("8.8.8.8")},
				{IP: net.ParseIP("1.1.1.1")},
			}, nil
		},
		func(_ context.Context, _ string, addr string) (net.Conn, error) {
			dialed = append(dialed, addr)
			if len(dialed) == 1 {
				return nil, firstErr
			}
			return clientConn, nil
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	if serverName != "origin.example.com" {
		t.Fatalf("serverName = %q, want original host", serverName)
	}
	want := []string{"8.8.8.8:443", "1.1.1.1:443"}
	if strings.Join(dialed, ",") != strings.Join(want, ",") {
		t.Fatalf("dialed %v, want %v", dialed, want)
	}
}

func TestDialValidatedIPReturnsContextErrorAfterDialFailure(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	dialErr := errors.New("dial failed")
	_, _, err := dialValidatedIP(
		ctx,
		"tcp",
		"origin.example.com:443",
		func(context.Context, string) ([]net.IPAddr, error) {
			return []net.IPAddr{{IP: net.ParseIP("8.8.8.8")}}, nil
		},
		func(context.Context, string, string) (net.Conn, error) {
			cancel()
			return nil, dialErr
		},
	)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("error = %v, want context.Canceled", err)
	}
}

func TestCloneTLSConfigNilReturnsUsableConfig(t *testing.T) {
	cfg := cloneTLSConfig(nil)
	if cfg == nil {
		t.Fatal("expected config")
	}
	cfg.ServerName = "example.com"
	if cloneTLSConfig(nil).ServerName != "" {
		t.Fatal("cloneTLSConfig(nil) should return a fresh config")
	}
}

func TestSafeDialerTLSUsesOriginalHostnameAsServerName(t *testing.T) {
	serverNames := make(chan string, 1)
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		serverName := ""
		if r.TLS != nil {
			serverName = r.TLS.ServerName
		}
		serverNames <- serverName
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	serverURL, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	_, serverPort, err := net.SplitHostPort(serverURL.Host)
	if err != nil {
		t.Fatal(err)
	}

	const validatedIP = "8.8.8.8"
	wantDialAddr := net.JoinHostPort(validatedIP, serverPort)
	dialed := make(chan string, 1)
	resolveCalls := 0
	tr := safeDialerTransportWith(
		func(_ context.Context, host string) ([]net.IPAddr, error) {
			resolveCalls++
			if host != "example.com" {
				return nil, fmt.Errorf("resolved host %q, want example.com", host)
			}
			if resolveCalls > 1 {
				return []net.IPAddr{{IP: net.ParseIP("192.168.1.1")}}, nil
			}
			return []net.IPAddr{{IP: net.ParseIP(validatedIP)}}, nil
		},
		func(ctx context.Context, network, addr string) (net.Conn, error) {
			dialed <- addr
			if addr != wantDialAddr {
				return nil, fmt.Errorf("dialed %q, want %q", addr, wantDialAddr)
			}
			var d net.Dialer
			return d.DialContext(ctx, network, server.Listener.Addr().String())
		},
	)
	tr.TLSClientConfig = server.Client().Transport.(*http.Transport).TLSClientConfig.Clone()

	client := &http.Client{Transport: tr}
	resp, err := client.Get("https://example.com:" + serverPort + "/")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusNoContent)
	}
	if resolveCalls != 1 {
		t.Fatalf("resolver called %d times, want 1", resolveCalls)
	}
	if got := <-dialed; got != wantDialAddr {
		t.Fatalf("dialed %q, want %q", got, wantDialAddr)
	}
	if got := <-serverNames; got != "example.com" {
		t.Fatalf("TLS ServerName = %q, want example.com", got)
	}
}

func TestSafeDialerTLSClosesConnectionOnHandshakeError(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	_ = serverConn.Close()
	trackedConn := &closeTrackingConn{Conn: clientConn}
	tr := safeDialerTransportWith(
		func(context.Context, string) ([]net.IPAddr, error) {
			return []net.IPAddr{{IP: net.ParseIP("8.8.8.8")}}, nil
		},
		func(context.Context, string, string) (net.Conn, error) {
			return trackedConn, nil
		},
	)

	_, err := tr.DialTLSContext(context.Background(), "tcp", "origin.example.com:443")
	if err == nil {
		t.Fatal("expected TLS handshake error")
	}
	if !trackedConn.closed {
		t.Fatal("expected failed TLS handshake to close the dialed connection")
	}
}

type closeTrackingConn struct {
	net.Conn
	closed bool
}

func (c *closeTrackingConn) Close() error {
	c.closed = true
	return c.Conn.Close()
}

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func captureStderr(t *testing.T, fn func()) string {
	t.Helper()

	orig := os.Stderr
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stderr = w
	wClosed := false
	defer func() {
		os.Stderr = orig
		if !wClosed {
			_ = w.Close()
		}
		_ = r.Close()
	}()

	fn()

	os.Stderr = orig
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	wClosed = true

	var buf bytes.Buffer
	if _, err := buf.ReadFrom(r); err != nil {
		t.Fatal(err)
	}
	return buf.String()
}
