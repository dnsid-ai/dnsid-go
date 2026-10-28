package httpsig

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/dnsid-ai/dnsid-go"
)

func serveNegotiatedResponse(t *testing.T, f *responseFixture, w http.ResponseWriter, req *http.Request, status int) {
	t.Helper()
	res := responseMessage("response content")
	res.StatusCode = status
	if status == http.StatusFound {
		res.Header.Set("Location", "/redirected")
	}
	signed, err := f.signer.SignRequestedHTTPResponse(req, res)
	if err != nil {
		t.Errorf("server signing: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	defer signed.Body.Close()
	for name, values := range signed.Header {
		w.Header()[name] = values
	}
	w.WriteHeader(status)
	if req.Method != http.MethodHead && status != http.StatusNoContent && status != http.StatusNotModified {
		_, _ = io.Copy(w, signed.Body)
	}
}

func TestNegotiatedResponse_ClientStatusesAndRequestOnly(t *testing.T) {
	for _, status := range []int{http.StatusOK, http.StatusBadRequest, http.StatusInternalServerError, http.StatusFound} {
		for _, enabled := range []bool{false, true} {
			t.Run(http.StatusText(status)+map[bool]string{false: "/request-only", true: "/negotiated"}[enabled], func(t *testing.T) {
				f := newResponseFixture(t)
				var calls atomic.Int32
				server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
					calls.Add(1)
					if enabled {
						serveNegotiatedResponse(t, f, w, req, status)
						return
					}
					if req.Header.Get("Accept-Signature") != "" {
						t.Error("request-only added negotiation")
					}
					w.WriteHeader(status)
					_, _ = io.WriteString(w, "unsigned")
				}))
				defer server.Close()
				base := server.Client()
				base.CheckRedirect = func(*http.Request, []*http.Request) error {
					t.Error("caller redirect hook invoked")
					return errors.New("redirect")
				}
				opts := SigningOptions{}
				if enabled {
					opts.ResponseSignature = &f.opts
				}
				client := f.signer.CreateSignedHTTPClient(base, opts)
				// Signing and verification use the same profile, with a real core resolver.
				f.signer.resolver = f.checker.resolver
				req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, server.URL+"/resource", nil)
				res, err := client.Do(req)
				if err != nil {
					t.Fatal(err)
				}
				defer res.Body.Close()
				body, _ := io.ReadAll(res.Body)
				want := "unsigned"
				if enabled {
					want = "response content"
				}
				if res.StatusCode != status || string(body) != want || calls.Load() != 1 {
					t.Fatalf("response=%d %q requests=%d", res.StatusCode, body, calls.Load())
				}
			})
		}
	}
}

func TestNegotiatedResponse_ClientUnsignedErrorsReject(t *testing.T) {
	for _, status := range []int{http.StatusOK, http.StatusUnauthorized, http.StatusServiceUnavailable, http.StatusFound} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			f := newResponseFixture(t)
			var calls atomic.Int32
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				calls.Add(1)
				w.Header().Set("Location", "/redirected")
				w.WriteHeader(status)
				_, _ = io.WriteString(w, "unsigned")
			}))
			defer server.Close()
			client := f.signer.CreateSignedHTTPClient(server.Client(), SigningOptions{ResponseSignature: &f.opts})
			req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, server.URL, nil)
			if res, err := client.Do(req); err == nil || res != nil {
				if res != nil {
					res.Body.Close()
				}
				t.Fatal("unsigned response escaped")
			}
			if calls.Load() != 1 {
				t.Fatal("redirect or replay sent another request")
			}
		})
	}
}

func TestNegotiatedResponse_ClientSnapshotsAndRepeatedAttempts(t *testing.T) {
	f := newResponseFixture(t)
	f.signer.resolver = f.checker.resolver
	f.opts.AdditionalComponents = []ComponentIdentifier{{Name: "content-type"}, {Name: "x-meta", Params: map[string]any{"key": "choice"}, ParamOrder: []string{"key"}}}
	prepared, release := make(chan string, 2), make(chan struct{}, 2)
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		prepared <- req.Header.Get("Accept-Signature")
		<-release
		serveNegotiatedResponse(t, f, w, req, http.StatusOK)
	}))
	defer server.Close()
	client := f.signer.CreateSignedHTTPClient(server.Client(), SigningOptions{ResponseSignature: &f.opts})
	original, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, server.URL+"/original", nil)
	result := make(chan error, 1)
	go func() {
		res, err := client.Do(original)
		if res != nil {
			res.Body.Close()
		}
		result <- err
	}()
	first := <-prepared
	// The transport has its own request and the wrapper has retained its own context.
	original.Method = http.MethodDelete
	original.URL.Path = "/changed"
	original.Host = "other.example"
	original.Header.Set("Accept-Signature", "changed")
	f.opts.ExpectedDomain = "attacker.example"
	f.opts.AdditionalComponents[0].Name = "location"
	f.opts.AdditionalComponents[1].Params["key"] = "absent"
	f.opts.AdditionalComponents[1].ParamOrder[0] = "changed"
	release <- struct{}{}
	if err := <-result; err != nil {
		t.Fatalf("caller mutation changed in-flight policy: %v", err)
	}
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, server.URL+"/original", nil)
	go func() {
		res, err := client.Do(req)
		if res != nil {
			res.Body.Close()
		}
		result <- err
	}()
	second := <-prepared
	release <- struct{}{}
	if err := <-result; err != nil {
		t.Fatal(err)
	}
	if first == second {
		t.Fatal("repeated send reused challenge")
	}
}

func TestNegotiatedResponse_ClientReusesConnectionsOverHTTP2(t *testing.T) {
	f := newResponseFixture(t)
	f.signer.resolver = f.checker.resolver
	var calls, connections atomic.Int32
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		calls.Add(1)
		serveNegotiatedResponse(t, f, w, req, http.StatusOK)
	}))
	server.EnableHTTP2 = true
	server.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		if state == http.StateNew {
			connections.Add(1)
		}
	}
	server.StartTLS()
	defer server.Close()
	base := server.Client()
	client := f.signer.CreateSignedHTTPClient(base, SigningOptions{ResponseSignature: &f.opts})
	for attempt := 0; attempt < 2; attempt++ {
		req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, server.URL, nil)
		res, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		if res.ProtoMajor != 2 {
			t.Fatalf("protocol = %s", res.Proto)
		}
		res.Body.Close()
	}
	if calls.Load() != 2 || connections.Load() != 1 {
		t.Fatalf("requests=%d connections=%d", calls.Load(), connections.Load())
	}
	original := base.Transport.(*http.Transport)
	if original.DisableKeepAlives || original.DisableCompression {
		t.Fatal("modified caller transport")
	}
}

func TestNegotiatedResponse_ClientUsesCustomRoundTripper(t *testing.T) {
	f := newResponseFixture(t)
	f.signer.resolver = f.checker.resolver
	var calls int
	base := &http.Client{Transport: httpRoundTripperFunc(func(req *http.Request) (*http.Response, error) {
		calls++
		res := f.response(t, req)
		if calls == 2 {
			res.Header.Set("Cache-Control", "max-age=60")
		}
		return res, nil
	})}
	client := f.signer.CreateSignedHTTPClient(base, SigningOptions{ResponseSignature: &f.opts})
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "https://gateway.example/", nil)
	res, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	// A round tripper that rewrites covered fields causes rejection, not success.
	req, _ = http.NewRequestWithContext(context.Background(), http.MethodGet, "https://gateway.example/", nil)
	_, err = client.Do(req)
	var verification *dnsid.VerificationError
	if !errors.As(err, &verification) || calls != 2 {
		t.Fatalf("rewritten response accepted: %v calls=%d", err, calls)
	}
	var argument *dnsid.ArgumentError
	f.signer.resolver = nil
	base.Transport = &http.Transport{DialContext: func(context.Context, string, string) (net.Conn, error) {
		calls++
		return nil, errors.New("unexpected network work")
	}}
	client = f.signer.CreateSignedHTTPClient(base, SigningOptions{ResponseSignature: &f.opts})
	_, err = client.Do(req)
	if !errors.As(err, &argument) || calls != 2 {
		t.Fatalf("missing resolver was not rejected before send: %v calls=%d", err, calls)
	}
}

func TestNegotiatedResponse_ClientDeadlineAndCancellation(t *testing.T) {
	for _, cancelEarly := range []bool{false, true} {
		t.Run(map[bool]string{false: "deadline", true: "cancellation"}[cancelEarly], func(t *testing.T) {
			f := newResponseFixture(t)
			f.signer.resolver = f.checker.resolver
			started, closed := make(chan struct{}), make(chan struct{})
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				res := f.response(t, req)
				defer res.Body.Close()
				for name, values := range res.Header {
					w.Header()[name] = values
				}
				w.WriteHeader(http.StatusOK)
				_, _ = io.WriteString(w, "response ")
				w.(http.Flusher).Flush()
				close(started)
				<-req.Context().Done()
				close(closed)
			}))
			defer server.Close()
			client := f.signer.CreateSignedHTTPClient(server.Client(), SigningOptions{ResponseSignature: &f.opts})
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			req, _ := http.NewRequestWithContext(ctx, http.MethodGet, server.URL, nil)
			done := make(chan error, 1)
			go func() {
				res, err := client.Do(req)
				if res != nil {
					res.Body.Close()
					done <- errors.New("returned unverified content")
					return
				}
				done <- err
			}()
			select {
			case <-started:
			case err := <-done:
				t.Fatalf("send failed before response read: %v", err)
			case <-time.After(3 * time.Second):
				t.Fatal("response read did not start")
			}
			if cancelEarly {
				cancel()
			}
			select {
			case err := <-done:
				if err == nil {
					t.Fatal("budget exhaustion accepted")
				}
			case <-time.After(3 * time.Second):
				t.Fatal("budget not enforced")
			}
			select {
			case <-closed:
			case <-time.After(3 * time.Second):
				t.Fatal("owned connection not released")
			}
		})
	}
}

func TestNegotiatedResponse_ClientCacheReplayRejects(t *testing.T) {
	f := newResponseFixture(t)
	f.signer.resolver = f.checker.resolver
	var cached http.Header
	var calls int
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		calls++
		if cached == nil {
			res := f.response(t, req)
			cached = res.Header.Clone()
			res.Body.Close()
		}
		for name, values := range cached {
			w.Header()[name] = values
		}
		_, _ = io.WriteString(w, "response content")
	}))
	defer server.Close()
	client := f.signer.CreateSignedHTTPClient(server.Client(), SigningOptions{ResponseSignature: &f.opts})
	for i := 0; i < 2; i++ {
		req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, server.URL, nil)
		res, err := client.Do(req)
		if i == 0 && err != nil {
			t.Fatal(err)
		}
		if i == 1 && (err == nil || res != nil) {
			t.Fatal("cached response accepted for new challenge")
		}
		if res != nil {
			res.Body.Close()
		}
	}
	if calls != 2 {
		t.Fatal("wrapper reused a response")
	}
}

func TestNegotiatedResponse_ClientPreservesCodedContent(t *testing.T) {
	f := newResponseFixture(t)
	f.signer.resolver = f.checker.resolver
	// Compression stays disabled, including when the original transport enables it.
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.Header.Get("Accept-Encoding") != "" {
			t.Error("transport requested transparent decoding")
		}
		res := responseMessage("coded bytes")
		res.Header.Set("Content-Encoding", "gzip")
		signed, err := f.signer.SignRequestedHTTPResponse(req, res)
		if err != nil {
			t.Error(err)
			return
		}
		defer signed.Body.Close()
		for name, values := range signed.Header {
			w.Header()[name] = values
		}
		_, _ = io.Copy(w, signed.Body)
	}))
	defer server.Close()
	client := f.signer.CreateSignedHTTPClient(server.Client(), SigningOptions{ResponseSignature: &f.opts})
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, server.URL, nil)
	res, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	content, _ := io.ReadAll(res.Body)
	if string(content) != "coded bytes" || res.Uncompressed {
		t.Fatal("transport altered signed content")
	}
}

func TestNegotiatedResponse_CurrentPeerTakenFromResponseConnection(t *testing.T) {
	f := newResponseFixture(t)
	// The connection evidence route is tested with a resolver that delegates core
	// validation and records only the trusted options passed to it.
	resolver := &peerObservingResolver{IdentityResolver: f.checker.resolver}
	f.signer.resolver = resolver
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) { serveNegotiatedResponse(t, f, w, req, http.StatusOK) }))
	defer server.Close()
	client := f.signer.CreateSignedHTTPClient(server.Client(), SigningOptions{ResponseSignature: &f.opts})
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, server.URL, nil)
	req.TLS = &tls.ConnectionState{} // Caller-supplied request metadata is not server evidence.
	res, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if resolver.peer.PeerCertificate == nil || len(resolver.peer.VerifiedPeerCertificateChains) == 0 || !strings.EqualFold(resolver.peer.PeerCertificate.Subject.CommonName, server.Certificate().Subject.CommonName) {
		t.Fatal("did not forward current server peer")
	}
	if remaining := time.Until(resolver.deadline); remaining <= 0 || remaining > dnsid.DefaultVerificationTimeout {
		t.Fatal("send and verification did not share the finite default budget")
	}
}

type peerObservingResolver struct {
	dnsid.IdentityResolver
	peer     dnsid.VerifyDomainOpts
	deadline time.Time
}

func (r *peerObservingResolver) VerifyDomainWithOptions(ctx context.Context, domain string, opts dnsid.VerifyDomainOpts) (*dnsid.VerifiedDomain, error) {
	r.peer = opts
	r.deadline, _ = ctx.Deadline()
	return dnsid.VerifyIdentity(ctx, r.IdentityResolver, domain, opts)
}
