package httpsig

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/dnsid-ai/dnsid-go"
)

func TestNegotiatedResponse_NormalizedExpectedDomain(t *testing.T) {
	f := newResponseFixture(t)
	f.opts.ExpectedDomain = strings.ToUpper(f.opts.ExpectedDomain) + "."
	req := f.request(t)
	res := f.response(t, req)
	vd, err := f.checker.VerifySignedHTTPResponse(context.Background(), req, res, f.opts)
	if err != nil || vd.Domain() != "agent.example.com" {
		t.Fatalf("normalized policy: %v", err)
	}
	res.Body.Close()
}

func TestNegotiatedResponse_AdditionalComponentMatrixAndSigningConsistency(t *testing.T) {
	f := newResponseFixture(t)
	f.opts.AdditionalComponents = []ComponentIdentifier{
		{Name: "@path", Params: map[string]any{"req": true}},
		{Name: "@query-param", Params: map[string]any{"name": "q", "req": true}, ParamOrder: []string{"name", "req"}},
		{Name: "x-meta", Params: map[string]any{"key": "choice"}},
		{Name: "x-req-meta", Params: map[string]any{"key": "choice", "req": true}, ParamOrder: []string{"key", "req"}},
	}
	req := f.request(t)
	req.Header.Set("X-Req-Meta", `choice="request"`)
	res := responseMessage("response content")
	res.Header.Set("X-Meta", `choice="response"`)
	signed, err := f.signer.SignRequestedHTTPResponse(req, res)
	if err != nil {
		t.Fatal(err)
	}
	params := responseParams(t, signed)
	params.Components[len(params.Components)-1].ParamOrder = []string{"req", "key"}
	resignResponse(t, f, req, signed, params)
	if _, err := f.checker.VerifySignedHTTPResponse(context.Background(), req, signed, f.opts); err != nil {
		t.Fatal(err)
	}
	signed.Body.Close()
	for _, name := range []string{"signature", "signature-input"} {
		t.Run(name, func(t *testing.T) {
			opts := ResponseSignatureOptions{ExpectedDomain: f.opts.ExpectedDomain, AdditionalComponents: []ComponentIdentifier{{Name: name}}}
			unsigned, _ := http.NewRequest(http.MethodGet, "https://gateway.example/", nil)
			var argument *dnsid.ArgumentError
			if _, err := f.signer.CreateSignedHTTPRequest(unsigned, SigningOptions{ResponseSignature: &opts}); !errors.As(err, &argument) {
				t.Fatalf("want local argument rejection: %v", err)
			}
			f.opts.AdditionalComponents = nil
			req := f.request(t)
			req.Header.Set("Accept-Signature", strings.Replace(req.Header.Get("Accept-Signature"), ")", ` "`+name+`")`, 1))
			res := responseMessage("response content")
			signed, err := f.signer.SignRequestedHTTPResponse(req, res)
			var verification *dnsid.VerificationError
			if signed != nil || !errors.As(err, &verification) || res.Header.Get("Signature") != "" {
				t.Fatalf("want negotiation rejection without signing: %v", err)
			}
			res.Body.Close()
		})
	}
}

func TestNegotiatedResponse_NonCurrentOperationalKey(t *testing.T) {
	f, _, fetcher, _, _ := responseCoreFixture(t, dnsid.VerificationConfig{}, nil)
	req := f.request(t)
	res := f.response(t, req)
	next, err := f.keys.GenerateKey(dnsid.JoseAlgES256)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.keys.Activate(next); err != nil {
		t.Fatal(err)
	}
	current, err := json.Marshal(map[string]any{"keys": []any{f.keys.JWK()}})
	if err != nil {
		t.Fatal(err)
	}
	fetcher.responses["https://agent.example.com/ku.json"] = current
	// The old response signature remains mathematically valid, but its key is no
	// longer the operational key returned by real current-domain verification.
	assertResponseRejected(t, f, req, res)
}

func TestNegotiatedResponse_InvalidTimestampTypes(t *testing.T) {
	f := newResponseFixture(t)
	for _, name := range []string{"created", "expires"} {
		t.Run(name, func(t *testing.T) {
			req := f.request(t)
			res := f.response(t, req)
			params := responseParams(t, res)
			base, err := BuildSignatureInput(res, params)
			if err != nil {
				t.Fatal(err)
			}
			start := strings.Index(base, ";"+name+"=") + len(name) + 2
			end := start + strings.IndexAny(base[start:], ";\n")
			// Profile timestamps must remain integers, even with a valid signature.
			original := base[start:end]
			changed := `"` + original + `"`
			base = base[:start] + changed + base[end:]
			signature, err := f.keys.Sign([]byte(base))
			if err != nil {
				t.Fatal(err)
			}
			res.Header.Set("Signature-Input", strings.Replace(res.Header.Get("Signature-Input"), ";"+name+"="+original, ";"+name+"="+changed, 1))
			res.Header.Set("Signature", "sig1=:"+base64.StdEncoding.EncodeToString(signature.Signature)+":")
			assertResponseRejected(t, f, req, res)
		})
	}
}

func TestNegotiatedResponse_LocalFailureClosesOwnedRequest(t *testing.T) {
	f := newResponseFixture(t)
	body := &closeTrackingBody{Reader: strings.NewReader("request content")}
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodPost, "http://not-https.example/", body)
	client := f.signer.CreateSignedHTTPClient(nil, SigningOptions{ResponseSignature: &f.opts})
	res, err := client.Do(req)
	var argument *dnsid.ArgumentError
	if res != nil || !errors.As(err, &argument) || !body.closed {
		t.Fatalf("request cleanup failed: %v closed=%v", err, body.closed)
	}
}

type announcingBody struct {
	io.ReadCloser
	started chan struct{}
}

func (b *announcingBody) Read(p []byte) (int, error) {
	select {
	case <-b.started:
	default:
		close(b.started)
	}
	return b.ReadCloser.Read(p)
}

func TestNegotiatedResponse_ClientBodyReadCancellation(t *testing.T) {
	f := newResponseFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	reader, writer := io.Pipe()
	defer writer.Close()
	body := &announcingBody{ReadCloser: reader, started: make(chan struct{})}
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, "https://gateway.example/", body)
	client := f.signer.CreateSignedHTTPClient(nil, SigningOptions{ResponseSignature: &f.opts})
	done := make(chan error, 1)
	go func() {
		res, err := client.Do(req)
		if res != nil {
			res.Body.Close()
		}
		done <- err
	}()
	select {
	case <-body.started:
	case err := <-done:
		t.Fatalf("body preparation did not start: %v", err)
	case <-ctx.Done():
		t.Fatal("body preparation never started")
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("cancellation lost: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("blocked body preparation ignored cancellation")
	}
}

func TestNegotiatedResponse_WireFieldWhitespace(t *testing.T) {
	f := newResponseFixture(t)
	f.signer.resolver = f.checker.resolver
	f.opts.AdditionalComponents = []ComponentIdentifier{{Name: "content-type"}}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		res := responseMessage("response content")
		res.Header.Set("Cache-Control", "\tprivate\t")
		res.Header.Set("Content-Type", "\ttext/plain \t")
		signed, err := f.signer.SignRequestedHTTPResponse(req, res)
		if err != nil {
			t.Error(err)
			w.WriteHeader(http.StatusInternalServerError)
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
	if res.Header.Get("Content-Type") != "text/plain" {
		t.Fatal("wire field normalization mismatch")
	}
}

func TestNegotiatedResponse_RejectsControlCharactersInCoveredFields(t *testing.T) {
	f := newResponseFixture(t)
	f.opts.AdditionalComponents = []ComponentIdentifier{{Name: "content-type"}}
	req := f.request(t)
	for _, value := range []string{"text/plain\r\ninjected: yes", "text/\x00plain", "text/\x7fplain"} {
		res := responseMessage("response content")
		res.Header.Set("Content-Type", value)
		if signed, err := f.signer.SignRequestedHTTPResponse(req, res); signed != nil || err == nil {
			t.Fatal("signed invalid field bytes")
		}
		res.Body.Close()
	}
}

func TestNegotiatedResponse_Ed25519(t *testing.T) {
	issuer, keys, verifier := testManagersWithKeyProvider(t, dnsid.GenerateEd25519KeyProvider())
	f := &responseFixture{signer: NewFromIdentityManager(issuer, keys, Config{}), checker: NewFromIdentityManager(verifier, nil, Config{}), keys: keys, opts: ResponseSignatureOptions{ExpectedDomain: issuer.Domain()}}
	req := f.request(t)
	res := f.response(t, req)
	if responseParams(t, res).Alg != "ed25519" {
		t.Fatal("wrong HTTP algorithm mapping")
	}
	if _, err := f.checker.VerifySignedHTTPResponse(context.Background(), req, res, f.opts); err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
}

func TestNegotiatedResponse_ClientKnownNoContent(t *testing.T) {
	for _, tc := range []struct {
		method string
		status int
	}{{http.MethodHead, http.StatusOK}, {http.MethodGet, http.StatusNoContent}, {http.MethodGet, http.StatusResetContent}, {http.MethodGet, http.StatusNotModified}} {
		t.Run(tc.method+"/"+http.StatusText(tc.status), func(t *testing.T) {
			f := newResponseFixture(t)
			f.signer.resolver = f.checker.resolver
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) { serveNegotiatedResponse(t, f, w, req, tc.status) }))
			defer server.Close()
			client := f.signer.CreateSignedHTTPClient(server.Client(), SigningOptions{ResponseSignature: &f.opts})
			req, _ := http.NewRequestWithContext(context.Background(), tc.method, server.URL, nil)
			res, err := client.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			defer res.Body.Close()
			body, err := io.ReadAll(res.Body)
			if err != nil || len(body) != 0 {
				t.Fatalf("no-content response changed: %q, %v", body, err)
			}
		})
	}
}

func TestNegotiatedResponse_ClientRepeatedPOSTPreservesContent(t *testing.T) {
	f := newResponseFixture(t)
	f.signer.resolver = f.checker.resolver
	type observed struct{ body, challenge, signature string }
	requests := make(chan observed, 2)
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		body, err := io.ReadAll(req.Body)
		if err != nil {
			t.Error(err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		requests <- observed{string(body), req.Header.Get("Accept-Signature"), req.Header.Get("Signature")}
		serveNegotiatedResponse(t, f, w, req, http.StatusOK)
	}))
	defer server.Close()
	client := f.signer.CreateSignedHTTPClient(server.Client(), SigningOptions{ResponseSignature: &f.opts})
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodPost, server.URL, strings.NewReader("same operation content"))
	var previous observed
	for attempt := 0; attempt < 2; attempt++ {
		res, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		res.Body.Close()
		current := <-requests
		if current.body != "same operation content" {
			t.Fatalf("attempt %d changed body to %q", attempt, current.body)
		}
		if attempt > 0 && (current.challenge == previous.challenge || current.signature == previous.signature) {
			t.Fatal("explicit attempt reused challenge/signature")
		}
		previous = current
	}
	if req.Header.Get("Accept-Signature") != "" {
		t.Fatal("mutated original unsigned request policy")
	}
}
