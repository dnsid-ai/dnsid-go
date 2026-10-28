package httpsig

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestNegotiatedResponse_UpgradeAdvertisementIsOrdinary(t *testing.T) {
	f := newResponseFixture(t)
	req := f.request(t)
	res := responseMessage("response content")
	res.Header.Set("Upgrade", "h2")
	signed, err := f.signer.SignRequestedHTTPResponse(req, res)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.checker.VerifySignedHTTPResponse(context.Background(), req, signed, f.opts); err != nil {
		t.Fatal(err)
	}
}

func TestNegotiatedResponse_IntermediaryRequestSignatureLabel(t *testing.T) {
	f := newResponseFixture(t)
	req := f.request(t)
	// The server sees a request with an added gateway signature member.
	received := req.Clone(context.Background())
	received.Header.Set("Signature-Input", req.Header.Get("Signature-Input")+`, gateway=("@method");created=1`)
	received.Header.Set("Signature", req.Header.Get("Signature")+", gateway=:AAAA:")
	signed, err := f.signer.SignRequestedHTTPResponse(received, responseMessage("response content"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.checker.VerifySignedHTTPResponse(context.Background(), req, signed, f.opts); err != nil {
		t.Fatal(err)
	}
}

func TestNegotiatedResponse_LifetimeIndependentOfMaxAge(t *testing.T) {
	f := newResponseFixture(t)
	f.signer.cfg.MaxAge = 10 * time.Minute
	f.checker.cfg.MaxAge = 30 * time.Second
	req := f.request(t)
	res := f.response(t, req)
	params := responseParams(t, res)
	if params.Expires-params.Created != 60 {
		t.Fatalf("lifetime = %d", params.Expires-params.Created)
	}
	if _, err := f.checker.VerifySignedHTTPResponse(context.Background(), req, res, f.opts); err != nil {
		t.Fatal(err)
	}
}

func TestNegotiatedResponse_SigningMiddleware(t *testing.T) {
	f := newResponseFixture(t)
	f.signer.resolver = f.checker.resolver
	handler := f.signer.ResponseSigningMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-App", "secret")
		if r.URL.Path == "/large" {
			_, _ = w.Write(make([]byte, 8<<20+1))
			return
		}
		w.WriteHeader(http.StatusCreated)
		_, _ = io.WriteString(w, "created")
	}))
	server := httptest.NewTLSServer(handler)
	defer server.Close()

	client := f.signer.CreateSignedHTTPClient(server.Client(), SigningOptions{ResponseSignature: &f.opts})
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodPost, server.URL+"/", strings.NewReader("x"))
	res, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(res.Body)
	res.Body.Close()
	if res.StatusCode != http.StatusCreated || string(body) != "created" {
		t.Fatalf("response = %d %q", res.StatusCode, body)
	}

	plain, err := server.Client().Get(server.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	plain.Body.Close()
	if plain.Header.Get("Signature") != "" || plain.StatusCode != http.StatusCreated {
		t.Fatal("request without negotiation was signed or changed")
	}

	for _, path := range []string{"/large", "/missing-field"} {
		opts := f.opts
		if path == "/missing-field" {
			opts.AdditionalComponents = []ComponentIdentifier{{Name: "x-absent"}}
		}
		prepared, _ := http.NewRequest(http.MethodGet, server.URL+path, nil)
		signedReq, err := f.signer.CreateSignedHTTPRequest(prepared, SigningOptions{ResponseSignature: &opts})
		if err != nil {
			t.Fatal(err)
		}
		failed, err := server.Client().Do(signedReq)
		if err != nil {
			t.Fatal(err)
		}
		content, _ := io.ReadAll(failed.Body)
		failed.Body.Close()
		if failed.StatusCode != http.StatusInternalServerError || len(content) != 0 || failed.Header.Get("X-App") != "" || failed.Header.Get("Signature") != "" {
			t.Fatalf("%s: unsigned application response sent: %d %q", path, failed.StatusCode, content)
		}
	}
}
