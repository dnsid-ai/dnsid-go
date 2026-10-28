package httpsig

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"io"
	"net/http"
	"slices"
	"strings"
	"testing"
	"testing/iotest"
	"time"

	"github.com/dnsid-ai/dnsid-go"
	"github.com/forcebit/http-message-signatures-rfc9421-go/pkg/sfv"
	"github.com/lestrrat-go/jwx/v3/jwk"
)

type responseFixture struct {
	signer, checker *Profile
	keys            dnsid.KeyProvider
	opts            ResponseSignatureOptions
}

func newResponseFixture(t *testing.T) *responseFixture {
	t.Helper()
	issuer, kp, verifier := testManagers(t)
	return &responseFixture{NewFromIdentityManager(issuer, kp, Config{}), NewFromIdentityManager(verifier, nil, Config{}), kp, ResponseSignatureOptions{ExpectedDomain: issuer.Domain()}}
}

func (f *responseFixture) request(t *testing.T) *http.Request {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, "https://gateway.example/resource?q=1", strings.NewReader("original request content"))
	if err != nil {
		t.Fatal(err)
	}
	signed, err := f.signer.CreateSignedHTTPRequest(req, SigningOptions{ResponseSignature: &f.opts})
	if err != nil {
		t.Fatal(err)
	}
	return signed
}

func responseMessage(content string) *http.Response {
	return &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Content-Type": {"text/plain"}, "Cache-Control": {"private"}, "X-Meta": {`choice="value"`}}, Body: io.NopCloser(strings.NewReader(content))}
}

func (f *responseFixture) response(t *testing.T, req *http.Request) *http.Response {
	t.Helper()
	res, err := f.signer.SignRequestedHTTPResponse(req, responseMessage("response content"))
	if err != nil {
		t.Fatal(err)
	}
	return res
}

func responseParams(t *testing.T, res *http.Response) SignatureParams {
	t.Helper()
	inputs, err := ParseSignatureInput(res.Header.Get("Signature-Input"))
	if err != nil {
		t.Fatal(err)
	}
	params := inputs["sig1"]
	params.Parameters = nil
	return params
}

func resignResponse(t *testing.T, f *responseFixture, req *http.Request, res *http.Response, params SignatureParams) {
	t.Helper()
	res.Request = req
	if err := SignHTTPMessage(res, params, f.keys); err != nil {
		t.Fatal(err)
	}
}

func assertResponseRejected(t *testing.T, f *responseFixture, req *http.Request, res *http.Response) {
	t.Helper()
	vd, err := f.checker.VerifySignedHTTPResponse(context.Background(), req, res, f.opts)
	var verification *dnsid.VerificationError
	if vd != nil || !errors.As(err, &verification) || verification.Transient() {
		t.Fatalf("want permanent verification rejection, got %v, %v", vd, err)
	}
}

func TestNegotiatedResponse_PreparationAndRequestOnly(t *testing.T) {
	f := newResponseFixture(t)
	req, _ := http.NewRequest(http.MethodGet, "https://gateway.example/resource", nil)
	plain, err := f.signer.CreateSignedHTTPRequest(req, SigningOptions{})
	if err != nil || plain.Header.Get("Accept-Signature") != "" {
		t.Fatalf("request-only preparation: %v", err)
	}
	f.opts.AdditionalComponents = []ComponentIdentifier{{Name: "content-type"}}
	first, second := f.request(t), f.request(t)
	if first.Header.Get("Accept-Signature") == second.Header.Get("Accept-Signature") || first.Header.Get("Signature") == second.Header.Get("Signature") {
		t.Fatal("attempt reused challenge or signature")
	}
	dict, err := sfv.NewParser(first.Header.Get("Accept-Signature"), sfv.DefaultLimits()).ParseDictionary()
	if err != nil || !slices.Equal(dict.Keys, []string{"sig1"}) {
		t.Fatalf("negotiation dictionary: %v", err)
	}
	inner := dict.Values["sig1"].(sfv.InnerList)
	if len(inner.Items) != 10 || len(inner.Parameters) != 3 || inner.Parameters[0] != (sfv.Parameter{Key: "created", Value: true}) || inner.Parameters[1] != (sfv.Parameter{Key: "expires", Value: true}) {
		t.Fatalf("negotiation = %+v", inner)
	}
	for i, want := range append(requiredResponseComponents("sig1"), ComponentIdentifier{Name: "content-type"}) {
		if inner.Items[i].Value != want.Name {
			t.Fatalf("component %d = %+v", i, inner.Items[i])
		}
		if want.Params["req"] == true && (len(inner.Items[i].Parameters) != len(want.Params) || inner.Items[i].Parameters[0] != (sfv.Parameter{Key: "req", Value: true})) {
			t.Fatal("missing request context")
		}
		if key, ok := want.Params["key"]; ok && inner.Items[i].Parameters[1] != (sfv.Parameter{Key: "key", Value: key}) {
			t.Fatal("request signature member is not key-selected")
		}
	}
	nonce := inner.Parameters[2].Value.(string)
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(nonce)
	if err != nil || len(decoded) < 32 || base64.RawURLEncoding.EncodeToString(decoded) != nonce {
		t.Fatal("invalid challenge entropy/encoding")
	}
	inputs, _ := ParseSignatureInput(first.Header.Get("Signature-Input"))
	if !containsComponent(inputs["sig1"].Components, ComponentIdentifier{Name: "accept-signature"}) {
		t.Fatal("request does not cover negotiation")
	}
	if _, err := f.checker.VerifyHTTPRequest(context.Background(), first); err != nil {
		t.Fatal(err)
	}
	first.Header.Set("Accept-Signature", second.Header.Get("Accept-Signature"))
	if _, err := f.checker.VerifyHTTPRequest(context.Background(), first); err == nil {
		t.Fatal("request negotiation change accepted")
	}
}

type countingKeys struct {
	dnsid.KeyProvider
	calls         int
	metadataCalls int
	sign          func([]byte) (*dnsid.KeySignature, error)
}

func (k *countingKeys) JWK(kid ...string) jwk.Key {
	k.metadataCalls++
	return k.KeyProvider.JWK(kid...)
}
func (k *countingKeys) ListKeyIds() []string { k.metadataCalls++; return k.KeyProvider.ListKeyIds() }

func (k *countingKeys) Sign(input []byte) (*dnsid.KeySignature, error) {
	k.calls++
	if k.sign != nil {
		return k.sign(input)
	}
	return k.KeyProvider.Sign(input)
}

func TestNegotiatedResponse_InvalidLocalOptionsBeforeIO(t *testing.T) {
	f := newResponseFixture(t)
	for _, name := range []string{"domain", "http", "header", "lowercase-header", "empty-header", "unsupported", "duplicate", "missing-req", "oversized-target", "oversized-headers"} {
		t.Run(name, func(t *testing.T) {
			keys := &countingKeys{KeyProvider: f.keys}
			profile := New(nil, f.opts.ExpectedDomain, keys, Config{})
			req, _ := http.NewRequest(http.MethodGet, "https://gateway.example/", nil)
			opts := f.opts
			switch name {
			case "domain":
				opts.ExpectedDomain = "https://not-a-domain/"
			case "http":
				req.URL.Scheme = "http"
			case "header":
				req.Header.Set("Accept-Signature", "caller-policy")
			case "lowercase-header":
				req.Header["accept-signature"] = []string{"caller-policy"}
			case "empty-header":
				req.Header["Accept-Signature"] = nil
			case "unsupported":
				opts.AdditionalComponents = []ComponentIdentifier{{Name: "content-type", Params: map[string]any{"sf": true}}}
			case "duplicate":
				opts.AdditionalComponents = []ComponentIdentifier{{Name: "@status"}}
			case "missing-req":
				opts.AdditionalComponents = []ComponentIdentifier{{Name: " @path "}}
			case "oversized-target":
				req.URL.Path = "/" + strings.Repeat("x", 64<<10)
			case "oversized-headers":
				req.Header.Set("X-Large", strings.Repeat("x", 1<<20))
			}
			_, err := profile.CreateSignedHTTPRequest(req, SigningOptions{ResponseSignature: &opts})
			var argument *dnsid.ArgumentError
			if !errors.As(err, &argument) || keys.calls != 0 || keys.metadataCalls != 0 {
				t.Fatalf("want local argument rejection without signing: %v, calls=%d", err, keys.calls)
			}
			if name == "header" && req.Header.Get("Accept-Signature") != "caller-policy" {
				t.Fatal("caller policy overwritten")
			}
		})
	}
}

func TestNegotiatedResponse_ServerNoNegotiation(t *testing.T) {
	f := newResponseFixture(t)
	req, _ := http.NewRequest(http.MethodGet, "https://gateway.example/", nil)
	keys := &countingKeys{KeyProvider: f.keys}
	for _, profile := range []*Profile{New(nil, "", nil, Config{}), New(nil, f.opts.ExpectedDomain, keys, Config{})} {
		res := responseMessage("unchanged")
		got, err := profile.SignRequestedHTTPResponse(req, res)
		if err != nil || got != res || keys.calls != 0 || keys.metadataCalls != 0 || res.Header.Get("Content-Digest") != "" {
			t.Fatalf("unsigned no-op failed: %v", err)
		}
	}
}

func TestNegotiatedResponse_NonDefaultLabelAndEquivalentFlags(t *testing.T) {
	f := newResponseFixture(t)
	f.opts.AdditionalComponents = []ComponentIdentifier{{Name: "content-type"}}
	req := f.request(t)
	value := req.Header.Get("Accept-Signature")
	value = strings.Replace(value, "sig1=", "service=", 1)
	value = strings.Replace(value, `"@status" "@method";req`, `"@method";req=?1 "@status"`, 1)
	value = strings.Replace(value, ";created;expires;", ";expires=?1;created=?1;", 1)
	req.Header.Set("Accept-Signature", value)
	res := f.response(t, req)
	if !strings.HasPrefix(res.Header.Get("Signature-Input"), "service=") || !strings.Contains(res.Header.Get("Signature-Input"), `("@method";req "@status"`) {
		t.Fatalf("request not preserved: %s", res.Header.Get("Signature-Input"))
	}
	if _, err := f.checker.VerifySignedHTTPResponse(context.Background(), req, res, f.opts); err != nil {
		t.Fatal(err)
	}
	if got, _ := io.ReadAll(res.Body); string(got) != "response content" {
		t.Fatalf("body = %q", got)
	}
}

func TestNegotiatedResponse_MalformedNegotiation(t *testing.T) {
	f := newResponseFixture(t)
	valid := f.request(t).Header.Get("Accept-Signature")
	withoutNonce := valid[:strings.Index(valid, ";nonce=")]
	cases := map[string]string{
		"empty": "", "not-list": "sig1=?1", "trailing-junk": valid + " junk", "trailing-comma": valid + ",",
		"duplicate-label": valid + ", " + valid, "multiple-members": valid + ", " + strings.Replace(valid, "sig1=", "other=", 1),
		"duplicate-parameter": valid + ";created", "wrong-time-type": strings.Replace(valid, ";created;", ";created=1;", 1),
		"false-time": strings.Replace(valid, ";expires;", ";expires=?0;", 1), "unknown-constraint": valid + `;keyid="agent.example.com#key"`,
		"duplicate-component":       strings.Replace(valid, `"@status"`, `"@status" "@status"`, 1),
		"duplicate-component-param": strings.Replace(valid, `;req `, `;req;req `, 1),
		"unsupported-component":     strings.Replace(valid, `"@status"`, `"@unknown"`, 1),
		"unsupported-param":         strings.Replace(valid, `"content-digest"`, `"content-digest";sf`, 1),
		"false-req":                 strings.Replace(valid, `;req `, `;req=?0 `, 1),
		"missing-required":          strings.Replace(valid, `"signature-input";req;key="sig1" `, "", 1),
		"mismatched-member-keys":    strings.Replace(valid, `"signature";req;key="sig1"`, `"signature";req;key="other"`, 1),
		"short-nonce":               withoutNonce + `;nonce="AA"`,
		"noncanonical-nonce":        withoutNonce + `;nonce="` + strings.Repeat("A", 42) + `B"`,
		"wrong-nonce-type":          withoutNonce + `;nonce=?1`,
		"space-in-component":        strings.Replace(valid, `"@status"`, `" @status "`, 1),
		"unkeyed-request-signature": strings.Replace(valid, `"signature";req;key="sig1"`, `"signature";req`, 1),
		"padded-nonce":              valid[:len(valid)-1] + `="`,
		"token-nonce":               valid[:strings.Index(valid, `;nonce=`)] + `;nonce=token`,
		"long-nonce":                valid[:strings.Index(valid, `;nonce=`)] + `;nonce="` + strings.Repeat("A", 1026) + `"`,
		"oversized":                 valid + strings.Repeat(" ", 16<<10),
	}
	for name, value := range cases {
		t.Run(name, func(t *testing.T) {
			req := f.request(t)
			req.Header.Set("Accept-Signature", value)
			res := responseMessage("not sent")
			keys := &countingKeys{KeyProvider: f.keys}
			profile := New(nil, f.opts.ExpectedDomain, keys, Config{})
			got, err := profile.SignRequestedHTTPResponse(req, res)
			var verification *dnsid.VerificationError
			if got != nil || !errors.As(err, &verification) || verification.Transient() || keys.calls != 0 || keys.metadataCalls != 0 {
				t.Fatalf("partial/unsigned success or wrong rejection: %v, calls=%d", err, keys.calls)
			}
			if res.Header.Get("Content-Digest") != "" || res.Header.Get("Signature") != "" || res.Header.Get("Cache-Control") != "private" {
				t.Fatal("failed negotiation committed fields")
			}
		})
	}
}

func TestNegotiatedResponse_ContentAndCleanup(t *testing.T) {
	for _, name := range []string{"ordinary", "empty", "HEAD", "204", "205", "304"} {
		t.Run(name, func(t *testing.T) {
			f := newResponseFixture(t)
			req := f.request(t)
			content := "response content"
			if name != "ordinary" {
				content = ""
			}
			original := &closeTrackingBody{Reader: strings.NewReader(content)}
			res := responseMessage(content)
			res.Body = original
			switch name {
			case "HEAD":
				req.Method = http.MethodHead
				res.Body = nil
			case "204":
				res.StatusCode = http.StatusNoContent
				res.Body = nil
			case "205":
				res.StatusCode = http.StatusResetContent
				res.Body = nil
			case "304":
				res.StatusCode = http.StatusNotModified
				res.Body = nil
			}
			signed, err := f.signer.SignRequestedHTTPResponse(req, res)
			if err != nil {
				t.Fatal(err)
			}
			sum := sha256.Sum256([]byte(content))
			if signed.Header.Get("Content-Digest") != "sha-256=:"+base64.StdEncoding.EncodeToString(sum[:])+":" || signed.Header.Get("Cache-Control") != "private, no-store" {
				t.Fatal("incorrect digest/cache policy")
			}
			vd, err := f.checker.VerifySignedHTTPResponse(context.Background(), req, signed, f.opts)
			if err != nil || vd.Domain() != f.opts.ExpectedDomain {
				t.Fatalf("verify: %v", err)
			}
			body, _ := io.ReadAll(signed.Body)
			if string(body) != content {
				t.Fatalf("body changed: %q", body)
			}
			if err := signed.Body.Close(); err != nil {
				t.Fatal(err)
			}
			if (name == "ordinary" || name == "empty") && !original.closed {
				t.Fatal("lost original cleanup")
			}
		})
	}
}

func TestNegotiatedResponse_MetadataAndUnavailableContent(t *testing.T) {
	for _, name := range []string{"missing-field", "changed-field", "omitted-coverage", "unavailable-server-body", "unavailable-client-body", "decoded-server", "decoded-client", "uncovered-metadata", "read-error"} {
		t.Run(name, func(t *testing.T) {
			f := newResponseFixture(t)
			if name != "uncovered-metadata" {
				f.opts.AdditionalComponents = []ComponentIdentifier{{Name: "content-type"}}
			}
			req := f.request(t)
			res := responseMessage("response content")
			switch name {
			case "missing-field":
				res.Header.Del("Content-Type")
			case "unavailable-server-body":
				res.Body = nil
			case "decoded-server":
				res.Uncompressed = true
			}
			signed, err := f.signer.SignRequestedHTTPResponse(req, res)
			if name == "missing-field" || name == "unavailable-server-body" || name == "decoded-server" {
				if err == nil || signed != nil {
					t.Fatal("invalid server response signed")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			switch name {
			case "changed-field", "uncovered-metadata":
				signed.Header.Set("Content-Type", "application/json")
			case "omitted-coverage":
				params := responseParams(t, signed)
				params.Components = params.Components[:len(params.Components)-1]
				resignResponse(t, f, req, signed, params)
			case "unavailable-client-body":
				signed.Body = nil
			case "decoded-client":
				signed.Uncompressed = true
			case "read-error":
				signed.Body = &closeTrackingBody{Reader: iotest.ErrReader(io.ErrUnexpectedEOF)}
			}
			if name == "uncovered-metadata" {
				if _, err := f.checker.VerifySignedHTTPResponse(context.Background(), req, signed, f.opts); err != nil {
					t.Fatal(err)
				}
				return
			}
			assertResponseRejected(t, f, req, signed)
		})
	}
}

func TestNegotiatedResponse_LabelCollisionAndPreservation(t *testing.T) {
	f := newResponseFixture(t)
	for _, name := range []string{"Signature", "Signature-Input", "unrelated"} {
		t.Run(name, func(t *testing.T) {
			req := f.request(t)
			res := responseMessage("response content")
			label := "sig1"
			if name == "unrelated" {
				label = "other"
			}
			params := SignatureParams{Label: label, Components: []ComponentIdentifier{{Name: "@status"}}, Created: time.Now().Unix()}
			if err := SignHTTPMessage(res, params, f.keys); err != nil {
				t.Fatal(err)
			}
			if name == "Signature" {
				res.Header.Del("Signature-Input")
			}
			if name == "Signature-Input" {
				res.Header.Del("Signature")
			}
			before := res.Header.Clone()
			signed, err := f.signer.SignRequestedHTTPResponse(req, res)
			if name != "unrelated" {
				if err == nil || signed != nil || !slices.Equal(res.Header.Values(name), before.Values(name)) {
					t.Fatal("collision replaced")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(signed.Header.Get("Signature"), before.Get("Signature")) {
				t.Fatal("other label lost")
			}
			if _, err := f.checker.VerifySignedHTTPResponse(context.Background(), req, signed, f.opts); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestNegotiatedResponse_SigningFailureAtomicity(t *testing.T) {
	f := newResponseFixture(t)
	for _, name := range []string{"provider-fails", "key-changes", "oversized-body"} {
		t.Run(name, func(t *testing.T) {
			keys := &countingKeys{KeyProvider: f.keys}
			if name == "provider-fails" {
				keys.sign = func([]byte) (*dnsid.KeySignature, error) { return nil, errors.New("provider unavailable") }
			}
			if name == "key-changes" {
				keys.sign = func(b []byte) (*dnsid.KeySignature, error) {
					sig, err := f.keys.Sign(b)
					sig.Kid = "different"
					return sig, err
				}
			}
			profile := New(nil, f.opts.ExpectedDomain, keys, Config{})
			res := responseMessage("response content")
			if name == "oversized-body" {
				res.Body = io.NopCloser(bytes.NewReader(make([]byte, (8<<20)+1)))
			}
			if got, err := profile.SignRequestedHTTPResponse(f.request(t), res); err == nil || got != nil {
				t.Fatal("signing failure became unsigned success")
			}
			if res.Header.Get("Signature") != "" || res.Header.Get("Content-Digest") != "" || res.Header.Get("Cache-Control") != "private" {
				t.Fatal("failed signing committed response fields")
			}
		})
	}
}

func TestNegotiatedResponse_SelectionAndFreshnessBoundaries(t *testing.T) {
	for _, name := range []string{"unsigned", "wrong-label", "missing-signature", "missing-input", "coverage", "order", "nonce", "missing-nonce", "created", "expires", "equal-times", "expired", "future", "lifetime", "algorithm", "missing-algorithm", "wrong-key-metadata", "non-current-key", "no-store", "quoted-no-store", "unicode-no-store", "non-OWS-no-store"} {
		t.Run(name, func(t *testing.T) {
			f := newResponseFixture(t)
			req := f.request(t)
			res := f.response(t, req)
			params := responseParams(t, res)
			switch name {
			case "unsigned":
				res.Header.Del("Signature")
				res.Header.Del("Signature-Input")
			case "wrong-label":
				params.Label = "unrelated"
				res.Header.Del("Signature")
				res.Header.Del("Signature-Input")
				resignResponse(t, f, req, res, params)
			case "missing-signature":
				res.Header.Del("Signature")
			case "missing-input":
				res.Header.Del("Signature-Input")
			default:
				switch name {
				case "coverage":
					params.Components = params.Components[1:]
				case "order":
					params.Components[0], params.Components[1] = params.Components[1], params.Components[0]
				case "nonce":
					params.Nonce = base64.RawURLEncoding.EncodeToString(make([]byte, 32))
				case "missing-nonce":
					params.Nonce = ""
				case "created":
					params.Created = 0
				case "expires":
					params.Expires = 0
				case "equal-times":
					params.Expires = params.Created
				case "expired":
					params.Created -= 100
					params.Expires = params.Created + 1
				case "future":
					params.Created += 400
					params.Expires += 400
				case "lifetime":
					params.Expires = params.Created + 61
				case "algorithm":
					params.Alg = "rsa-pss-sha512"
				case "missing-algorithm":
					params.Alg = ""
				case "wrong-key-metadata":
					params.Alg = "ed25519"
				case "non-current-key":
					params.KeyID = f.opts.ExpectedDomain + "#retired"
				case "no-store":
					res.Header.Set("Cache-Control", "private")
				case "quoted-no-store":
					res.Header.Set("Cache-Control", `extension="x,no-store,y"`)
				case "unicode-no-store":
					res.Header.Set("Cache-Control", "no-ſtore")
				case "non-OWS-no-store":
					res.Header.Set("Cache-Control", "\u00a0no-store\u00a0")
				}
				resignResponse(t, f, req, res, params)
			}
			// A well-formed valid unrelated signature cannot replace the selected label.
			if name == "missing-signature" || name == "missing-input" || name == "unsigned" {
				other := responseParamsForRequest(t, f, req)
				other.Label = "unrelated"
				resignResponse(t, f, req, res, other)
			}
			assertResponseRejected(t, f, req, res)
		})
	}
}

func responseParamsForRequest(t *testing.T, f *responseFixture, req *http.Request) SignatureParams {
	t.Helper()
	res := f.response(t, req)
	defer res.Body.Close()
	return responseParams(t, res)
}

func TestNegotiatedResponse_TamperingAndGatewayRelay(t *testing.T) {
	for _, name := range []string{"status", "content", "cache", "method", "authority", "target", "negotiation", "signature-input", "signature", "gateway-relay"} {
		t.Run(name, func(t *testing.T) {
			f := newResponseFixture(t)
			req := f.request(t)
			res := f.response(t, req)
			res.Request, _ = http.NewRequest(http.MethodGet, "https://attacker.example/echo", nil)
			switch name {
			case "status":
				res.StatusCode = http.StatusForbidden
			case "content":
				res.Body = io.NopCloser(strings.NewReader("changed"))
			case "cache":
				res.Header.Set("Cache-Control", "public, no-store")
			case "method":
				req.Method = http.MethodDelete
			case "authority":
				req.Host = "attacker.example"
			case "target":
				req.URL.RawQuery = "different=1"
			case "negotiation":
				req.Header.Set("Accept-Signature", f.request(t).Header.Get("Accept-Signature"))
			case "signature-input":
				req.Header.Set("Signature-Input", req.Header.Get("Signature-Input")+";extension")
			case "signature":
				req.Header.Set("Signature", "sig1=:Y2hhbmdlZA==:")
			case "gateway-relay":
				gateway := New(nil, "gateway.example", dnsid.GenerateES256KeyProvider(), Config{})
				copied := req.Clone(req.Context())
				copied.Body = io.NopCloser(strings.NewReader("changed operation"))
				copied.Header.Del("Signature")
				copied.Header.Del("Signature-Input")
				forwarded, err := gateway.CreateSignedHTTPRequest(copied, SigningOptions{})
				if err != nil {
					t.Fatal(err)
				}
				res = f.response(t, forwarded)
				if _, err := f.checker.VerifySignedHTTPResponse(context.Background(), forwarded, res, f.opts); err != nil {
					t.Fatalf("relay fixture not valid for forwarded request: %v", err)
				}
			}
			assertResponseRejected(t, f, req, res)
		})
	}
}

// countingResolver observes the real core resolver boundary, not a fixture verdict.
type countingResolver struct {
	dnsid.IdentityResolver
	calls int
}

func (r *countingResolver) VerifyDomain(ctx context.Context, domain string) (*dnsid.VerifiedDomain, error) {
	r.calls++
	return r.IdentityResolver.VerifyDomain(ctx, domain)
}

func TestNegotiatedResponse_UnexpectedDomainBeforeLookup(t *testing.T) {
	f := newResponseFixture(t)
	req := f.request(t)
	other := New(nil, "other.example", f.keys, Config{})
	res, err := other.SignRequestedHTTPResponse(req, responseMessage("response content"))
	if err != nil {
		t.Fatal(err)
	}
	counter := &countingResolver{IdentityResolver: f.checker.resolver}
	f.checker.resolver = counter
	assertResponseRejected(t, f, req, res)
	if counter.calls != 0 {
		t.Fatal("looked up untrusted signer domain")
	}
}
