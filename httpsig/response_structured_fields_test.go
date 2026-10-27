package httpsig

import (
	"context"
	"encoding/base64"
	"strings"
	"testing"

	"github.com/dnsid-ai/dnsid-go/internal/joseutil"
	"github.com/lestrrat-go/jwx/v3/jwk"
)

func TestNegotiatedResponse_ValidParameterWhitespace(t *testing.T) {
	f := newResponseFixture(t)
	req := f.request(t)
	// RFC 8941 section 3.1.2 permits SP after each parameter semicolon.
	req.Header.Set("Accept-Signature", strings.ReplaceAll(req.Header.Get("Accept-Signature"), ";", "; "))
	if _, err := f.signer.SignRequestedHTTPResponse(req, responseMessage("response content")); err != nil {
		t.Fatalf("valid RFC 8941 negotiation rejected: %v", err)
	}
}

func TestNegotiatedResponse_ValidUnknownDecimal(t *testing.T) {
	f := newResponseFixture(t)
	req := f.request(t)
	res := f.response(t, req)
	inputs, err := ParseSignatureInput(res.Header.Get("Signature-Input"))
	if err != nil {
		t.Fatal(err)
	}
	params := inputs["sig1"]
	params.Parameters = append(params.Parameters, SignatureParameter{Name: "extension", Value: int64(1)})
	if err := SignHTTPMessage(res, params, f.keys); err != nil {
		t.Fatal(err)
	}
	base, err := BuildSignatureInput(res, params)
	if err != nil {
		t.Fatal(err)
	}
	// The canonical RFC 8941 decimal serialization is 1.5, not integer 1.
	if strings.Count(base, ";extension=1") != 1 {
		t.Fatal("unexpected fixture base")
	}
	base = strings.Replace(base, ";extension=1", ";extension=1.5", 1)
	signature, err := f.keys.Sign([]byte(base))
	if err != nil {
		t.Fatal(err)
	}
	if !joseutil.VerifySignature(joseutil.ProtectedHeader{Alg: signature.Alg, Kid: signature.Kid}, joseutil.SignatureParts{SigningInput: []byte(base), Signature: signature.Signature}, []jwk.Key{f.keys.JWK()}) {
		t.Fatal("probe signature is not cryptographically valid")
	}
	res.Header.Set("Signature-Input", strings.Replace(res.Header.Get("Signature-Input"), ";extension=1", ";extension=1.5", 1))
	res.Header.Set("Signature", "sig1=:"+base64.StdEncoding.EncodeToString(signature.Signature)+":")
	if _, err := f.checker.VerifySignedHTTPResponse(context.Background(), req, res, f.opts); err != nil {
		t.Fatalf("valid signed response with RFC 8941 extension rejected: %v", err)
	}
}
