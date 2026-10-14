package httpsig

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
)

func TestBuildSignatureInput_KeyedContentDigest(t *testing.T) {
	req, _ := http.NewRequest(http.MethodGet, "https://api.example.com/", nil)
	req.Header.Set("Content-Digest", "sha-256=:YWJj:, sha-512=:ZGVm:")
	base, err := BuildSignatureInput(req, SignatureParams{Components: []ComponentIdentifier{{Name: "content-digest", Params: map[string]any{"key": "sha-256"}}}})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(base, "\"content-digest\";key=\"sha-256\": :YWJj:\n") {
		t.Fatalf("keyed digest base includes more than the selected member: %s", base)
	}
}

func TestProfile_KeyedContentDigestRequiresSuppliedContent(t *testing.T) {
	issuer, kp, verifier := testManagers(t)
	signer := NewFromIdentityManager(issuer, kp, Config{})
	checker := NewFromIdentityManager(verifier, nil, Config{})
	for _, mode := range []string{"missing", "explicit-empty", "keyed-empty-mismatch", "keyed-only-with-body"} {
		t.Run(mode, func(t *testing.T) {
			req, _ := http.NewRequest(http.MethodGet, "https://api.example.com/", nil)
			req.Header.Set("Content-Digest", contentDigest(nil))
			if mode == "keyed-empty-mismatch" {
				req.Header.Set("Content-Digest", contentDigest([]byte("wrong")))
			}
			signed, err := signer.CreateSignedHTTPRequest(req, SigningOptions{AdditionalComponentIDs: []ComponentIdentifier{{Name: "content-digest", Params: map[string]any{"key": "sha-256"}}}})
			if err != nil {
				t.Fatal(err)
			}
			switch mode {
			case "explicit-empty", "keyed-empty-mismatch":
				signed.Body = http.NoBody
			case "keyed-only-with-body":
				signed.Body = io.NopCloser(strings.NewReader(""))
			}
			_, err = checker.VerifyHTTPRequest(context.Background(), signed)
			if mode == "explicit-empty" {
				if err != nil {
					t.Fatal(err)
				}
			} else if err == nil {
				t.Fatal("keyed digest accepted without supplied content or exact digest coverage")
			}
		})
	}
}
