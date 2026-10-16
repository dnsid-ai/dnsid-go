package httpsig

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
)

type closeTrackingBody struct {
	io.Reader
	closed bool
}

func (b *closeTrackingBody) Close() error {
	b.closed = true
	return nil
}

func TestProfile_BodyReplayPreservesClose(t *testing.T) {
	issuer, kp, verifier := testManagers(t)
	signer := NewFromIdentityManager(issuer, kp, Config{})
	checker := NewFromIdentityManager(verifier, nil, Config{})
	for _, mode := range []string{"signed", "original", "verified", "invalid-digest"} {
		t.Run(mode, func(t *testing.T) {
			original := &closeTrackingBody{Reader: strings.NewReader("hello")}
			req, _ := http.NewRequest(http.MethodPost, "https://target.example/path", original)
			signed, err := signer.CreateSignedHTTPRequest(req, SigningOptions{})
			if err != nil {
				t.Fatal(err)
			}
			body := signed.Body
			if mode == "original" {
				body = req.Body
			}
			if mode == "verified" || mode == "invalid-digest" {
				if mode == "invalid-digest" {
					original = &closeTrackingBody{Reader: strings.NewReader("changed")}
					signed.Body = original
				}
				_, err := checker.VerifyHTTPRequest(context.Background(), signed)
				if (err != nil) != (mode == "invalid-digest") {
					t.Fatalf("%v", err)
				}
				body = signed.Body
			}
			if original.closed {
				t.Fatal("operation closed caller-owned stream")
			}
			if err := body.Close(); err != nil {
				t.Fatal(err)
			}
			if !original.closed {
				t.Fatal("closing replay body did not close original stream")
			}
		})
	}
}
