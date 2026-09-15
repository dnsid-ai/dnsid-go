package joseutil

import (
	"encoding/base64"
	"strings"
	"testing"
)

func TestCompactAndJSON_RejectMalformedAndOversizedInput(t *testing.T) {
	for _, token := range []string{"e30.e30.AB", "e30.e30.AA\n", "e30=.e30.AA", "e30.e30.AA.extra", strings.Repeat("a", MaxTokenBytes+1)} {
		if _, _, _, err := Compact(token); err == nil {
			t.Fatalf("accepted malformed compact input (length %d)", len(token))
		}
	}
	for _, raw := range []string{`null`, `[]`, `{"x":1,"x":2}`, `{"x":[{"y":1,"y":2}]}`, `{"x":` + strings.Repeat("[", 65) + "0" + strings.Repeat("]", 65) + "}", "{\"x\":\"\xff\"}", strings.Repeat(" ", MaxPayloadBytes+1)} {
		if _, err := DecodeObject([]byte(raw)); err == nil {
			t.Fatal("accepted malformed or oversized JSON")
		}
	}
	token := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"ES256","kid":"key"}`)) + "..AA"
	if _, _, payload, err := Compact(token); err != nil || len(payload) != 0 {
		t.Fatal("empty encoded JWS payload rejected")
	}
}
