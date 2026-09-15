package httpsig

import (
	"bytes"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestHTTPVerification_ResourceLimits(t *testing.T) {
	if _, err := readBoundedBody(bytes.NewReader(make([]byte, (8<<20)+1))); err == nil {
		t.Fatal("oversized content accepted")
	}
	for _, name := range []string{"Signature", "Signature-Input"} {
		req := httptest.NewRequest(http.MethodGet, "https://example.com", nil)
		req.Header.Add(name, strings.Repeat("a", 16<<10))
		if _, err := parseHTTPSignatureHeaders(req); err == nil {
			t.Fatal("oversized signature header accepted")
		}
	}
	var labels, components []string
	for i := range 129 {
		labels = append(labels, fmt.Sprintf("a%d=();created=1", i))
		components = append(components, fmt.Sprintf(`"x%d"`, i))
	}
	for _, input := range []string{strings.Join(labels, ","), "sig=(" + strings.Join(components, " ") + ");created=1"} {
		if _, err := ParseSignatureInput(input); err == nil {
			t.Fatal("candidate/component limit not enforced")
		}
	}
}
