package httpsig_test

import (
	"fmt"
	"net/http"
	"strings"

	dnsid "github.com/dnsid-ai/dnsid-go"
	"github.com/dnsid-ai/dnsid-go/httpsig"
)

// Example signs an HTTP request with a locally generated key. A resolver is
// only needed for verification, so this signing-only profile passes nil.
func Example() {
	key := dnsid.GenerateEd25519KeyProvider()
	profile := httpsig.New(nil, "agent.example.com", key, httpsig.Config{})

	req, err := http.NewRequest(http.MethodGet, "https://api.example.com/search?q=dnsid", nil)
	if err != nil {
		panic(err)
	}
	signed, err := profile.CreateSignedHTTPRequest(req, httpsig.SigningOptions{})
	if err != nil {
		panic(err)
	}

	// Signature-Input records the covered components. Its created, keyid,
	// alg, and nonce parameters vary per run, so only the component list is
	// printed here.
	components, _, _ := strings.Cut(signed.Header.Get("Signature-Input"), ";created")
	fmt.Println(components)
	fmt.Println("signature present:", signed.Header.Get("Signature") != "")
	// Output:
	// sig1=("@method" "@authority" "@target-uri")
	// signature present: true
}
