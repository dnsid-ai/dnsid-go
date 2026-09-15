package webbotauth_test

import (
	"fmt"
	"net/http"

	dnsid "github.com/dnsid-ai/dnsid-go"
	"github.com/dnsid-ai/dnsid-go/webbotauth"
)

// Example creates a Web Bot Auth signed request. The signing key must be
// Ed25519.
func Example() {
	key := dnsid.GenerateEd25519KeyProvider()
	profile := webbotauth.New("bot.example.com", key, webbotauth.Config{})

	req, err := http.NewRequest(http.MethodGet, "https://target.example/search?q=dnsid", nil)
	if err != nil {
		panic(err)
	}
	signed, err := profile.CreateWebBotAuthSignedRequest(req, webbotauth.SigningOptions{})
	if err != nil {
		panic(err)
	}

	// Signature-Input and Signature vary per run; Signature-Agent tells the
	// origin where to fetch this agent's key directory.
	fmt.Println("Signature-Agent:", signed.Header.Get("Signature-Agent"))
	fmt.Println("signature present:", signed.Header.Get("Signature") != "")
	// Output:
	// Signature-Agent: sig1="https://bot.example.com";type=directory
	// signature present: true
}
