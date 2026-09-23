package main

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"

	dnsid "github.com/dnsid-ai/dnsid-go"
	"github.com/dnsid-ai/dnsid-go/config"
	"github.com/dnsid-ai/dnsid-go/webbotauth"
)

func main() {
	ctx := context.Background()

	idm, err := config.IdentityManagerFromDnsid(ctx, "", dnsid.Config{}, config.Dependencies{})
	if err != nil {
		die("creating identity manager from ~/.dnsid", err)
	}

	profile := webbotauth.NewFromIdentityManager(idm, webbotauth.Config{})

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://target.example/search?q=dnsid", nil)
	if err != nil {
		die("creating request", err)
	}
	signed, err := profile.CreateWebBotAuthSignedRequest(req, webbotauth.SigningOptions{})
	if err != nil {
		die("signing request", err)
	}

	fmt.Println("signed request headers:")
	fmt.Println("Signature-Agent:", signed.Header.Get("Signature-Agent"))
	fmt.Println("Signature-Input:", signed.Header.Get("Signature-Input"))
	fmt.Println("Signature:", signed.Header.Get("Signature"))

	dirReq, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+idm.Domain()+webbotauth.DirectoryPath, nil)
	dirRes, err := profile.ServeHttpMessageSignaturesDirectory(dirReq)
	if err != nil {
		die("serving directory", err)
	}
	defer dirRes.Body.Close()
	body, err := io.ReadAll(dirRes.Body)
	if err != nil {
		die("reading directory", err)
	}

	fmt.Println("\ndirectory response:")
	fmt.Println("Content-Type:", dirRes.Header.Get("Content-Type"))
	fmt.Println("Cache-Control:", dirRes.Header.Get("Cache-Control"))
	fmt.Println("Content-Digest:", dirRes.Header.Get("Content-Digest"))
	fmt.Println("Signature-Input:", dirRes.Header.Get("Signature-Input"))
	fmt.Println("Signature:", dirRes.Header.Get("Signature"))
	fmt.Println(string(body))
}

func die(action string, err error) {
	fmt.Fprintf(os.Stderr, "%s failed: %v\n", action, err)
	os.Exit(1)
}
