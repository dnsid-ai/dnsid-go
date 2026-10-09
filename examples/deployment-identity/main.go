package main

import (
	"context"
	"fmt"
	"net/http"
	"os"

	dnsid "github.com/dnsid-ai/dnsid-go"
	"github.com/dnsid-ai/dnsid-go/config"
	"github.com/dnsid-ai/dnsid-go/httpsig"
	_ "github.com/dnsid-ai/dnsid-go/key/aws" // Link the optional aws-kms factory.
)

func main() {
	if len(os.Args) != 2 {
		die("selecting deployment", fmt.Errorf("usage: go run . <deployment.json>"))
	}
	ctx := context.Background()
	loaded, err := config.LoadDeploymentFile(os.Args[1])
	if err != nil {
		die("loading deployment", err)
	}
	manager, err := config.Construct(ctx, loaded, config.Dependencies{})
	if err != nil {
		die("constructing identity manager", err)
	}

	// Construct opens the key but does not verify its published binding.
	published, err := manager.VerifyDomain(ctx, manager.Domain())
	if err != nil {
		die("verifying own published identity", err)
	}
	if err := requirePublishedKey(manager.GetKeySet(), published.KeySet()); err != nil {
		die("checking operational key binding", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://target.example/resource", nil)
	if err != nil {
		die("creating request", err)
	}
	profile := httpsig.NewFromIdentityManagerKeyProvider(manager, httpsig.Config{})
	signed, err := profile.CreateSignedHTTPRequest(req, httpsig.SigningOptions{})
	if err != nil {
		die("signing request", err)
	}
	fmt.Println(signed.Method, signed.URL)
	fmt.Println("Signature-Input:", signed.Header.Get("Signature-Input"))
	fmt.Println("Signature:", signed.Header.Get("Signature"))
	// No HTTP client dispatch: the signed request stays in this process.
}

func requirePublishedKey(selected, published *dnsid.JWKS) error {
	local, err := selected.CurrentOperationalSigningKey(dnsid.DefaultPublishProfile)
	if err != nil {
		return fmt.Errorf("selected operational key: %w", err)
	}
	current, err := published.CurrentOperationalSigningKey(dnsid.DefaultPublishProfile)
	if err != nil {
		return fmt.Errorf("published operational key: %w", err)
	}
	localThumbprint, err := local.Thumbprint()
	if err != nil {
		return err
	}
	currentThumbprint, err := current.Thumbprint()
	if err != nil {
		return err
	}
	if localThumbprint != currentThumbprint || local.Kid() != current.Kid() || local.Alg() != current.Alg() {
		return fmt.Errorf("selected key does not match the current published operational key; changing keyRef does not authorize rotation")
	}
	return nil
}

func die(action string, err error) {
	fmt.Fprintf(os.Stderr, "%s failed: %v\n", action, err)
	os.Exit(1)
}
