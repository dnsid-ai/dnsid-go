// Register and independently verify one managed dev sandbox identity.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"
	"unicode"

	dnsid "github.com/dnsid-ai/dnsid-go"
	"github.com/dnsid-ai/dnsid-go/config"
	"github.com/dnsid-ai/dnsid-go/registration"
)

const registryURL = "https://api.dev.dnsid.ai"
const governanceID = "dev.dnsid.ai"
const entityKeyURL = "https://dnsid.dev.dnsid.ai/.well-known/dnsid-ek.json"

func main() {
	directory := flag.String("state-dir", "", "dedicated private state directory (required)")
	keyFile := flag.String("api-key-file", "", "API token file; otherwise use DNSID_API_KEY")
	verified := flag.Bool("server-contract-verified", false, "confirm server integration tests verified permanent creation idempotency")
	flag.Parse()
	if *directory == "" || flag.NArg() != 0 {
		flag.Usage()
		os.Exit(2)
	}
	token := os.Getenv("DNSID_API_KEY")
	if *keyFile != "" {
		data, err := os.ReadFile(*keyFile)
		if err != nil {
			fmt.Fprintln(os.Stderr, "cannot read API key file")
			os.Exit(1)
		}
		token = string(data)
	}
	token = strings.TrimSpace(token)
	if err := run(context.Background(), *directory, token, *verified); err != nil {
		message := err.Error()
		if token != "" {
			message = strings.ReplaceAll(message, token, "[REDACTED]")
		}
		fmt.Fprintln(os.Stderr, message)
		fmt.Fprintln(os.Stderr, "Keep the state directory; rerun with the same directory to resume.")
		os.Exit(1)
	}
}

func run(ctx context.Context, directory, token string, contractVerified bool) error {
	if !contractVerified {
		return errors.New("verify permanent server-side creation idempotency with server integration tests before using --server-contract-verified")
	}
	if token == "" || strings.IndexFunc(token, unicode.IsSpace) >= 0 {
		return errors.New("provide one API token through DNSID_API_KEY or --api-key-file")
	}
	loaded, err := config.LoadEnvironment(os.Getenv)
	if err != nil {
		return err
	}
	if loaded.Registry.RegistryURL != "" && loaded.Registry.RegistryURL != registryURL {
		return errors.New("this example supports only the dev registry")
	}
	loaded.Registry.RegistryURL = registryURL
	loaded.Dnsid.Identity = nil
	loaded.KeySource = config.KeySource{}
	loaded.LogTrust = config.LogTrust{Managed: true}
	loaded.Registration = config.ManagedRegistrationConfig{GovernanceID: governanceID, EntityKeyURL: entityKeyURL}

	result, err := registration.RegisterManagedIdentity(ctx, loaded, token,
		registration.NewFileRegistrationStore(directory),
		&dnsid.AgentRegistrationInput{Environment: "sandbox"})
	if err != nil {
		return err
	}
	fmt.Printf("Verified: %s status=ACTIVE\n", result.Registration.Domain)
	return nil
}
