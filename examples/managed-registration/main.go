// Register and independently verify one named managed dev identity.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"
	"unicode"

	"github.com/dnsid-ai/dnsid-go/config"
	"github.com/dnsid-ai/dnsid-go/registration"
)

const registryURL = "https://api.dev.dnsid.ai"
const identityName = "managed-registration-example"

// Enable only after real hosted-server persistence/integration checks pass.
const namedRegistrationAvailable = false

func main() {
	deployment := flag.String("config", "", "deployment JSON file (required)")
	directory := flag.String("state-dir", "", "private state-store directory (required)")
	flag.Parse()
	if *deployment == "" || *directory == "" || flag.NArg() != 0 {
		flag.Usage()
		os.Exit(2)
	}
	token := strings.TrimSpace(os.Getenv("DNSID_API_KEY"))
	if err := run(context.Background(), *deployment, *directory, token); err != nil {
		message := err.Error()
		if token != "" {
			message = strings.ReplaceAll(message, token, "[REDACTED]")
		}
		fmt.Fprintln(os.Stderr, message)
		fmt.Fprintln(os.Stderr, "Keep the state directory; rerun with the same directory to resume.")
		os.Exit(1)
	}
}

func run(ctx context.Context, deployment, directory, token string) error {
	if token == "" || strings.IndexFunc(token, unicode.IsSpace) >= 0 {
		return errors.New("set DNSID_API_KEY to one API token")
	}
	if !namedRegistrationAvailable {
		return errors.New("dev named registration is disabled until permanent replay, name ownership, and issuance recovery pass real server integration tests")
	}
	loaded, err := config.LoadDeploymentFile(deployment)
	if err != nil {
		return err
	}
	if loaded.Registry.RegistryURL != registryURL {
		return errors.New("this example supports only the dev registry")
	}
	result, err := registration.RegisterManagedIdentity(ctx, identityName, loaded, token,
		registration.NewFileRegistrationStore(directory), nil)
	if err != nil {
		return err
	}
	fmt.Printf("Verified: %s status=ACTIVE\n", result.Registration.Domain)
	return nil
}
