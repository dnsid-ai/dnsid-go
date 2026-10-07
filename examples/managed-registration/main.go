// Register and independently verify one managed dev sandbox identity.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
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
	if err := run(context.Background(), *directory, token); err != nil {
		message := err.Error()
		if token != "" {
			message = strings.ReplaceAll(message, token, "[REDACTED]")
		}
		fmt.Fprintln(os.Stderr, message)
		fmt.Fprintln(os.Stderr, "Keep the state directory; rerun with the same directory to resume.")
		os.Exit(1)
	}
}

func run(ctx context.Context, directory, token string) error {
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
		&dnsid.AgentRegistrationInput{Environment: "sandbox"},
		registration.Options{NewAdapter: func(client *dnsid.HTTPRegistryClient) (registration.Adapter, error) {
			httpClient, err := dnsid.CreateDnsidHTTPClient(loaded.Dnsid.Transport)
			if err != nil {
				return nil, err
			}
			// Never forward the organization credential to a redirect target.
			httpClient.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
			return &devAdapter{HTTPRegistryClient: client, http: httpClient, token: token}, nil
		}})
	if err != nil {
		return err
	}
	fmt.Printf("Verified: %s status=ACTIVE\n", result.Registration.Domain)
	return nil
}

// The SDK has no portable organization endpoint or implicit replay guarantee.
// This adapter is specific to the hosted dev service, not a general preset.
type devAdapter struct {
	*dnsid.HTTPRegistryClient
	http  *http.Client
	token string
}

func (a *devAdapter) ResolveOrganization(ctx context.Context) (string, registration.ReplayGuarantee, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, registryURL+"/api/v1/auth/me", nil)
	if err != nil {
		return "", registration.ReplayGuarantee{}, err
	}
	req.Header.Set("Authorization", "Bearer "+a.token)
	response, err := a.http.Do(req)
	if err != nil {
		return "", registration.ReplayGuarantee{}, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return "", registration.ReplayGuarantee{}, fmt.Errorf("organization lookup HTTP %d", response.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, 65_537))
	if err != nil {
		return "", registration.ReplayGuarantee{}, err
	}
	if len(data) > 65_536 {
		return "", registration.ReplayGuarantee{}, errors.New("organization response exceeds 64 KiB")
	}
	var body struct {
		User struct {
			OrgID string `json:"org_id"`
		} `json:"user"`
	}
	if err := json.Unmarshal(data, &body); err != nil {
		return "", registration.ReplayGuarantee{}, err
	}
	if body.User.OrgID == "" {
		return "", registration.ReplayGuarantee{}, errors.New("authenticated organization is unavailable")
	}
	// Service contract: organization-scoped creation keys are retained for 24h
	// from claim, which is no earlier than the first request attempt. See the
	// source references and clock requirement in README.md. Expiry fails closed;
	// this adapter has no authoritative reconciliation endpoint.
	return body.User.OrgID, registration.ReplayGuarantee{
		Retention: 24 * time.Hour, ClockUncertainty: 5 * time.Minute,
		Scope: "registry/organization/request-key", StartConditions: "first request attempt",
	}, nil
}
