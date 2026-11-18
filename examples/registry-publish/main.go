package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"time"

	dnsid "github.com/dnsid-ai/dnsid-go"
	"github.com/dnsid-ai/dnsid-go/config"
)

func main() {
	if len(os.Args) != 1 {
		fmt.Fprintf(os.Stderr, "usage: %s (reads DNSID_REGISTRY_URL and DNSID_API_KEY; unset means the local registry)\n", os.Args[0])
		os.Exit(2)
	}
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run() error {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	// Sources in the fixed order: the CLI identity directory ($DNSID_CONFIG_DIR
	// under `dnsid local run`, otherwise ~/.dnsid), then the environment.
	env, err := config.LoadEnvironment(nil)
	if err != nil {
		return fmt.Errorf("reading DNSID_* environment failed: %w", err)
	}
	cli, err := config.LoadCliDirectory(env.KeySource.CliDirectory)
	if err != nil {
		return fmt.Errorf("reading DNSid identity directory failed: %w", err)
	}
	loaded := config.Merge(cli, env)
	if err := loaded.Dnsid.Validate(); err != nil {
		return fmt.Errorf("validating identity configuration failed: %w", err)
	}
	if loaded.Dnsid.Identity == nil {
		return fmt.Errorf("publication setup requires a local identity")
	}
	// Initial publication opens an existing key explicitly: ordinary Construct
	// requires established publication. This setup manager is not evidence of
	// an authenticated application signer; the caller owns binding and cleanup.
	provider, err := config.OperationalKeyProviderFrom(ctx, loaded.KeySource, loaded.Dnsid.Identity.Domain)
	if err != nil {
		return fmt.Errorf("opening operational key failed: %w", err)
	}
	if closer, ok := provider.(io.Closer); ok {
		defer func() { _ = closer.Close() }()
	}
	idm, err := config.Construct(ctx, loaded, config.Dependencies{KeyProvider: provider})
	if err != nil {
		return fmt.Errorf("creating identity manager failed: %w", err)
	}

	client, err := config.RegistryClientFromEnvironment(nil)
	if err != nil {
		return fmt.Errorf("creating registry client failed: %w", err)
	}

	registration, err := client.GetRegistration(ctx, idm.Domain())
	if err != nil {
		return fmt.Errorf("reading registration failed: %w", err)
	}
	fmt.Println("agent:", registration.Domain)
	fmt.Println("publication authority:", registration.PublicationAuthority)
	fmt.Println("registry status:", registration.RegistryStatus)

	var published *dnsid.PublishedRecord
	switch registration.PublicationAuthority {
	case dnsid.PublicationAuthorityClient:
		// The entity key is local: sign the registry-prepared canonical
		// identity record and submit the signature for publication.
		published, err = idm.PublishClientControlledRecord(ctx, client)
	case dnsid.PublicationAuthorityRegistry:
		// The registry signs and publishes: wait for DNS publication,
		// then verify the record observed through DNS.
		published, err = idm.AwaitRegistryManagedPublication(ctx, client, &dnsid.WaitForStatusOptions{
			PollInterval: 2 * time.Second,
		})
	default:
		return fmt.Errorf("publishing identity record failed: unknown publication authority %q", registration.PublicationAuthority)
	}
	if err != nil {
		return fmt.Errorf("publishing identity record failed: %w", err)
	}

	fmt.Println("\npublished identity record:")
	fmt.Println("owner name:", published.OwnerName)
	fmt.Println("ttl:", published.TTL)
	fmt.Println("publication status:", published.PublicationStatus)
	fmt.Println("txt record:", published.TXTRecord)
	return nil
}
