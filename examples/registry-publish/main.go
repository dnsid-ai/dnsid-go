package main

import (
	"context"
	"fmt"
	"os"
	"time"

	dnsid "github.com/dnsid-ai/dnsid-go"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintf(os.Stderr, "usage: %s <registry-url>\n", os.Args[0])
		os.Exit(2)
	}
	registryURL := os.Args[1]

	token := os.Getenv("DNSID_TOKEN")
	if token == "" {
		fmt.Fprintln(os.Stderr, "set DNSID_TOKEN to a registry bearer token")
		os.Exit(2)
	}

	idm, err := dnsid.NewIdentityManagerFromDnsid("", dnsid.Config{})
	if err != nil {
		die("creating identity manager from ~/.dnsid", err)
	}

	client, err := dnsid.NewRegistryClientWithOptions(registryURL, dnsid.WithAuthToken(token))
	if err != nil {
		die("creating registry client", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	registration, err := client.GetRegistration(ctx, idm.Domain())
	if err != nil {
		die("reading registration", err)
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
		die("publishing identity record", fmt.Errorf("unknown publication authority %q", registration.PublicationAuthority))
	}
	if err != nil {
		die("publishing identity record", err)
	}

	fmt.Println("\npublished identity record:")
	fmt.Println("owner name:", published.OwnerName)
	fmt.Println("ttl:", published.TTL)
	fmt.Println("publication status:", published.PublicationStatus)
	fmt.Println("txt record:", published.TXTRecord)
}

func die(action string, err error) {
	fmt.Fprintf(os.Stderr, "%s failed: %v\n", action, err)
	os.Exit(1)
}
