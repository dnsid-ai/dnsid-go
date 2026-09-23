package main

import (
	"context"
	"fmt"
	"os"
	"time"

	dnsid "github.com/dnsid-ai/dnsid-go"
	"github.com/dnsid-ai/dnsid-go/config"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintf(os.Stderr, "usage: %s <dnsid-domain>\n", os.Args[0])
		os.Exit(2)
	}
	domain := os.Args[1]

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Log trust comes from DNSID_LOG_TRUST_PROFILE_FILE, DNSID_LOG_POLICY_FILE,
	// or DNSID_LOG_POLICY_URL; transport from DNSID_DNS_SERVER, DNSID_CA_BUNDLE,
	// and DNSID_PRIVATE_HOSTS (all exported by `dnsid local env`). Without any
	// of them the SDK uses production defaults and log checks fail closed.
	idm, err := config.IdentityManagerFromEnvironment(ctx, nil, dnsid.Config{}, config.Dependencies{})
	if err != nil {
		fmt.Fprintf(os.Stderr, "setup failed: %v\n", err)
		os.Exit(2)
	}

	verified, err := idm.VerifyDomain(ctx, domain)
	if err != nil {
		fmt.Fprintf(os.Stderr, "verification failed: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("verified: %s\n", verified.Domain())
	fmt.Printf("dnssec: %s\n", verified.DNSSECState())
	fmt.Printf("status: %s\n", verified.Status().State)
}
