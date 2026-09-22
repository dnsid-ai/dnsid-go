package main

import (
	"context"
	"fmt"
	"os"
	"time"

	dnsid "github.com/dnsid-ai/dnsid-go"
	"github.com/dnsid-ai/dnsid-go/log/c2sptlog"
	"golang.org/x/mod/sumdb/note"
)

// This policy is trusted configuration for DNSid's public test log.
// Production applications should select their own trusted policy.
const policyURL = "https://log.dnsid.dev/dnsid-policy"

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintf(os.Stderr, "usage: %s <dnsid-domain>\n", os.Args[0])
		os.Exit(2)
	}
	domain := os.Args[1]

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Empty outside `eval "$(dnsid local env)"`: SDK defaults are production defaults.
	transport := dnsid.TransportConfig{
		DNSServer:    os.Getenv("DNSID_DNS_SERVER"),
		CABundlePath: os.Getenv("DNSID_CA_BUNDLE"),
	}
	config := c2sptlog.VerificationRegistryConfig{
		Transport:        transport,
		CheckpointMaxAge: 10 * time.Minute,
		AllowedClockSkew: time.Minute,
	}
	switch {
	case os.Getenv("DNSID_LOG_POLICY_URL") != "":
		// The local registry serves no stream bundles; verify by raw-log scan.
		config.PolicyURL = os.Getenv("DNSID_LOG_POLICY_URL")
	case os.Getenv("DNSID_TRUST_PROFILE") != "":
		data, err := os.ReadFile(os.Getenv("DNSID_TRUST_PROFILE"))
		if err != nil {
			fmt.Fprintf(os.Stderr, "reading DNSID_TRUST_PROFILE: %v\n", err)
			os.Exit(2)
		}
		profile, err := c2sptlog.ParseTrustProfile(data)
		if err != nil {
			fmt.Fprintf(os.Stderr, "invalid DNSID_TRUST_PROFILE: %v\n", err)
			os.Exit(2)
		}
		config.TrustProfile = &profile
		config.MaxBundleLifetime = 10 * time.Minute
		config.RequireStreamBundle = true
	default:
		bundleKey := os.Getenv("DNSID_BUNDLE_VERIFIER_KEY")
		if bundleKey == "" {
			fmt.Fprintln(os.Stderr, "DNSID_TRUST_PROFILE or DNSID_BUNDLE_VERIFIER_KEY is required")
			os.Exit(2)
		}
		bundleVerifier, err := note.NewVerifier(bundleKey)
		if err != nil {
			fmt.Fprintf(os.Stderr, "invalid DNSID_BUNDLE_VERIFIER_KEY: %v\n", err)
			os.Exit(2)
		}
		config.BundleVerifiers = []note.Verifier{bundleVerifier}
		config.MaxBundleLifetime = 10 * time.Minute
		config.RequireStreamBundle = true
		config.PolicyURL = os.Getenv("DNSID_POLICY_URL")
		if config.PolicyURL == "" {
			config.PolicyURL = policyURL
		}
	}

	registry, err := c2sptlog.NewVerificationRegistry(ctx, config)
	if err != nil {
		fmt.Fprintf(os.Stderr, "log setup failed: %v\n", err)
		os.Exit(1)
	}
	idm, err := dnsid.NewIdentityManager(dnsid.Config{Transport: transport}, nil, dnsid.WithLogRegistry(registry))
	if err != nil {
		fmt.Fprintf(os.Stderr, "setup failed: %v\n", err)
		os.Exit(1)
	}

	verified, err := idm.VerifyDomain(ctx, domain)
	if err != nil {
		fmt.Fprintf(os.Stderr, "verification failed: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("verified: %s\n", verified.Domain())
	fmt.Printf("dnssec: %s\n", verified.DNSSECState())
	fmt.Printf("status: %s\n", verified.Status().State)
	if config.RequireStreamBundle {
		fmt.Println("stream bundle: verified (required)")
	} else {
		fmt.Println("log: raw-log scan")
	}
}
