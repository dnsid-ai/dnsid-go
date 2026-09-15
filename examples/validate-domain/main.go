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

// This policy is trusted configuration for the public log used by the DNSid
// sandbox. Production applications should select their own trusted policy.
const policyURL = "https://log.dnsid.dev/dnsid-policy"

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintf(os.Stderr, "usage: %s <dnsid-domain>\n", os.Args[0])
		os.Exit(2)
	}
	domain := os.Args[1]
	config := c2sptlog.VerificationRegistryConfig{
		MaxBundleLifetime:   10 * time.Minute,
		CheckpointMaxAge:    10 * time.Minute,
		AllowedClockSkew:    time.Minute,
		RequireStreamBundle: true,
	}
	if profilePath := os.Getenv("DNSID_TRUST_PROFILE"); profilePath != "" {
		data, err := os.ReadFile(profilePath)
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
	} else {
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
		config.PolicyURL = os.Getenv("DNSID_POLICY_URL")
		if config.PolicyURL == "" {
			config.PolicyURL = policyURL
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	registry, err := c2sptlog.NewVerificationRegistry(ctx, config)
	if err != nil {
		fmt.Fprintf(os.Stderr, "log setup failed: %v\n", err)
		os.Exit(1)
	}
	idm, err := dnsid.NewVerifier(dnsid.WithLogRegistry(registry))
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
	fmt.Println("stream bundle: verified (required)")
}
