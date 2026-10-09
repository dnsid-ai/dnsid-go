package main

import (
	"context"
	"fmt"
	"os"
	"time"

	dnsid "github.com/dnsid-ai/dnsid-go"
	"github.com/dnsid-ai/dnsid-go/log/c2sptlog"
)

func run(args []string) error {
	if len(args) != 4 {
		return fmt.Errorf("usage: trust-policy <domain> <trusted-profile.json> <gi> <ek-thumbprint>")
	}
	data, err := os.ReadFile(args[1])
	if err != nil {
		return err
	}
	profile, err := c2sptlog.ParseTrustProfile(data)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	registry, err := c2sptlog.NewVerificationRegistry(ctx, c2sptlog.VerificationRegistryConfig{
		TrustProfile:      &profile,
		CheckpointMaxAge:  10 * time.Minute,
		MaxBundleLifetime: 5 * time.Minute,
	})
	if err != nil {
		return err
	}
	verifier, err := dnsid.NewIdentityManager(dnsid.Config{
		Verification: dnsid.VerificationConfig{
			StatusCheckInterval: 30 * time.Second,
			TrustedEntities: []dnsid.TrustedEntity{
				{GovernanceID: args[2], EntityKeyThumbprints: []string{args[3]}},
			},
		},
	}, nil, dnsid.WithLogRegistry(registry))
	if err != nil {
		return err
	}
	vd, err := verifier.VerifyDomain(ctx, args[0])
	if err != nil {
		return err
	}
	fmt.Println(vd.Domain(), vd.Status().State)
	return nil
}

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
