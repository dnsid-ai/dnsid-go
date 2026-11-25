package main

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/dnsid-ai/dnsid-go/config"
	dnsidlog "github.com/dnsid-ai/dnsid-go/log"
	"github.com/dnsid-ai/dnsid-go/log/c2sptlog"
)

type logID struct {
	scope, prefix string
}

func main() {
	if len(os.Args) < 4 {
		panic("usage: multiple-log-providers <profile-a.json> <profile-b.json> <domain> [domain...]")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Verification-only configuration; add normal transport settings here if needed.
	settings := config.Loaded{}
	providers := map[logID]*dnsidlog.LogRegistry{}
	for _, path := range os.Args[1:3] {
		data, err := os.ReadFile(path) // #nosec G703 -- The operator selects these local trust files.
		if err != nil {
			panic(err)
		}
		profile, err := c2sptlog.ParseTrustProfile(data)
		if err != nil {
			panic(err)
		}
		// shortcut: no migration verifier; add one if cross-log histories are needed.
		provider, err := config.LogRegistryFromTrust(ctx,
			config.LogTrust{Profile: &profile}, settings.Dnsid.Transport)
		if err != nil {
			panic(err)
		}
		providers[logID{profile.Scope, profile.LogPrefix}] = provider
	}

	// One factory per log method: select the provider by exact scope and prefix.
	registry := dnsidlog.NewLogRegistry()
	err := registry.Register(c2sptlog.Method, func(lr string) dnsidlog.LogReader {
		ref, err := c2sptlog.ParseReference(lr)
		if err != nil {
			return nil
		}
		provider := providers[logID{ref.Scope, ref.LogPrefix}]
		if provider == nil {
			return nil // The registry returns a reader that rejects untrusted logs.
		}
		reader, err := provider.NewReader(lr)
		if err != nil {
			return nil
		}
		return reader
	})
	if err != nil {
		panic(err)
	}

	// Inject the combined registry instead of selecting a single settings.LogTrust.
	verifier, err := config.Construct(ctx, settings, config.Dependencies{LogRegistry: registry})
	if err != nil {
		panic(err)
	}
	for _, domain := range os.Args[3:] {
		verified, err := verifier.VerifyDomain(ctx, domain)
		if err != nil {
			panic(err)
		}
		fmt.Println(verified.Domain(), verified.Status().State)
	}
}
