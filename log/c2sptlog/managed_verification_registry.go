package c2sptlog

import (
	"context"
	"fmt"
	"time"

	dnsid "github.com/dnsid-ai/dnsid-go"
	dnsidlog "github.com/dnsid-ai/dnsid-go/log"
)

// These reviewed snapshots mirror the DNSid product CLI trust catalog. They
// change only in an SDK release, never through runtime discovery from a log.
const (
	managedVerificationFreshness = 10 * time.Minute
	managedDevelopmentProfile    = `{
  "version": 1,
  "scope": "public",
  "log_prefix": "https://log.dnsid.dev",
  "tlog_policy": "log log.dnsid.dev+052e4f74+AeVyq6M2TaREOeeZ4lsQ5XEm9B0w1FtvS5TO8iWKyTN0\nwitness dnsid-witness-1 witness.dnsid.dev/w1+6a659d6a+BKY6cayDG6j/EW1YMrZwzqUWNudBIphAkWkOvAtwgiy7\nquorum dnsid-witness-1\n",
  "bundle_verifier_keys": [
    "dnsid-stream-bundle+403a6611+AeE6U4Cbeke0Y9/7TiJve8CJPTFY/KDI0ZIlSU4pfbBD"
  ]
}`
	managedProductionProfile = `{
  "version": 1,
  "scope": "public",
  "log_prefix": "https://log.dnsid.ai",
  "tlog_policy": "log log.dnsid.ai+c4683585+AWZYC4OLE9KeRnpaI9xaHWwHUKoxgp/24ukzgVYlDwIt\nwitness dnsid-witness-1 witness.dnsid.ai/w1+b5ea211e+BH0nGTkjF4tYpkefsQhHNg0YagPvQ6H96Y3UBbXo7a/b\nquorum dnsid-witness-1\n",
  "bundle_verifier_keys": [
    "dnsid-stream-bundle+ee2b26d2+AWGLBe4LhJKumyDpH8VJ0vyATB081i1HseVeETu4TONR"
  ]
}`
)

// DnsidManagedVerificationConfig configures shared infrastructure for
// NewDnsidManagedVerificationRegistry. Trust roots, freshness, resource limits,
// and bundle requirements are fixed by the managed catalog; callers needing
// different policy use NewVerificationRegistry.
type DnsidManagedVerificationConfig struct {
	// ResourceFetcher is shared by every managed log reader. When nil, the
	// standard safe bounded fetcher is used.
	ResourceFetcher BoundedResourceFetcher
	// TrustedCheckpointStore is shared by every managed log reader. When nil,
	// an in-memory store protects against rollback for this registry's lifetime.
	TrustedCheckpointStore TrustedC2spCheckpointStore
}

type managedTrustEntry struct {
	scope                string
	logPrefix            string
	trustProfileDocument string
	policyDocument       string
}

type managedTrustSelector struct {
	scope     string
	logPrefix string
}

var dnsidManagedTrustCatalog = []managedTrustEntry{
	{scope: "public", logPrefix: "https://log.dnsid.dev", trustProfileDocument: managedDevelopmentProfile},
	{scope: "public", logPrefix: "https://log.dnsid.ai", trustProfileDocument: managedProductionProfile},
}

// NewDnsidManagedVerificationRegistry creates a LogRegistry for the reviewed,
// SDK-embedded trust roots of Identity Digital-managed DNSid logs. Calling this
// separately named factory is an explicit application trust decision; the
// generic NewVerificationRegistry never selects these roots implicitly.
//
// Development and production verification prefer signed stream bundles with
// safe raw-scan fallback. The default checkpoint store is restart-ephemeral;
// deployments needing rollback protection across restarts should inject durable
// storage and retain the returned registry for the process lifetime.
func NewDnsidManagedVerificationRegistry(ctx context.Context, config DnsidManagedVerificationConfig) (*dnsidlog.LogRegistry, error) {
	return newDnsidManagedVerificationRegistry(ctx, config, dnsidManagedTrustCatalog)
}

func newDnsidManagedVerificationRegistry(ctx context.Context, config DnsidManagedVerificationConfig, catalog []managedTrustEntry) (*dnsidlog.LogRegistry, error) {
	if ctx == nil {
		return nil, dnsid.NewArgumentError("dnsid: c2sp-tlog managed verification context is required", nil)
	}
	fetcher := config.ResourceFetcher
	if fetcher == nil {
		var err error
		fetcher, err = factoryResourceFetcher(VerificationRegistryConfig{})
		if err != nil {
			return nil, err
		}
	}
	store := config.TrustedCheckpointStore
	if store == nil {
		store = NewMemoryTrustedC2spCheckpointStore()
	}

	registries := make(map[managedTrustSelector]*dnsidlog.LogRegistry, len(catalog))
	for _, entry := range catalog {
		ref, err := ParseReference(Method + ":" + entry.scope + ":" + entry.logPrefix + "#managed-catalog")
		if err != nil {
			return nil, fmt.Errorf("dnsid: invalid managed c2sp-tlog catalog selector: %w", err)
		}
		selector := managedTrustSelector{scope: ref.Scope, logPrefix: ref.LogPrefix}
		if registries[selector] != nil {
			return nil, fmt.Errorf("dnsid: duplicate managed c2sp-tlog catalog selector")
		}

		verificationConfig := VerificationRegistryConfig{
			ResourceFetcher:        fetcher,
			TrustedCheckpointStore: store,
			CheckpointMaxAge:       managedVerificationFreshness,
		}
		switch {
		case entry.trustProfileDocument != "" && entry.policyDocument == "":
			profile, err := ParseTrustProfile([]byte(entry.trustProfileDocument))
			if err != nil {
				return nil, err
			}
			if profile.Scope != ref.Scope || profile.LogPrefix != ref.LogPrefix {
				return nil, fmt.Errorf("dnsid: managed c2sp-tlog trust profile selector mismatch")
			}
			verificationConfig.TrustProfile = &profile
			verificationConfig.MaxBundleLifetime = managedVerificationFreshness
		case entry.policyDocument != "" && entry.trustProfileDocument == "":
			policy, err := ParsePolicy([]byte(entry.policyDocument))
			if err != nil {
				return nil, err
			}
			origin, err := ref.Origin()
			if err != nil || policy.LogVerifier == nil || policy.LogVerifier.Name() != origin {
				return nil, fmt.Errorf("dnsid: managed c2sp-tlog policy selector mismatch")
			}
			verificationConfig.PolicyDocument = []byte(entry.policyDocument)
		default:
			return nil, fmt.Errorf("dnsid: managed c2sp-tlog catalog entry must contain exactly one trust document")
		}

		registry, err := NewVerificationRegistry(ctx, verificationConfig)
		if err != nil {
			return nil, err
		}
		registries[selector] = registry
	}

	registry := dnsidlog.NewLogRegistry()
	if err := registry.Register(Method, func(lr string) dnsidlog.LogReader {
		ref, err := ParseReference(lr)
		if err != nil {
			return errorReader{err: err}
		}
		selected := registries[managedTrustSelector{scope: ref.Scope, logPrefix: ref.LogPrefix}]
		if selected == nil {
			return errorReader{err: fmt.Errorf("dnsid: unknown managed c2sp-tlog trust selector")}
		}
		reader, err := selected.NewReader(lr)
		if err != nil {
			return errorReader{err: err}
		}
		return reader
	}); err != nil {
		return nil, err
	}
	return registry, nil
}
