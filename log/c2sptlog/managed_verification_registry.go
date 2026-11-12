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
  "log_prefix": "https://log.dev.dnsid.ai",
  "tlog_policy": "log log.dev.dnsid.ai+cad12acd+Afnd3sdzfp8nCXzDQchrnWn9QOox5AglR147bURESRqu\nwitness dnsid-witness-1 witness.dev.dnsid.ai/w1+50822ded+BAH9KuulelD3yZBDTneG46gKZY+OWwdUPBmLmq/YjOkO\nquorum dnsid-witness-1\n",
  "bundle_verifier_keys": [
    "dnsid-stream-bundle+0c241174+AeuT9PKyiewb9hkzygvki7UuOs5ly2kfY/C4Tfh7/ix0",
    "dnsid-stream-bundle+62f7f9fa+ATdOWF5P759HgvDod9mIC0r1nXhTtJ7x1Ws0fjTvqwDV"
  ]
}`
	managedProductionProfile = `{
  "version": 1,
  "scope": "public",
  "log_prefix": "https://log.dnsid.ai",
  "tlog_policy": "log log.dnsid.ai+f10a26bc+Aeo6u4o1XvQlcRczgY462ZdIGpm/ejBC2G3vSbyYYqqY\nwitness dnsid-witness-1 witness.dnsid.ai/w1+706fd4fb+BLqX21Sx9xG5+5vK7kSK5omcu9+2il20PLdfpOp8lQOJ\nquorum dnsid-witness-1\n",
  "bundle_verifier_keys": [
    "dnsid-stream-bundle+2e77a3f1+AbKj/zrAfK04/NM07Zj7kxP2YXbM5neT8ym6juXC2PXG",
    "dnsid-stream-bundle+0f5a76a0+AXavEa0+EGj/qZFH4QuAOeomigSukspWQHC7PrVJa7pj"
  ]
}`

	// managedPartnersProfile matches the reviewed service profile in
	// Identity-Digital/dnsid#2639; discovery endpoints are not trust anchors.
	managedPartnersProfile = `{
  "version": 1,
  "scope": "public",
  "log_prefix": "https://log.partners.dnsid.ai",
  "tlog_policy": "log log.partners.dnsid.ai+f0143e09+Ae5vrTVQUr0h2GKbeHq70ml37N+uVBsU4NpZD4qMqAu1\nwitness dnsid-witness-1 witness.partners.dnsid.ai/w1+a115eb67+BB0avWVeSelUBk2w8FtTbT+orf2i826q9VemA0jaXxg4\nquorum dnsid-witness-1\n",
  "bundle_verifier_keys": [
    "dnsid-stream-bundle+b1e0b597+AQt9ol4cfwPHxdH4NHNRidsAvU2bYE7KVItOlBG/bsaZ",
    "dnsid-stream-bundle+bc0d8136+AVfizbWWQD+s2N7OfpOeP7IaWF8nAeTqT4JpD03vKqc6"
  ]
}`

	// managedStagingProfile matches the reviewed service profile
	// internal/c2sptrust/profiles/staging.json in Identity-Digital/dnsid (its second
	// bundle key from Identity-Digital/dnsid#3526); the log's discovery endpoints are
	// not trust anchors. note.NewVerifier rejects a key whose ID does not match its
	// key bytes.
	managedStagingProfile = `{
  "version": 1,
  "scope": "public",
  "log_prefix": "https://log.stg.dnsid.ai",
  "tlog_policy": "log log.stg.dnsid.ai+f6ad3bd8+ARl6baGOUzNIH2QvsnlqA8C71WM4SYecXE7eAwmytAsL\nwitness dnsid-witness-1 witness.stg.dnsid.ai/w1+11a84cde+BEKB6hwsWXOm+PMnS7/JvO4i6bazjzJ8ojECphOTB3gt\nquorum dnsid-witness-1\n",
  "bundle_verifier_keys": [
    "dnsid-stream-bundle+65c31b14+AXCMTPR4I/fqOgSHge4AEMp+1pWcflDqC1YEDaHDe3Ps",
    "dnsid-stream-bundle+cdd64875+ATu1SYXvRiZPBUzrUJAfKHeMH3eHr3T22jKez/C3Yl1m"
  ]
}`

	// managedKnownDevelopmentProfile matches the reviewed service profile
	// internal/c2sptrust/profiles/known-dev.json in Identity-Digital/dnsid for the
	// Known development log (https://log.dev.knownsystems.ai); the log's discovery endpoints are not trust anchors.
	managedKnownDevelopmentProfile = `{
  "version": 1,
  "scope": "public",
  "log_prefix": "https://log.dev.knownsystems.ai",
  "tlog_policy": "log log.dev.knownsystems.ai+78742e4f+AWJIIC/ZPaSwAprXLHT+JZ7lbTipE3MciQOdUGqG1T3j\nwitness dnsid-witness-1 witness.dev.knownsystems.ai/w1+21be2f43+BLsio+pQhADB8grceyZnOVERcoq+V6oJuUNy/IEfhsgt\nquorum dnsid-witness-1\n",
  "bundle_verifier_keys": [
    "dnsid-stream-bundle+138e0d41+AXy9jwvH7hY3LgjqoZn3GmNllKTj2TyNApRLKbt/2WSU",
    "dnsid-stream-bundle+ad87852b+AWWyHhKGf9oKqaRCQfrk9kixjuz4fmhI5P08W5bsYxzj"
  ]
}`

	// managedKnownStagingProfile matches the reviewed service profile
	// internal/c2sptrust/profiles/known-staging.json in Identity-Digital/dnsid for the
	// Known staging log (https://log.stg.knownsystems.ai); the log's discovery endpoints are not trust anchors.
	managedKnownStagingProfile = `{
  "version": 1,
  "scope": "public",
  "log_prefix": "https://log.stg.knownsystems.ai",
  "tlog_policy": "log log.stg.knownsystems.ai+d3504618+AaUJP26XksZKcjmWHs7Cyq244q2efKUH1geUNb6bK5G7\nwitness dnsid-witness-1 witness.stg.knownsystems.ai/w1+e3954927+BA8QcWZ+kIuuakqhAbltJ1lFAYeuEqE98AYWyG9eKTil\nquorum dnsid-witness-1\n",
  "bundle_verifier_keys": [
    "dnsid-stream-bundle+85bbbf6c+AQEr6kb1rP1ZUJxEUl5ai5KxD86uHDRhHoF9rGewVgvC",
    "dnsid-stream-bundle+64bf74b3+Aa0M4XaiO7BzP4fn7gLnWOw570/ml9x8xnEiv5fUqIW1"
  ]
}`

	// managedKnownProductionProfile matches the reviewed service profile
	// internal/c2sptrust/profiles/known-production.json in Identity-Digital/dnsid for the
	// Known production log (https://log.knownsystems.ai); the log's discovery endpoints are not trust anchors.
	managedKnownProductionProfile = `{
  "version": 1,
  "scope": "public",
  "log_prefix": "https://log.knownsystems.ai",
  "tlog_policy": "log log.knownsystems.ai+ffa9d1c9+Ad/NRlpkBsb9RjFstpUI2V38LF0G9DaJgHWtx5UtS6a7\nwitness dnsid-witness-1 witness.knownsystems.ai/w1+f726713e+BPq3DkSLKz0bMwDnwhwb9yhsGKT/0g0iPKZYekuumLfV\nquorum dnsid-witness-1\n",
  "bundle_verifier_keys": [
    "dnsid-stream-bundle+4c5de6cf+AeoiHt6HX3fniAPFeNMerJ52HKAlfLxbwFnxvyVM8GPj",
    "dnsid-stream-bundle+4296adc5+AX8gHt0vQT0mICUKU2svFWcdcIhcQmGHYuR2kk/EsXex"
  ]
}`
)

// DnsidManagedVerificationConfig configures shared infrastructure for
// NewDnsidManagedVerificationRegistry. Trust roots, freshness, resource limits,
// and bundle requirements are fixed by the managed catalog; callers needing
// different policy use NewVerificationRegistry.
type DnsidManagedVerificationConfig struct {
	// Transport applies deployment controls to SDK-managed public log reads.
	// An explicit ResourceFetcher remains caller-owned and takes precedence.
	Transport dnsid.TransportConfig
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
	{scope: "public", logPrefix: "https://log.dev.dnsid.ai", trustProfileDocument: managedDevelopmentProfile},
	{scope: "public", logPrefix: "https://log.dnsid.ai", trustProfileDocument: managedProductionProfile},
	{scope: "public", logPrefix: "https://log.partners.dnsid.ai", trustProfileDocument: managedPartnersProfile},
	{scope: "public", logPrefix: "https://log.stg.dnsid.ai", trustProfileDocument: managedStagingProfile},
	{scope: "public", logPrefix: "https://log.dev.knownsystems.ai", trustProfileDocument: managedKnownDevelopmentProfile},
	{scope: "public", logPrefix: "https://log.stg.knownsystems.ai", trustProfileDocument: managedKnownStagingProfile},
	{scope: "public", logPrefix: "https://log.knownsystems.ai", trustProfileDocument: managedKnownProductionProfile},
}

// NewDnsidManagedVerificationRegistry creates a LogRegistry for the reviewed,
// SDK-embedded trust roots of DNSid-managed DNSid logs. Calling this
// separately named factory is an explicit application trust decision; the
// generic NewVerificationRegistry never selects these roots implicitly.
//
// The catalog covers the DNSid development, production, partner
// (https://log.partners.dnsid.ai), and staging (https://log.stg.dnsid.ai) logs,
// and the Known development (https://log.dev.knownsystems.ai), staging
// (https://log.stg.knownsystems.ai), and production (https://log.knownsystems.ai)
// logs. Each prefers signed stream bundles with
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
		fetcher, err = factoryResourceFetcher(VerificationRegistryConfig{Transport: config.Transport})
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
