package c2sptlog

import (
	"context"
	"fmt"
	"net/http"
	"time"

	dnsid "github.com/dnsid-ai/dnsid-go"
	"github.com/dnsid-ai/dnsid-go/internal/netguard"
	dnsidlog "github.com/dnsid-ai/dnsid-go/log"
	"golang.org/x/mod/sumdb/note"
)

const (
	defaultMaxPolicyBytes       = 1 << 20
	defaultResourceFetchTimeout = 30 * time.Second
)

// VerificationRegistryConfig configures NewVerificationRegistry. Exactly one
// of TrustProfile, PolicyDocument, and PolicyURL must be set. A PolicyURL is a
// caller-selected trust-policy location; it is never inferred from an
// identity's untrusted lr value.
type VerificationRegistryConfig struct {
	// TrustProfile binds one exact scope and log prefix to an independently
	// distributed policy document and bundle signer keys.
	TrustProfile *TrustProfile
	// PolicyDocument contains an independently trusted C2SP tlog-policy
	// document. The bytes are parsed locally and are not fetched from the log.
	PolicyDocument []byte
	// PolicyURL is an independently trusted HTTPS location from which to fetch
	// the C2SP tlog-policy document. Redirects are rejected.
	PolicyURL string
	// ScanSourceConfig configures the bounded standard tiled-log scanner. A
	// custom Transport is accepted only by lower-level NewScanSource; this safe
	// factory accepts nil or *http.Transport and wraps it with safe dialing.
	ScanSourceConfig ScanSourceConfig
	// ResourceFetcher is trusted caller infrastructure used for both PolicyURL
	// and all standard log resources. Its public-read guarantees are validated
	// eagerly. It is mutually exclusive with scanner HTTP transport options.
	ResourceFetcher BoundedResourceFetcher
	// TrustedCheckpointStore records accepted checkpoints. When nil, an
	// in-memory store protects against rollback for this process's lifetime.
	TrustedCheckpointStore TrustedC2spCheckpointStore
	// MaxPolicyBytes bounds a PolicyURL response. Zero uses 1 MiB.
	MaxPolicyBytes int64
	// CheckpointMaxAge enables fresh logged-state and non-revocation checks.
	// Zero leaves freshness unset, so those checks fail closed.
	CheckpointMaxAge time.Duration
	// AllowedClockSkew permits this much future skew in checkpoint witness
	// timestamps. Zero is the default and negative values are rejected.
	AllowedClockSkew time.Duration
	// BundleVerifiers are independently trusted stream-bundle signer keys.
	// When non-empty, bundles are preferred over raw global-log scans.
	BundleVerifiers []note.Verifier
	// MaxBundleLifetime is required when BundleVerifiers is non-empty.
	MaxBundleLifetime time.Duration
	// MaxStreamBundleBytes and MaxStreamBundleEvents bound bundle responses.
	// Zero uses the package defaults.
	MaxStreamBundleBytes  int
	MaxStreamBundleEvents int
	// RequireStreamBundle disables raw-scan history fallback. ReadEvent may use
	// the scanner to discover the FQDN before requiring its bundle history.
	RequireStreamBundle bool
}

// NewVerificationRegistry creates a LogRegistry ready for verification of
// c2sp-tlog lifecycle references. It loads and parses the caller-selected trust
// policy, configures the bounded standard tiled-log scanner, and installs a
// process-lifetime checkpoint store unless the caller supplies a durable one.
//
// PolicyURL is trusted configuration, not discovery. Applications must not
// derive it from an unverified identity record or from the log prefix itself.
// Advanced deployments with private transports or custom stream sources should
// compose ParsePolicy, NewScanSource, and Register directly.
func NewVerificationRegistry(ctx context.Context, config VerificationRegistryConfig) (*dnsidlog.LogRegistry, error) {
	var profileOptions []Option
	if config.TrustProfile != nil {
		if config.PolicyDocument != nil || config.PolicyURL != "" || len(config.BundleVerifiers) != 0 {
			return nil, dnsid.NewArgumentError("dnsid: c2sp-tlog trust profile is mutually exclusive with direct policy and bundle verifier configuration", nil)
		}
		verifiers, err := config.TrustProfile.validate()
		if err != nil {
			return nil, dnsid.NewArgumentError("dnsid: invalid c2sp-tlog trust profile", err)
		}
		config.PolicyDocument = []byte(config.TrustProfile.PolicyDocument)
		config.BundleVerifiers = verifiers
		profileOptions = append(profileOptions, withTrustProfile(config.TrustProfile.Scope, config.TrustProfile.LogPrefix))
		config.TrustProfile = nil
	}
	fetcher, maximum, err := validateVerificationRegistryConfig(ctx, config)
	if err != nil {
		return nil, err
	}

	document := config.PolicyDocument
	if config.PolicyURL != "" {
		document, err = fetchBounded(fetcher, ctx, config.PolicyURL, maximum)
		if err != nil {
			return nil, err
		}
	}

	policy, err := ParsePolicy(document)
	if err != nil {
		return nil, err
	}
	policy.MaxCheckpointAge = config.CheckpointMaxAge
	policy.ClockSkew = config.AllowedClockSkew

	store := config.TrustedCheckpointStore
	if store == nil {
		store = NewMemoryTrustedC2spCheckpointStore()
	}

	scanConfig := config.ScanSourceConfig
	scanConfig.HTTPClient = nil
	scanConfig.Transport = nil
	scanConfig.ResourceFetcher = fetcher
	var source Source
	source, err = NewScanSource(policy, scanConfig)
	if err != nil {
		return nil, dnsid.NewArgumentError("dnsid: invalid c2sp-tlog scanner options", err)
	}
	if len(config.BundleVerifiers) > 0 {
		source = &fetchedStreamBundleSource{
			fetcher:       fetcher,
			fallback:      source,
			requireBundle: config.RequireStreamBundle,
			trust: StreamBundleTrust{
				PolicyDocument:         append([]byte(nil), document...),
				BundleVerifiers:        append([]note.Verifier(nil), config.BundleVerifiers...),
				MaxBundleLifetime:      config.MaxBundleLifetime,
				MaxCheckpointAge:       config.CheckpointMaxAge,
				ClockSkew:              config.AllowedClockSkew,
				MaxBundleBytes:         config.MaxStreamBundleBytes,
				MaxEvents:              config.MaxStreamBundleEvents,
				MaxTreeSize:            scanConfig.MaxTreeSize,
				TrustedCheckpointStore: store,
			},
		}
	}

	registry := dnsidlog.NewLogRegistry()
	options := []Option{WithSource(source), WithPolicy(policy), WithTrustedCheckpointStore(store)}
	options = append(options, profileOptions...)
	if err := Register(registry, options...); err != nil {
		return nil, err
	}
	return registry, nil
}

func validateVerificationRegistryConfig(ctx context.Context, config VerificationRegistryConfig) (BoundedResourceFetcher, int64, error) {
	if ctx == nil {
		return nil, 0, dnsid.NewArgumentError("dnsid: c2sp-tlog verification context is required", nil)
	}
	hasDocument := config.PolicyDocument != nil
	hasURL := config.PolicyURL != ""
	if hasDocument == hasURL {
		return nil, 0, dnsid.NewArgumentError("dnsid: exactly one c2sp-tlog policy document or URL is required", nil)
	}
	if hasURL {
		if _, err := parseResourceURL(config.PolicyURL, true); err != nil {
			return nil, 0, dnsid.NewArgumentError("dnsid: c2sp-tlog policy URL must be an absolute HTTPS URL without userinfo or fragment", err)
		}
	}
	maximum := configuredScanLimit(config.MaxPolicyBytes, defaultMaxPolicyBytes)
	if maximum < 1 {
		return nil, 0, dnsid.NewArgumentError("dnsid: c2sp-tlog policy byte limit must be positive", nil)
	}
	if config.CheckpointMaxAge < 0 {
		return nil, 0, dnsid.NewArgumentError("dnsid: c2sp-tlog checkpoint maximum age must be positive when supplied", nil)
	}
	if config.AllowedClockSkew < 0 {
		return nil, 0, dnsid.NewArgumentError("dnsid: c2sp-tlog allowed clock skew must be non-negative", nil)
	}
	if config.RequireStreamBundle && len(config.BundleVerifiers) == 0 {
		return nil, 0, dnsid.NewArgumentError("dnsid: required c2sp stream bundles need an accepted verifier", nil)
	}
	if len(config.BundleVerifiers) > 0 && config.MaxBundleLifetime <= 0 {
		return nil, 0, dnsid.NewArgumentError("dnsid: c2sp stream bundle maximum lifetime must be positive", nil)
	}
	if config.MaxStreamBundleBytes < 0 || config.MaxStreamBundleEvents < 0 {
		return nil, 0, dnsid.NewArgumentError("dnsid: c2sp stream bundle limits must be positive", nil)
	}
	for _, verifier := range config.BundleVerifiers {
		if verifier == nil {
			return nil, 0, dnsid.NewArgumentError("dnsid: c2sp stream bundle verifier must not be nil", nil)
		}
	}
	if err := validateFactoryScanLimits(config.ScanSourceConfig); err != nil {
		return nil, 0, err
	}
	fetcher, err := factoryResourceFetcher(config)
	if err != nil {
		return nil, 0, err
	}
	if !fetcher.SecurityGuarantees().SupportsPublicReads() {
		return nil, 0, dnsid.NewArgumentError("dnsid: c2sp-tlog resource fetcher lacks required public-read security guarantees", nil)
	}
	return fetcher, maximum, nil
}

func validateFactoryScanLimits(config ScanSourceConfig) error {
	if config.MaxCheckpointBytes < 0 || config.MaxEntryBundleBytes < 0 || config.MaxTotalEntryBytes < 0 {
		return dnsid.NewArgumentError("dnsid: c2sp-tlog scan byte limits must be positive", nil)
	}
	if config.ResourceFetcher != nil {
		return dnsid.NewArgumentError("dnsid: set VerificationRegistryConfig.ResourceFetcher when using the safe factory", nil)
	}
	return nil
}

func factoryResourceFetcher(config VerificationRegistryConfig) (BoundedResourceFetcher, error) {
	scan := config.ScanSourceConfig
	if config.ResourceFetcher != nil {
		if scan.HTTPClient != nil || scan.Transport != nil {
			return nil, dnsid.NewArgumentError("dnsid: c2sp-tlog resource fetcher is mutually exclusive with HTTP client and transport", nil)
		}
		return config.ResourceFetcher, nil
	}

	base := scan.HTTPClient
	if scan.Transport != nil {
		transport, ok := scan.Transport.(*http.Transport)
		if !ok {
			return nil, dnsid.NewArgumentError(fmt.Sprintf("dnsid: unsupported c2sp-tlog RoundTripper %T in safe verification factory", scan.Transport), nil)
		}
		if base == nil {
			base = &http.Client{}
		} else {
			copy := *base
			base = &copy
		}
		base.Transport = transport
	}
	if base != nil && base.Transport != nil {
		if _, ok := base.Transport.(*http.Transport); !ok {
			return nil, dnsid.NewArgumentError(fmt.Sprintf("dnsid: unsupported c2sp-tlog RoundTripper %T in safe verification factory", base.Transport), nil)
		}
	}
	client := netguard.NewSafeHTTPClientFrom(base)
	if client.Timeout <= 0 {
		client.Timeout = defaultResourceFetchTimeout
	}
	client.CheckRedirect = rejectResourceRedirect
	return &httpBoundedResourceFetcher{
		client:    client,
		httpsOnly: true,
		guarantees: ResourceFetchGuarantees{
			HTTPSOnly:                     true,
			RejectsRedirects:              true,
			ValidatesAllResolvedAddresses: true,
			ConnectsToValidatedAddress:    true,
			BoundsResponseDuringRead:      true,
		},
	}, nil
}
