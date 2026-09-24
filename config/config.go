// Package config loads DNSid SDK configuration from sources other than code
// (DNSID_* environment variables and a DNSid CLI identity directory), merges
// partial results, and constructs an IdentityManager from them.
//
// Loaders parse; constructors default. Each Load function returns only the
// fields present in its source: empty or whitespace-only values are absent,
// nothing is defaulted or derived, and no second source is consulted. Merge
// combines partial results field-wise (later wins; lists replace; LogTrust is
// atomic). Construct fills the dependencies the caller did not supply from
// LogTrust and KeySource, then calls dnsid.NewIdentityManager, which applies
// every default and validation.
package config

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"time"

	dnsid "github.com/dnsid-ai/dnsid-go"
	dnsidlog "github.com/dnsid-ai/dnsid-go/log"
	"github.com/dnsid-ai/dnsid-go/log/c2sptlog"
)

// Loaded is the partial configuration produced by every source. Absent fields
// are their Go zero value; nil slices are absent while empty non-nil slices are
// present and meaningful (an explicit empty allowlist denies all).
type Loaded struct {
	Dnsid     dnsid.Config
	LogTrust  LogTrust
	Registry  Registry
	KeySource KeySource
}

// LogTrust selects the lifecycle-log trust used to build a LogRegistry when
// the caller does not inject one. Exactly one variant must be set when the
// section is present; Construct rejects two or more.
type LogTrust struct {
	// Managed selects the SDK-embedded DNSid-managed trust catalog.
	Managed bool
	// Profile is a parsed DNSid C2SP trust-profile document.
	Profile *c2sptlog.TrustProfile
	// PolicyDocument is an independently trusted C2SP tlog-policy document.
	PolicyDocument []byte
	// PolicyURL is an independently trusted HTTPS trust-policy location.
	PolicyURL string
}

func (t LogTrust) isZero() bool {
	return !t.Managed && t.Profile == nil && t.PolicyDocument == nil && t.PolicyURL == ""
}

// Registry holds registry control-plane settings.
type Registry struct {
	RegistryURL string
}

// KeySource names where local key material lives. Variants are not
// exclusive: CliDirectory supplies the operational key when present,
// otherwise KeyStorePath; EntityKeyPath supplies the entity key whenever set.
type KeySource struct {
	// CliDirectory is a DNSid CLI identity directory holding private.jwk or
	// <domain>/private.jwk.
	CliDirectory string
	// EntityKeyPath is the accountable-entity key file. LoadCliDirectory
	// resolves config.json entity_key_path against the directory.
	EntityKeyPath string
	// KeyStorePath is a local key store file readable by dnsid.NewLocalKeyProvider.
	KeyStorePath string
}

func (k KeySource) isZero() bool {
	return k.CliDirectory == "" && k.EntityKeyPath == "" && k.KeyStorePath == ""
}

// Dependencies are the caller-supplied runtime dependencies for Construct.
// Explicit fields let Construct skip loaded values displaced by the caller.
type Dependencies struct {
	KeyProvider       dnsid.KeyProvider
	EntityKeyProvider dnsid.KeyProvider
	LogRegistry       *dnsidlog.LogRegistry
	DNSResolver       dnsid.DNSResolver
	HTTPSFetcher      dnsid.HTTPSFetcher
	IdentityCache     *dnsid.IdentityCache
	HTTPClient        *http.Client
}

// LoadEnvironment reads the DNSID_* variables defined by the SDK environment
// schema. A nil getenv reads the process environment. Values are trimmed;
// unset, empty, or whitespace-only variables are absent. Unknown DNSID_*
// variables are ignored. DNSID_DNSSEC_MODE outside auto/validated/required is
// an *dnsid.ArgumentError; DNSID_LOG_POLICY_FILE and
// DNSID_LOG_TRUST_PROFILE_FILE are read and parsed here. DNSID_API_KEY is a
// secret, not loaded configuration; RegistryClientFromEnvironment reads it
// directly without placing it in Loaded.
func LoadEnvironment(getenv func(string) string) (Loaded, error) {
	if getenv == nil {
		getenv = os.Getenv
	}
	env := func(name string) string { return strings.TrimSpace(getenv(name)) }
	var l Loaded

	identity := dnsid.IdentityConfig{
		Domain:          env("DNSID_DOMAIN"),
		GovernanceID:    env("DNSID_GOVERNANCE_ID"),
		StatusURL:       env("DNSID_STATUS_URL"),
		LogRef:          env("DNSID_LOG_REF"),
		EntityKeyURL:    env("DNSID_EK_URL"),
		KeyURL:          env("DNSID_KU_URL"),
		PublishProfile:  env("DNSID_PUBLISH_PROFILE"),
		CapabilitiesURL: env("DNSID_CAPABILITIES_URL"),
	}
	if !reflect.ValueOf(identity).IsZero() {
		l.Dnsid.Identity = &identity
	}

	switch mode := dnsid.DNSSECMode(env("DNSID_DNSSEC_MODE")); mode {
	case "", dnsid.DNSSECModeAuto, dnsid.DNSSECModeValidated, dnsid.DNSSECModeRequired:
		l.Dnsid.Verification.DNSSECMode = mode
	default:
		return Loaded{}, dnsid.NewArgumentError("dnsid: DNSID_DNSSEC_MODE must be auto, validated, or required", nil)
	}

	l.Dnsid.Transport.DNSServer = env("DNSID_DNS_SERVER")
	l.Dnsid.Transport.CABundlePath = env("DNSID_CA_BUNDLE")
	for _, host := range strings.Split(env("DNSID_PRIVATE_HOSTS"), ",") {
		if host = strings.TrimSpace(host); host != "" {
			l.Dnsid.Transport.PrivateAddressHosts = append(l.Dnsid.Transport.PrivateAddressHosts, host)
		}
	}

	l.LogTrust.PolicyURL = env("DNSID_LOG_POLICY_URL")
	if path := env("DNSID_LOG_POLICY_FILE"); path != "" {
		data, err := os.ReadFile(path)
		if err != nil {
			return Loaded{}, dnsid.NewParseError("dnsid: reading DNSID_LOG_POLICY_FILE", err)
		}
		l.LogTrust.PolicyDocument = data
	}
	if path := env("DNSID_LOG_TRUST_PROFILE_FILE"); path != "" {
		data, err := os.ReadFile(path)
		if err != nil {
			return Loaded{}, dnsid.NewParseError("dnsid: reading DNSID_LOG_TRUST_PROFILE_FILE", err)
		}
		profile, err := c2sptlog.ParseTrustProfile(data)
		if err != nil {
			return Loaded{}, err
		}
		l.LogTrust.Profile = &profile
	}

	l.Registry.RegistryURL = env("DNSID_REGISTRY_URL")
	l.KeySource.CliDirectory = env("DNSID_CONFIG_DIR")
	l.KeySource.KeyStorePath = env("DNSID_KEY_STORE")
	return l, nil
}

// cliConfig is the snake_case config.json the DNSid CLI writes. Fields that
// are not SDK configuration (server_url, agent_id, environment) are ignored.
type cliConfig struct {
	Domain          string `json:"domain"`
	GovernanceID    string `json:"governance_id"`
	StatusURL       string `json:"status_url"`
	KeyURL          string `json:"ku_url"`
	EntityKeyURL    string `json:"ek_url"`
	EntityKeyPath   string `json:"entity_key_path"`
	LogRef          string `json:"log_ref"`
	CapabilitiesURL string `json:"capabilities_url"`
	PublishProfile  string `json:"publish_profile"`
	MaxKeyAge       string `json:"max_key_age"`
}

// LoadCliDirectory reads <dir>/config.json written by the DNSid CLI. An empty
// dir reads ~/.dnsid; DNSID_CONFIG_DIR is not consulted (LoadEnvironment
// carries it as KeySource.CliDirectory). Persisted publication fields map into
// Dnsid.Identity exactly as written: status_url is never derived from
// server_url and no log reference is substituted. The directory becomes
// KeySource.CliDirectory and entity_key_path, resolved against the directory
// of the config.json that carries it, becomes KeySource.EntityKeyPath.
//
// The CLI treats a root config.json as the current-identity pointer: when it
// names a domain and <dir>/<domain>/config.json exists, that per-identity file
// is read instead. A leaf identity directory is read as-is.
func LoadCliDirectory(dir string) (Loaded, error) {
	if dir == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return Loaded{}, dnsid.NewArgumentError("dnsid: locating home directory", err)
		}
		dir = filepath.Join(home, ".dnsid")
	}
	configDir := dir
	cfg, err := readCliConfig(configDir)
	if err != nil {
		return Loaded{}, err
	}
	if pointer := strings.TrimSpace(cfg.Domain); pointer != "" {
		if normalized, err := dnsid.NormalizeFQDN(pointer); err == nil {
			if leaf := filepath.Join(dir, normalized); fileExists(filepath.Join(leaf, "config.json")) {
				if cfg, err = readCliConfig(leaf); err != nil {
					return Loaded{}, err
				}
				configDir = leaf
			}
		}
	}
	identity := dnsid.IdentityConfig{
		Domain:          strings.TrimSpace(cfg.Domain),
		GovernanceID:    strings.TrimSpace(cfg.GovernanceID),
		StatusURL:       strings.TrimSpace(cfg.StatusURL),
		KeyURL:          strings.TrimSpace(cfg.KeyURL),
		EntityKeyURL:    strings.TrimSpace(cfg.EntityKeyURL),
		LogRef:          strings.TrimSpace(cfg.LogRef),
		CapabilitiesURL: strings.TrimSpace(cfg.CapabilitiesURL),
		PublishProfile:  strings.TrimSpace(cfg.PublishProfile),
		MaxKeyAge:       dnsid.KeyAge(strings.TrimSpace(cfg.MaxKeyAge)),
	}
	l := Loaded{KeySource: KeySource{CliDirectory: dir}}
	if !reflect.ValueOf(identity).IsZero() {
		l.Dnsid.Identity = &identity
	}
	if p := strings.TrimSpace(cfg.EntityKeyPath); p != "" {
		if !filepath.IsAbs(p) {
			p = filepath.Join(configDir, p)
		}
		l.KeySource.EntityKeyPath = p
	}
	return l, nil
}

func readCliConfig(dir string) (cliConfig, error) {
	data, err := os.ReadFile(filepath.Join(dir, "config.json"))
	if err != nil {
		return cliConfig{}, dnsid.NewParseError("dnsid: reading DNSid config", err)
	}
	var cfg cliConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		return cliConfig{}, dnsid.NewParseError("dnsid: parsing DNSid config", err)
	}
	return cfg, nil
}

func fileExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}

// Merge applies overlay onto base field-wise: a present overlay field replaces
// the base field, an absent one leaves base unchanged. Slices replace as a
// whole (nil is absent, empty is present). LogTrust is replaced as a whole
// section when overlay sets any variant.
//
// Scalar zero values are absent: overlays cannot clear loaded Identity strings,
// Verification.DNSSECMode or StatusCheckInterval, Transport.DNSServer or
// CABundlePath, Registry.RegistryURL, or KeySource paths.
// Non-nil empty slices remain present. To clear a field, edit the merged
// config before passing it to the ordinary constructor. No loader sets
// StatusCheckInterval, so its zero-value limitation affects code overlays only.
func Merge(base, overlay Loaded) Loaded {
	if overlay.Dnsid.Identity != nil {
		merged := overlayIdentity(derefIdentity(base.Dnsid.Identity), *overlay.Dnsid.Identity)
		base.Dnsid.Identity = &merged
	}
	if overlay.Dnsid.Verification.DNSSECMode != "" {
		base.Dnsid.Verification.DNSSECMode = overlay.Dnsid.Verification.DNSSECMode
	}
	if overlay.Dnsid.Verification.StatusCheckInterval != 0 {
		base.Dnsid.Verification.StatusCheckInterval = overlay.Dnsid.Verification.StatusCheckInterval
	}
	if overlay.Dnsid.Verification.TrustedEntities != nil {
		base.Dnsid.Verification.TrustedEntities = overlay.Dnsid.Verification.TrustedEntities
	}
	if overlay.Dnsid.Transport.DNSServer != "" {
		base.Dnsid.Transport.DNSServer = overlay.Dnsid.Transport.DNSServer
	}
	if overlay.Dnsid.Transport.CABundlePath != "" {
		base.Dnsid.Transport.CABundlePath = overlay.Dnsid.Transport.CABundlePath
	}
	if overlay.Dnsid.Transport.PrivateAddressHosts != nil {
		base.Dnsid.Transport.PrivateAddressHosts = overlay.Dnsid.Transport.PrivateAddressHosts
	}
	if !overlay.LogTrust.isZero() {
		base.LogTrust = overlay.LogTrust
	}
	if overlay.Registry.RegistryURL != "" {
		base.Registry.RegistryURL = overlay.Registry.RegistryURL
	}
	if overlay.KeySource.CliDirectory != "" {
		base.KeySource.CliDirectory = overlay.KeySource.CliDirectory
	}
	if overlay.KeySource.EntityKeyPath != "" {
		base.KeySource.EntityKeyPath = overlay.KeySource.EntityKeyPath
	}
	if overlay.KeySource.KeyStorePath != "" {
		base.KeySource.KeyStorePath = overlay.KeySource.KeyStorePath
	}
	return base
}

func derefIdentity(p *dnsid.IdentityConfig) dnsid.IdentityConfig {
	if p == nil {
		return dnsid.IdentityConfig{}
	}
	return *p
}

func overlayIdentity(base, o dnsid.IdentityConfig) dnsid.IdentityConfig {
	if o.Domain != "" {
		base.Domain = o.Domain
	}
	if o.GovernanceID != "" {
		base.GovernanceID = o.GovernanceID
	}
	if o.LogRef != "" {
		base.LogRef = o.LogRef
	}
	if o.StatusURL != "" {
		base.StatusURL = o.StatusURL
	}
	if o.PolicyFlags != nil {
		base.PolicyFlags = o.PolicyFlags
	}
	if o.MaxKeyAge != "" {
		base.MaxKeyAge = o.MaxKeyAge
	}
	if o.KeyURL != "" {
		base.KeyURL = o.KeyURL
	}
	if o.EntityKeyURL != "" {
		base.EntityKeyURL = o.EntityKeyURL
	}
	if o.CapabilitiesURL != "" {
		base.CapabilitiesURL = o.CapabilitiesURL
	}
	if o.PublishProfile != "" {
		base.PublishProfile = o.PublishProfile
	}
	return base
}

// Fixed defaults the managed catalog documents; applied to the generic
// factory for profile, policy-document, and policy-URL trust.
const logTrustFreshness = 10 * time.Minute

// Construct builds an IdentityManager from a merged Loaded and the caller's
// dependencies. Caller dependencies win: LogRegistry is built from LogTrust
// only when deps.LogRegistry is nil, and key providers are built from
// KeySource only when Dnsid.Identity is present and the corresponding provider
// is nil. loaded.Dnsid is validated first so invalid configuration never
// triggers a key-file read or policy fetch; dnsid.NewIdentityManager then
// applies every default and validation.
func Construct(ctx context.Context, loaded Loaded, deps Dependencies) (*dnsid.IdentityManager, error) {
	// Fail on configuration before reading key files or fetching a policy.
	if err := loaded.Dnsid.Validate(); err != nil {
		return nil, err
	}
	if deps.HTTPClient != nil && deps.HTTPSFetcher != nil {
		return nil, dnsid.NewArgumentError("dnsid: HTTPClient and HTTPSFetcher cannot both be supplied", nil)
	}
	if deps.LogRegistry == nil && !loaded.LogTrust.isZero() {
		registry, err := logRegistryFromTrust(ctx, loaded.LogTrust, loaded.Dnsid.Transport)
		if err != nil {
			return nil, err
		}
		deps.LogRegistry = registry
	}
	if loaded.Dnsid.Identity != nil && !loaded.KeySource.isZero() {
		if deps.KeyProvider == nil {
			kp, err := operationalKeyProvider(loaded.KeySource, loaded.Dnsid.Identity.Domain)
			if err != nil {
				return nil, err
			}
			deps.KeyProvider = kp
		}
		if deps.EntityKeyProvider == nil && loaded.KeySource.EntityKeyPath != "" {
			kp, err := dnsid.NewLocalKeyProvider(loaded.KeySource.EntityKeyPath)
			if err != nil {
				return nil, err
			}
			deps.EntityKeyProvider = kp
		}
	}
	var opts []dnsid.IdentityManagerOption
	if deps.DNSResolver != nil {
		opts = append(opts, dnsid.WithDNSResolver(deps.DNSResolver))
	}
	if deps.HTTPClient != nil {
		opts = append(opts, dnsid.WithHTTPClient(deps.HTTPClient))
	}
	if deps.HTTPSFetcher != nil {
		opts = append(opts, dnsid.WithHTTPSFetcher(deps.HTTPSFetcher))
	}
	if deps.IdentityCache != nil {
		opts = append(opts, dnsid.WithIdentityCache(deps.IdentityCache))
	}
	if deps.LogRegistry != nil {
		opts = append(opts, dnsid.WithLogRegistry(deps.LogRegistry))
	}
	if deps.EntityKeyProvider != nil {
		opts = append(opts, dnsid.WithEntityKeyProvider(deps.EntityKeyProvider))
	}
	return dnsid.NewIdentityManager(loaded.Dnsid, deps.KeyProvider, opts...)
}

func logRegistryFromTrust(ctx context.Context, t LogTrust, transport dnsid.TransportConfig) (*dnsidlog.LogRegistry, error) {
	variants := 0
	for _, set := range []bool{t.Managed, t.Profile != nil, t.PolicyDocument != nil, t.PolicyURL != ""} {
		if set {
			variants++
		}
	}
	if variants != 1 {
		return nil, dnsid.NewArgumentError("dnsid: LogTrust must set exactly one of Managed, Profile, PolicyDocument, or PolicyURL", nil)
	}
	if t.Managed {
		return c2sptlog.NewDnsidManagedVerificationRegistry(ctx, c2sptlog.DnsidManagedVerificationConfig{})
	}
	return c2sptlog.NewVerificationRegistry(ctx, c2sptlog.VerificationRegistryConfig{
		TrustProfile:      t.Profile,
		PolicyDocument:    t.PolicyDocument,
		PolicyURL:         t.PolicyURL,
		Transport:         transport,
		CheckpointMaxAge:  logTrustFreshness,
		MaxBundleLifetime: logTrustFreshness,
	})
}

// operationalKeyProvider locates the operational key under CliDirectory
// (private.jwk, then <domain>/private.jwk using the effective identity
// domain) or, without a directory, at KeyStorePath.
func operationalKeyProvider(src KeySource, domain string) (dnsid.KeyProvider, error) {
	if src.CliDirectory == "" {
		if src.KeyStorePath == "" {
			return nil, dnsid.NewArgumentError("dnsid: KeySource has no operational key location for the configured identity", nil)
		}
		return dnsid.NewLocalKeyProvider(src.KeyStorePath)
	}
	path := filepath.Join(src.CliDirectory, "private.jwk")
	if _, err := os.Stat(path); os.IsNotExist(err) {
		normalized, err := dnsid.NormalizeFQDN(domain)
		if err != nil {
			return nil, dnsid.NewArgumentError("dnsid: invalid IdentityConfig.Domain", err)
		}
		path = filepath.Join(src.CliDirectory, normalized, "private.jwk")
	}
	return dnsid.NewLocalKeyProvider(path)
}

// IdentityManagerFromEnvironment is Construct(Merge(LoadEnvironment(getenv),
// {Dnsid: overlay}), deps). A nil getenv reads the process environment. With
// no DNSID_DOMAIN the result is a verification-only manager; under `dnsid
// local run`, DNSID_CONFIG_DIR supplies the key files.
func IdentityManagerFromEnvironment(ctx context.Context, getenv func(string) string, overlay dnsid.Config, deps Dependencies) (*dnsid.IdentityManager, error) {
	loaded, err := LoadEnvironment(getenv)
	if err != nil {
		return nil, err
	}
	return Construct(ctx, Merge(loaded, Loaded{Dnsid: overlay}), deps)
}

// IdentityManagerFromDnsid is Construct(Merge(LoadCliDirectory(dir),
// {Dnsid: overlay}), deps). An empty dir reads ~/.dnsid.
func IdentityManagerFromDnsid(ctx context.Context, dir string, overlay dnsid.Config, deps Dependencies) (*dnsid.IdentityManager, error) {
	loaded, err := LoadCliDirectory(dir)
	if err != nil {
		return nil, err
	}
	return Construct(ctx, Merge(loaded, Loaded{Dnsid: overlay}), deps)
}

// RegistryClientFromEnvironment builds a registry client from
// DNSID_REGISTRY_URL and DNSID_API_KEY. A nil getenv reads the process
// environment. The constructor applies the loopback default when the URL is
// absent. Explicit opts are applied after the environment credential and win.
func RegistryClientFromEnvironment(getenv func(string) string, opts ...dnsid.RegistryClientOption) (*dnsid.HTTPRegistryClient, error) {
	if getenv == nil {
		getenv = os.Getenv
	}
	loaded, err := LoadEnvironment(getenv)
	if err != nil {
		return nil, err
	}
	if token := strings.TrimSpace(getenv("DNSID_API_KEY")); token != "" {
		opts = append([]dnsid.RegistryClientOption{dnsid.WithAuthToken(token)}, opts...)
	}
	return dnsid.NewRegistryClientWithOptions(loaded.Registry.RegistryURL, opts...)
}
