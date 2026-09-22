package dnsid

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
)

type dnsidIdentityConfig struct {
	ServerURL       string `json:"server_url"`
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

// NewIdentityManagerFromDnsid constructs a local-identity IdentityManager from
// a DNSid CLI config directory. Empty dir uses DNSID_CONFIG_DIR when set,
// otherwise ~/.dnsid. The persisted publication fields become defaults for
// cfg.Identity; any non-empty field in cfg.Identity wins. cfg.Verification and
// cfg.Transport are used as supplied and are never inferred from the loaded
// identity. The key files select the operational and entity KeyProviders;
// a WithEntityKeyProvider option wins over the loaded entity key.
func NewIdentityManagerFromDnsid(dir string, cfg Config, opts ...IdentityManagerOption) (*IdentityManager, error) {
	loaded, configPath, err := readDnsidIdentityConfig(dir)
	if err != nil {
		return nil, err
	}
	configDir := filepath.Dir(configPath)
	if loaded.EntityKeyPath != "" && strings.TrimSpace(loaded.LogRef) == "" {
		return nil, NewValidationError("dnsid: config with entity_key_path must include log_ref", nil)
	}
	identity := IdentityConfig{
		Domain:          loaded.Domain,
		GovernanceID:    loaded.GovernanceID,
		LogRef:          loaded.LogRef,
		StatusURL:       loaded.StatusURL,
		KeyURL:          loaded.KeyURL,
		EntityKeyURL:    loaded.EntityKeyURL,
		CapabilitiesURL: loaded.CapabilitiesURL,
		PublishProfile:  loaded.PublishProfile,
		MaxKeyAge:       KeyAge(loaded.MaxKeyAge),
	}
	// Explicit caller settings win over persisted defaults before any
	// normalization or derivation.
	if cfg.Identity != nil {
		identity = overlayIdentity(identity, *cfg.Identity)
	}
	domain, err := NormalizeFQDN(identity.Domain)
	if err != nil {
		return nil, err
	}
	identity.Domain = domain
	if identity.LogRef == "" {
		// Older CLI configs did not carry publication inputs. Keep them usable
		// for verification and non-publishing workflows, but never invent values
		// for a config capable of client-controlled publication.
		identity.LogRef = "noop:0"
	}
	if identity.StatusURL == "" {
		if loaded.ServerURL == "" {
			return nil, NewValidationError("dnsid: config must include status_url or server_url", nil)
		}
		identity.StatusURL, err = dnsidStatusURL(loaded.ServerURL, domain)
		if err != nil {
			return nil, err
		}
	}
	cfg.Identity = &identity

	keyPath := filepath.Join(configDir, "private.jwk")
	if _, err := os.Stat(keyPath); os.IsNotExist(err) {
		keyPath = filepath.Join(configDir, domain, "private.jwk")
	}
	kp, err := NewLocalKeyProvider(keyPath)
	if err != nil {
		return nil, err
	}
	managerOpts := opts
	if loaded.EntityKeyPath != "" {
		entityKeyPath := loaded.EntityKeyPath
		if !filepath.IsAbs(entityKeyPath) {
			entityKeyPath = filepath.Join(configDir, entityKeyPath)
		}
		entityKeys, loadErr := NewLocalKeyProvider(entityKeyPath)
		if loadErr != nil {
			return nil, loadErr
		}
		managerOpts = append([]IdentityManagerOption{WithEntityKeyProvider(entityKeys)}, opts...)
	}
	return NewIdentityManager(cfg, kp, managerOpts...)
}

// overlayIdentity returns base with every non-zero field of override applied.
// Slices replace rather than merge.
func overlayIdentity(base, override IdentityConfig) IdentityConfig {
	if override.Domain != "" {
		base.Domain = override.Domain
	}
	if override.GovernanceID != "" {
		base.GovernanceID = override.GovernanceID
	}
	if override.LogRef != "" {
		base.LogRef = override.LogRef
	}
	if override.StatusURL != "" {
		base.StatusURL = override.StatusURL
	}
	if override.PolicyFlags != nil {
		base.PolicyFlags = override.PolicyFlags
	}
	if override.MaxKeyAge != "" {
		base.MaxKeyAge = override.MaxKeyAge
	}
	if override.KeyURL != "" {
		base.KeyURL = override.KeyURL
	}
	if override.EntityKeyURL != "" {
		base.EntityKeyURL = override.EntityKeyURL
	}
	if override.CapabilitiesURL != "" {
		base.CapabilitiesURL = override.CapabilitiesURL
	}
	if override.PublishProfile != "" {
		base.PublishProfile = override.PublishProfile
	}
	return base
}

func readDnsidIdentityConfig(dir string) (*dnsidIdentityConfig, string, error) {
	if dir == "" {
		dir = strings.TrimSpace(os.Getenv("DNSID_CONFIG_DIR"))
	}
	if dir == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return nil, "", NewArgumentError("dnsid: locating home directory", err)
		}
		dir = filepath.Join(home, ".dnsid")
	}
	configPath := filepath.Join(dir, "config.json")
	data, err := os.ReadFile(configPath)
	if err != nil {
		return nil, "", NewParseError("dnsid: reading DNSid config", err)
	}
	var cfg dnsidIdentityConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, "", NewParseError("dnsid: parsing DNSid config", err)
	}
	return &cfg, configPath, nil
}

// ConfigFromEnv builds a Config from the DNSID_* variables that `dnsid local
// env` and `dnsid testnet run` export. Transport reads DNSID_DNS_SERVER,
// DNSID_CA_BUNDLE, and comma-separated DNSID_PRIVATE_HOSTS; Verification reads
// DNSID_DNSSEC_MODE. Identity is set only when DNSID_DOMAIN is present and
// reads DNSID_GOVERNANCE_ID, DNSID_LOG_REF (default "noop:0"), DNSID_STATUS_URL
// (default derived from DNSID_REGISTRY_URL or DefaultRegistryURL),
// DNSID_KU_URL, DNSID_EK_URL, and DNSID_PUBLISH_PROFILE. Values are trimmed and
// empty list items are dropped. This loader is explicit: NewIdentityManager
// never reads the environment.
func ConfigFromEnv() (Config, error) {
	env := func(name string) string { return strings.TrimSpace(os.Getenv(name)) }
	cfg := Config{
		Verification: VerificationConfig{DNSSECMode: DNSSECMode(env("DNSID_DNSSEC_MODE"))},
		Transport:    TransportConfig{DNSServer: env("DNSID_DNS_SERVER"), CABundlePath: env("DNSID_CA_BUNDLE")},
	}
	for _, host := range strings.Split(env("DNSID_PRIVATE_HOSTS"), ",") {
		if host = strings.TrimSpace(host); host != "" {
			cfg.Transport.PrivateAddressHosts = append(cfg.Transport.PrivateAddressHosts, host)
		}
	}
	if err := cfg.Transport.validate(); err != nil {
		return Config{}, err
	}
	if err := cfg.Verification.validate(); err != nil {
		return Config{}, err
	}
	if domain := env("DNSID_DOMAIN"); domain != "" {
		identity := &IdentityConfig{
			Domain:         domain,
			GovernanceID:   env("DNSID_GOVERNANCE_ID"),
			LogRef:         env("DNSID_LOG_REF"),
			StatusURL:      env("DNSID_STATUS_URL"),
			KeyURL:         env("DNSID_KU_URL"),
			EntityKeyURL:   env("DNSID_EK_URL"),
			PublishProfile: env("DNSID_PUBLISH_PROFILE"),
		}
		if identity.LogRef == "" {
			identity.LogRef = "noop:0"
		}
		if identity.StatusURL == "" {
			registryURL := env("DNSID_REGISTRY_URL")
			if registryURL == "" {
				registryURL = DefaultRegistryURL
			}
			statusURL, err := dnsidStatusURL(registryURL, domain)
			if err != nil {
				return Config{}, err
			}
			identity.StatusURL = statusURL
		}
		cfg.Identity = identity
	}
	return cfg, nil
}

func dnsidStatusURL(registryURL, domain string) (string, error) {
	if registryURL == "" || domain == "" {
		return "", nil
	}
	u, err := url.Parse(strings.TrimRight(registryURL, "/"))
	if err != nil || u.Scheme == "" || u.Host == "" {
		return "", NewValidationError(fmt.Sprintf("dnsid: invalid server_url %q", registryURL), err)
	}
	u.Path = strings.TrimRight(u.Path, "/") + "/v1/status/" + url.PathEscape(domain)
	u.RawQuery = ""
	u.Fragment = ""
	return u.String(), nil
}
