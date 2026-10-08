package config

import (
	"context"
	"fmt"
	"log/slog"
	"sync"

	dnsid "github.com/dnsid-ai/dnsid-go"
)

// KeyGenerationConfig identifies a recoverable key generation operation.
// Cloud packages without atomic create-or-recover support require KeyRef instead.
type KeyGenerationConfig struct {
	Locator   string        `json:"locator"`
	Algorithm dnsid.JoseAlg `json:"algorithm"`
}

// KeyProviderFactory validates non-secret settings and opens an existing key.
// Validate must not generate keys or perform network requests.
type KeyProviderFactory struct {
	Validate func(KeySource) error
	Open     func(context.Context, KeySource, string) (dnsid.KeyProvider, error)
}

var keyFactories = struct {
	sync.RWMutex
	values map[string]KeyProviderFactory
}{values: make(map[string]KeyProviderFactory)}

// RegisterKeyProviderFactory links an optional provider package's factory.
// Packages call this in init; importing the module alone does not link it.
func RegisterKeyProviderFactory(name string, factory KeyProviderFactory) {
	if name != "aws-kms" && name != "google-kms" && name != "azure-key-vault" {
		panic("dnsid: unknown key provider factory")
	}
	if factory.Validate == nil || factory.Open == nil {
		panic("dnsid: incomplete key provider factory")
	}
	keyFactories.Lock()
	defer keyFactories.Unlock()
	if _, exists := keyFactories.values[name]; exists {
		panic("dnsid: duplicate key provider factory")
	}
	keyFactories.values[name] = factory
}

// ValidateKeySource checks availability and settings without opening a key.
// Injected providers bypass this selection entirely.
func ValidateKeySource(src KeySource) error {
	if src.KeyRef != "" && src.Generation != nil {
		return dnsid.NewArgumentError("dnsid: keySource.keyRef and generation are mutually exclusive", nil)
	}
	if src.CliDirectory != "" || src.KeyStorePath != "" {
		if (src.Provider != "" && src.Provider != "file") || src.KeyRef != "" || src.Generation != nil {
			return dnsid.NewArgumentError("dnsid: CLI/key-store paths cannot combine with cloud selection, keyRef, or generation", nil)
		}
	}
	if src.Provider == "" || src.Provider == "file" {
		if len(src.Settings) != 0 {
			return dnsid.NewArgumentError("dnsid: file key source has no settings", nil)
		}
		if g := src.Generation; g != nil && (g.Locator == "" || (g.Algorithm != dnsid.JoseAlgEdDSA && g.Algorithm != dnsid.JoseAlgES256)) {
			return dnsid.NewArgumentError("dnsid: file generation requires a locator and EdDSA or ES256", nil)
		}
		return nil
	}
	factory, err := keyFactory(src.Provider)
	if err != nil {
		return err
	}
	return factory.Validate(src)
}

func keyFactory(name string) (KeyProviderFactory, error) {
	keyFactories.RLock()
	factory, ok := keyFactories.values[name]
	keyFactories.RUnlock()
	if !ok {
		return KeyProviderFactory{}, dnsid.NewArgumentError(fmt.Sprintf("dnsid: key provider %q is unavailable; add its provider package dependency, import it, and rebuild (no file fallback)", name), nil)
	}
	return factory, nil
}

// OperationalKeyProviderFrom opens an existing selected key; it never generates.
func OperationalKeyProviderFrom(ctx context.Context, src KeySource, domain string) (dnsid.KeyProvider, error) {
	if err := ValidateKeySource(src); err != nil {
		return nil, err
	}
	if src.Generation != nil {
		return nil, dnsid.NewArgumentError("dnsid: Construct opens existing keys only; generation belongs to managed registration", nil)
	}
	if src.Provider == "" || src.Provider == "file" {
		WarnLocalKeys()
		if src.KeyRef != "" {
			return dnsid.NewLocalKeyProvider(src.KeyRef)
		}
		return operationalKeyProvider(src, domain)
	}
	factory, err := keyFactory(src.Provider)
	if err != nil {
		return nil, err
	}
	return factory.Open(ctx, src, domain)
}

// WarnLocalKeys explains the custody limit of the development file provider.
func WarnLocalKeys() {
	slog.Warn("DNSid file keys are unsuitable for production; configure a cloud key provider such as aws-kms")
}
