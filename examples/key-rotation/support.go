package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	dnsid "github.com/dnsid-ai/dnsid-go"
	"github.com/dnsid-ai/dnsid-go/config"
	"github.com/dnsid-ai/dnsid-go/jose"
	"github.com/dnsid-ai/dnsid-go/log/c2sptlog"
)

// Testnet setup, durable files, and a single-process signing gate.
type demo struct {
	directory    string
	keyPath      string
	logReference string
	rotation     *c2sptlog.ManagedKeyRotationState
	provider     *dnsid.LocalKeyProvider
	manager      *dnsid.IdentityManager
	registry     *dnsid.HTTPRegistryClient
	profile      *jose.Profile
	publication  *dnsid.VerifiedDomain
	paused       bool
}

type journal struct {
	KeyPath string                            `json:"key_path"`
	State   *c2sptlog.ManagedKeyRotationState `json:"state"`
}

func openDemo(ctx context.Context) (*demo, error) {
	configDir := os.Getenv("DNSID_CONFIG_DIR")
	if configDir == "" || os.Getenv("DNSID_LOG_POLICY_URL") == "" {
		return nil, fmt.Errorf("run with dnsid local run")
	}
	directory, err := filepath.Abs(filepath.Join(configDir, "rotation-go"))
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(directory, 0700); err != nil {
		return nil, err
	}
	if err := syncDirectory(filepath.Dir(directory)); err != nil {
		return nil, err
	}
	d := &demo{directory: directory, keyPath: filepath.Join(directory, "keys.json")}
	var saved journal
	if data, err := os.ReadFile(filepath.Join(directory, "rotation.json")); err == nil {
		if err := json.Unmarshal(data, &saved); err != nil {
			return nil, err
		}
		if saved.State == nil || saved.KeyPath != d.keyPath {
			return nil, fmt.Errorf("invalid saved provider reference")
		}
		d.rotation = saved.State
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	if _, err := os.Stat(d.keyPath); os.IsNotExist(err) {
		if d.rotation != nil {
			return nil, fmt.Errorf("saved provider is missing; do not generate a replacement")
		}
		data, err := os.ReadFile(filepath.Join(configDir, "private.jwk"))
		if err != nil {
			return nil, err
		}
		if err := save(d.keyPath, json.RawMessage(data)); err != nil {
			return nil, err
		}
	} else if err != nil {
		return nil, err
	}
	d.provider, err = dnsid.NewLocalKeyProvider(d.keyPath)
	if err != nil {
		return nil, err
	}
	loaded, err := config.LoadEnvironment(nil)
	if err != nil {
		return nil, err
	}
	identity := loaded.Dnsid.Identity
	if identity == nil || !strings.HasSuffix(identity.Domain, ".test") || !strings.HasPrefix(identity.LogRef, "c2sp-tlog:testnet:") {
		return nil, fmt.Errorf("this example only rotates testnet identities")
	}
	if d.rotation != nil && (d.rotation.Domain != identity.Domain || d.rotation.LogReference != identity.LogRef) {
		return nil, fmt.Errorf("saved identity binding changed")
	}
	d.logReference = identity.LogRef
	// Terminal recovery must not run network-backed configuration discovery.
	if d.rotation != nil && d.rotation.Activated {
		d.manager, err = dnsid.NewIdentityManager(loaded.Dnsid, d.provider)
	} else {
		d.manager, err = config.Construct(ctx, loaded, config.Dependencies{KeyProvider: d.provider})
	}
	if err != nil {
		return nil, err
	}
	d.registry, err = dnsid.NewRegistryClient(loaded.Registry.RegistryURL)
	if err != nil {
		return nil, err
	}
	if err := d.registry.SetAuthToken(os.Getenv("DNSID_API_KEY")); err != nil {
		return nil, err
	}
	// shortcut: one process owns this store; add locking and request draining before sharing it.
	d.paused = d.rotation != nil
	d.profile = jose.New(d, d.manager.Domain(), d.provider, jose.Config{})
	return d, nil
}

func (d *demo) PersistManagedKeyRotation(_ context.Context, state *c2sptlog.ManagedKeyRotationState) error {
	if err := save(filepath.Join(d.directory, "rotation.json"), journal{KeyPath: d.keyPath, State: state}); err != nil {
		return err
	}
	d.rotation = state
	status := "prepared"
	if state.Submission != nil {
		status = string(state.Submission.State)
	}
	fmt.Printf("saved: %s, activated=%v, paused=%v\n", status, state.Activated, state.ApplicationSigningPaused)
	return nil
}

func (d *demo) SetApplicationSigningPaused(_ context.Context, value bool) error {
	if !value && (d.rotation == nil || !d.rotation.Activated) {
		return fmt.Errorf("activation is not durable")
	}
	d.paused = value
	return nil
}

func (d *demo) VerifyDomain(_ context.Context, domain string) (*dnsid.VerifiedDomain, error) {
	if d.publication == nil || domain != d.publication.Domain() {
		return nil, fmt.Errorf("self-check requires the local identity")
	}
	return d.publication, nil // Local self-checks do not apply counterparty policy.
}

func (d *demo) signAndVerify(ctx context.Context, evidence *dnsid.VerifiedDomain) (string, error) {
	if d.paused {
		return "", fmt.Errorf("application signing is paused")
	}
	if evidence.Record().LogRef != d.logReference {
		return "", fmt.Errorf("CLI log reference does not match publication")
	}
	d.publication = evidence
	message, err := d.profile.CreateJWS([]byte("rotation example"))
	if err != nil {
		return "", err
	}
	_, _, err = d.profile.VerifyJWS(ctx, message)
	return message, err
}

func (d *demo) saveOldMessage(message string) error {
	return save(filepath.Join(d.directory, "old-message.json"), message)
}

func (d *demo) rejectOldMessage(ctx context.Context) error {
	data, err := os.ReadFile(filepath.Join(d.directory, "old-message.json"))
	if err != nil {
		return err
	}
	var message string
	if err := json.Unmarshal(data, &message); err != nil {
		return err
	}
	_, _, err = d.profile.VerifyJWS(ctx, message)
	var rejected *dnsid.VerificationError
	if !errors.As(err, &rejected) || rejected.Code() != dnsid.VerificationCodeKeyNotFound {
		return errors.Join(errors.New("expected old-key rejection after refresh"), err)
	}
	return nil
}

func syncDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}

func save(destination string, value any) error {
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	file, err := os.CreateTemp(filepath.Dir(destination), ".rotation-*")
	if err != nil {
		return err
	}
	defer os.Remove(file.Name())
	if _, err := file.Write(append(data, '\n')); err != nil {
		file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	if err := os.Rename(file.Name(), destination); err != nil {
		return err
	}
	return syncDirectory(filepath.Dir(destination))
}
