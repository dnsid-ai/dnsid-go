package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	dnsid "github.com/dnsid-ai/dnsid-go"
	"github.com/dnsid-ai/dnsid-go/config"
	"github.com/dnsid-ai/dnsid-go/jose"
	"github.com/dnsid-ai/dnsid-go/log/c2sptlog"
)

type journal struct {
	KeyPath string                            `json:"key_path"`
	State   *c2sptlog.ManagedKeyRotationState `json:"state"`
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "rotation:", err, "\nRerun the same command to recover; do not delete the saved state.")
		os.Exit(1)
	}
}

func run() error {
	ctx := context.Background()
	configDir := os.Getenv("DNSID_CONFIG_DIR")
	if configDir == "" || os.Getenv("DNSID_LOG_POLICY_URL") == "" {
		return fmt.Errorf("run with dnsid local run")
	}
	directory, err := filepath.Abs(filepath.Join(configDir, "rotation-go"))
	if err != nil {
		return err
	}
	if err := os.MkdirAll(directory, 0700); err != nil {
		return err
	}
	if err := syncDirectory(filepath.Dir(directory)); err != nil {
		return err
	}
	keyPath, journalPath := filepath.Join(directory, "keys.json"), filepath.Join(directory, "rotation.json")
	saved := journal{KeyPath: keyPath}
	if data, err := os.ReadFile(journalPath); err == nil {
		if err := json.Unmarshal(data, &saved); err != nil {
			return err
		}
		if saved.State == nil || saved.KeyPath != keyPath {
			return fmt.Errorf("invalid saved provider reference")
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	if _, err := os.Stat(keyPath); os.IsNotExist(err) {
		if saved.State != nil {
			return fmt.Errorf("saved provider is missing; do not generate a replacement")
		}
		data, err := os.ReadFile(filepath.Join(configDir, "private.jwk"))
		if err != nil {
			return err
		}
		if err := save(keyPath, json.RawMessage(data)); err != nil {
			return err
		}
	} else if err != nil {
		return err
	}
	// shortcut: one process owns this store; add a cross-process lock before sharing it.
	provider, err := dnsid.NewLocalKeyProvider(keyPath)
	if err != nil {
		return err
	}
	loaded, err := config.LoadEnvironment(nil)
	if err != nil {
		return err
	}
	if loaded.Dnsid.Identity == nil || !strings.HasSuffix(loaded.Dnsid.Identity.Domain, ".test") || !strings.HasPrefix(loaded.Dnsid.Identity.LogRef, "c2sp-tlog:testnet:") {
		return fmt.Errorf("this example only rotates testnet identities")
	}
	// Recovery reopens the saved provider instead of selecting a deployment key.
	manager, err := config.Construct(ctx, loaded, config.Dependencies{KeyProvider: provider})
	if err != nil {
		return err
	}
	registry, err := dnsid.NewRegistryClient(loaded.Registry.RegistryURL)
	if err != nil {
		return err
	}
	if err := registry.SetAuthToken(os.Getenv("DNSID_API_KEY")); err != nil {
		return err
	}
	paused := true // Every restart begins closed, even after a completed rotation.
	profile := jose.New(manager, manager.Domain(), provider, jose.Config{})
	sign := func() (string, error) {
		if paused {
			return "", fmt.Errorf("application signing is paused")
		}
		return profile.CreateJWS([]byte("rotation example"))
	}
	store := c2sptlog.ManagedKeyRotationStoreFunc(func(_ context.Context, state *c2sptlog.ManagedKeyRotationState) error {
		if saved.State != nil && (saved.State.EntryHash != state.EntryHash || saved.State.IdempotencyKey != state.IdempotencyKey) {
			return fmt.Errorf("recovery changed the signed operation")
		}
		next := journal{KeyPath: keyPath, State: state}
		if err := save(journalPath, next); err != nil {
			return err
		}
		saved = next
		status := "prepared"
		if state.Submission != nil {
			status = string(state.Submission.State)
		}
		fmt.Printf("saved: %s, activated=%v, paused=%v\n", status, state.Activated, state.ApplicationSigningPaused)
		return nil
	})
	signing := c2sptlog.ApplicationSigningControllerFunc(func(_ context.Context, value bool) error {
		if !value && (saved.State == nil || !saved.State.Activated) {
			return fmt.Errorf("activation is not durable")
		}
		paused = value // All signatures use sign(); no concurrent requests to drain.
		return nil
	})
	verify := func(ctx context.Context, domain string) (*dnsid.VerifiedDomain, error) {
		return manager.RefreshDomain(ctx, domain, dnsid.VerifyDomainOpts{})
	}
	resume := func() (*c2sptlog.ManagedKeyRotationState, error) {
		return c2sptlog.ResumeManagedOperationalKeyRotation(ctx, c2sptlog.ResumeManagedKeyRotationOptions{
			KeyProvider: provider, RegistryClient: registry, Rotation: saved.State,
			Store: store, ApplicationSigning: signing, VerifyPublicationEvidence: verify,
		})
	}
	var rotation *c2sptlog.ManagedKeyRotationState
	if saved.State == nil {
		before, err := verify(ctx, manager.Domain())
		if err != nil {
			return err
		}
		if before.Record().LogRef != loaded.Dnsid.Identity.LogRef {
			return fmt.Errorf("CLI log reference does not match publication")
		}
		key, err := before.KeySet().CurrentOperationalSigningKey(before.Record().Version)
		if err != nil {
			return err
		}
		kid, _ := provider.JWK().KeyID()
		if key.Kid() != kid {
			return fmt.Errorf("local key does not match publication")
		}
		paused = false
		oldMessage, err := sign()
		if err != nil {
			return err
		}
		if _, _, err := profile.VerifyJWS(ctx, oldMessage); err != nil {
			return err
		}
		if err := save(filepath.Join(directory, "old-message.json"), oldMessage); err != nil {
			return err
		}
		fmt.Println("old key signs and verifies")
		client, ok := before.LogReader().(*c2sptlog.Client)
		if !ok {
			return fmt.Errorf("this example requires c2sp-tlog")
		}
		var nonce [16]byte
		if _, err := rand.Read(nonce[:]); err != nil {
			return err
		}
		rotation, err = c2sptlog.RotateManagedOperationalKey(ctx, c2sptlog.ManagedKeyRotationOptions{
			Domain: manager.Domain(), Client: client, KeyProvider: provider,
			RegistryClient: registry, IdempotencyKey: hex.EncodeToString(nonce[:]),
			Store: store, ApplicationSigning: signing, VerifyPublicationEvidence: verify,
		})
		if err != nil {
			return err
		}
	} else {
		if saved.State.Domain != manager.Domain() || saved.State.LogReference != loaded.Dnsid.Identity.LogRef {
			return fmt.Errorf("saved identity binding changed")
		}
		rotation, err = resume()
	}
	if err != nil {
		return err
	}
	for attempt := 0; !rotation.Activated && attempt < 60; attempt++ {
		time.Sleep(time.Second)
		rotation, err = resume()
		if err != nil {
			return err
		}
	}
	if !rotation.Activated || paused {
		return fmt.Errorf("rotation unresolved; rerun the same command")
	}
	observed, err := verify(ctx, manager.Domain())
	if err != nil {
		return err
	}
	key, err := observed.KeySet().CurrentOperationalSigningKey(observed.Record().Version)
	if err != nil {
		return err
	}
	if len(observed.KeySet().SigningKeys()) != 1 || key.Kid() != rotation.NewKid || provider.JWK(rotation.PreviousKid) != nil {
		return fmt.Errorf("incorrect final key state")
	}
	signed, err := sign()
	if err != nil {
		return err
	}
	if _, _, err := profile.VerifyJWS(ctx, signed); err != nil {
		return err
	}
	data, err := os.ReadFile(filepath.Join(directory, "old-message.json"))
	if err != nil {
		return err
	}
	var oldMessage string
	if err := json.Unmarshal(data, &oldMessage); err != nil {
		return err
	}
	_, _, err = profile.VerifyJWS(ctx, oldMessage)
	var rejected *dnsid.VerificationError
	if !errors.As(err, &rejected) || rejected.Code() != dnsid.VerificationCodeKeyNotFound {
		return fmt.Errorf("expected old-key rejection after refresh, got %v", err)
	}
	fmt.Printf("rotation verified: %s -> %s\nnew key signs and verifies; old key is absent from live JWKS and provider\n", rotation.PreviousKid, rotation.NewKid)
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
