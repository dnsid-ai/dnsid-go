package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"

	"github.com/dnsid-ai/dnsid-go/log/c2sptlog"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "rotation:", err, "\nRerun the same command to recover; do not delete the saved state.")
		os.Exit(1)
	}
}

func run() error {
	ctx := context.Background()
	demo, err := openDemo(ctx)
	if err != nil {
		return err
	}
	restoring := demo.rotation != nil && demo.rotation.Activated

	var rotation *c2sptlog.ManagedKeyRotationState
	if demo.rotation != nil {
		// Resume the saved operation, never prepare a replacement.
		rotation, err = c2sptlog.ResumeManagedOperationalKeyRotation(ctx, c2sptlog.ResumeManagedKeyRotationOptions{
			Rotation: demo.rotation, KeyProvider: demo.provider, RegistryClient: demo.registry,
			Store: demo, ApplicationSigning: demo, Publication: demo.manager,
		})
	} else {
		// Show that the current key works before rotating it.
		before, err := demo.manager.VerifyLocalPublication(ctx)
		if err != nil {
			return err
		}
		oldMessage, err := demo.signAndVerify(ctx, before)
		if err != nil {
			return err
		}
		if err := demo.saveOldMessage(oldMessage); err != nil {
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
			Domain: demo.manager.Domain(), Client: client, KeyProvider: demo.provider,
			RegistryClient: demo.registry, IdempotencyKey: hex.EncodeToString(nonce[:]),
			Store: demo, ApplicationSigning: demo, Publication: demo.manager,
		})
		if err != nil {
			return err
		}
	}
	if err != nil {
		return err
	}
	if !rotation.Activated || rotation.ApplicationSigningPaused {
		return fmt.Errorf("rotation pending; rerun the same command to resume")
	}
	if restoring {
		fmt.Println("saved rotation restored; no network checks")
		return nil
	}

	// Fetch current evidence: the new key must work and the old key must fail.
	after, err := demo.manager.VerifyLocalPublication(ctx)
	if err != nil {
		return err
	}
	key, err := after.KeySet().CurrentOperationalSigningKey(after.Record().Version)
	if err != nil {
		return err
	}
	if len(after.KeySet().SigningKeys()) != 1 || key.Kid() != rotation.NewKid || demo.provider.JWK(rotation.PreviousKid) != nil {
		return fmt.Errorf("incorrect final key state")
	}
	if _, err := demo.signAndVerify(ctx, after); err != nil {
		return err
	}
	if err := demo.rejectOldMessage(ctx); err != nil {
		return err
	}
	fmt.Printf("rotation verified: %s -> %s\n", rotation.PreviousKid, rotation.NewKid)
	fmt.Println("new key signs and verifies; old key is absent from live JWKS and provider")
	return nil
}
