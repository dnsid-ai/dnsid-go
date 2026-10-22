package c2sptlog

import (
	"context"
	"errors"
	"testing"

	dnsid "github.com/dnsid-ai/dnsid-go"
	"github.com/lestrrat-go/jwx/v3/jwk"
)

func TestManagedRotationRejectsStalePublicationBeforeActivation(t *testing.T) {
	ctx := context.Background()
	client, provider, verify := managedRotationFixture(t)
	stale, err := verify(ctx)
	if err != nil {
		t.Fatal(err)
	}
	paused := false
	rotation, err := RotateManagedOperationalKey(ctx, ManagedKeyRotationOptions{
		Domain: "agent.example.com", Client: client, KeyProvider: provider,
		RegistryClient:     &managedRotationRegistry{client: client, state: dnsid.SubmissionStateAccepted},
		IdempotencyKey:     "stale-publication",
		Store:              ManagedKeyRotationStoreFunc(func(context.Context, *ManagedKeyRotationState) error { return nil }),
		ApplicationSigning: ApplicationSigningControllerFunc(func(_ context.Context, value bool) error { paused = value; return nil }),
		Publication:        publicationFunc(func(context.Context) (*dnsid.VerifiedDomain, error) { return stale, nil }),
	})
	var activationErr *ManagedKeyRotationActivationError
	if !errors.As(err, &activationErr) || rotation.Activated || !paused {
		t.Fatalf("stale publication did not fail closed: rotation=%#v paused=%v err=%v", rotation, paused, err)
	}
	kid, _ := provider.JWK().KeyID()
	if kid != rotation.PreviousKid {
		t.Fatal("activated a key before verifying its publication")
	}
}

func TestManagedRotationRecoveryRejectsUnrelatedProvider(t *testing.T) {
	ctx := context.Background()
	client, provider, verify := managedRotationFixture(t)
	registry := &managedRotationRegistry{client: client, state: dnsid.SubmissionStateAccepted}
	store := ManagedKeyRotationStoreFunc(func(context.Context, *ManagedKeyRotationState) error { return nil })
	rotation, err := RotateManagedOperationalKey(ctx, ManagedKeyRotationOptions{
		Domain: "agent.example.com", Client: client, KeyProvider: provider,
		RegistryClient: registry, IdempotencyKey: "recovery-binding", Store: store,
		Publication: verify,
		ApplicationSigning: ApplicationSigningControllerFunc(func(_ context.Context, paused bool) error {
			if !paused {
				return errors.New("interrupted before signing resumed")
			}
			return nil
		}),
	})
	var activationErr *ManagedKeyRotationActivationError
	if !errors.As(err, &activationErr) || rotation == nil || !rotation.Activated || !rotation.ApplicationSigningPaused {
		t.Fatalf("failed to reach activated-but-paused state: %v", err)
	}
	for _, completed := range []bool{false, true} {
		t.Run(map[bool]string{false: "paused", true: "completed"}[completed], func(t *testing.T) {
			saved := cloneManagedRotation(rotation)
			saved.ApplicationSigningPaused = !completed
			called := false
			_, err := ResumeManagedOperationalKeyRotation(ctx, ResumeManagedKeyRotationOptions{
				KeyProvider: dnsid.GenerateEd25519KeyProvider(), RegistryClient: registry,
				Rotation: saved, Store: store, Publication: verify,
				ApplicationSigning: ApplicationSigningControllerFunc(func(context.Context, bool) error { called = true; return nil }),
			})
			if err == nil || called || len(registry.submissions) != 1 {
				t.Fatalf("unsafe recovery: err=%v signingCallback=%v submissions=%d", err, called, len(registry.submissions))
			}
		})
	}
}

func TestManagedRotationRequiresPublicationVerifierBeforeGeneration(t *testing.T) {
	client, provider, _ := managedRotationFixture(t)
	registry := &managedRotationRegistry{client: client, state: dnsid.SubmissionStateAccepted}
	_, err := RotateManagedOperationalKey(context.Background(), ManagedKeyRotationOptions{
		Domain: "agent.example.com", Client: client, KeyProvider: provider,
		RegistryClient: registry, IdempotencyKey: "missing-verifier",
		Store:              ManagedKeyRotationStoreFunc(func(context.Context, *ManagedKeyRotationState) error { return nil }),
		ApplicationSigning: ApplicationSigningControllerFunc(func(context.Context, bool) error { return nil }),
	})
	if err == nil || registry.prepareCalls != 0 {
		t.Fatalf("missing publication verifier: err=%v preparations=%d", err, registry.prepareCalls)
	}
}

type interruptedRotationProvider struct {
	dnsid.KeyProvider
	failSupersede  bool
	unavailableKid string
	activations    int
}

func (p *interruptedRotationProvider) Activate(kid string) error {
	p.activations++
	return p.KeyProvider.Activate(kid)
}

func (p *interruptedRotationProvider) Supersede(kid string) error {
	if p.failSupersede {
		return errors.New("interrupted before supersession")
	}
	return p.KeyProvider.Supersede(kid)
}

func (p *interruptedRotationProvider) JWK(kid ...string) jwk.Key {
	if len(kid) > 0 && kid[0] == p.unavailableKid {
		return nil
	}
	return p.KeyProvider.JWK(kid...)
}

func TestManagedRotationRecoveryBetweenActivationAndSupersession(t *testing.T) {
	for _, unavailable := range []bool{false, true} {
		t.Run(map[bool]string{false: "available", true: "unavailable"}[unavailable], func(t *testing.T) {
			ctx := context.Background()
			client, source, verify := managedRotationFixture(t)
			provider := &interruptedRotationProvider{KeyProvider: source, failSupersede: true}
			registry := &managedRotationRegistry{client: client, state: dnsid.SubmissionStateAccepted}
			var saved *ManagedKeyRotationState
			store := ManagedKeyRotationStoreFunc(func(_ context.Context, state *ManagedKeyRotationState) error {
				saved = cloneManagedRotation(state)
				return nil
			})
			paused := false
			signing := ApplicationSigningControllerFunc(func(_ context.Context, value bool) error { paused = value; return nil })
			_, err := RotateManagedOperationalKey(ctx, ManagedKeyRotationOptions{
				Domain: "agent.example.com", Client: client, KeyProvider: provider,
				RegistryClient: registry, IdempotencyKey: "partial-activation",
				Store: store, ApplicationSigning: signing, Publication: verify,
			})
			var activationErr *ManagedKeyRotationActivationError
			if !errors.As(err, &activationErr) || saved.Activated || !paused || saved.Submission.State != dnsid.SubmissionStateAccepted {
				t.Fatalf("expected accepted-but-incomplete activation: %v", err)
			}
			active, _ := provider.JWK().KeyID()
			if active != saved.NewKid || !containsString(provider.ListKeyIds(), saved.PreviousKid) {
				t.Fatal("expected new active key and retained previous key")
			}
			provider.failSupersede = false
			if unavailable {
				provider.unavailableKid = saved.PreviousKid
			}
			result, err := ResumeManagedOperationalKeyRotation(ctx, ResumeManagedKeyRotationOptions{
				KeyProvider: provider, RegistryClient: registry, Rotation: saved,
				Store: store, ApplicationSigning: signing, Publication: verify,
			})
			if unavailable {
				if err == nil || !paused {
					t.Fatalf("unavailable retained key did not fail closed: %v", err)
				}
			} else if err != nil || !result.Activated || paused || containsString(provider.ListKeyIds(), result.PreviousKid) {
				t.Fatalf("supersession recovery failed: %v", err)
			}
			if provider.activations != 1 || len(registry.submissions) != 1 {
				t.Fatal("recovery activated twice or resubmitted saved acceptance")
			}
		})
	}
}

func TestManagedRotationRecoveryPersistsBeforeSubmissionOrActivation(t *testing.T) {
	for _, accepted := range []bool{false, true} {
		t.Run(map[bool]string{false: "prepared", true: "accepted"}[accepted], func(t *testing.T) {
			ctx := context.Background()
			client, provider, verify := managedRotationFixture(t)
			registry := &managedRotationRegistry{client: client, state: dnsid.SubmissionStateAccepted}
			blocked := true
			var durable *ManagedKeyRotationState
			store := ManagedKeyRotationStoreFunc(func(_ context.Context, state *ManagedKeyRotationState) error {
				if blocked && (!accepted || state.Submission != nil) {
					return errors.New("storage unavailable")
				}
				durable = cloneManagedRotation(state)
				return nil
			})
			signing := ApplicationSigningControllerFunc(func(context.Context, bool) error { return nil })
			rotation, err := RotateManagedOperationalKey(ctx, ManagedKeyRotationOptions{
				Domain: "agent.example.com", Client: client, KeyProvider: provider,
				RegistryClient: registry, IdempotencyKey: "persistence-retry",
				Store: store, ApplicationSigning: signing, Publication: verify,
			})
			var submissionErr *ManagedKeyRotationSubmissionError
			if !errors.As(err, &submissionErr) || rotation == nil {
				t.Fatalf("expected recoverable persistence failure: %v", err)
			}
			if accepted && (rotation.Submission == nil || rotation.Submission.State != dnsid.SubmissionStateAccepted) {
				t.Fatal("acceptance was lost from the recoverable state")
			}
			submissions := len(registry.submissions)
			_, err = ResumeManagedOperationalKeyRotation(ctx, ResumeManagedKeyRotationOptions{
				KeyProvider: provider, RegistryClient: registry, Rotation: rotation,
				Store: store, ApplicationSigning: signing, Publication: verify,
			})
			active, _ := provider.JWK().KeyID()
			if err == nil || active != rotation.PreviousKid || len(registry.submissions) != submissions {
				t.Fatalf("recovery crossed the failed persistence boundary: %v", err)
			}
			blocked = false
			result, err := ResumeManagedOperationalKeyRotation(ctx, ResumeManagedKeyRotationOptions{
				KeyProvider: provider, RegistryClient: registry, Rotation: rotation,
				Store: store, ApplicationSigning: signing, Publication: verify,
			})
			if err != nil || !result.Activated || durable == nil || !durable.Activated || len(registry.submissions) != 1 || registry.prepareCalls != 1 {
				t.Fatalf("persisted recovery failed: %v", err)
			}
		})
	}
}

func TestManagedRotationResumeAfterActivationNeedsNoNetwork(t *testing.T) {
	for _, paused := range []bool{true, false} {
		t.Run(map[bool]string{true: "paused", false: "completed"}[paused], func(t *testing.T) {
			ctx := context.Background()
			client, provider, verify := managedRotationFixture(t)
			registry := &managedRotationRegistry{client: client, state: dnsid.SubmissionStateAccepted}
			completed, err := RotateManagedOperationalKey(ctx, ManagedKeyRotationOptions{
				Domain: "agent.example.com", Client: client, KeyProvider: provider,
				RegistryClient: registry, IdempotencyKey: "after-activation", Publication: verify,
				Store:              ManagedKeyRotationStoreFunc(func(context.Context, *ManagedKeyRotationState) error { return nil }),
				ApplicationSigning: ApplicationSigningControllerFunc(func(context.Context, bool) error { return nil }),
			})
			if err != nil || !completed.Activated || completed.ApplicationSigningPaused {
				t.Fatalf("rotation did not complete: %v", err)
			}
			saved := cloneManagedRotation(completed)
			saved.ApplicationSigningPaused = paused
			var persisted int
			var signing []bool
			verified := false
			result, err := ResumeManagedOperationalKeyRotation(ctx, ResumeManagedKeyRotationOptions{
				KeyProvider: provider, RegistryClient: registry, Rotation: saved,
				Store: ManagedKeyRotationStoreFunc(func(context.Context, *ManagedKeyRotationState) error { persisted++; return nil }),
				ApplicationSigning: ApplicationSigningControllerFunc(func(_ context.Context, value bool) error {
					signing = append(signing, value)
					return nil
				}),
				Publication: publicationFunc(func(context.Context) (*dnsid.VerifiedDomain, error) {
					verified = true
					return nil, errors.New("offline")
				}),
			})
			if err != nil || !result.Activated || result.ApplicationSigningPaused || verified || len(registry.submissions) != 1 {
				t.Fatalf("resume = %#v, %v; verified=%v submissions=%d", result, err, verified, len(registry.submissions))
			}
			if paused && (persisted != 1 || len(signing) != 1 || signing[0]) {
				t.Fatalf("paused resume: persisted=%d signing=%v", persisted, signing)
			}
			if !paused && (persisted != 0 || len(signing) != 0) {
				t.Fatalf("terminal resume changed state: persisted=%d signing=%v", persisted, signing)
			}
		})
	}
}
