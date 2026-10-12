package c2sptlog

import (
	"context"
	"path/filepath"
	"testing"

	dnsid "github.com/dnsid-ai/dnsid-go"
)

func TestManagedRotation_SameSavedReferenceUsesOneProviderInstance(t *testing.T) {
	path := filepath.Join(t.TempDir(), "keys.json")
	provider, err := dnsid.LoadOrCreateLocalKeyProvider(path, dnsid.JoseAlgEdDSA)
	if err != nil {
		t.Fatal(err)
	}
	client, _ := managedRotationFixtureWithProvider(t, provider)
	registry := &managedRotationRegistry{client: client, state: dnsid.SubmissionStatePending}
	store := ManagedKeyRotationStoreFunc(func(context.Context, *ManagedKeyRotationState) error { return nil })
	signing := ApplicationSigningControllerFunc(func(context.Context, bool) error { return nil })
	rotation, err := RotateManagedOperationalKey(context.Background(), ManagedKeyRotationOptions{
		Domain: "agent.example.com", Client: client, KeyProvider: provider,
		PreviousProviderRef: path, PublicationVerifier: rotationPublicationVerifier{}, WireSigner: rotationWireSigner,
		RegistryClient: registry, IdempotencyKey: "same-provider", Store: store, ApplicationSigning: signing,
	})
	if err != nil {
		t.Fatal(err)
	}
	registry.state = dnsid.SubmissionStateAccepted
	resolutions := 0
	rotation, err = ResumeManagedOperationalKeyRotation(context.Background(), ResumeManagedKeyRotationOptions{
		Client: client, Rotation: rotation, PublicationVerifier: rotationPublicationVerifier{}, WireSigner: rotationWireSigner,
		ResolveProvider: func(_ context.Context, ref string) (dnsid.KeyProvider, error) {
			resolutions++
			return dnsid.NewLocalKeyProvider(ref)
		},
		RegistryClient: registry, Store: store, ApplicationSigning: signing,
	})
	if err != nil || resolutions != 1 {
		t.Fatalf("same provider recovery: %v resolutions=%d", err, resolutions)
	}
	restored, err := dnsid.NewLocalKeyProvider(path)
	if err != nil {
		t.Fatal(err)
	}
	kid, _ := restored.JWK().KeyID()
	if kid != rotation.NewKid || restored.JWK(rotation.PreviousKid) != nil {
		t.Fatal("recovery overwrote the active key store")
	}
}
