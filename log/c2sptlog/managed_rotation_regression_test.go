package c2sptlog

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"testing"

	dnsid "github.com/dnsid-ai/dnsid-go"
	dnsidlog "github.com/dnsid-ai/dnsid-go/log"
	"github.com/lestrrat-go/jwx/v3/jwk"
)

type rotationMemorySource struct{ memorySource }

func (s rotationMemorySource) ReadEvent(_ context.Context, ref dnsidlog.LogRef) (ProvenEntry, error) {
	_, index, err := ParseFinalEventRef(ref)
	if err != nil || index >= uint64(len(s.entries)) {
		return ProvenEntry{}, errors.New("missing final entry")
	}
	return s.entries[index], nil
}

type rotationPublicationVerifier struct {
	err    error
	logRef string
}

func (rotationPublicationVerifier) Domain() string { return "agent.example.com" }
func (v rotationPublicationVerifier) LogReference() string {
	if v.logRef != "" {
		return v.logRef
	}
	return "c2sp-tlog:testnet:https://log.example#instance_AAAAAAAAAAAAAAAAAAAAAA"
}
func (v rotationPublicationVerifier) VerifyLocalOperationalKey(context.Context, dnsid.KeyProvider, string) (*dnsid.VerifiedDomain, error) {
	return nil, v.err
}

type rotationAlgorithmProvider struct {
	dnsid.KeyProvider
	algorithm          dnsid.JoseAlg
	generatedAlgorithm dnsid.JoseAlg
	generations        int
}

func (p *rotationAlgorithmProvider) GenerateKey(alg dnsid.JoseAlg) (string, error) {
	p.generations++
	if alg != p.algorithm {
		return "", errors.New("target does not support requested algorithm")
	}
	if p.generatedAlgorithm != "" {
		alg = p.generatedAlgorithm
	}
	return p.KeyProvider.GenerateKey(alg)
}

type unavailableRotationProvider struct {
	dnsid.KeyProvider
	kid string
}

func (unavailableRotationProvider) JWK(...string) jwk.Key  { return nil }
func (p unavailableRotationProvider) ListKeyIds() []string { return []string{p.kid} }

func rotationWireSigner(context.Context, dnsid.KeyProvider) error { return nil }
func rotationProviderResolver(provider dnsid.KeyProvider) func(context.Context, string) (dnsid.KeyProvider, error) {
	return func(_ context.Context, ref string) (dnsid.KeyProvider, error) {
		if ref != "test-provider" {
			return nil, errors.New("unknown saved provider")
		}
		return provider, nil
	}
}

func TestManagedRotation_CrossProviderRestartBeforeSignerWiring(t *testing.T) {
	previousPath := filepath.Join(t.TempDir(), "previous.json")
	targetPath := filepath.Join(t.TempDir(), "target.json")
	previous, err := dnsid.LoadOrCreateLocalKeyProvider(previousPath, dnsid.JoseAlgEdDSA)
	if err != nil {
		t.Fatal(err)
	}
	target, err := dnsid.LoadOrCreateLocalKeyProvider(targetPath, dnsid.JoseAlgEdDSA)
	if err != nil {
		t.Fatal(err)
	}
	client, _ := managedRotationFixtureWithProvider(t, previous)
	registry := &managedRotationRegistry{client: client, state: dnsid.SubmissionStateAccepted}
	var saved *ManagedKeyRotationState
	var wired dnsid.KeyProvider = previous
	paused := false
	store := ManagedKeyRotationStoreFunc(func(_ context.Context, s *ManagedKeyRotationState) error { saved = cloneManagedRotation(s); return nil })
	signing := ApplicationSigningControllerFunc(func(_ context.Context, p bool) error {
		if !p && (wired.JWK() == nil || wired == previous) {
			t.Fatal("unpaused before restoring saved signer")
		}
		paused = p
		return nil
	})
	rotation, err := RotateManagedOperationalKey(context.Background(), ManagedKeyRotationOptions{
		Domain: "agent.example.com", Client: client, KeyProvider: previous, TargetProvider: target,
		PreviousProviderRef: "old-provider", NewProviderRef: "new-provider", PublicationVerifier: rotationPublicationVerifier{},
		WireSigner:     func(context.Context, dnsid.KeyProvider) error { return errors.New("crash before wiring") },
		RegistryClient: registry, IdempotencyKey: "cross-provider", Store: store, ApplicationSigning: signing,
	})
	var activation *ManagedKeyRotationActivationError
	if !errors.As(err, &activation) || !rotation.Activated || !saved.Activated || !paused {
		t.Fatalf("crash state: %#v %v", rotation, err)
	}
	serialized, err := json.Marshal(saved)
	if err != nil {
		t.Fatal(err)
	}
	saved = new(ManagedKeyRotationState)
	if err := json.Unmarshal(serialized, saved); err != nil {
		t.Fatal(err)
	}
	resolved := []string{}
	var restoredTarget dnsid.KeyProvider
	rotation, err = ResumeManagedOperationalKeyRotation(context.Background(), ResumeManagedKeyRotationOptions{
		Client: client, PublicationVerifier: rotationPublicationVerifier{}, Rotation: saved,
		ResolveProvider: func(_ context.Context, ref string) (dnsid.KeyProvider, error) {
			resolved = append(resolved, ref)
			switch ref {
			case "old-provider":
				return dnsid.NewLocalKeyProvider(previousPath)
			case "new-provider":
				return dnsid.NewLocalKeyProvider(targetPath)
			}
			return nil, errors.New("unexpected configuration reference")
		},
		WireSigner:     func(_ context.Context, p dnsid.KeyProvider) error { wired = p; restoredTarget = p; return nil },
		RegistryClient: registry, Store: store, ApplicationSigning: signing,
	})
	if err != nil || paused || wired.JWK() == nil || restoredTarget == nil || rotation.ApplicationSigningPaused || len(registry.submissions) != 1 || len(resolved) != 2 {
		t.Fatalf("restart did not restore saved signer: %#v %v refs=%v", rotation, err, resolved)
	}
}

func TestManagedRotation_RecoveryValidatesRetiredSource(t *testing.T) {
	for _, scenario := range []string{"retired source", "unrelated active source", "unavailable listed key"} {
		t.Run(scenario, func(t *testing.T) {
			ctx := context.Background()
			client, previous := managedRotationFixture(t)
			target := dnsid.GenerateEd25519KeyProvider()
			registry := &managedRotationRegistry{client: client, state: dnsid.SubmissionStateAccepted}
			store := ManagedKeyRotationStoreFunc(func(context.Context, *ManagedKeyRotationState) error { return nil })
			saved, err := RotateManagedOperationalKey(ctx, ManagedKeyRotationOptions{
				Domain: "agent.example.com", Client: client, KeyProvider: previous, TargetProvider: target,
				PreviousProviderRef: "previous", NewProviderRef: "target", PublicationVerifier: rotationPublicationVerifier{},
				WireSigner:     func(context.Context, dnsid.KeyProvider) error { return errors.New("crash before wiring") },
				RegistryClient: registry, IdempotencyKey: "source-binding", Store: store,
				ApplicationSigning: ApplicationSigningControllerFunc(func(context.Context, bool) error { return nil }),
			})
			var activation *ManagedKeyRotationActivationError
			if !errors.As(err, &activation) || saved == nil || !saved.Activated {
				t.Fatalf("crash state: %#v %v", saved, err)
			}
			resolvedPrevious := previous
			switch scenario {
			case "unrelated active source":
				resolvedPrevious = dnsid.GenerateEd25519KeyProvider()
			case "unavailable listed key":
				resolvedPrevious = unavailableRotationProvider{KeyProvider: previous, kid: saved.PreviousKid}
			}
			wired, unpaused := false, false
			_, err = ResumeManagedOperationalKeyRotation(ctx, ResumeManagedKeyRotationOptions{
				Client: client, PublicationVerifier: rotationPublicationVerifier{}, Rotation: saved,
				ResolveProvider: func(_ context.Context, ref string) (dnsid.KeyProvider, error) {
					if ref == "previous" {
						return resolvedPrevious, nil
					}
					if ref == "target" {
						return target, nil
					}
					return nil, errors.New("unexpected provider reference")
				},
				WireSigner:     func(context.Context, dnsid.KeyProvider) error { wired = true; return nil },
				RegistryClient: registry, Store: store,
				ApplicationSigning: ApplicationSigningControllerFunc(func(_ context.Context, paused bool) error { unpaused = !paused; return nil }),
			})
			if scenario == "retired source" {
				if err != nil || !wired || !unpaused {
					t.Fatalf("retired source blocked recovery: %v", err)
				}
			} else if !errors.As(err, &activation) || wired || unpaused {
				t.Fatalf("invalid source accepted: %v wired=%v unpaused=%v", err, wired, unpaused)
			}
			if len(registry.submissions) != 1 {
				t.Fatal("accepted recovery resubmitted")
			}
		})
	}
}

func TestManagedRotation_RejectsChangedSourceWithRetainedOldKey(t *testing.T) {
	previous, target := dnsid.GenerateEd25519KeyProvider(), dnsid.GenerateES256KeyProvider()
	oldKid, oldThumb, oldAlg, err := managedRotationKey(previous.JWK())
	if err != nil {
		t.Fatal(err)
	}
	newKid, newThumb, newAlg, err := managedRotationKey(target.JWK())
	if err != nil {
		t.Fatal(err)
	}
	unrelatedKid, err := previous.GenerateKey(dnsid.JoseAlgEdDSA)
	if err != nil {
		t.Fatal(err)
	}
	if err := previous.Activate(unrelatedKid); err != nil {
		t.Fatal(err)
	}
	rotation := &ManagedKeyRotationState{
		PreviousProviderRef: "previous", NewProviderRef: "target",
		PreviousKid: oldKid, PreviousThumbprint: oldThumb, PreviousAlgorithm: oldAlg,
		NewKid: newKid, NewThumbprint: newThumb, NewAlgorithm: newAlg,
		Submission: &dnsid.SubmissionResult{State: dnsid.SubmissionStateAccepted},
	}
	if err := validateManagedProviderBindings(previous, target, rotation); err == nil {
		t.Fatal("retained old key masked an unrelated active source signer")
	}
}

func TestManagedRotation_TargetAlgorithm(t *testing.T) {
	for _, tc := range []struct {
		name      string
		selected  dnsid.JoseAlg
		generated dnsid.JoseAlg
		wantError bool
	}{
		{"preserve source algorithm", "", "", false},
		{"EdDSA to ES256", dnsid.JoseAlgES256, "", false},
		{"unsupported algorithm", "RS256", "", true},
		{"provider returned wrong algorithm", dnsid.JoseAlgES256, dnsid.JoseAlgEdDSA, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client, previous := managedRotationFixture(t)
			algorithm := tc.selected
			if algorithm == "" {
				algorithm = dnsid.JoseAlgEdDSA
			}
			target := &rotationAlgorithmProvider{KeyProvider: dnsid.GenerateES256KeyProvider(), algorithm: algorithm, generatedAlgorithm: tc.generated}
			registry := &managedRotationRegistry{client: client, state: dnsid.SubmissionStateAccepted}
			var saved *ManagedKeyRotationState
			var wired dnsid.KeyProvider
			unpaused := false
			rotation, err := RotateManagedOperationalKey(context.Background(), ManagedKeyRotationOptions{
				Domain: "agent.example.com", Client: client, KeyProvider: previous, TargetProvider: target,
				TargetAlgorithm: tc.selected, PreviousProviderRef: "previous", NewProviderRef: "target",
				PublicationVerifier: rotationPublicationVerifier{}, RegistryClient: registry, IdempotencyKey: "target-algorithm",
				Store: ManagedKeyRotationStoreFunc(func(_ context.Context, state *ManagedKeyRotationState) error {
					saved = cloneManagedRotation(state)
					return nil
				}),
				WireSigner:         func(_ context.Context, provider dnsid.KeyProvider) error { wired = provider; return nil },
				ApplicationSigning: ApplicationSigningControllerFunc(func(_ context.Context, paused bool) error { unpaused = !paused; return nil }),
			})
			if tc.wantError {
				if err == nil || registry.prepareCalls != 0 || len(registry.submissions) != 0 || saved != nil || wired != nil || unpaused {
					t.Fatalf("invalid target advanced rotation: %v", err)
				}
				if tc.selected == "RS256" && target.generations != 0 {
					t.Fatal("unsupported algorithm reached generation")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if rotation.PreviousAlgorithm != dnsid.JoseAlgEdDSA || rotation.NewAlgorithm != algorithm || saved.NewAlgorithm != algorithm || wired != target || !unpaused {
				t.Fatalf("target algorithm not bound: %#v", rotation)
			}
			_, _, activeAlgorithm, err := managedRotationKey(target.JWK())
			if err != nil || activeAlgorithm != algorithm {
				t.Fatalf("wrong active algorithm: %s %v", activeAlgorithm, err)
			}
			if err := validatePersistedManagedRotation(saved); err != nil {
				t.Fatal(err)
			}
			wired, unpaused = nil, false
			_, err = ResumeManagedOperationalKeyRotation(context.Background(), ResumeManagedKeyRotationOptions{
				Client: client, Rotation: saved, PublicationVerifier: rotationPublicationVerifier{},
				ResolveProvider: func(_ context.Context, ref string) (dnsid.KeyProvider, error) {
					if ref == "previous" {
						return previous, nil
					}
					if ref == "target" {
						return target, nil
					}
					return nil, errors.New("unexpected provider reference")
				},
				WireSigner:         func(_ context.Context, provider dnsid.KeyProvider) error { wired = provider; return nil },
				RegistryClient:     registry,
				Store:              ManagedKeyRotationStoreFunc(func(context.Context, *ManagedKeyRotationState) error { return nil }),
				ApplicationSigning: ApplicationSigningControllerFunc(func(_ context.Context, paused bool) error { unpaused = !paused; return nil }),
			})
			if err != nil || wired != target || !unpaused || len(registry.submissions) != 1 {
				t.Fatalf("saved algorithm recovery failed: %v", err)
			}
		})
	}
}

func TestManagedRotation_RejectsUnverifiedPublicationAndContinuity(t *testing.T) {
	for _, boundary := range []string{"publication", "continuity", "wrong publication log", "wrong saved target"} {
		t.Run(boundary, func(t *testing.T) {
			client, provider := managedRotationFixture(t)
			registry := &managedRotationRegistry{client: client, state: dnsid.SubmissionStatePending}
			opts := ManagedKeyRotationOptions{
				Domain: "agent.example.com", Client: client, KeyProvider: provider,
				PreviousProviderRef: "test-provider", PublicationVerifier: rotationPublicationVerifier{}, WireSigner: rotationWireSigner,
				RegistryClient: registry, IdempotencyKey: "rotation", Store: ManagedKeyRotationStoreFunc(func(context.Context, *ManagedKeyRotationState) error { return nil }),
				ApplicationSigning: ApplicationSigningControllerFunc(func(context.Context, bool) error { return nil }),
			}
			rotation, err := RotateManagedOperationalKey(context.Background(), opts)
			if err != nil {
				t.Fatal(err)
			}
			registry.state = dnsid.SubmissionStateAccepted
			verifier := rotationPublicationVerifier{}
			if boundary == "publication" {
				verifier.err = errors.New("invalid signed publication")
			}
			if boundary == "wrong publication log" {
				verifier.logRef = "c2sp-tlog:testnet:https://other.example#instance_AAAAAAAAAAAAAAAAAAAAAA"
			}
			resolver := rotationProviderResolver(provider)
			if boundary == "wrong saved target" {
				resolver = rotationProviderResolver(dnsid.GenerateEd25519KeyProvider())
			}
			if boundary == "continuity" {
				source := client.source.(rotationMemorySource)
				source.entries[0].Entry = []byte("{}")
				client.source = source
			}
			unpaused := false
			_, err = ResumeManagedOperationalKeyRotation(context.Background(), ResumeManagedKeyRotationOptions{
				Client: client, ResolveProvider: resolver, PublicationVerifier: verifier, WireSigner: rotationWireSigner,
				RegistryClient: registry, Rotation: rotation, Store: opts.Store,
				ApplicationSigning: ApplicationSigningControllerFunc(func(_ context.Context, p bool) error { unpaused = !p; return nil }),
			})
			var activation *ManagedKeyRotationActivationError
			if !errors.As(err, &activation) || unpaused {
				t.Fatalf("unsafe activation: %v", err)
			}
			kid, _ := provider.JWK().KeyID()
			if kid != rotation.PreviousKid {
				t.Fatal("invalid publication activated target")
			}
		})
	}
}
