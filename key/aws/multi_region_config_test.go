package awskms

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/kms/types"
	dnsid "github.com/dnsid-ai/dnsid-go"
	"github.com/dnsid-ai/dnsid-go/config"
)

// Regional configuration preserves exact ARN binding. Mode: real-capable (AWS=loopback fake); mismatched response: fake-only.
func TestConfigFactory_RegionalEd25519Binding(t *testing.T) {
	for _, region := range []string{"us-east-1", "us-west-2"} {
		reference := "arn:aws:kms:" + region + ":123456789012:key/mrk-0123456789abcdef0123456789abcdef"
		for _, test := range []struct {
			name             string
			mismatch         bool
			otherPublication bool
		}{

			{"EdDSA", false, false},
			{"different ARN", true, false},
			{"same public different publication ARN", false, true},
		} {
			t.Run(region+"/"+test.name, func(t *testing.T) {
				// Mode: fake-only for AWS (official client, loopback GetPublicKey);
				// real deployment loading and local entity key. No live KMS claim.
				seed, err := hex.DecodeString("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
				if err != nil {
					t.Fatal(err)
				}
				private := ed25519.NewKeyFromSeed(seed)
				fake := &regionalFakeKMS{t, reference, private}
				wantAlgorithm := dnsid.JoseAlgEdDSA
				public, err := fake.GetPublicKey(context.Background(), GetPublicKeyInput{KeyID: reference})
				if err != nil {
					t.Fatal(err)
				}
				if test.mismatch {
					public.KeyID = reference + "-different"
				}
				source := config.KeySource{Provider: "aws-kms", KeyRef: reference, Settings: map[string]string{"region": region, "algorithm": "EdDSA"}}
				// Establish publication before configuration startup with the independent
				// fixture provider. Startup itself still opens the official AWS client.
				algorithm := types.SigningAlgorithmSpecEd25519Sha512
				fixtureProvider, err := New(context.Background(), fake, Config{State: State{ActiveKeyID: reference}, Algorithm: algorithm})
				if err != nil {
					t.Fatal(err)
				}
				if test.otherPublication {
					otherRegion := "us-east-1"
					if region == otherRegion {
						otherRegion = "us-west-2"
					}
					otherReference := strings.Replace(reference, region, otherRegion, 1)
					published := openRegionalProvider(t, otherReference, private)
					selectedKey, publishedKey := fixtureProvider.JWK(), published.JWK()
					selectedJSON, err := json.Marshal(selectedKey)
					if err != nil {
						t.Fatal(err)
					}
					publishedJSON, err := json.Marshal(publishedKey)
					if err != nil {
						t.Fatal(err)
					}
					var selectedMaterial, publishedMaterial map[string]any
					if err := json.Unmarshal(selectedJSON, &selectedMaterial); err != nil {
						t.Fatal(err)
					}
					if err := json.Unmarshal(publishedJSON, &publishedMaterial); err != nil {
						t.Fatal(err)
					}
					for _, member := range []string{"kty", "crv", "x", "alg"} {
						if selectedMaterial[member] == nil || selectedMaterial[member] != publishedMaterial[member] {
							t.Fatalf("same-public fixture %s differs", member)
						}
					}
					if selectedMaterial["kid"] != reference || publishedMaterial["kid"] != otherReference {
						t.Fatal("fixture must expose distinct regional ARN kids")
					}
					fixtureProvider = published
				}
				loaded, deps, calls := awsConfigFixture(t, source, public, fixtureProvider)
				// The factory boundary has no publication input: a downstream binding
				// failure cannot satisfy this immutable-reference rejection guard.
				if test.mismatch {
					selected, factoryErr := config.OperationalKeyProviderFrom(context.Background(), loaded.KeySource, "agent.example")
					if factoryErr == nil || selected != nil {
						t.Fatalf("factory must reject mismatched immutable ARN before publication: provider=%v error=%v", selected, factoryErr)
					}
				}
				// When constructing through the actual configuration factory.
				manager, err := config.Construct(context.Background(), loaded, deps)
				var provider dnsid.KeyProvider
				if manager != nil {
					provider = manager.KeyProvider()
				}
				// Then key selection/failure is preserved, with no local operational warning.
				if test.mismatch {
					if err == nil || provider != nil {
						t.Fatal("factory accepted another immutable key reference")
					}
				} else if test.otherPublication {
					if err == nil || provider != nil || !strings.Contains(err.Error(), "configured operational key does not match verified local publication") {
						t.Fatalf("same public material with different regional kid must reject publication binding: %v", err)
					}
				} else {
					if err != nil {
						t.Fatal(err)
					}
					key := provider.JWK()
					kid, _ := key.KeyID()
					algorithm, _ := key.Algorithm()
					if kid != reference || algorithm.String() != string(wantAlgorithm) {
						t.Fatalf("loaded key = %s/%s", kid, algorithm)
					}
				}
				wantCalls := int32(1)
				if test.mismatch {
					wantCalls++
				}
				if calls.Load() != wantCalls {
					t.Fatalf("GetPublicKey calls = %d, want %d", calls.Load(), wantCalls)
				}
			})
		}

	}
}
