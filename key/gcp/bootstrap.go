package gcpkms

import (
	"context"
	"fmt"
	"regexp"

	kms "cloud.google.com/go/kms/apiv1"
	"cloud.google.com/go/kms/apiv1/kmspb"
	dnsid "github.com/dnsid-ai/dnsid-go"
	"github.com/googleapis/gax-go/v2"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// BootstrapClient is the caller-owned KMS surface for explicit initial key
// provisioning. An official *kms.KeyManagementClient implements it directly.
// Bootstrap does not require ancestor creation or rotation operations.
type BootstrapClient interface {
	Client
	GetCryptoKey(context.Context, *kmspb.GetCryptoKeyRequest, ...gax.CallOption) (*kmspb.CryptoKey, error)
	CreateCryptoKey(context.Context, *kmspb.CreateCryptoKeyRequest, ...gax.CallOption) (*kmspb.CryptoKey, error)
	GetCryptoKeyVersion(context.Context, *kmspb.GetCryptoKeyVersionRequest, ...gax.CallOption) (*kmspb.CryptoKeyVersion, error)
}

var _ BootstrapClient = (*kms.KeyManagementClient)(nil)

// BootstrapConfig selects the exact caller-allocated identity to create or reuse.
// Names are not normalized or randomly suffixed; the key ring must already exist.
type BootstrapConfig struct {
	// Parent is projects/{project}/locations/{location}/keyRings/{ring}.
	Parent string
	// CryptoKeyID is a stable name containing 1–63 letters, digits, underscores or hyphens.
	CryptoKeyID string
}

// BootstrapResult contains a validated initial key, not an agent registration.
// Closing Provider does not close the caller's BootstrapClient.
type BootstrapResult struct {
	// KeyVersionName is the exact named key's immutable cryptoKeyVersions/1 reference.
	KeyVersionName string
	Provider       *Provider
}

var bootstrapParent = regexp.MustCompile(`^projects/[A-Za-z0-9_-]+/locations/[A-Za-z0-9_-]+/keyRings/[A-Za-z0-9_-]+$`)
var bootstrapKeyID = regexp.MustCompile(`^[A-Za-z0-9_-]{1,63}$`)

// CreateOrReuse explicitly provisions or reuses one named software Ed25519 key.
// Only an exact-key NotFound permits creation. An AlreadyExists create response
// causes one reread of the winner; all other service and context errors are
// returned unchanged. No application retry or backoff is added.
//
// The key template and enabled immutable version 1 must be compatible. New then
// validates the public key and constructs the provider. Missing or incompatible
// versions never authorize another version, fallback signer or ancestor creation.
// A failed attempt returns no result, even if creation committed remotely; a
// fresh explicit call with the same scope can discover that committed key.
//
// This is initial provisioning, not rotation recovery: open an established
// identity's persisted authorized version with New or Open. Bootstrap never
// registers an agent; applications perform that separate step after key success.
//
// Bootstrap adds no deadline; supply a context with the required deadline or
// cancellation. The injected client's transport timeouts and retries also apply.
func CreateOrReuse(ctx context.Context, client BootstrapClient, cfg BootstrapConfig) (*BootstrapResult, error) {
	if client == nil || !bootstrapParent.MatchString(cfg.Parent) || !bootstrapKeyID.MatchString(cfg.CryptoKeyID) {
		return nil, dnsid.NewArgumentError("dnsid/gcpkms: bootstrap requires a client, fully qualified key ring and valid CryptoKey ID", nil)
	}
	name := cfg.Parent + "/cryptoKeys/" + cfg.CryptoKeyID
	key, err := client.GetCryptoKey(ctx, &kmspb.GetCryptoKeyRequest{Name: name})
	if status.Code(err) == codes.NotFound {
		key, err = client.CreateCryptoKey(ctx, &kmspb.CreateCryptoKeyRequest{
			Parent: cfg.Parent, CryptoKeyId: cfg.CryptoKeyID,
			CryptoKey: &kmspb.CryptoKey{
				Purpose: kmspb.CryptoKey_ASYMMETRIC_SIGN,
				VersionTemplate: &kmspb.CryptoKeyVersionTemplate{
					Algorithm:       kmspb.CryptoKeyVersion_EC_SIGN_ED25519,
					ProtectionLevel: kmspb.ProtectionLevel_SOFTWARE,
				},
			},
			SkipInitialVersionCreation: false,
		})
		if status.Code(err) == codes.AlreadyExists {
			key, err = client.GetCryptoKey(ctx, &kmspb.GetCryptoKeyRequest{Name: name})
		}
	}
	if err != nil {
		return nil, err
	}
	if key == nil || key.Name != name || key.Purpose != kmspb.CryptoKey_ASYMMETRIC_SIGN || key.VersionTemplate == nil || key.VersionTemplate.Algorithm != kmspb.CryptoKeyVersion_EC_SIGN_ED25519 || key.VersionTemplate.ProtectionLevel != kmspb.ProtectionLevel_SOFTWARE {
		return nil, fmt.Errorf("dnsid/gcpkms: invalid bootstrap key binding, purpose or template")
	}
	versionName := name + "/cryptoKeyVersions/1"
	version, err := client.GetCryptoKeyVersion(ctx, &kmspb.GetCryptoKeyVersionRequest{Name: versionName})
	if err != nil {
		return nil, err
	}
	if version == nil || version.Name != versionName || version.State != kmspb.CryptoKeyVersion_ENABLED || version.Algorithm != kmspb.CryptoKeyVersion_EC_SIGN_ED25519 || version.ProtectionLevel != kmspb.ProtectionLevel_SOFTWARE {
		return nil, fmt.Errorf("dnsid/gcpkms: invalid bootstrap version binding, state, algorithm or protection level")
	}
	provider, err := New(ctx, client, Config{KeyVersionName: versionName})
	if err != nil {
		return nil, err
	}
	return &BootstrapResult{KeyVersionName: versionName, Provider: provider}, nil
}
