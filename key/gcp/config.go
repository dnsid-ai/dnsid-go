package gcpkms

import (
	"context"
	"strings"

	kms "cloud.google.com/go/kms/apiv1"
	dnsid "github.com/dnsid-ai/dnsid-go"
	"github.com/dnsid-ai/dnsid-go/config"
	"google.golang.org/api/option"
)

func init() {
	config.RegisterKeyProviderFactory("google-kms", config.KeyProviderFactory{Validate: validateSource, Open: openSource})
}

func validateSource(src config.KeySource) error {
	if err := validateVersion(src.KeyRef); err != nil {
		return err
	}
	parts := strings.Split(src.KeyRef, "/")
	for name, value := range src.Settings {
		switch name {
		case "project":
			if value != parts[1] {
				return dnsid.NewArgumentError("dnsid/gcpkms: project differs from keyRef", nil)
			}
		case "location":
			if value != parts[3] {
				return dnsid.NewArgumentError("dnsid/gcpkms: location differs from keyRef", nil)
			}
		case "algorithm":
			if value != string(dnsid.JoseAlgEdDSA) {
				return dnsid.NewArgumentError("dnsid/gcpkms: algorithm must be EdDSA", nil)
			}
		default:
			return dnsid.NewArgumentError("dnsid/gcpkms: unknown setting; use project, location or algorithm (credentials use Application Default Credentials)", nil)
		}
	}
	return nil
}

func openSource(ctx context.Context, src config.KeySource, _ string) (dnsid.KeyProvider, error) {
	return Open(ctx, src)
}

// Open validates configuration and opens its existing immutable version using
// the official Google client. Options configure that client's transport and
// authentication; they do not become deployment settings. With no options,
// authentication uses Application Default Credentials, as in the registered
// google-kms factory. No key is created and no file signer is substituted.
//
// The returned provider owns the created client: call Close after all operations
// finish. On failure Open closes the created client. A connection supplied via
// option.WithGRPCConn is subject to the official client's Close behavior, which
// may close it (including on an opening failure). Supply a dedicated connection,
// not one shared with unrelated clients.
func Open(ctx context.Context, src config.KeySource, opts ...option.ClientOption) (*Provider, error) {
	if err := validateSource(src); err != nil {
		return nil, err
	}
	client, err := kms.NewKeyManagementClient(ctx, opts...)
	if err != nil {
		return nil, err
	}
	provider, err := New(ctx, client, Config{KeyVersionName: src.KeyRef})
	if err != nil {
		_ = client.Close()
		return nil, err
	}
	provider.closeClient = client.Close
	return provider, nil
}
