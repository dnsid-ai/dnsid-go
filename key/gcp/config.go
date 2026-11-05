package gcpkms

import (
	"context"
	"strings"

	kms "cloud.google.com/go/kms/apiv1"
	dnsid "github.com/dnsid-ai/dnsid-go"
	"github.com/dnsid-ai/dnsid-go/config"
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
	if err := validateSource(src); err != nil {
		return nil, err
	}
	client, err := kms.NewKeyManagementClient(ctx)
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
