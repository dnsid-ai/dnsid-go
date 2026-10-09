package awskms

import (
	"context"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws/arn"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
	dnsid "github.com/dnsid-ai/dnsid-go"
	"github.com/dnsid-ai/dnsid-go/config"
)

func init() {
	config.RegisterKeyProviderFactory("aws-kms", config.KeyProviderFactory{
		Validate: validateSource,
		Open:     openSource,
	})
}

func validateSource(src config.KeySource) error {
	reference, err := arn.Parse(src.KeyRef)
	if err != nil || reference.Service != "kms" || reference.Partition == "" || reference.Region == "" || reference.AccountID == "" || !strings.HasPrefix(reference.Resource, "key/") || len(reference.Resource) <= len("key/") || strings.ContainsAny(src.KeyRef, " \t\r\n#") {
		return dnsid.NewArgumentError("dnsid: aws-kms keyRef must be an immutable KMS key ARN, not an alias", nil)
	}
	for name, value := range src.Settings {
		switch name {
		case "region":
			if value != reference.Region {
				return dnsid.NewArgumentError("dnsid: aws-kms region differs from immutable key ARN", nil)
			}
		case "profile":
			if strings.TrimSpace(value) == "" {
				return dnsid.NewArgumentError("dnsid: aws-kms settings must be nonempty", nil)
			}
		case "algorithm":
			if value != string(dnsid.JoseAlgES256) && value != string(dnsid.JoseAlgEdDSA) {
				return dnsid.NewArgumentError("dnsid: aws-kms algorithm must be ES256 or EdDSA", nil)
			}
		default:
			return dnsid.NewArgumentError("dnsid: unknown aws-kms setting; use region, profile, or algorithm (credentials use the AWS chain)", nil)
		}
	}
	return nil
}

func openSource(ctx context.Context, src config.KeySource, _ string) (dnsid.KeyProvider, error) {
	reference, err := arn.Parse(src.KeyRef)
	if err != nil {
		return nil, err
	}
	region := src.Settings["region"]
	if region == "" {
		region = reference.Region
	}
	options := []func(*awsconfig.LoadOptions) error{awsconfig.WithRegion(region)}
	if profile := src.Settings["profile"]; profile != "" {
		options = append(options, awsconfig.WithSharedConfigProfile(profile))
	}
	cfg, err := awsconfig.LoadDefaultConfig(ctx, options...)
	if err != nil {
		return nil, err
	}
	algorithm := types.SigningAlgorithmSpecEcdsaSha256
	if src.Settings["algorithm"] == string(dnsid.JoseAlgEdDSA) {
		algorithm = types.SigningAlgorithmSpecEd25519Sha512
	}
	provider, err := Load(ctx, SDKClient{Client: kms.NewFromConfig(cfg)}, Config{
		State: State{ActiveKeyID: src.KeyRef}, Algorithm: algorithm,
	})
	if err != nil {
		return nil, err
	}
	if provider.State().ActiveKeyID != src.KeyRef {
		return nil, dnsid.NewArgumentError("dnsid: KMS returned a different immutable key reference", nil)
	}
	return provider, nil
}
