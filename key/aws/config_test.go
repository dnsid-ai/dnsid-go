package awskms

import (
	"testing"

	"github.com/dnsid-ai/dnsid-go/config"
)

func TestConfigFactory_ValidatesImmutableExistingKeys(t *testing.T) {
	const arn = "arn:aws:kms:us-east-1:123456789012:key/11111111-1111-4111-8111-111111111111"
	valid := config.KeySource{Provider: "aws-kms", KeyRef: arn, Settings: map[string]string{"region": "us-east-1", "algorithm": "ES256"}}
	if err := config.ValidateKeySource(valid); err != nil {
		t.Fatalf("factory was not registered: %v", err)
	}
	for _, invalid := range []config.KeySource{
		{Provider: "aws-kms", KeyRef: "alias/active"},
		{Provider: "aws-kms", KeyRef: arn, Generation: &config.KeyGenerationConfig{Locator: "new", Algorithm: "ES256"}},
		{Provider: "aws-kms", Generation: &config.KeyGenerationConfig{Locator: "new", Algorithm: "ES256"}},
		{Provider: "aws-kms", KeyRef: arn, Settings: map[string]string{"algorithm": "RS256"}},
		{Provider: "aws-kms", KeyRef: arn, Settings: map[string]string{"accessKey": "secret"}},
	} {
		if err := config.ValidateKeySource(invalid); err == nil {
			t.Fatalf("accepted invalid settings: %#v", invalid)
		}
	}
}
