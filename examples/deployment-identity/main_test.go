package main

import (
	"reflect"
	"strings"
	"testing"

	dnsid "github.com/dnsid-ai/dnsid-go"
	"github.com/dnsid-ai/dnsid-go/config"
)

func TestRequirePublishedKey(t *testing.T) {
	key := `{"kty":"OKP","crv":"Ed25519","x":"AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE","kid":"operational","alg":"EdDSA"}`
	parse := func(keys string) *dnsid.JWKS {
		t.Helper()
		set, err := dnsid.ParseJWKS([]byte(`{"keys":[` + keys + `]}`))
		if err != nil {
			t.Fatal(err)
		}
		return set
	}
	for _, tc := range []struct {
		name      string
		published *dnsid.JWKS
		wantError bool
	}{
		{"match", parse(key), false},
		{"same-kid-different-key", parse(strings.Replace(key, "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE", "AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI", 1)), true},
		{"same-key-different-kid", parse(strings.Replace(key, "operational", "other", 1)), true},
		{"missing", nil, true},
		{"empty", parse(""), true},
		{"multiple", parse(key + "," + strings.Replace(key, "operational", "other", 1)), true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := requirePublishedKey(parse(key), tc.published); (err != nil) != tc.wantError {
				t.Fatalf("requirePublishedKey() = %v, wantError %v", err, tc.wantError)
			}
		})
	}
	if err := requirePublishedKey(nil, parse(key)); err == nil {
		t.Fatal("missing selected key accepted")
	}
}

func TestDeploymentFiles(t *testing.T) {
	aws, err := config.LoadDeploymentFile("deployment.aws.json")
	if err != nil {
		t.Fatal(err)
	}
	file, err := config.LoadDeploymentFile("deployment.file.json")
	if err != nil {
		t.Fatal(err)
	}
	if aws.Dnsid.Identity == nil || !reflect.DeepEqual(aws.Dnsid, file.Dnsid) || !aws.LogTrust.Managed || !file.LogTrust.Managed {
		t.Fatal("deployment files must illustrate the same publication settings and explicit managed trust")
	}
	if aws.KeySource.Provider != "aws-kms" || aws.KeySource.KeyRef != "<immutable signing-key ARN>" || aws.KeySource.Settings["algorithm"] != "ES256" {
		t.Fatal("AWS deployment lost its existing-key selection or placeholder")
	}
	// A valid reference checks factory linking without credentials or KMS calls.
	aws.KeySource.KeyRef = "arn:aws:kms:us-east-1:111122223333:key/example-key-id"
	if err := config.ValidateKeySource(aws.KeySource); err != nil {
		t.Fatal(err)
	}
	if file.KeySource.Provider != "file" || file.KeySource.KeyRef != "./keys.json" {
		t.Fatal("file deployment lost its existing-key selection")
	}
	if err := config.ValidateKeySource(file.KeySource); err != nil {
		t.Fatal(err)
	}
}
