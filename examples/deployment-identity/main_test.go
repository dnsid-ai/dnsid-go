package main

import (
	"reflect"
	"testing"

	"github.com/dnsid-ai/dnsid-go/config"
)

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
