package config_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/dnsid-ai/dnsid-go/config"
)

// Mode: fake-only. Only temporary deployment files; no key factories or network.
// Contract: compliance 939d241, 12-configuration-loading.md, Principle and Merge.
func loadKeySourceFixture(t *testing.T, source map[string]any) config.Loaded {
	t.Helper()
	path := filepath.Join(t.TempDir(), "deployment.json")
	data, err := json.Marshal(map[string]any{"keySource": source})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	loaded, err := config.LoadDeploymentFile(path)
	if err != nil {
		t.Fatalf("load deployment file: %v", err)
	}
	return loaded
}

func TestDeploymentKeySource_BlankStringsAreAbsent(t *testing.T) {
	for _, field := range []string{"provider", "keyRef", "cliDirectory", "keyStorePath", "entityKeyPath"} {
		for _, blank := range []string{"", " \t\r\n "} {
			t.Run(field+"/"+map[bool]string{true: "empty", false: "whitespace"}[blank == ""], func(t *testing.T) {
				// Given an optional deployment-file string containing no non-whitespace.
				// When the file is loaded.
				loaded := loadKeySourceFixture(t, map[string]any{field: blank})
				// Then it contributes no key-source field or constructor default.
				if !reflect.DeepEqual(loaded.KeySource, config.KeySource{}) {
					t.Errorf("keySource = %#v, want absent optional strings", loaded.KeySource)
				}
			})
		}
	}
}

func TestDeploymentKeySource_BlankOperationalOverlayRetainsBase(t *testing.T) {
	base := config.Loaded{KeySource: config.KeySource{Provider: "aws-kms", KeyRef: "stable-key", Settings: map[string]string{"region": "us-east-1"}, EntityKeyPath: "/base/entity.jwk"}}
	for _, field := range []string{"provider", "keyRef", "cliDirectory", "keyStorePath", "all"} {
		for _, blank := range []string{"", " \t\r\n "} {
			t.Run(field+"/"+map[bool]string{true: "empty", false: "whitespace"}[blank == ""], func(t *testing.T) {
				// Given a base cloud selection and a file with only blank operational strings.
				source := map[string]any{field: blank}
				if field == "all" {
					source = map[string]any{"provider": blank, "keyRef": blank, "cliDirectory": blank, "keyStorePath": blank}
				}
				overlay := loadKeySourceFixture(t, source)
				// When the loaded overlay is merged.
				got := config.Merge(base, overlay).KeySource
				// Then no operational group replacement occurs, including settings and entity.
				if !reflect.DeepEqual(got, base.KeySource) {
					t.Errorf("merged keySource = %#v, want base %#v", got, base.KeySource)
				}
			})
		}
	}
}

func TestDeploymentKeySource_BlankEntityRetainsIndependentBasePath(t *testing.T) {
	base := config.Loaded{KeySource: config.KeySource{CliDirectory: "/base/cli", EntityKeyPath: "/base/entity.jwk"}}
	for _, blank := range []string{"", " \t\r\n "} {
		t.Run(map[bool]string{true: "empty", false: "whitespace"}[blank == ""], func(t *testing.T) {
			// Given a new operational source and a blank independent entity path.
			overlay := loadKeySourceFixture(t, map[string]any{"provider": "aws-kms", "keyRef": "next-key", "settings": map[string]string{"region": "us-east-1"}, "entityKeyPath": blank})
			// When merging the loaded file over a CLI base.
			got := config.Merge(base, overlay).KeySource
			// Then operational fields replace as a group, but the base entity path survives.
			want := config.KeySource{Provider: "aws-kms", KeyRef: "next-key", Settings: map[string]string{"region": "us-east-1"}, EntityKeyPath: "/base/entity.jwk"}
			if !reflect.DeepEqual(got, want) {
				t.Errorf("merged keySource = %#v, want %#v", got, want)
			}
		})
	}
}

func TestDeploymentKeySource_PreservesNonblankStringsAndSettings(t *testing.T) {
	// Given padded nonempty file strings and opaque provider settings.
	source := map[string]any{"provider": " aws-kms ", "keyRef": " stable-key ", "cliDirectory": " /cli ", "keyStorePath": " /store ", "entityKeyPath": " /entity ", "settings": map[string]string{"region": " us-east-1 ", "blank": " \t ", "empty": ""}}
	// When parsed without constructing a provider (factory validation is separate).
	got := loadKeySourceFixture(t, source).KeySource
	// Then file values and provider settings remain exactly as supplied.
	want := config.KeySource{Provider: " aws-kms ", KeyRef: " stable-key ", CliDirectory: " /cli ", KeyStorePath: " /store ", EntityKeyPath: " /entity ", Settings: map[string]string{"region": " us-east-1 ", "blank": " \t ", "empty": ""}}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("keySource = %#v, want unchanged %#v", got, want)
	}
}
