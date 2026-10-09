package config

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"reflect"
	"strings"
	"time"

	dnsid "github.com/dnsid-ai/dnsid-go"
	"github.com/dnsid-ai/dnsid-go/internal/jsonutil"
	"github.com/dnsid-ai/dnsid-go/log/c2sptlog"
)

// LoadDeploymentFile parses a shared deployment document. It reads no other
// source and accepts only non-secret key-source settings, never credentials. Durations
// use Go duration strings. Scalar zero values remain absent during Merge.
func LoadDeploymentFile(path string) (Loaded, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Loaded{}, dnsid.NewParseError("dnsid: reading deployment file", err)
	}
	var file struct {
		Dnsid struct {
			Identity *struct {
				Domain          string             `json:"domain"`
				GovernanceID    string             `json:"governanceId"`
				StatusURL       string             `json:"statusUrl"`
				LogRef          string             `json:"logRef"`
				EntityKeyURL    string             `json:"entityKeyUrl"`
				KeyURL          string             `json:"keyUrl"`
				PublishProfile  string             `json:"publishProfile"`
				CapabilitiesURL string             `json:"capabilitiesUrl"`
				MaxKeyAge       dnsid.KeyAge       `json:"maxKeyAge"`
				PolicyFlags     []dnsid.PolicyFlag `json:"policyFlags"`
			} `json:"identity"`
			Verification struct {
				DNSSECMode          dnsid.DNSSECMode `json:"dnssecMode"`
				StatusCheckInterval string           `json:"statusCheckInterval"`
				TrustedEntities     []struct {
					GovernanceID         string   `json:"governanceId"`
					EntityKeyThumbprints []string `json:"entityKeyThumbprints"`
				} `json:"trustedEntities"`
			} `json:"verification"`
			Transport struct {
				DNSServer           string   `json:"dnsServer"`
				CABundlePath        string   `json:"caBundlePath"`
				PrivateAddressHosts []string `json:"privateAddressHosts"`
			} `json:"transport"`
		} `json:"dnsid"`
		LogTrust *struct {
			Managed   *bool                  `json:"managed"`
			Profile   *c2sptlog.TrustProfile `json:"profile"`
			PolicyURL string                 `json:"policyUrl"`
		} `json:"logTrust"`
		Registry struct {
			RegistryURL string `json:"registryUrl"`
		} `json:"registry"`
		KeySource KeySource `json:"keySource"`
	}
	object, err := decodeDeployment(data, &file)
	if err != nil {
		return Loaded{}, err
	}
	l := Loaded{KeySource: file.KeySource, Registry: Registry{RegistryURL: file.Registry.RegistryURL}}
	if i := file.Dnsid.Identity; i != nil && len(object["dnsid"].(map[string]any)["identity"].(map[string]any)) > 0 {
		l.Dnsid.Identity = &dnsid.IdentityConfig{Domain: i.Domain, GovernanceID: i.GovernanceID, StatusURL: i.StatusURL, LogRef: i.LogRef, EntityKeyURL: i.EntityKeyURL, KeyURL: i.KeyURL, PublishProfile: i.PublishProfile, CapabilitiesURL: i.CapabilitiesURL, MaxKeyAge: i.MaxKeyAge, PolicyFlags: i.PolicyFlags}
	}
	v := file.Dnsid.Verification
	l.Dnsid.Verification.DNSSECMode = v.DNSSECMode
	if v.StatusCheckInterval != "" {
		duration, err := time.ParseDuration(v.StatusCheckInterval)
		if err != nil {
			return Loaded{}, dnsid.NewArgumentError("dnsid: invalid statusCheckInterval", err)
		}
		l.Dnsid.Verification.StatusCheckInterval = duration
	}
	if v.TrustedEntities != nil {
		l.Dnsid.Verification.TrustedEntities = make([]dnsid.TrustedEntity, 0, len(v.TrustedEntities))
		for _, e := range v.TrustedEntities {
			l.Dnsid.Verification.TrustedEntities = append(l.Dnsid.Verification.TrustedEntities, dnsid.TrustedEntity{GovernanceID: e.GovernanceID, EntityKeyThumbprints: e.EntityKeyThumbprints})
		}
	}
	t := file.Dnsid.Transport
	l.Dnsid.Transport = dnsid.TransportConfig{DNSServer: t.DNSServer, CABundlePath: t.CABundlePath, PrivateAddressHosts: t.PrivateAddressHosts}
	if t := file.LogTrust; t != nil {
		if t.Managed != nil && !*t.Managed {
			return Loaded{}, dnsid.NewArgumentError("dnsid: omit logTrust.managed instead of setting false", nil)
		}
		l.LogTrust = LogTrust{Managed: t.Managed != nil, Profile: t.Profile, PolicyURL: t.PolicyURL}
		if l.LogTrust.isZero() {
			return Loaded{}, dnsid.NewArgumentError("dnsid: logTrust must select a variant", nil)
		}
	}
	return l, nil
}

// decodeDeployment rejects duplicate members, nulls, and case aliases.
func decodeDeployment(data []byte, value any) (map[string]any, error) {
	object, err := jsonutil.DecodeObject(data, true)
	if err == nil {
		err = deploymentMembers(object, reflect.TypeOf(value).Elem())
	}
	if err != nil {
		return nil, dnsid.NewArgumentError("dnsid: invalid deployment JSON", err)
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(value); err != nil {
		return nil, dnsid.NewArgumentError("dnsid: invalid deployment configuration", err)
	}
	return object, nil
}

func deploymentMembers(value any, schema reflect.Type) error {
	if value == nil {
		return fmt.Errorf("null is not a configuration value")
	}
	if schema.Kind() == reflect.Pointer {
		schema = schema.Elem()
	}
	switch v := value.(type) {
	case map[string]any:
		if schema.Kind() == reflect.Map && schema.Key().Kind() == reflect.String {
			for _, child := range v {
				if err := deploymentMembers(child, schema.Elem()); err != nil {
					return err
				}
			}
			return nil
		}
		if schema.Kind() != reflect.Struct {
			return fmt.Errorf("unexpected object")
		}
		for name, child := range v {
			var field reflect.Type
			for i := 0; i < schema.NumField(); i++ {
				f := schema.Field(i)
				fieldName, _, _ := strings.Cut(f.Tag.Get("json"), ",")
				if fieldName == name {
					field = f.Type
					break
				}
			}
			if field == nil {
				return fmt.Errorf("unknown member %q", name)
			}
			if err := deploymentMembers(child, field); err != nil {
				return err
			}
		}
	case []any:
		if schema.Kind() != reflect.Slice {
			return fmt.Errorf("unexpected list")
		}
		for _, child := range v {
			if err := deploymentMembers(child, schema.Elem()); err != nil {
				return err
			}
		}
	}
	return nil
}
