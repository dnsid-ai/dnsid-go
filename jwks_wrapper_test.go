package dnsid

import (
	"crypto"
	"encoding/base64"
	"errors"
	"strings"
	"testing"

	"github.com/lestrrat-go/jwx/v3/jwk"
)

const (
	testOKPX1 = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE"
	testOKPX2 = "AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI"
	testOKPX3 = "AwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwM"
	testOKPX4 = "BAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQ"
	testOKPX5 = "BQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQU"
	testOKPX6 = "BgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgY"
	testP256X = "axfR8uEsQkf4vOblY6RA8ncDfYEt6zOg9KE5RdiYwpY"
	testP256Y = "T-NC4v4af5uO5-tKfA-eFivOM1drMV7Oy7ZAaDe_UfU"
)

const validTwoKeyJWKS = `{
  "keys": [
    {
      "kty": "OKP",
      "crv": "Ed25519",
      "x": "` + testOKPX1 + `",
      "kid": "known-kid",
      "alg": "EdDSA",
      "use": "sig"
    },
    {
      "kty": "OKP",
      "crv": "Ed25519",
      "x": "` + testOKPX2 + `",
      "kid": "second-kid",
      "alg": "EdDSA"
    }
  ]
}`

func TestParseJWKSValidDocument(t *testing.T) {
	wrapper, err := ParseJWKS([]byte(validTwoKeyJWKS))
	if err != nil {
		t.Fatalf("ParseJWKS: %v", err)
	}
	if wrapper == nil {
		t.Fatal("ParseJWKS returned nil wrapper")
	}
	if wrapper.set.Len() != 2 {
		t.Fatalf("set length = %d, want 2", wrapper.set.Len())
	}
}

func TestParseJWKSInvalidJSON(t *testing.T) {
	_, err := ParseJWKS([]byte(`{"keys":[`))
	if err == nil {
		t.Fatal("expected ParseJWKS error")
	}
	if !strings.Contains(err.Error(), "jwks: parsing JWKS") {
		t.Fatalf("error = %q, want jwks parse context", err.Error())
	}
}

func TestJWKSSigningKeys(t *testing.T) {
	wrapper := mustParseJWKS(t, `{
	  "keys": [
	    {"kty":"OKP","crv":"Ed25519","x":"`+testOKPX1+`","kid":"no-use","alg":"EdDSA"},
	    {"kty":"OKP","crv":"Ed25519","x":"`+testOKPX2+`","kid":"sig-use","alg":"EdDSA","use":"sig"},
	    {"kty":"OKP","crv":"Ed25519","x":"`+testOKPX4+`","kid":"enc-use","alg":"EdDSA","use":"enc"}
	  ]
	}`)

	keys := wrapper.SigningKeys()
	if len(keys) != 2 {
		t.Fatalf("SigningKeys length = %d, want 2", len(keys))
	}

	wantKids := []string{"no-use", "sig-use"}
	for i, want := range wantKids {
		if keys[i].Kid() != want {
			t.Fatalf("SigningKeys[%d].Kid() = %q, want %q", i, keys[i].Kid(), want)
		}
	}
}

func TestJWKSKeyByID(t *testing.T) {
	wrapper := mustParseJWKS(t, validTwoKeyJWKS)

	key := wrapper.KeyByID("known-kid")
	if key == nil {
		t.Fatal("KeyByID(known-kid) = nil")
	}
	if key.Kid() != "known-kid" {
		t.Fatalf("KeyByID(known-kid).Kid() = %q", key.Kid())
	}

	if key := wrapper.KeyByID("unknown-kid"); key != nil {
		t.Fatalf("KeyByID(unknown-kid) = %#v, want nil", key)
	}
}

func TestJWKSKeyByIDEmptyKidDoesNotMatchUnsetKid(t *testing.T) {
	wrapper := mustParseJWKS(t, `{"keys":[
	  {"kty":"OKP","crv":"Ed25519","x":"`+testOKPX1+`","alg":"EdDSA"}
	]}`)

	if key := wrapper.KeyByID(""); key != nil {
		t.Fatalf("KeyByID(empty) = %#v, want nil", key)
	}
}

func TestJWKSKeyByIDIsUnfiltered(t *testing.T) {
	wrapper := mustParseJWKS(t, `{"keys":[
	  {"kty":"OKP","crv":"Ed25519","x":"`+testOKPX1+`","kid":"enc-kid","alg":"EdDSA","use":"enc"}
	]}`)

	key := wrapper.KeyByID("enc-kid")
	if key == nil {
		t.Fatal("KeyByID(enc-kid) = nil")
	}
	if key.Use() != "enc" {
		t.Fatalf("KeyByID(enc-kid).Use() = %q, want enc", key.Use())
	}
}

func TestJWKSValidate(t *testing.T) {
	tests := []struct {
		name    string
		data    string
		wantErr string
	}{
		{
			name: "custom owner use rejected",
			data: `{"keys":[
			  {"kty":"OKP","crv":"Ed25519","x":"` + testOKPX1 + `","kid":"owner-use","alg":"EdDSA","use":"owner"}
			]}`,
			wantErr: "jwks: parsing JWKS: dnsid: Ed25519 key \"owner-use\" has unsupported use \"owner\"",
		},
		{
			name: "missing kid",
			data: `{"keys":[
			  {"kty":"OKP","crv":"Ed25519","x":"` + testOKPX1 + `","alg":"EdDSA"}
			]}`,
			wantErr: "jwks: signing key at index 0 missing kid",
		},
		{
			name: "missing alg derived for Ed25519",
			data: `{"keys":[
			  {"kty":"OKP","crv":"Ed25519","x":"` + testOKPX2 + `","kid":"missing-alg"}
			]}`,
		},
		{
			name:    "empty JWKS",
			data:    `{"keys":[]}`,
			wantErr: "jwks: no usable signing key",
		},
		{
			name: "enc only",
			data: `{"keys":[
			  {"kty":"OKP","crv":"Ed25519","x":"` + testOKPX3 + `","kid":"enc-only","alg":"EdDSA","use":"enc"}
			]}`,
			wantErr: "jwks: no usable signing key",
		},
		{
			name: "mixed enc before missing kid uses signing index",
			data: `{"keys":[
			  {"kty":"OKP","crv":"Ed25519","x":"` + testOKPX4 + `","kid":"enc-only","alg":"EdDSA","use":"enc"},
			  {"kty":"OKP","crv":"Ed25519","x":"` + testOKPX5 + `","alg":"EdDSA"}
			]}`,
			wantErr: "jwks: signing key at index 0 missing kid",
		},
		{
			name: "P-256 missing alg derived",
			data: `{"keys":[
			  {"kty":"EC","crv":"P-256","x":"` + testP256X + `","y":"` + testP256Y + `","kid":"missing-alg"}
			]}`,
		},
		{
			name: "present inconsistent alg rejected",
			data: `{"keys":[
			  {"kty":"OKP","crv":"Ed25519","x":"` + testOKPX5 + `","kid":"bad-alg","alg":"ES256"}
			]}`,
			wantErr: "jwks: parsing JWKS: dnsid: Ed25519 key \"bad-alg\" has inconsistent alg \"ES256\"",
		},
		{
			name: "unsupported signing key skipped",
			data: `{"keys":[
			  {"kty":"oct","k":"` + testOKPX1 + `","kid":"unsupported"}
			]}`,
			wantErr: "jwks: no usable signing key",
		},
		{
			name: "unknown key type skipped",
			data: `{"keys":[
			  {"kty":"future","kid":"future"},
			  {"kty":"OKP","crv":"Ed25519","x":"` + testOKPX2 + `","kid":"ed"}
			]}`,
		},
		{
			name: "well formed",
			data: validTwoKeyJWKS,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			wrapper, parseErr := ParseJWKS([]byte(tt.data))
			if parseErr != nil {
				if tt.wantErr == "" {
					t.Fatalf("ParseJWKS: %v", parseErr)
				}
				if parseErr.Error() != tt.wantErr {
					t.Fatalf("ParseJWKS error = %q, want %q", parseErr.Error(), tt.wantErr)
				}
				return
			}

			err := wrapper.Validate()
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("Validate() = %v, want nil", err)
				}
				return
			}
			if err == nil {
				t.Fatal("Validate() = nil, want error")
			}
			if err.Error() != tt.wantErr {
				t.Fatalf("Validate() error = %q, want %q", err.Error(), tt.wantErr)
			}
		})
	}
}

func TestJWKSProfileCurrentSigningKeys(t *testing.T) {
	wrapper := mustParseJWKS(t, `{"keys":[
	  {"kty":"OKP","crv":"Ed25519","x":"`+testOKPX1+`","kid":"current","alg":"EdDSA","use":"sig"}
	]}`)

	for _, profile := range []string{"", DefaultPublishProfile, "DNSid1"} {
		recordKey, err := wrapper.CurrentRecordSigningKey(profile)
		if err != nil {
			t.Fatalf("CurrentRecordSigningKey(%q): %v", profile, err)
		}
		if recordKey.Kid() != "current" {
			t.Fatalf("CurrentRecordSigningKey(%q).Kid() = %q, want current", profile, recordKey.Kid())
		}
		if alg, err := recordKey.SignatureAlg(profile); err != nil || alg != JoseAlgEdDSA {
			t.Fatalf("CurrentRecordSigningKey(%q).SignatureAlg() = %q, %v; want EdDSA, nil", profile, alg, err)
		}
		operationalKey, err := wrapper.CurrentOperationalSigningKey(profile)
		if err != nil {
			t.Fatalf("CurrentOperationalSigningKey(%q): %v", profile, err)
		}
		if operationalKey.Kid() != "current" {
			t.Fatalf("CurrentOperationalSigningKey(%q).Kid() = %q, want current", profile, operationalKey.Kid())
		}
		if err := wrapper.ValidateRecordSigning(profile); err != nil {
			t.Fatalf("ValidateRecordSigning(%q): %v", profile, err)
		}
		if err := wrapper.ValidateOperational(profile); err != nil {
			t.Fatalf("ValidateOperational(%q): %v", profile, err)
		}
	}
}

func TestJWKSignatureAlgRequiresProfileAlg(t *testing.T) {
	missingAlg := mustParseJWKS(t, `{"keys":[
	  {"kty":"OKP","crv":"Ed25519","x":"`+testOKPX1+`","kid":"current"}
	]}`).SigningKeys()[0]
	if _, err := missingAlg.SignatureAlg(DefaultPublishProfile); err == nil || !strings.Contains(err.Error(), "must include alg") {
		t.Fatalf("SignatureAlg() error = %v, want missing alg", err)
	}
	if _, err := missingAlg.SignatureAlg("dnsid-draft-99"); err == nil || !strings.Contains(err.Error(), "unsupported identity-record profile") {
		t.Fatalf("SignatureAlg(unsupported) error = %v, want unsupported profile", err)
	}
	var nilKey *JWK
	if _, err := nilKey.SignatureAlg(DefaultPublishProfile); err == nil || !strings.Contains(err.Error(), "nil JWK") {
		t.Fatalf("nil SignatureAlg() error = %v, want nil JWK", err)
	}
}

func TestJWKSProfileValidationRejectsInvalidSets(t *testing.T) {
	tests := []struct {
		name    string
		data    string
		profile string
		wantErr string
	}{
		{
			name: "multiple current keys",
			data: `{"keys":[
			  {"kty":"OKP","crv":"Ed25519","x":"` + testOKPX1 + `","kid":"one","alg":"EdDSA"},
			  {"kty":"OKP","crv":"Ed25519","x":"` + testOKPX2 + `","kid":"two","alg":"EdDSA"}
			]}`,
			wantErr: "exactly one current signing key",
		},
		{
			name: "missing alg",
			data: `{"keys":[
			  {"kty":"OKP","crv":"Ed25519","x":"` + testOKPX1 + `","kid":"current"}
			]}`,
			wantErr: "must include alg",
		},
		{
			name: "unsupported profile",
			data: `{"keys":[
			  {"kty":"OKP","crv":"Ed25519","x":"` + testOKPX1 + `","kid":"current","alg":"EdDSA"}
			]}`,
			profile: "dnsid-draft-99",
			wantErr: "unsupported identity-record profile",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			wrapper := mustParseJWKS(t, tt.data)
			if _, err := wrapper.CurrentRecordSigningKey(tt.profile); err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("CurrentRecordSigningKey(%q) error = %v, want containing %q", tt.profile, err, tt.wantErr)
			}
			if _, err := wrapper.CurrentOperationalSigningKey(tt.profile); err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("CurrentOperationalSigningKey(%q) error = %v, want containing %q", tt.profile, err, tt.wantErr)
			}
		})
	}
}

func TestParseJWKSEncryptionKeysSkipKidCheck(t *testing.T) {
	tests := []struct {
		name string
		data string
	}{
		{
			name: "P-256 encryption key without kid is allowed alongside Ed25519 signing key",
			data: `{"keys":[
			  {"kty":"OKP","crv":"Ed25519","x":"` + testOKPX1 + `","kid":"sig","alg":"EdDSA","use":"sig"},
			  {"kty":"EC","crv":"P-256","x":"` + testP256X + `","y":"` + testP256Y + `","alg":"ES256","use":"enc"}
			]}`,
		},
		{
			name: "Ed25519 encryption key without kid is allowed alongside Ed25519 signing key",
			data: `{"keys":[
			  {"kty":"OKP","crv":"Ed25519","x":"` + testOKPX1 + `","kid":"sig","alg":"EdDSA","use":"sig"},
			  {"kty":"OKP","crv":"Ed25519","x":"` + testOKPX2 + `","alg":"EdDSA","use":"enc"}
			]}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			wrapper, err := ParseJWKS([]byte(tt.data))
			if err != nil {
				t.Fatalf("ParseJWKS: %v", err)
			}
			if wrapper.set.Len() != 2 {
				t.Fatalf("set length = %d, want 2", wrapper.set.Len())
			}
			signing := wrapper.SigningKeys()
			if len(signing) != 1 {
				t.Fatalf("SigningKeys length = %d, want 1 (enc key excluded)", len(signing))
			}
			if signing[0].Kid() != "sig" {
				t.Fatalf("SigningKeys[0].Kid() = %q, want sig", signing[0].Kid())
			}
		})
	}
}

func TestJWKThumbprint(t *testing.T) {
	wrapper := mustParseJWKS(t, validTwoKeyJWKS)
	key := wrapper.KeyByID("known-kid")
	if key == nil {
		t.Fatal("known key not found")
	}

	rawThumbprint, err := key.Raw().Thumbprint(crypto.SHA256)
	if err != nil {
		t.Fatalf("raw Thumbprint: %v", err)
	}
	want := base64.RawURLEncoding.EncodeToString(rawThumbprint)

	got, err := key.Thumbprint()
	if err != nil {
		t.Fatalf("Thumbprint: %v", err)
	}
	if got != want {
		t.Fatalf("Thumbprint() = %q, want %q", got, want)
	}
}

func TestJWKThumbprintWrapsUnderlyingError(t *testing.T) {
	key := &JWK{key: thumbprintErrorKey{}}

	_, err := key.Thumbprint()
	if err == nil {
		t.Fatal("Thumbprint() = nil, want error")
	}
	if !strings.Contains(err.Error(), "jwks: computing JWK thumbprint") {
		t.Fatalf("Thumbprint() error = %q, want context", err.Error())
	}
	if !errors.Is(err, errTestThumbprint) {
		t.Fatalf("Thumbprint() error does not wrap underlying error: %v", err)
	}
}

func TestJWKAccessors(t *testing.T) {
	wrapper := mustParseJWKS(t, validTwoKeyJWKS)

	sigKey := wrapper.KeyByID("known-kid")
	if sigKey == nil {
		t.Fatal("known key not found")
	}
	if sigKey.Kid() != "known-kid" {
		t.Fatalf("Kid() = %q, want known-kid", sigKey.Kid())
	}
	if sigKey.Alg() != "EdDSA" {
		t.Fatalf("Alg() = %q, want EdDSA", sigKey.Alg())
	}
	if sigKey.Use() != "sig" {
		t.Fatalf("Use() = %q, want sig", sigKey.Use())
	}

	noUseKey := wrapper.KeyByID("second-kid")
	if noUseKey == nil {
		t.Fatal("second key not found")
	}
	if noUseKey.Use() != "" {
		t.Fatalf("Use() = %q, want empty", noUseKey.Use())
	}

	missingFields := &JWK{key: mustParseKey(t, `{
	  "kty":"OKP","crv":"Ed25519","x":"`+testOKPX5+`"
	}`)}
	if missingFields.Kid() != "" {
		t.Fatalf("Kid() = %q, want empty", missingFields.Kid())
	}
	if missingFields.Alg() != "EdDSA" {
		t.Fatalf("Alg() = %q, want derived EdDSA", missingFields.Alg())
	}
}

func TestJWKRaw(t *testing.T) {
	set := jwk.NewSet()
	key := mustParseKey(t, `{
	  "kty": "OKP",
	  "crv": "Ed25519",
	  "x": "`+testOKPX6+`",
	  "kid": "raw-kid",
	  "alg": "EdDSA"
	}`)
	if err := set.AddKey(key); err != nil {
		t.Fatalf("AddKey: %v", err)
	}

	wrapper := NewJWKS(set)
	got := wrapper.KeyByID("raw-kid")
	if got == nil {
		t.Fatal("raw key not found")
	}
	if got.Raw() != key {
		t.Fatal("Raw() did not return the underlying jwk.Key")
	}
}

func TestNilWrappers(t *testing.T) {
	var wrapper *JWKS
	if keys := wrapper.SigningKeys(); keys != nil {
		t.Fatalf("nil JWKS SigningKeys() = %#v, want nil", keys)
	}
	if key := wrapper.KeyByID("kid"); key != nil {
		t.Fatalf("nil JWKS KeyByID() = %#v, want nil", key)
	}
	if err := wrapper.Validate(); err == nil || err.Error() != "jwks: no usable signing key" {
		t.Fatalf("nil JWKS Validate() = %v, want no usable signing key", err)
	}

	wrapper = NewJWKS(nil)
	if keys := wrapper.SigningKeys(); keys != nil {
		t.Fatalf("nil set SigningKeys() = %#v, want nil", keys)
	}
	if key := wrapper.KeyByID("kid"); key != nil {
		t.Fatalf("nil set KeyByID() = %#v, want nil", key)
	}
	if err := wrapper.Validate(); err == nil || err.Error() != "jwks: no usable signing key" {
		t.Fatalf("nil set Validate() = %v, want no usable signing key", err)
	}

	var key *JWK
	if _, err := key.Thumbprint(); err == nil || err.Error() != "jwks: nil JWK" {
		t.Fatalf("nil JWK Thumbprint() = %v, want nil JWK error", err)
	}
	if key.Kid() != "" {
		t.Fatalf("nil JWK Kid() = %q, want empty", key.Kid())
	}
	if key.Alg() != "" {
		t.Fatalf("nil JWK Alg() = %q, want empty", key.Alg())
	}
	if key.Use() != "" {
		t.Fatalf("nil JWK Use() = %q, want empty", key.Use())
	}
	if key.Raw() != nil {
		t.Fatalf("nil JWK Raw() = %#v, want nil", key.Raw())
	}

	key = &JWK{}
	if _, err := key.Thumbprint(); err == nil || err.Error() != "jwks: nil JWK" {
		t.Fatalf("empty JWK Thumbprint() = %v, want nil JWK error", err)
	}
	if key.Kid() != "" {
		t.Fatalf("empty JWK Kid() = %q, want empty", key.Kid())
	}
	if key.Alg() != "" {
		t.Fatalf("empty JWK Alg() = %q, want empty", key.Alg())
	}
	if key.Use() != "" {
		t.Fatalf("empty JWK Use() = %q, want empty", key.Use())
	}
	if key.Raw() != nil {
		t.Fatalf("empty JWK Raw() = %#v, want nil", key.Raw())
	}

	if isSigningKey(nil) {
		t.Fatal("isSigningKey(nil) = true, want false")
	}
}

func mustParseJWKS(t *testing.T, data string) *JWKS {
	t.Helper()

	wrapper, err := ParseJWKS([]byte(data))
	if err != nil {
		t.Fatalf("ParseJWKS: %v", err)
	}

	return wrapper
}

func mustParseKey(t *testing.T, data string) jwk.Key {
	t.Helper()

	key, err := jwk.ParseKey([]byte(data))
	if err != nil {
		t.Fatalf("ParseKey: %v", err)
	}

	return key
}

var errTestThumbprint = errors.New("thumbprint failed")

type thumbprintErrorKey struct {
	jwk.Key
}

func (thumbprintErrorKey) Thumbprint(crypto.Hash) ([]byte, error) {
	return nil, errTestThumbprint
}
