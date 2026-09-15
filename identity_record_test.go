package dnsid

import (
	"errors"
	"strings"
	"testing"
)

type failingSigningProvider struct {
	KeyProvider
	err error
}

func (p failingSigningProvider) Sign([]byte) (*KeySignature, error) { return nil, p.err }

func TestSignRecordWithKeyProviderPreservesSigningError(t *testing.T) {
	cause := errors.New("signer unavailable")
	kp := failingSigningProvider{KeyProvider: GenerateES256KeyProvider(), err: cause}
	record := &TXTRecord{
		Version: identityRecordDraft01, GovernanceID: "example.com",
		EntityKeyURI: "https://example.com/ek", KeyURI: "https://agent.example.com/ku",
		LogRef: "test:agent", StatusURI: "https://agent.example.com/status",
	}
	_, err := signRecordWithKeyProvider(record, kp)
	var argumentErr *ArgumentError
	if !errors.Is(err, cause) || errors.As(err, &argumentErr) {
		t.Fatalf("signing error = %T %v, want preserved non-argument cause", err, err)
	}
}

func TestParseTXTRecord_UnknownTagIsPreserved(t *testing.T) {
	record, err := ParseTXTRecord("v=DNSid1;gi=example.com;ek=https://example.com/ek;ku=https://agent.example.com/ku;lr=test:agent;su=https://agent.example.com/status;oi=legacy;sg=placeholder")
	if err != nil {
		t.Fatalf("ParseTXTRecord: %v", err)
	}
	if record.UnknownTags["oi"] != "legacy" || !strings.Contains(record.Canonical(), "oi=legacy") {
		t.Fatalf("unknown oi tag not preserved: %#v", record)
	}
}

func TestDraft01VersionSelectors(t *testing.T) {
	if DefaultPublishProfile != identityRecordDraft01 {
		t.Fatalf("DefaultPublishProfile = %q, want %q", DefaultPublishProfile, identityRecordDraft01)
	}
	for _, version := range []string{identityRecordDraft01, identityRecordDNSid1} {
		t.Run(version, func(t *testing.T) {
			key := GenerateES256KeyProvider()
			record := &TXTRecord{
				Version:      version,
				GovernanceID: "example.com",
				EntityKeyURI: "https://example.com/ek",
				KeyURI:       "https://agent.example.com/ku",
				LogRef:       "test:agent",
				StatusURI:    "https://agent.example.com/status",
			}
			if _, err := signRecordWithKeyProvider(record, key); err != nil {
				t.Fatalf("signRecordWithKeyProvider: %v", err)
			}
			if !strings.HasSuffix(record.Canonical(), ";v="+version) {
				t.Fatalf("Canonical() = %q, want exact selector %q", record.Canonical(), version)
			}
			parsed, err := ParseTXTRecord(record.Serialize())
			if err != nil {
				t.Fatalf("ParseTXTRecord: %v", err)
			}
			if parsed.Version != version {
				t.Fatalf("Version = %q, want exact selector %q", parsed.Version, version)
			}
			if err := verifyRecordSignatureWithJWKS(parsed, mustJWKSet(t, key.JWK())); err != nil {
				t.Fatalf("verifyRecordSignatureWithJWKS: %v", err)
			}
		})
	}
}

func TestDNSid1IsVerificationOnly(t *testing.T) {
	_, err := NewIdentityManager(Config{Identity: &IdentityConfig{
		Domain:         "agent.example.com",
		GovernanceID:   "example.com",
		LogRef:         "test:agent",
		StatusURL:      "https://agent.example.com/status",
		KeyURL:         "https://agent.example.com/ku",
		EntityKeyURL:   "https://example.com/ek",
		PublishProfile: identityRecordDNSid1,
	}}, GenerateES256KeyProvider(), WithEntityKeyProvider(GenerateES256KeyProvider()))
	if err == nil {
		t.Fatal("DNSid1 was accepted as a publish profile")
	}
}

func TestParseTXTRecord_MissingRequiredTagIsParseError(t *testing.T) {
	valid := "v=dnsid-draft-01;gi=example.com;ek=https://example.com/ek;ku=https://agent.example.com/ku;lr=test:agent;su=https://agent.example.com/status;sg=placeholder"
	for _, field := range []string{"gi=example.com;", "ek=https://example.com/ek;", "lr=test:agent;", "sg=placeholder"} {
		_, err := ParseTXTRecord(strings.Replace(valid, field, "", 1))
		var parseErr *ParseError
		if !errors.As(err, &parseErr) {
			t.Errorf("missing %q: error = %T, want *ParseError", field, err)
		}
	}
}

func TestParseTXTRecord_UnsupportedVersionIsParseError(t *testing.T) {
	cases := []string{
		"dnsid-draft-00",
		"dnsid-draft01",
		"dnsid-draft-01-20260504",
		"dnsid-draft-01-20260527",
		"dnsid-draft-01-20260626",
		"draft-dnsid-00",
		"draft-dnsid-01",
		"draft-dnsid-02",
		"draft-dnsid-future",
		"dnsid-future",
	}
	for _, version := range cases {
		txt := "v=" + version + ";gi=example.com;ku=https://example.com/jwks;lr=algorand:ADDR123;sg=EdDSA:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA;su=https://example.com/status"
		_, err := ParseTXTRecord(txt)
		if err == nil {
			t.Fatalf("version %q: expected error", version)
		}
		var perr *ParseError
		if !errors.As(err, &perr) {
			t.Fatalf("version %q: error = %T %[2]v, want ParseError", version, err)
		}
	}
}
