package dnsid

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	dnsidlog "github.com/dnsid-ai/dnsid-go/log"
	"github.com/lestrrat-go/jwx/v3/jwk"
)

func dnsid1Publisher(t *testing.T, alg JoseAlg) (*IdentityManager, KeyProvider, KeyProvider) {
	t.Helper()
	var operational, entity KeyProvider
	if alg == JoseAlgEdDSA {
		operational = GenerateEd25519KeyProvider()
		entity = GenerateEd25519KeyProvider()
	} else {
		operational = GenerateES256KeyProvider()
		entity = GenerateES256KeyProvider()
	}
	m, err := NewIdentityManager(Config{Identity: &IdentityConfig{
		Domain:       "agent.example.com",
		GovernanceID: "example.com",
		LogRef:       "testlog:agent",
		StatusURL:    "https://agent.example.com/status",
		KeyURL:       "https://agent.example.com/ku.json",
		EntityKeyURL: "https://keys.example.com/ek.json",
	}}, operational, WithEntityKeyProvider(entity))
	if err != nil {
		t.Fatalf("NewIdentityManager: %v", err)
	}
	return m, entity, operational
}

func TestDraft01CreateTXTRecord(t *testing.T) {
	for _, alg := range []JoseAlg{JoseAlgEdDSA, JoseAlgES256} {
		t.Run(string(alg), func(t *testing.T) {
			publisher, entity, _ := dnsid1Publisher(t, alg)
			unsigned, err := publisher.BuildUnsignedTXTRecord()
			if err != nil {
				t.Fatalf("BuildUnsignedTXTRecord: %v", err)
			}
			if unsigned.Signature != "" {
				t.Fatalf("unsigned record has signature %q", unsigned.Signature)
			}
			record, err := publisher.CreateTXTRecord()
			if err != nil {
				t.Fatalf("CreateTXTRecord: %v", err)
			}
			if record.Version != DefaultPublishProfile {
				t.Fatalf("Version = %q, want %q", record.Version, DefaultPublishProfile)
			}
			if strings.ContainsAny(record.Signature, ":=") {
				t.Fatalf("draft 01 signature is not bare unpadded base64url: %q", record.Signature)
			}
			if !strings.HasSuffix(record.Canonical(), ";v="+DefaultPublishProfile) {
				t.Fatalf("Canonical() = %q, want exact v sorted last", record.Canonical())
			}
			if !strings.HasPrefix(record.Serialize(), "v="+DefaultPublishProfile+";") {
				t.Fatalf("Serialize() = %q, want exact v first", record.Serialize())
			}
			set := jwk.NewSet()
			if err := set.AddKey(entity.JWK()); err != nil {
				t.Fatal(err)
			}
			if err := verifyRecordSignatureWithJWKS(record, set); err != nil {
				t.Fatalf("verifyRecordSignatureWithJWKS: %v", err)
			}
			prefixed := *record
			prefixed.Signature = alg.String() + ":" + record.Signature
			if err := verifyRecordSignatureWithJWKS(&prefixed, set); err == nil {
				t.Fatal("algorithm-prefixed DNSid1 signature was accepted")
			}

			keyJSON, err := json.Marshal(entity.JWK())
			if err != nil {
				t.Fatal(err)
			}
			missingAlg, err := jwk.ParseKey(keyJSON)
			if err != nil {
				t.Fatal(err)
			}
			if err := missingAlg.Remove(jwk.AlgorithmKey); err != nil {
				t.Fatal(err)
			}
			if err := verifyRecordSignatureWithJWKS(record, mustJWKSet(t, missingAlg)); err == nil {
				t.Fatal("DNSid1 record-signing key without alg was accepted")
			}

			keyJSON, err = json.Marshal(entity.JWK())
			if err != nil {
				t.Fatal(err)
			}
			missingKid, err := jwk.ParseKey(keyJSON)
			if err != nil {
				t.Fatal(err)
			}
			if err := missingKid.Remove(jwk.KeyIDKey); err != nil {
				t.Fatal(err)
			}
			if err := verifyRecordSignatureWithJWKS(record, mustJWKSet(t, missingKid)); err == nil {
				t.Fatal("DNSid1 record-signing key without kid was accepted")
			}

			incompatibleOps := entity.JWK()
			if err := incompatibleOps.Set(jwk.KeyOpsKey, jwk.KeyOperationList{jwk.KeyOpEncrypt}); err != nil {
				t.Fatal(err)
			}
			if err := verifyRecordSignatureWithJWKS(record, mustJWKSet(t, incompatibleOps)); err == nil {
				t.Fatal("DNSid1 signing key with incompatible key_ops was accepted")
			}

			extraWithoutAlg := GenerateEd25519KeyProvider().JWK()
			if err := extraWithoutAlg.Set(jwk.KeyUsageKey, string(jwk.ForEncryption)); err != nil {
				t.Fatal(err)
			}
			if err := extraWithoutAlg.Remove(jwk.AlgorithmKey); err != nil {
				t.Fatal(err)
			}
			withMissingAlg := mustJWKSet(t, entity.JWK())
			if err := withMissingAlg.AddKey(extraWithoutAlg); err != nil {
				t.Fatal(err)
			}
			if err := verifyRecordSignatureWithJWKS(record, withMissingAlg); err == nil {
				t.Fatal("DNSid1 JWKS containing a key without alg was accepted")
			}

			multi := mustJWKSet(t, entity.JWK())
			var extra jwk.Key
			if alg == JoseAlgEdDSA {
				extra = GenerateEd25519KeyProvider().JWK()
			} else {
				extra = GenerateES256KeyProvider().JWK()
			}
			if err := multi.AddKey(extra); err != nil {
				t.Fatal(err)
			}
			if err := verifyRecordSignatureWithJWKS(record, multi); err == nil {
				t.Fatal("DNSid1 ek JWKS with multiple current signing keys was accepted")
			}
		})
	}
}

func TestDNSid1RejectsNonCanonicalGovernanceID(t *testing.T) {
	record := &TXTRecord{
		Version:      identityRecordDNSid1,
		GovernanceID: "EXAMPLE.COM",
		EntityKeyURI: "https://example.com/ek.json",
		KeyURI:       "https://agent.example.com/ku.json",
		LogRef:       "testlog:agent",
		StatusURI:    "https://agent.example.com/status",
		Signature:    "placeholder",
	}
	if err := record.Validate("agent.example.com"); err == nil {
		t.Fatal("DNSid1 record with uppercase gi was accepted")
	}

	manager, err := NewIdentityManager(Config{Identity: &IdentityConfig{
		Domain:       "agent.example.com",
		GovernanceID: "EXAMPLE.COM",
		LogRef:       "testlog:agent",
		StatusURL:    "https://agent.example.com/status",
		KeyURL:       "https://agent.example.com/ku.json",
		EntityKeyURL: "https://example.com/ek.json",
	}}, GenerateES256KeyProvider(), WithEntityKeyProvider(GenerateES256KeyProvider()))
	if err != nil {
		t.Fatalf("NewIdentityManager: %v", err)
	}
	if _, err = manager.BuildUnsignedTXTRecord(); err == nil {
		t.Fatal("DNSid1 publisher with uppercase GovernanceID was accepted")
	}
}

func TestDNSid1AllowsEntityKeyHostBelowGovernanceID(t *testing.T) {
	record := &TXTRecord{
		Version:      identityRecordDNSid1,
		GovernanceID: "example.com",
		EntityKeyURI: "https://keys.example.com/ek.json",
		KeyURI:       "https://agent.example.com/ku.json",
		LogRef:       "testlog:agent",
		StatusURI:    "https://agent.example.com/status",
		Signature:    "placeholder",
	}
	if err := record.Validate("agent.example.com"); err != nil {
		t.Fatalf("DNSid1 record with ek below gi was rejected: %v", err)
	}

	_, err := NewIdentityManager(Config{Identity: &IdentityConfig{
		Domain:       "agent.example.com",
		GovernanceID: "example.com",
		LogRef:       "testlog:agent",
		StatusURL:    "https://agent.example.com/status",
		KeyURL:       "https://agent.example.com/ku.json",
		EntityKeyURL: "https://keys.example.com/ek.json",
	}}, GenerateES256KeyProvider(), WithEntityKeyProvider(GenerateES256KeyProvider()))
	if err != nil {
		t.Fatalf("DNSid1 publisher with ek below gi was rejected: %v", err)
	}
}

func TestDNSid1VerifyDomainExposesOperationLogCheck(t *testing.T) {
	publisher, entity, operational := dnsid1Publisher(t, JoseAlgES256)
	publisher.identity.PolicyFlags = []PolicyFlag{PolicyFlagLogCheck}
	record, err := publisher.CreateTXTRecord()
	if err != nil {
		t.Fatalf("CreateTXTRecord: %v", err)
	}
	ekJSON, err := json.Marshal(NewJWKS(mustJWKSet(t, entity.JWK())).Raw())
	if err != nil {
		t.Fatal(err)
	}
	kuJSON, err := json.Marshal(NewJWKS(mustJWKSet(t, operational.JWK())).Raw())
	if err != nil {
		t.Fatal(err)
	}
	dns := &testDNSResolver{records: map[string][]TXTRecordRData{
		"_dnsid.agent.example.com": {{Value: record.Serialize(), TTL: time.Minute}},
	}}
	https := testHTTPSFetcher{responses: map[string]json.RawMessage{
		record.EntityKeyURI: ekJSON,
		record.KeyURI:       kuJSON,
		record.StatusURI:    json.RawMessage(freshStatus()),
	}}
	reader := &testLogReader{revoked: true}
	registry := dnsidlog.NewLogRegistry()
	if err := registry.Register("testlog", func(string) dnsidlog.LogReader { return reader }); err != nil {
		t.Fatal(err)
	}
	verifier, err := NewVerifier(WithDNSResolver(dns), WithHTTPSFetcher(&https), WithLogRegistry(registry))
	if err != nil {
		t.Fatal(err)
	}

	vd, err := verifier.VerifyDomain(context.Background(), "agent.example.com")
	if err != nil {
		t.Fatalf("VerifyDomain: %v", err)
	}
	if !vd.RequiresLogCheck() || reader.nonRevocationCalls != 0 {
		t.Fatalf("RequiresLogCheck = %v, VerifyNonRevocation calls = %d", vd.RequiresLogCheck(), reader.nonRevocationCalls)
	}

	_, err = verifier.VerifyLogEvidence(context.Background(), vd, time.Time{})
	var verificationErr *VerificationError
	if !errors.As(err, &verificationErr) || verificationErr.Code() != VerificationCodeLogError {
		t.Fatalf("VerifyLogEvidence error = %v, want log_error", err)
	}
	if reader.nonRevocationCalls != 1 {
		t.Fatalf("VerifyNonRevocation calls = %d, want 1", reader.nonRevocationCalls)
	}
}

func TestDNSid1VerifyDomain(t *testing.T) {
	publisher, entity, operational := dnsid1Publisher(t, JoseAlgES256)
	record, err := publisher.CreateTXTRecord()
	if err != nil {
		t.Fatalf("CreateTXTRecord: %v", err)
	}
	ekJSON, err := json.Marshal(NewJWKS(mustJWKSet(t, entity.JWK())).Raw())
	if err != nil {
		t.Fatal(err)
	}
	kuJSON, err := json.Marshal(NewJWKS(mustJWKSet(t, operational.JWK())).Raw())
	if err != nil {
		t.Fatal(err)
	}
	status := json.RawMessage(`{"state":"ACTIVE","lastTransitionAt":"` + time.Now().UTC().Format(time.RFC3339Nano) + `"}`)
	dns := &testDNSResolver{records: map[string][]TXTRecordRData{
		"_dnsid.agent.example.com": {{Value: record.Serialize(), TTL: time.Minute}},
	}}
	fetchOptions := make(map[string]FetchOptions)
	https := testHTTPSFetcher{responses: map[string]json.RawMessage{
		record.EntityKeyURI: ekJSON,
		record.KeyURI:       kuJSON,
		record.StatusURI:    status,
	}, options: fetchOptions}

	withoutLog, err := NewIdentityManager(Config{}, nil, WithDNSResolver(dns), WithHTTPSFetcher(&https))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := withoutLog.VerifyDomain(context.Background(), "agent.example.com"); err == nil {
		t.Fatal("DNSid1 verification succeeded without a registered log reader")
	}

	reader := &testLogReader{revoked: true} // ordinary verification does not enforce operation-level non-revocation
	registry := dnsidlog.NewLogRegistry()
	if err := registry.Register("testlog", func(string) dnsidlog.LogReader { return reader }); err != nil {
		t.Fatal(err)
	}
	verifier, err := NewIdentityManager(Config{}, nil, WithDNSResolver(dns), WithHTTPSFetcher(&https), WithLogRegistry(registry))
	if err != nil {
		t.Fatal(err)
	}
	verified, err := verifier.VerifyDomain(context.Background(), "agent.example.com")
	if err != nil {
		t.Fatalf("VerifyDomain: %v", err)
	}
	if got := fetchOptions[record.EntityKeyURI]; got.AllowedHost != "example.com" || !got.DomainBoundary || got.RedirectPolicy != RedirectPolicySameHost {
		t.Fatalf("ek fetch options = %#v, want gi domain boundary", got)
	}
	if !reader.bindingHit || !reader.continuityHit || reader.bindingInput.OperationalKey == nil {
		t.Fatal("DNSid1 bilateral binding and continuity did not receive the current ku key")
	}
	reader.bindingHit, reader.continuityHit = false, false
	if _, err := verifier.VerifyDomain(context.Background(), "agent.example.com"); err != nil {
		t.Fatalf("cached VerifyDomain: %v", err)
	}
	if reader.bindingHit || reader.continuityHit {
		t.Fatal("cached VerifyDomain repeated lifecycle verification")
	}
	keys := verified.KeySet().SigningKeys()
	if len(keys) != 1 {
		t.Fatalf("runtime key count = %d, want 1", len(keys))
	}
	want, _ := (&JWK{key: operational.JWK()}).Thumbprint()
	got, _ := keys[0].Thumbprint()
	if got != want {
		t.Fatalf("runtime key thumbprint = %q, want ku %q", got, want)
	}
	recordSigningKeys := verified.RecordSigningKeySet().SigningKeys()
	if len(recordSigningKeys) != 1 {
		t.Fatalf("record-signing key count = %d, want 1", len(recordSigningKeys))
	}
	want, _ = (&JWK{key: entity.JWK()}).Thumbprint()
	got, _ = recordSigningKeys[0].Thumbprint()
	if got != want {
		t.Fatalf("record-signing key thumbprint = %q, want ek %q", got, want)
	}
}

func mustJWKSet(t *testing.T, key jwk.Key) jwk.Set {
	t.Helper()
	set := jwk.NewSet()
	if err := set.AddKey(key); err != nil {
		t.Fatal(err)
	}
	return set
}
