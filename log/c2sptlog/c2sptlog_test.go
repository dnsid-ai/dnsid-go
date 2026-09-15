package c2sptlog

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"strings"
	"testing"
	"time"

	dnsid "github.com/dnsid-ai/dnsid-go"
	dnsidlog "github.com/dnsid-ai/dnsid-go/log"
	"github.com/lestrrat-go/jwx/v3/jwk"
	formatlog "github.com/transparency-dev/formats/log"
	formatproof "github.com/transparency-dev/formats/proof"
	"golang.org/x/mod/sumdb/note"
)

const (
	aeJWK  = `{"alg":"EdDSA","crv":"Ed25519","kid":"ae-test-1","kty":"OKP","x":"iojj3XQJ8ZX9UtstPLpdcspnCb8dlBIb83SIAbQPb1w"}`
	op1JWK = `{"alg":"EdDSA","crv":"Ed25519","kid":"op-test-1","kty":"OKP","x":"gTl3Dqh9F19Wo1Rmw0x-zMuNipG07jeiXfYPW4_Js5Q"}`
	op2JWK = `{"alg":"EdDSA","crv":"Ed25519","kid":"op-test-2","kty":"OKP","x":"ypOsFwUYcHHWe4PH_w7-gQjo7EUwV113JoeTM9vavnw"}`

	issuanceCanonical   = `{"ek":{"alg":"EdDSA","crv":"Ed25519","kid":"ae-test-1","kty":"OKP","x":"iojj3XQJ8ZX9UtstPLpdcspnCb8dlBIb83SIAbQPb1w"},"fqdn":"agent.example","gi":"example.com","kind":"dnsid.lifecycle","ku":{"alg":"EdDSA","crv":"Ed25519","kid":"op-test-1","kty":"OKP","x":"gTl3Dqh9F19Wo1Rmw0x-zMuNipG07jeiXfYPW4_Js5Q"},"ts":1782172800,"type":"ISSUANCE","v":1}`
	legacyIssuanceEntry = `{"ek":{"alg":"EdDSA","crv":"Ed25519","kid":"ae-test-1","kty":"OKP","x":"iojj3XQJ8ZX9UtstPLpdcspnCb8dlBIb83SIAbQPb1w"},"fqdn":"agent.example","gi":"example.com","kind":"dnsid.lifecycle","ku":{"alg":"EdDSA","crv":"Ed25519","kid":"op-test-1","kty":"OKP","x":"gTl3Dqh9F19Wo1Rmw0x-zMuNipG07jeiXfYPW4_Js5Q"},"sigs":{"ae":{"kid":"ae-test-1","sig":"Qp_IOg6S-ksElLBrMTwUqQ6slrt-W-wbXtadHY6nXOPbUXs1013_kNdrMWYEWjVZcvXptqxwshbKu-wtz4h6CQ"},"op":{"kid":"op-test-1","sig":"jWSZhq4Cm5FeHipM1MX5LVdej9cpStNAaoCFZSG3G_w-0w4rhYss2Vvi0lz7DcvVFO8K2nde0VfX2c5Ga5bvAg"}},"ts":1782172800,"type":"ISSUANCE","v":1}`

	legacyKeyRotationEntry = `{"fqdn":"agent.example","kind":"dnsid.lifecycle","new_ku":{"alg":"EdDSA","crv":"Ed25519","kid":"op-test-2","kty":"OKP","x":"ypOsFwUYcHHWe4PH_w7-gQjo7EUwV113JoeTM9vavnw"},"new_thumb":"d8Me3uJ82jhdsCstWyVMr3_I2ueeTYG5agM1-2r1_bY","prev_thumb":"aVBtapLd11SUVKIMGJfPzOEDuN0sXcmzJQNVT-_sKEU","sigs":{"new_op":{"kid":"op-test-2","sig":"JfWp_M8PVCoWAAqkiCX-3OjLlrRZLEcgusyTK6yDSJmeP0Ojw9Nc6cy-nDQjs21vx9-CyNMmWPOXAU_YJ6ddBg"},"prev_op":{"kid":"op-test-1","sig":"pPTFBLO3qGxqJ9xOrppA-z5SlQuPoCq1Sf9OwrizoN8K8VTtIuxg0xJDXE1BVzWnMt9GAcyx1yM3Rx3JZ16oCQ"}},"ts":1782259200,"type":"KEY_ROTATION","v":1}`
	legacyRevocationEntry  = `{"fqdn":"agent.example","kind":"dnsid.lifecycle","reason":"keyCompromise","sigs":{"ae":{"kid":"ae-test-1","sig":"CjrMHNl_BdMG5qkbyttuCGyhlchkhTowOyfkZn2T-Wl_jnqYB5Jh0TYuNS6BLJlDLYS9OFD8FItH2dEJ0f4eCw"}},"ts":1782345600,"type":"REVOCATION","v":1}`
)

func TestParseReferenceAndOrigin(t *testing.T) {
	ref, err := ParseReference("c2sp-tlog:testnet:http://dnsid-ledger:8080/log#identity-01")
	if err != nil {
		t.Fatalf("ParseReference: %v", err)
	}
	if ref.Scope != "testnet" || ref.LogPrefix != "http://dnsid-ledger:8080/log" || ref.StreamID != "identity-01" {
		t.Fatalf("ref = %#v", ref)
	}
	origin, err := ref.Origin()
	if err != nil {
		t.Fatalf("Origin: %v", err)
	}
	if origin != "dnsid-ledger:8080/log" {
		t.Fatalf("Origin = %q", origin)
	}
	if _, err := ParseReference("c2sp-tlog:public:http://example.com/log#agent.example"); err == nil {
		t.Fatal("public http reference accepted")
	}
}

func TestGenerateStreamID(t *testing.T) {
	seen := make(map[string]struct{}, 64)
	for range 64 {
		streamID, err := GenerateStreamID()
		if err != nil {
			t.Fatalf("GenerateStreamID: %v", err)
		}
		if strings.Contains(streamID, "=") {
			t.Fatalf("stream ID %q contains base64 padding", streamID)
		}
		decoded, err := base64.RawURLEncoding.DecodeString(streamID)
		if err != nil {
			t.Fatalf("stream ID %q is not unpadded base64url: %v", streamID, err)
		}
		if len(decoded) != streamIDBytes {
			t.Fatalf("stream ID decodes to %d bytes, want %d", len(decoded), streamIDBytes)
		}
		if _, ok := seen[streamID]; ok {
			t.Fatalf("GenerateStreamID returned duplicate %q", streamID)
		}
		seen[streamID] = struct{}{}
	}
}

func TestCanonicalEntryAndLeafHashVectors(t *testing.T) {
	event := dnsidlog.LogEvent{
		Type:                        dnsidlog.LogEventIssuance,
		Domain:                      "agent.example",
		GovernanceID:                "example.com",
		Timestamp:                   time.Unix(1782172800, 0).UTC(),
		InitialOperationalPublicKey: mustKey(t, op1JWK),
		InitialEntityPublicKey:      mustKey(t, aeJWK),
		InitialEntityKid:            "ae-test-1",
		InitialEntitySignature:      "Qp_IOg6S-ksElLBrMTwUqQ6slrt-W-wbXtadHY6nXOPbUXs1013_kNdrMWYEWjVZcvXptqxwshbKu-wtz4h6CQ",
		InitialOperationalKid:       "op-test-1",
		InitialOperationalSignature: "jWSZhq4Cm5FeHipM1MX5LVdej9cpStNAaoCFZSG3G_w-0w4rhYss2Vvi0lz7DcvVFO8K2nde0VfX2c5Ga5bvAg",
	}
	canonical, err := Canonical(event)
	if err != nil {
		t.Fatalf("Canonical: %v", err)
	}
	if string(canonical) != issuanceCanonical {
		t.Fatalf("Canonical mismatch\n got: %s\nwant: %s", canonical, issuanceCanonical)
	}
	entry, err := EntryBytes(event)
	if err != nil {
		t.Fatalf("EntryBytes: %v", err)
	}
	if string(entry) != legacyIssuanceEntry {
		t.Fatalf("Entry mismatch\n got: %s\nwant: %s", entry, legacyIssuanceEntry)
	}
	hash := LeafHash(entry)
	gotHash := base64.StdEncoding.EncodeToString(hash[:])
	if gotHash != "0B3JZBn2fwm7Ei8RI4w0Eud3KVXBWqtWpy156PwQD24=" {
		t.Fatalf("leaf hash = %q", gotHash)
	}
}

func TestPrepareEventAcceptsOpaqueIdentityInstanceStream(t *testing.T) {
	client, err := New("c2sp-tlog:public:https://log.example#EREREREREREREREREREREQ")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	event := dnsidlog.LogEvent{
		Type:                        dnsidlog.LogEventIssuance,
		Domain:                      "agent.example",
		GovernanceID:                "example.com",
		Timestamp:                   time.Unix(1782172800, 0).UTC(),
		InitialEntityPublicKey:      mustKey(t, aeJWK),
		InitialOperationalPublicKey: mustKey(t, op1JWK),
	}
	_, err = client.PrepareEvent(event)
	if err != nil {
		t.Fatalf("PrepareEvent: %v", err)
	}
}

func TestPrepareEventRejectsDomainAsStreamID(t *testing.T) {
	client, err := New("c2sp-tlog:public:https://log.example#agent.example")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	event := dnsidlog.LogEvent{
		Type:                        dnsidlog.LogEventIssuance,
		Domain:                      "agent.example",
		GovernanceID:                "example.com",
		Timestamp:                   time.Unix(1782172800, 0).UTC(),
		InitialEntityPublicKey:      mustKey(t, aeJWK),
		InitialOperationalPublicKey: mustKey(t, op1JWK),
	}
	checks := []struct {
		name string
		call func() error
	}{
		{name: "prepare", call: func() error { _, err := client.PrepareEvent(event); return err }},
		{name: "canonical", call: func() error { _, err := client.Canonical(event); return err }},
		{name: "entry bytes", call: func() error { _, err := client.EntryBytes(event); return err }},
		{name: "write", call: func() error { _, err := client.WriteEvent(context.Background(), event); return err }},
	}
	for _, check := range checks {
		if err := check.call(); err == nil || !strings.Contains(err.Error(), "must not equal") {
			t.Fatalf("%s error = %v, want normalized-fqdn stream rejection", check.name, err)
		}
	}
	if _, err := ParseReference("c2sp-tlog:public:https://log.example#agent.example"); err != nil {
		t.Fatalf("ParseReference historical domain stream: %v", err)
	}
}

func TestCanonicalJSONUsesJCSUnicodeOrderingAndEscaping(t *testing.T) {
	got, err := canonicalJSON(map[string]any{
		"€":      "euro",
		"\r":     "cr",
		"דּ":      "hebrew",
		"1":      "one",
		"😀":      "emoji",
		"\u0080": "control",
		"ö":      "line\u2028separator",
	})
	if err != nil {
		t.Fatalf("canonicalJSON: %v", err)
	}
	want := "{\"\\r\":\"cr\",\"1\":\"one\",\"\u0080\":\"control\",\"ö\":\"line\u2028separator\",\"€\":\"euro\",\"😀\":\"emoji\",\"דּ\":\"hebrew\"}"
	if string(got) != want {
		t.Fatalf("canonical JSON\n got: %s\nwant: %s", got, want)
	}
}

func TestLogEventFromEntryRejectsDuplicateMembers(t *testing.T) {
	entry := []byte(`{"v":1,"v":1,"kind":"dnsid.lifecycle","type":"ISSUANCE","fqdn":"agent.example","ts":1}`)
	if _, err := LogEventFromEntry(entry); err == nil || !strings.Contains(err.Error(), "duplicate") {
		t.Fatalf("LogEventFromEntry error = %v, want duplicate rejection", err)
	}
}

func TestLogEventFromEntryClassifiesSemanticMismatchAsValidationError(t *testing.T) {
	entry := canonicalEntryMutation(t, issuanceEntry, func(payload map[string]any) {
		sigs := payload["sigs"].(map[string]any)
		ae := sigs["ae"].(map[string]any)
		ae["kid"] = "wrong-entity-kid"
	})
	_, err := LogEventFromEntry(entry)
	var validationErr *dnsid.ValidationError
	if !errors.As(err, &validationErr) {
		t.Fatalf("LogEventFromEntry error = %T %v, want *dnsid.ValidationError", err, err)
	}
}

func TestEntryBytesRejectsOversizedEntryBeforeAppend(t *testing.T) {
	event := dnsidlog.LogEvent{
		Type:                   dnsidlog.LogEventDelegation,
		Domain:                 "agent.example",
		Timestamp:              time.Unix(1782345600, 0).UTC(),
		InitialEntityKid:       "ae-test-1",
		InitialEntitySignature: "sig",
		Delegatee:              "delegate.example",
		Scope:                  strings.Repeat("x", maxEntrySize),
		Expiry:                 time.Unix(1782432000, 0).UTC(),
	}
	if _, err := EntryBytes(event); err == nil || !strings.Contains(err.Error(), "maximum") {
		t.Fatalf("EntryBytes error = %v, want size rejection", err)
	}
}

func TestPublicClientAddsAndRequiresReferenceMetadata(t *testing.T) {
	client, err := New("c2sp-tlog:public:https://tlog.example.com/dnsid#instance-01", withProofVerifySkipped())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	event := dnsidlog.LogEvent{Type: dnsidlog.LogEventRevocation, Domain: "agent.example", Timestamp: time.Unix(1782345600, 0).UTC(), InitialEntityKid: "ae", InitialEntitySignature: "sig", Reason: "keyCompromise"}
	entry, err := entryBytes(event, &client.ref)
	if err != nil {
		t.Fatalf("entryBytes: %v", err)
	}
	for _, want := range []string{`"method":"c2sp-tlog"`, `"log_origin":"tlog.example.com/dnsid"`, `"stream_id":"instance-01"`, `"lr":"c2sp-tlog:public:https://tlog.example.com/dnsid#instance-01"`} {
		if !strings.Contains(string(entry), want) {
			t.Fatalf("entry missing %s: %s", want, entry)
		}
	}
	if err := client.validateEntryMetadata([]byte(legacyRevocationEntry)); err == nil || !strings.Contains(err.Error(), "missing") {
		t.Fatalf("validateEntryMetadata = %v, want missing public metadata", err)
	}
}

func TestParseReferenceRejectsNonCanonicalLogPrefix(t *testing.T) {
	bad := []string{
		"c2sp-tlog:public:https://USER@example.com/log#agent.example",
		"c2sp-tlog:public:https://Example.com/log#agent.example",
		"c2sp-tlog:public:https://example.com:443/log#agent.example",
		"c2sp-tlog:public:https://example.com/a/../log#agent.example",
		"c2sp-tlog:public:https://example.com/%6Cog#agent.example",
	}
	for _, lr := range bad {
		if _, err := ParseReference(lr); err == nil {
			t.Fatalf("ParseReference(%q) succeeded", lr)
		}
	}
}

func TestReferenceErrorsUseSharedTaxonomy(t *testing.T) {
	if _, err := ParseReference("bad"); err == nil {
		t.Fatal("ParseReference succeeded")
	} else {
		var parseErr *dnsid.ParseError
		if !errors.As(err, &parseErr) {
			t.Fatalf("ParseReference error = %T, want *dnsid.ParseError", err)
		}
	}
	if err := (Reference{}).Validate(); err == nil {
		t.Fatal("Reference.Validate succeeded")
	} else {
		var validationErr *dnsid.ValidationError
		if !errors.As(err, &validationErr) {
			t.Fatalf("Reference.Validate error = %T, want *dnsid.ValidationError", err)
		}
	}
}

func TestParsePreparedEventErrorsUseSharedTaxonomy(t *testing.T) {
	var nilClient *Client
	if _, err := nilClient.ParsePreparedEvent(nil); err == nil {
		t.Fatal("nil Client.ParsePreparedEvent succeeded")
	} else {
		var argumentErr *dnsid.ArgumentError
		if !errors.As(err, &argumentErr) {
			t.Fatalf("nil client error = %T, want *dnsid.ArgumentError", err)
		}
	}
	client, err := New("c2sp-tlog:testnet:http://dnsid-ledger:8080/log#identity-01", withProofVerifySkipped())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, err := client.ParsePreparedEvent([]byte(`{`)); err == nil {
		t.Fatal("ParsePreparedEvent accepted malformed entry")
	} else {
		var parseErr *dnsid.ParseError
		if !errors.As(err, &parseErr) {
			t.Fatalf("malformed entry error = %T, want *dnsid.ParseError", err)
		}
	}
	invalid := []byte(`{"fqdn":"other.example","kind":"dnsid.lifecycle","ts":1782172800,"type":"REVOCATION","v":1}`)
	if _, err := client.ParsePreparedEvent(invalid); err == nil {
		t.Fatal("ParsePreparedEvent accepted event for another stream")
	} else {
		var validationErr *dnsid.ValidationError
		if !errors.As(err, &validationErr) {
			t.Fatalf("invalid event error = %T, want *dnsid.ValidationError", err)
		}
		var parseErr *dnsid.ParseError
		if errors.As(err, &parseErr) {
			t.Fatalf("invalid event error = %T, unexpectedly matches *dnsid.ParseError", err)
		}
	}
}

func TestParseFinalEventRefRejectsNonCanonicalIndex(t *testing.T) {
	base := dnsidlog.LogRef("c2sp-tlog:public:https://example.com/log#agent.example@")
	for _, index := range []string{"00", "+1", "-1", " 1"} {
		if _, _, err := ParseFinalEventRef(base + dnsidlog.LogRef(index)); err == nil {
			t.Fatalf("ParseFinalEventRef accepted index %q", index)
		}
	}
	if _, index, err := ParseFinalEventRef(base + "0"); err != nil || index != 0 {
		t.Fatalf("ParseFinalEventRef canonical zero = %d, %v", index, err)
	}
}

func TestRebuildHistoryIgnoresInvalidGlobalCandidates(t *testing.T) {
	wrongDomain := canonicalEntryMutation(t, issuanceEntry, func(payload map[string]any) {
		payload["fqdn"] = "other.example"
	})
	wrongContext := canonicalEntryMutation(t, issuanceEntry, func(payload map[string]any) {
		payload["lr"] = "c2sp-tlog:testnet:http://other-ledger:8080/log#agent.example"
	})
	unsupportedVersion := canonicalEntryMutation(t, issuanceEntry, func(payload map[string]any) {
		payload["v"] = 2
	})
	unsupportedType := canonicalEntryMutation(t, issuanceEntry, func(payload map[string]any) {
		payload["type"] = "FUTURE"
	})
	invalidSignature := canonicalEntryMutation(t, issuanceEntry, func(payload map[string]any) {
		payload["sigs"].(map[string]any)["ae"].(map[string]any)["sig"] = "AA"
	})
	source := globalMemorySource{memorySource: memorySource{entries: []ProvenEntry{
		{Index: 0, Entry: []byte(`{`)},
		{Index: 1, Entry: []byte(`{"not":"dnsid"}`)},
		{Index: 2, Entry: unsupportedVersion},
		{Index: 3, Entry: unsupportedType},
		{Index: 4, Entry: wrongDomain},
		{Index: 5, Entry: wrongContext},
		{Index: 6, Entry: invalidSignature},
		{Index: 7, Entry: []byte(issuanceEntry)},
	}}}
	client, err := New("c2sp-tlog:testnet:http://dnsid-ledger:8080/log#identity-01", WithSource(source), withProofVerifySkipped())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	events, err := client.RebuildHistory(context.Background(), "agent.example")
	if err != nil {
		t.Fatalf("RebuildHistory: %v", err)
	}
	if len(events) != 1 || events[0].Type != dnsidlog.LogEventIssuance {
		t.Fatalf("events = %#v, want one ISSUANCE", events)
	}
}

func TestRebuildHistoryIgnoresInvalidCountersignature(t *testing.T) {
	malformed := canonicalEntryMutation(t, keyRotationEntry, func(payload map[string]any) {
		payload["sigs"].(map[string]any)["new_op"].(map[string]any)["kid"] = "wrong-new-key"
	})
	source := globalMemorySource{memorySource: memorySource{entries: []ProvenEntry{
		{Index: 0, Entry: []byte(issuanceEntry)},
		{Index: 1, Entry: malformed},
	}}}
	client, err := New("c2sp-tlog:testnet:http://dnsid-ledger:8080/log#identity-01", WithSource(source), withProofVerifySkipped())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	events, err := client.RebuildHistory(context.Background(), "agent.example")
	if err != nil || len(events) != 1 {
		t.Fatalf("invalid countersignature must be noise: %v, %v", events, err)
	}
}

func TestRebuildHistoryIgnoresCandidateWithInvalidProof(t *testing.T) {
	proof, verifier := signedSingleEntryProof(t, "dnsid-ledger:8080/log", []byte(issuanceEntry), 0)
	source := globalMemorySource{memorySource: memorySource{entries: []ProvenEntry{
		{Index: 0, Entry: []byte(issuanceEntry), Proof: []byte("invalid proof")},
		{Index: 0, Entry: []byte(issuanceEntry), Proof: proof},
	}}}
	client, err := New(
		"c2sp-tlog:testnet:http://dnsid-ledger:8080/log#identity-01",
		WithSource(source),
		WithPolicy(Policy{LogVerifier: verifier}),
	)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	events, err := client.RebuildHistory(context.Background(), "agent.example")
	if err != nil {
		t.Fatalf("RebuildHistory: %v", err)
	}
	if len(events) != 1 || events[0].Type != dnsidlog.LogEventIssuance {
		t.Fatalf("events = %#v, want one ISSUANCE", events)
	}
}

func TestSelectedHistorySourceFailsInvalidEntry(t *testing.T) {
	source := memorySource{entries: []ProvenEntry{
		{Index: 0, Entry: []byte(issuanceEntry)},
		{Index: 1, Entry: []byte(`{`)},
	}}
	client, err := New("c2sp-tlog:testnet:http://dnsid-ledger:8080/log#identity-01", WithSource(source), withProofVerifySkipped())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, err := client.RebuildHistory(context.Background(), "agent.example"); err == nil {
		t.Fatal("accepted noncanonical entry in selected history")
	}
}

func TestSelectedHistorySourceCategorizesInvalidEvidence(t *testing.T) {
	_, verifier := signedSingleEntryProof(t, "dnsid-ledger:8080/log", []byte(issuanceEntry), 0)
	client, err := New(
		"c2sp-tlog:testnet:http://dnsid-ledger:8080/log#identity-01",
		WithSource(memorySource{entries: []ProvenEntry{{Index: 0, Entry: []byte(issuanceEntry), Proof: []byte("invalid")}}}),
		WithPolicy(Policy{LogVerifier: verifier}),
	)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	_, err = client.RebuildHistory(context.Background(), "agent.example")
	var verificationErr *dnsid.VerificationError
	if !errors.As(err, &verificationErr) || verificationErr.Code() != dnsid.VerificationCodeInvalidEvidence {
		t.Fatalf("RebuildHistory error = %v, want INVALID_EVIDENCE", err)
	}
}

func TestRebuildHistoryClassifiesSourceFailureAsTransient(t *testing.T) {
	client, err := New("c2sp-tlog:testnet:http://dnsid-ledger:8080/log#identity-01", WithSource(failingSource{}), withProofVerifySkipped())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	_, err = client.RebuildHistory(context.Background(), "agent.example")
	var verificationErr *dnsid.VerificationError
	if !errors.As(err, &verificationErr) || verificationErr.Code() != dnsid.VerificationCodeLogError || !verificationErr.Transient() {
		t.Fatalf("error = %T %[1]v, want transient LogError", err)
	}
}

func TestVerifyLifecyclePublicAuthenticatedMissingChainFieldsFails(t *testing.T) {
	issuance := verifiedFromEntry(t, 0, issuanceEntry)
	seq := uint64(0)
	issuance.chain.sequence = &seq
	revocation := verifiedFromEntry(t, 1, revocationEntry)
	_, err := verifyLifecycle([]verifiedEvent{issuance, revocation})
	var verificationErr *dnsid.VerificationError
	if !errors.As(err, &verificationErr) || verificationErr.Code() != dnsid.VerificationCodeChainContinuity {
		t.Fatalf("verifyLifecycle error = %v, want CHAIN_CONTINUITY", err)
	}
}

func TestVerifyLifecyclePublicAuthenticatedWrongStateHashFails(t *testing.T) {
	issuance := verifiedFromEntry(t, 0, issuanceEntry)
	seq0 := uint64(0)
	issuance.chain.sequence = &seq0
	revocation := verifiedFromEntry(t, 1, revocationEntry)
	seq1 := uint64(1)
	revocation.chain.sequence = &seq1
	revocation.chain.previousEventID = EventID(issuance.signed)
	revocation.chain.previousStateHash = "non-empty-but-wrong"
	_, err := verifyLifecycle([]verifiedEvent{issuance, revocation})
	var verificationErr *dnsid.VerificationError
	if !errors.As(err, &verificationErr) || verificationErr.Code() != dnsid.VerificationCodeChainContinuity {
		t.Fatalf("verifyLifecycle error = %v, want CHAIN_CONTINUITY", err)
	}
	revocation.chain.previousStateHash = lifecycleStateHash(activeLifecycleState("agent.example", mustThumbprint(t, aeJWK), mustThumbprint(t, op1JWK)))
	events, err := verifyLifecycle([]verifiedEvent{issuance, revocation})
	if err != nil {
		t.Fatalf("verifyLifecycle valid chain: %v", err)
	}
	if len(events) != 2 {
		t.Fatalf("events = %d, want 2", len(events))
	}
}

func TestVerifyLifecyclePublicAppliedSequenceGapFails(t *testing.T) {
	issuance := verifiedFromEntry(t, 0, issuanceEntry)
	seq0 := uint64(0)
	issuance.chain.sequence = &seq0
	rotation := verifiedFromEntry(t, 2, keyRotationEntry)
	seq2 := uint64(2)
	rotation.chain.sequence = &seq2
	rotation.chain.previousEventID = "missing-event"
	rotation.chain.previousStateHash = lifecycleStateHash(activeLifecycleState("agent.example", mustThumbprint(t, aeJWK), mustThumbprint(t, op1JWK)))
	_, err := verifyLifecycle([]verifiedEvent{issuance, rotation})
	var verificationErr *dnsid.VerificationError
	if !errors.As(err, &verificationErr) || verificationErr.Code() != dnsid.VerificationCodeChainContinuity {
		t.Fatalf("verifyLifecycle error = %v, want CHAIN_CONTINUITY", err)
	}
}

func TestVerifyLifecyclePublicInvalidSignatureBadChainIgnored(t *testing.T) {
	issuance := verifiedFromEntry(t, 0, issuanceEntry)
	seq := uint64(0)
	issuance.chain.sequence = &seq
	attacker := verifiedFromEntry(t, 1, revocationEntry)
	attacker.event.InitialEntitySignature = "bad"
	rotation := verifiedFromEntry(t, 2, keyRotationEntry)
	seq1 := uint64(1)
	rotation.chain.sequence = &seq1
	rotation.chain.previousEventID = EventID(issuance.signed)
	rotation.chain.previousStateHash = lifecycleStateHash(activeLifecycleState("agent.example", mustThumbprint(t, aeJWK), mustThumbprint(t, op1JWK)))
	events, err := verifyLifecycle([]verifiedEvent{issuance, attacker, rotation})
	if err != nil {
		t.Fatalf("verifyLifecycle: %v", err)
	}
	if len(events) != 2 || events[0].Type != dnsidlog.LogEventIssuance || events[1].Type != dnsidlog.LogEventKeyRotation {
		t.Fatalf("events = %#v", events)
	}
}

func TestVerifyLifecycleAuthenticatedAdditionalIssuanceFails(t *testing.T) {
	entity := dnsid.GenerateEd25519KeyProvider()
	first := signedIssuanceCandidate(t, 0, time.Unix(1782172800, 0).UTC(), entity, dnsid.GenerateEd25519KeyProvider())
	second := signedIssuanceCandidate(t, 1, time.Unix(1782259200, 0).UTC(), entity, dnsid.GenerateEd25519KeyProvider())

	_, err := verifyLifecycle([]verifiedEvent{first, second})
	var verificationErr *dnsid.VerificationError
	if !errors.As(err, &verificationErr) || verificationErr.Code() != dnsid.VerificationCodeDuplicateIssuance {
		t.Fatalf("verifyLifecycle error = %v, want DUPLICATE_ISSUANCE", err)
	}
}

func TestVerifyLifecycleExactCompleteEntryDuplicateIsIgnored(t *testing.T) {
	issuance := verifiedFromEntry(t, 0, issuanceEntry)
	duplicate := verifiedFromEntry(t, 1, issuanceEntry)
	rotation := verifiedFromEntry(t, 2, keyRotationEntry)

	events, err := verifyLifecycle([]verifiedEvent{issuance, duplicate, rotation})
	if err != nil {
		t.Fatalf("verifyLifecycle: %v", err)
	}
	if len(events) != 2 || events[0].Type != dnsidlog.LogEventIssuance || events[1].Type != dnsidlog.LogEventKeyRotation {
		t.Fatalf("events = %#v, want one ISSUANCE effect and KEY_ROTATION", events)
	}
}

func TestVerifyLifecycleRejectsOutboundMigration(t *testing.T) {
	issuance := verifiedFromEntry(t, 0, issuanceEntry)
	migration := verifiedFromEntry(t, 1, correctedFixture(legacyRevocationEntry, issuanceEntry, op1JWK, 1))
	migration.event.Type = dnsidlog.LogEventMigration
	migration.event.PreviousLog = "c2sp-tlog:testnet:http://old-ledger:8080/log#agent.example"
	migration.event.NewLog = "c2sp-tlog:testnet:http://new-ledger:8080/log#agent.example"
	migration.event.FinalEntryRef = "c2sp-tlog:testnet:http://old-ledger:8080/log#agent.example@0"
	_, err := verifyLifecycle([]verifiedEvent{issuance, migration})
	var verificationErr *dnsid.VerificationError
	if !errors.As(err, &verificationErr) || verificationErr.Code() != dnsid.VerificationCodeInvalidMigration {
		t.Fatalf("verifyLifecycle error = %v, want INVALID_MIGRATION", err)
	}
}

func TestVerifyLifecycleAuthenticatedPostTerminalEventFails(t *testing.T) {
	issuance := verifiedFromEntry(t, 0, issuanceEntry)
	revocation := verifiedFromEntry(t, 1, correctedFixture(legacyRevocationEntry, issuanceEntry, op1JWK, 1))
	rotation := verifiedFromEntry(t, 2, keyRotationEntry)

	_, err := verifyLifecycle([]verifiedEvent{issuance, revocation, rotation})
	var verificationErr *dnsid.VerificationError
	if !errors.As(err, &verificationErr) || verificationErr.Code() != dnsid.VerificationCodeTerminalState {
		t.Fatalf("verifyLifecycle error = %v, want TERMINAL_STATE", err)
	}
}

func TestVerifyLifecycleExactPostTerminalDuplicateIsIgnored(t *testing.T) {
	issuance := verifiedFromEntry(t, 0, issuanceEntry)
	revocation := verifiedFromEntry(t, 1, correctedFixture(legacyRevocationEntry, issuanceEntry, op1JWK, 1))
	duplicate := revocation
	duplicate.index = 2

	events, err := verifyLifecycle([]verifiedEvent{issuance, revocation, duplicate})
	if err != nil {
		t.Fatalf("verifyLifecycle: %v", err)
	}
	if len(events) != 2 || events[1].Type != dnsidlog.LogEventRevocation {
		t.Fatalf("events = %#v, want one terminal REVOCATION", events)
	}
}

func TestVerifyLifecycleInvalidDuplicateDoesNotShadowValidEntry(t *testing.T) {
	invalid := verifiedFromEntry(t, 0, issuanceEntry)
	invalid.event.InitialEntitySignature = "bad"
	valid := verifiedFromEntry(t, 1, issuanceEntry)
	events, err := verifyLifecycle([]verifiedEvent{invalid, valid})
	if err != nil {
		t.Fatalf("verifyLifecycle: %v", err)
	}
	if len(events) != 1 || events[0].Type != dnsidlog.LogEventIssuance {
		t.Fatalf("events = %#v", events)
	}
}

func TestVerifyLifecycleRejectsMigrationInWithoutPriorHistoryVerification(t *testing.T) {
	migration := verifiedFromEntry(t, 0, issuanceEntry)
	migration.event.Type = dnsidlog.LogEventMigration
	migration.event.PreviousLog = "c2sp-tlog:testnet:http://old-ledger:8080/log#agent.example"
	migration.event.NewLog = "c2sp-tlog:testnet:http://new-ledger:8080/log#agent.example"
	migration.event.FinalEntryRef = "c2sp-tlog:testnet:http://old-ledger:8080/log#agent.example@7"
	_, err := verifyLifecycle([]verifiedEvent{migration})
	var verificationErr *dnsid.VerificationError
	if !errors.As(err, &verificationErr) || verificationErr.Code() != dnsid.VerificationCodeInvalidMigration {
		t.Fatalf("verifyLifecycle error = %v, want INVALID_MIGRATION", err)
	}
}

func TestVerifyLifecycleRejectsMigrationInWithoutPriorLogRef(t *testing.T) {
	migration := verifiedFromEntry(t, 0, issuanceEntry)
	migration.event.Type = dnsidlog.LogEventMigration
	_, err := verifyLifecycle([]verifiedEvent{migration})
	var verificationErr *dnsid.VerificationError
	if !errors.As(err, &verificationErr) || verificationErr.Code() != dnsid.VerificationCodeInvalidMigration {
		t.Fatalf("verifyLifecycle error = %v, want INVALID_MIGRATION", err)
	}
}

func TestVerifyLifecycleStitchesVerifiedInboundMigration(t *testing.T) {
	priorIssuance := verifiedFromEntry(t, 0, issuanceEntry).event
	migration := verifiedFromEntry(t, 0, issuanceEntry)
	migration.event.Type = dnsidlog.LogEventMigration
	migration.event.PreviousLog = "c2sp-tlog:testnet:http://old-ledger:8080/log#agent.example"
	migration.event.NewLog = "c2sp-tlog:testnet:http://new-ledger:8080/log#agent.example"
	migration.event.FinalEntryRef = "c2sp-tlog:testnet:http://old-ledger:8080/log#agent.example@7"
	rotation := verifiedFromEntry(t, 1, keyRotationEntry)

	accepted, prior, err := verifyLifecycleVerifiedWithMigration(
		context.Background(),
		[]verifiedEvent{migration, rotation},
		func(context.Context, dnsidlog.LogEvent) (MigrationVerificationResult, error) {
			return MigrationVerificationResult{
				EntityKey:            priorIssuance.InitialEntityPublicKey,
				ActiveOperationalKey: priorIssuance.InitialOperationalPublicKey,
				PriorHistory:         []dnsidlog.LogEvent{priorIssuance},
			}, nil
		},
		migration.event.NewLog,
	)
	if err != nil {
		t.Fatalf("verifyLifecycleVerifiedWithMigration: %v", err)
	}
	if len(prior) != 1 || prior[0].Type != dnsidlog.LogEventIssuance {
		t.Fatalf("prior history = %#v, want one ISSUANCE", prior)
	}
	if len(accepted) != 2 || accepted[0].event.Type != dnsidlog.LogEventMigration || accepted[1].event.Type != dnsidlog.LogEventKeyRotation {
		t.Fatalf("accepted events = %#v, want MIGRATION and KEY_ROTATION", accepted)
	}
}

func TestVerifyLifecycleRejectsMigrationFromTerminalHistory(t *testing.T) {
	priorIssuance := verifiedFromEntry(t, 0, issuanceEntry).event
	priorRevocation := verifiedFromEntry(t, 1, revocationEntry).event
	migration := dnsidlog.LogEvent{
		Type:          dnsidlog.LogEventMigration,
		Domain:        "agent.example",
		PreviousLog:   "c2sp-tlog:testnet:http://old-ledger:8080/log#old-stream",
		NewLog:        "c2sp-tlog:testnet:http://new-ledger:8080/log#new-stream",
		FinalEntryRef: "c2sp-tlog:testnet:http://old-ledger:8080/log#old-stream@1",
	}
	err := validateMigrationResult(migration, MigrationVerificationResult{
		EntityKey:            priorIssuance.InitialEntityPublicKey,
		ActiveOperationalKey: priorIssuance.InitialOperationalPublicKey,
		PriorHistory:         []dnsidlog.LogEvent{priorIssuance, priorRevocation},
	})
	var verificationErr *dnsid.VerificationError
	if !errors.As(err, &verificationErr) || verificationErr.Code() != dnsid.VerificationCodeInvalidMigration {
		t.Fatalf("validateMigrationResult error = %v, want INVALID_MIGRATION", err)
	}
}

func TestMigrationVerificationResourceLimits(t *testing.T) {
	const (
		oldLR = "c2sp-tlog:testnet:http://old-ledger:8080/log#agent.example"
		newLR = "c2sp-tlog:testnet:http://new-ledger:8080/log#agent.example"
	)
	event := dnsidlog.LogEvent{Type: dnsidlog.LogEventMigration, PreviousLog: oldLR, NewLog: newLR}

	t.Run("history and response", func(t *testing.T) {
		client, err := New(newLR,
			WithMigrationVerifier(func(context.Context, dnsidlog.LogEvent) (MigrationVerificationResult, error) {
				return MigrationVerificationResult{PriorHistory: []dnsidlog.LogEvent{{}, {}}}, nil
			}),
			WithMigrationVerificationLimits(MigrationVerificationLimits{MaxHistoryEvents: 1}),
		)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := client.verifyBoundedMigration(context.Background(), event); err == nil || !strings.Contains(err.Error(), "history exceeds") {
			t.Fatalf("history limit error = %v", err)
		}

		client, err = New(newLR,
			WithMigrationVerifier(func(context.Context, dnsidlog.LogEvent) (MigrationVerificationResult, error) {
				return MigrationVerificationResult{PriorHistory: []dnsidlog.LogEvent{{Domain: strings.Repeat("x", 128)}}}, nil
			}),
			WithMigrationVerificationLimits(MigrationVerificationLimits{MaxResponseBytes: 64}),
		)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := client.verifyBoundedMigration(context.Background(), event); err == nil || !strings.Contains(err.Error(), "byte maximum") {
			t.Fatalf("response limit error = %v", err)
		}
	})

	t.Run("depth and cycle", func(t *testing.T) {
		limits := MigrationVerificationLimits{MaxDepth: 2}
		ctx, _, err := enterMigration(context.Background(), event, newLR, limits)
		if err != nil {
			t.Fatal(err)
		}
		prior := dnsidlog.LogEvent{Type: dnsidlog.LogEventMigration, PreviousLog: "c2sp-tlog:testnet:http://first-ledger:8080/log#agent.example", NewLog: oldLR}
		ctx, _, err = enterMigration(ctx, prior, oldLR, limits)
		if err != nil {
			t.Fatal(err)
		}
		if _, _, err := enterMigration(ctx, dnsidlog.LogEvent{PreviousLog: newLR}, prior.PreviousLog, limits); err == nil || !strings.Contains(err.Error(), "recursion") {
			t.Fatalf("depth limit error = %v", err)
		}

		cyclic := MigrationVerificationResult{PriorHistory: []dnsidlog.LogEvent{
			{Type: dnsidlog.LogEventMigration, PreviousLog: "a", NewLog: "b"},
			{Type: dnsidlog.LogEventMigration, PreviousLog: "b", NewLog: "a"},
		}}
		if err := validateMigrationResources(dnsidlog.LogEvent{PreviousLog: "a", NewLog: "c"}, cyclic, MigrationVerificationLimits{}); err == nil || !strings.Contains(err.Error(), "cycle") {
			t.Fatalf("cycle error = %v", err)
		}
	})

	if _, err := New(newLR, WithMigrationVerificationLimits(MigrationVerificationLimits{MaxDepth: -1})); err == nil {
		t.Fatal("New accepted a negative migration limit")
	}
}

func TestClientRebuildHistoryStitchesInboundMigrationAndClassifiesResolverFailure(t *testing.T) {
	const (
		oldLR = "c2sp-tlog:testnet:http://old-ledger:8080/log#old-instance"
		newLR = "c2sp-tlog:testnet:http://new-ledger:8080/log#new-instance"
	)
	entity := dnsid.GenerateEd25519KeyProvider()
	operational := dnsid.GenerateEd25519KeyProvider()
	rotated := dnsid.GenerateEd25519KeyProvider()
	operationalThumb, err := thumbprint(operational.JWK())
	if err != nil {
		t.Fatalf("operational thumbprint: %v", err)
	}
	rotatedThumb, err := thumbprint(rotated.JWK())
	if err != nil {
		t.Fatalf("rotated thumbprint: %v", err)
	}
	entityThumb, err := thumbprint(entity.JWK())
	if err != nil {
		t.Fatalf("entity thumbprint: %v", err)
	}
	priorIssuance := dnsidlog.LogEvent{
		Type: dnsidlog.LogEventIssuance, Domain: "agent.example", GovernanceID: "example.com",
		Timestamp: time.Unix(1782172800, 0).UTC(), InitialEntityPublicKey: entity.JWK(), InitialEntityThumbprint: entityThumb,
		InitialOperationalPublicKey: operational.JWK(), InitialOperationalThumbprint: operationalThumb,
	}
	unsignedMigration := dnsidlog.LogEvent{
		Type: dnsidlog.LogEventMigration, Domain: "agent.example", Timestamp: time.Unix(1782259200, 0).UTC(),
		PreviousLog: oldLR, NewLog: newLR, FinalEntryRef: oldLR + "@7",
	}
	unsignedRotation := dnsidlog.LogEvent{
		Type: dnsidlog.LogEventKeyRotation, Domain: "agent.example", Timestamp: time.Unix(1782345600, 0).UTC(),
		PreviousOperationalThumbprint: operationalThumb, NewOperationalPublicKey: rotated.JWK(), NewOperationalThumbprint: rotatedThumb,
	}
	writer, err := New(newLR)
	if err != nil {
		t.Fatal(err)
	}
	chain := Chain{}
	sign := func(event dnsidlog.LogEvent, role SignerRole, key dnsid.KeyProvider) dnsidlog.LogEvent {
		t.Helper()
		canonical, err := writer.CanonicalWithChain(event, chain)
		if err != nil {
			t.Fatalf("Canonical(%s): %v", event.Type, err)
		}
		signed, err := key.Sign(canonical)
		if err != nil {
			t.Fatalf("Sign(%s, %s): %v", event.Type, role, err)
		}
		encoded := base64.RawURLEncoding.EncodeToString(signed.Signature)
		switch role {
		case SignerEntity:
			event.InitialEntityKid, event.InitialEntitySignature = signed.Kid, encoded
		case SignerPreviousOperational:
			event.PreviousOperationalKid, event.PreviousOperationalSignature = signed.Kid, encoded
		case SignerNewOperational:
			event.NewOperationalKid, event.NewOperationalSignature = signed.Kid, encoded
		}
		return event
	}
	entryBytes := func(event dnsidlog.LogEvent) []byte {
		t.Helper()
		entry, err := writer.EntryBytesWithChain(event, chain)
		if err != nil {
			t.Fatalf("EntryBytes(%s): %v", event.Type, err)
		}
		return entry
	}
	migrationEntry := entryBytes(sign(unsignedMigration, SignerEntity, entity))
	migrationSigned, err := CanonicalFromEntry(migrationEntry)
	if err != nil {
		t.Fatal(err)
	}
	chain = Chain{Sequence: 1, PreviousEventID: EventID(migrationSigned), PreviousStateHash: lifecycleStateHash(activeLifecycleState("agent.example", entityThumb, operationalThumb))}
	rotation := sign(unsignedRotation, SignerPreviousOperational, operational)
	rotation = sign(rotation, SignerNewOperational, rotated)
	rotationEntry := entryBytes(rotation)
	now := time.Unix(1782345601, 0).UTC()
	source := memorySource{entries: []ProvenEntry{{Index: 0, Entry: migrationEntry}, {Index: 1, Entry: rotationEntry}}, complete: true, freshness: now}
	priorEvidence := dnsidlog.LoggedStateEvidence{
		LogReference: oldLR, LoggedState: dnsidlog.AgentStateActive,
		HistoryStart: dnsidlog.LogRef(unsignedMigration.FinalEntryRef), HistoryEnd: dnsidlog.LogRef(unsignedMigration.FinalEntryRef),
		CompleteThrough: "8", CompletenessMode: "test-complete", Checkpoint: []byte("old-checkpoint"), FreshnessTime: now.Add(-time.Minute),
	}
	verifier := func(context.Context, dnsidlog.LogEvent) (MigrationVerificationResult, error) {
		return MigrationVerificationResult{
			EntityKey: entity.JWK(), ActiveOperationalKey: operational.JWK(),
			PriorHistory: []dnsidlog.LogEvent{priorIssuance}, PriorEvidence: &priorEvidence,
			PriorHistoryReferences: []dnsidlog.LogRef{dnsidlog.LogRef(unsignedMigration.FinalEntryRef)},
		}, nil
	}
	reader, err := New(newLR, WithSource(source), WithMigrationVerifier(verifier), WithPolicy(Policy{MaxCheckpointAge: time.Hour, Now: func() time.Time { return now }}), withProofVerifySkipped())
	if err != nil {
		t.Fatalf("New reader: %v", err)
	}
	history, err := reader.RebuildHistory(context.Background(), "agent.example")
	if err != nil {
		t.Fatalf("RebuildHistory: %v", err)
	}
	if len(history) != 3 || history[0].Type != dnsidlog.LogEventIssuance || history[1].Type != dnsidlog.LogEventMigration || history[2].Type != dnsidlog.LogEventKeyRotation {
		t.Fatalf("history = %#v, want stitched ISSUANCE, MIGRATION, KEY_ROTATION", history)
	}
	binding, err := reader.VerifyLifecycleBinding(context.Background(), dnsidlog.BilateralBindingInput{
		Domain: "agent.example", GovernanceID: "example.com", EntityKey: entity.JWK(), OperationalKey: rotated.JWK(),
	}, rotatedThumb)
	if err != nil {
		t.Fatalf("VerifyLifecycleBinding after migration: %v", err)
	}
	if binding.InitialOperationalThumbprint != operationalThumb || !binding.Timestamp.Equal(priorIssuance.Timestamp) {
		t.Fatalf("binding = %#v, want prior ISSUANCE anchor", binding)
	}

	evidence, err := reader.VerifyNonRevocation(context.Background(), "agent.example", now)
	if err != nil {
		t.Fatalf("VerifyNonRevocation after migration: %v", err)
	}
	if evidence.LogReference != newLR || evidence.HistoryStart != dnsidlog.LogRef(unsignedMigration.FinalEntryRef) || evidence.HistoryEnd != newLR+"@1" || evidence.LoggedState != dnsidlog.AgentStateActive || len(evidence.PriorEvidence) != 1 || evidence.PriorEvidence[0].HistoryEnd != dnsidlog.LogRef(unsignedMigration.FinalEntryRef) {
		t.Fatalf("VerifyNonRevocation evidence = %#v", evidence)
	}
	beforeMigration, err := reader.VerifyNonRevocation(context.Background(), "agent.example", priorIssuance.Timestamp)
	if err != nil {
		t.Fatalf("VerifyNonRevocation before migration: %v", err)
	}
	if beforeMigration.HistoryEnd != dnsidlog.LogRef(unsignedMigration.FinalEntryRef) || beforeMigration.LoggedState != dnsidlog.AgentStateActive || len(beforeMigration.PriorEvidence) != 1 {
		t.Fatalf("before-migration evidence = %#v", beforeMigration)
	}

	ref, err := ParseReference(newLR)
	if err != nil {
		t.Fatal(err)
	}
	bundleSource := &StreamBundleSource{
		reference: ref, domain: "agent.example", entries: source.entries,
		checkpoint: []byte("bundle-checkpoint"), completeThrough: 2,
		completenessMode: StreamBundleTrustedIndex, checkpointFreshness: now,
	}
	bundleReader, err := New(newLR, WithSource(bundleSource), WithMigrationVerifier(verifier), WithPolicy(Policy{MaxCheckpointAge: time.Hour, Now: func() time.Time { return now }}), withProofVerifySkipped())
	if err != nil {
		t.Fatal(err)
	}
	if bundled, err := bundleReader.VerifyNonRevocation(context.Background(), "agent.example", now); err != nil || len(bundled.PriorEvidence) != 1 {
		t.Fatalf("bundled VerifyNonRevocation = %#v, %v", bundled, err)
	}

	oldestLR := "c2sp-tlog:testnet:http://oldest-ledger:8080/log#agent.example"
	nestedMigration := dnsidlog.LogEvent{
		Type: dnsidlog.LogEventMigration, Domain: "agent.example", Timestamp: priorIssuance.Timestamp.Add(time.Hour),
		PreviousLog: oldestLR, NewLog: oldLR, FinalEntryRef: oldestLR + "@3",
	}
	oldestEvidence := dnsidlog.LoggedStateEvidence{
		LogReference: dnsidlog.LogRef(oldestLR), LoggedState: dnsidlog.AgentStateActive,
		HistoryStart: dnsidlog.LogRef(nestedMigration.FinalEntryRef), HistoryEnd: dnsidlog.LogRef(nestedMigration.FinalEntryRef),
		CompleteThrough: "4", CompletenessMode: "test-complete", Checkpoint: []byte("oldest-checkpoint"), FreshnessTime: now.Add(-2 * time.Minute),
	}
	nestedPriorEvidence := priorEvidence
	nestedPriorEvidence.PriorEvidence = []dnsidlog.LoggedStateEvidence{oldestEvidence}
	nestedVerifier := func(context.Context, dnsidlog.LogEvent) (MigrationVerificationResult, error) {
		return MigrationVerificationResult{
			EntityKey: entity.JWK(), ActiveOperationalKey: operational.JWK(),
			PriorHistory: []dnsidlog.LogEvent{priorIssuance, nestedMigration}, PriorEvidence: &nestedPriorEvidence,
			PriorHistoryReferences: []dnsidlog.LogRef{dnsidlog.LogRef(nestedMigration.FinalEntryRef), dnsidlog.LogRef(unsignedMigration.FinalEntryRef)},
		}, nil
	}
	nestedReader, err := New(newLR, WithSource(source), WithMigrationVerifier(nestedVerifier), WithPolicy(Policy{MaxCheckpointAge: time.Hour, Now: func() time.Time { return now }}), withProofVerifySkipped())
	if err != nil {
		t.Fatal(err)
	}
	if nested, err := nestedReader.VerifyNonRevocation(context.Background(), "agent.example", now); err != nil || len(nested.PriorEvidence) != 2 || nested.PriorEvidence[0].LogReference != dnsidlog.LogRef(oldestLR) || nested.PriorEvidence[1].LogReference != dnsidlog.LogRef(oldLR) {
		t.Fatalf("nested VerifyNonRevocation = %#v, %v", nested, err)
	}

	for _, test := range []struct {
		name     string
		evidence *dnsidlog.LoggedStateEvidence
	}{
		{name: "missing"},
		{name: "cutoff mismatch", evidence: func() *dnsidlog.LoggedStateEvidence {
			copy := priorEvidence
			copy.HistoryEnd = dnsidlog.LogRef(oldLR + "@8")
			return &copy
		}()},
		{name: "terminal", evidence: func() *dnsidlog.LoggedStateEvidence {
			copy := priorEvidence
			copy.LoggedState = dnsidlog.AgentStateRetired
			return &copy
		}()},
	} {
		t.Run("prior evidence "+test.name, func(t *testing.T) {
			invalidVerifier := func(context.Context, dnsidlog.LogEvent) (MigrationVerificationResult, error) {
				return MigrationVerificationResult{
					EntityKey: entity.JWK(), ActiveOperationalKey: operational.JWK(),
					PriorHistory: []dnsidlog.LogEvent{priorIssuance}, PriorEvidence: test.evidence,
					PriorHistoryReferences: []dnsidlog.LogRef{dnsidlog.LogRef(unsignedMigration.FinalEntryRef)},
				}, nil
			}
			invalidReader, err := New(newLR, WithSource(source), WithMigrationVerifier(invalidVerifier), WithPolicy(Policy{MaxCheckpointAge: time.Hour, Now: func() time.Time { return now }}), withProofVerifySkipped())
			if err != nil {
				t.Fatal(err)
			}
			_, err = invalidReader.VerifyNonRevocation(context.Background(), "agent.example", now)
			var verificationErr *dnsid.VerificationError
			if !errors.As(err, &verificationErr) || verificationErr.Code() != dnsid.VerificationCodeInvalidEvidence {
				t.Fatalf("VerifyNonRevocation error = %v, want INVALID_EVIDENCE", err)
			}
		})
	}

	t.Run("prior history after cutoff", func(t *testing.T) {
		later := dnsidlog.LogEvent{Type: dnsidlog.LogEventDelegation, Domain: "agent.example", Timestamp: unsignedMigration.Timestamp.Add(-time.Minute)}
		pastCutoff := func(context.Context, dnsidlog.LogEvent) (MigrationVerificationResult, error) {
			return MigrationVerificationResult{
				EntityKey: entity.JWK(), ActiveOperationalKey: operational.JWK(),
				PriorHistory: []dnsidlog.LogEvent{priorIssuance, later}, PriorEvidence: &priorEvidence,
				PriorHistoryReferences: []dnsidlog.LogRef{dnsidlog.LogRef(unsignedMigration.FinalEntryRef), dnsidlog.LogRef(oldLR + "@8")},
			}, nil
		}
		invalidReader, err := New(newLR, WithSource(source), WithMigrationVerifier(pastCutoff), WithPolicy(Policy{MaxCheckpointAge: time.Hour, Now: func() time.Time { return now }}), withProofVerifySkipped())
		if err != nil {
			t.Fatal(err)
		}
		_, err = invalidReader.VerifyNonRevocation(context.Background(), "agent.example", now)
		var verificationErr *dnsid.VerificationError
		if !errors.As(err, &verificationErr) || verificationErr.Code() != dnsid.VerificationCodeInvalidEvidence {
			t.Fatalf("VerifyNonRevocation error = %v, want INVALID_EVIDENCE", err)
		}
	})

	reader, err = New(newLR, WithSource(source), withProofVerifySkipped(), WithMigrationVerifier(func(context.Context, dnsidlog.LogEvent) (MigrationVerificationResult, error) {
		return MigrationVerificationResult{}, errors.New("prior log unavailable")
	}))
	if err != nil {
		t.Fatalf("New failing reader: %v", err)
	}
	_, err = reader.RebuildHistory(context.Background(), "agent.example")
	var verificationErr *dnsid.VerificationError
	if !errors.As(err, &verificationErr) || verificationErr.Code() != dnsid.VerificationCodeInvalidMigration {
		t.Fatalf("RebuildHistory error = %v, want INVALID_MIGRATION", err)
	}
}

func TestRegisterPublicClientExposesOnlyDerivableGenericWrites(t *testing.T) {
	registry := dnsidlog.NewLogRegistry()
	if err := Register(registry, withProofVerifySkipped()); err != nil {
		t.Fatalf("Register: %v", err)
	}
	reader, err := registry.NewReader("c2sp-tlog:public:https://tlog.example.com/dnsid#agent.example")
	if err != nil {
		t.Fatalf("NewReader: %v", err)
	}
	log, ok := reader.(dnsidlog.Log)
	if !ok {
		t.Fatal("public c2sp-tlog reader does not expose derivable ISSUANCE writes")
	}
	if _, err := log.Canonical(dnsidlog.LogEvent{Type: dnsidlog.LogEventRevocation, Domain: "agent.example", Timestamp: time.Unix(1782345600, 0).UTC(), Reason: "keyCompromise"}); err == nil || !strings.Contains(err.Error(), "chain") {
		t.Fatalf("Canonical later public event error = %v, want prepared-chain requirement", err)
	}
}

func TestPublicWriteRequiresChainFields(t *testing.T) {
	appender := &memoryAppender{}
	client, err := New("c2sp-tlog:public:https://tlog.example.com/dnsid#identity-01", WithAppender(appender), withProofVerifySkipped())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, err := client.WriteEvent(context.Background(), dnsidlog.LogEvent{Type: dnsidlog.LogEventRevocation, Domain: "agent.example", Timestamp: time.Unix(1782345600, 0).UTC(), InitialEntityKid: "ae", InitialEntitySignature: "sig"}); err == nil || !strings.Contains(err.Error(), "chain") {
		t.Fatalf("WriteEvent error = %v, want chain requirement", err)
	}
	if _, err := client.Canonical(dnsidlog.LogEvent{Type: dnsidlog.LogEventRevocation, Domain: "agent.example", Timestamp: time.Unix(1782345600, 0).UTC(), InitialEntityKid: "ae", InitialEntitySignature: "sig"}); err == nil || !strings.Contains(err.Error(), "chain") {
		t.Fatalf("Canonical error = %v, want chain requirement before signing", err)
	}
	issuance, err := LogEventFromEntry([]byte(issuanceEntry))
	if err != nil {
		t.Fatalf("LogEventFromEntry: %v", err)
	}
	if _, err := client.WriteEvent(context.Background(), issuance); err == nil || !strings.Contains(err.Error(), "signature") {
		t.Fatalf("WriteEvent public issuance error = %v, want signature rejection after context changes", err)
	}
	hash := base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	chain := Chain{Sequence: 1, PreviousEventID: hash, PreviousStateHash: hash}
	revocation := dnsidlog.LogEvent{Type: dnsidlog.LogEventRevocation, Domain: "agent.example", Timestamp: time.Unix(1782345600, 0).UTC(), InitialEntityKid: "ae", InitialEntitySignature: "sig", Reason: "keyCompromise"}
	if _, err := client.WriteEventWithChain(context.Background(), revocation, chain); err == nil {
		t.Fatal("WriteEventWithChain accepted an unverified signature")
	}
	entry, err := client.EntryBytesWithChain(revocation, chain)
	if err != nil {
		t.Fatalf("EntryBytesWithChain: %v", err)
	}
	if got := string(entry); !strings.Contains(got, `"seq":1`) || !strings.Contains(got, `"prev_event_id":"`+hash+`"`) {
		t.Fatalf("EntryBytesWithChain entry missing chain fields: %s", got)
	}
}

func TestPublicMigrationChainShapeDistinguishesInboundGenesis(t *testing.T) {
	lr := "c2sp-tlog:public:https://tlog.example.com/dnsid#identity-01"
	client, err := New(lr)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	inbound := dnsidlog.LogEvent{
		Type:          dnsidlog.LogEventMigration,
		Domain:        "agent.example",
		Timestamp:     time.Unix(1782172800, 0).UTC(),
		PreviousLog:   "other:history",
		NewLog:        lr,
		FinalEntryRef: "other:history@3",
	}
	prepared, err := client.PrepareEvent(inbound)
	if err != nil {
		t.Fatalf("PrepareEvent inbound: %v", err)
	}
	if got := string(prepared.SignedBytes()); !strings.Contains(got, `"seq":0`) || strings.Contains(got, `"prev_index"`) {
		t.Fatalf("inbound migration signed bytes = %s, want seq=0 without previous fields", got)
	}

	outbound := inbound
	outbound.PreviousLog = lr
	outbound.NewLog = "other:new"
	outbound.FinalEntryRef = lr + "@3"
	if _, err := client.PrepareEvent(outbound); err == nil || !strings.Contains(err.Error(), "chain") {
		t.Fatalf("PrepareEvent outbound error = %v, want previous-chain requirement", err)
	}
	_, err = client.PrepareEventWithChain(outbound, Chain{
		Sequence:          4,
		PreviousEventID:   base64.RawURLEncoding.EncodeToString(make([]byte, 32)),
		PreviousStateHash: base64.RawURLEncoding.EncodeToString(make([]byte, 32)),
	})
	var verificationErr *dnsid.VerificationError
	if !errors.As(err, &verificationErr) || verificationErr.Code() != dnsid.VerificationCodeInvalidMigration {
		t.Fatalf("PrepareEventWithChain outbound error = %v, want INVALID_MIGRATION", err)
	}
}

func TestChainForWriteDerivesVerifiedPublicState(t *testing.T) {
	source := &memorySource{}
	client, err := New(
		"c2sp-tlog:public:https://tlog.example.com/dnsid#identity-01",
		WithSource(source),
		withProofVerifySkipped(),
	)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	entity := dnsid.GenerateEd25519KeyProvider()
	operational := dnsid.GenerateEd25519KeyProvider()
	issuance := dnsidlog.LogEvent{
		Type:                        dnsidlog.LogEventIssuance,
		Domain:                      "agent.example",
		GovernanceID:                "example.com",
		Timestamp:                   time.Unix(1782172800, 0).UTC(),
		InitialEntityPublicKey:      entity.JWK(),
		InitialOperationalPublicKey: operational.JWK(),
	}
	prepared, err := client.PrepareEvent(issuance)
	if err != nil {
		t.Fatalf("PrepareEvent: %v", err)
	}
	prepared, err = client.SignPreparedEvent(context.Background(), prepared, SignerEntity, entity)
	if err != nil {
		t.Fatalf("SignPreparedEvent entity: %v", err)
	}
	prepared, err = client.SignPreparedEvent(context.Background(), prepared, SignerOperationalCountersignature, operational)
	if err != nil {
		t.Fatalf("SignPreparedEvent operational: %v", err)
	}
	entry, err := client.PreparedEntryBytes(context.Background(), prepared)
	if err != nil {
		t.Fatalf("PreparedEntryBytes: %v", err)
	}
	source.entries = []ProvenEntry{{Index: 7, Entry: entry}}

	revocation := dnsidlog.LogEvent{
		Type:      dnsidlog.LogEventRevocation,
		Domain:    "agent.example",
		Timestamp: time.Unix(1782345600, 0).UTC(),
		Reason:    "keyCompromise",
	}
	chain, err := client.ChainForWrite(context.Background(), revocation)
	if err != nil {
		t.Fatalf("ChainForWrite: %v", err)
	}
	leaf := LeafHash(entry)
	wantLeaf := base64.RawURLEncoding.EncodeToString(leaf[:])
	entityThumb, err := thumbprint(entity.JWK())
	if err != nil {
		t.Fatalf("entity thumbprint: %v", err)
	}
	operationalThumb, err := thumbprint(operational.JWK())
	if err != nil {
		t.Fatalf("operational thumbprint: %v", err)
	}
	wantState := lifecycleStateHash(activeLifecycleState("agent.example", entityThumb, operationalThumb))
	signed, err := CanonicalFromEntry(entry)
	if err != nil {
		t.Fatal(err)
	}
	if chain.Sequence != 1 || chain.PreviousEventID != EventID(signed) || chain.PreviousStateHash != wantState {
		t.Fatalf("ChainForWrite = %#v, want seq=1 index=7 leaf=%q state=%q", chain, wantLeaf, wantState)
	}
	if _, err := client.PrepareEventWithChain(revocation, chain); err != nil {
		t.Fatalf("PrepareEventWithChain derived chain: %v", err)
	}
}

func TestPrepareAndAppendExactPublicEntry(t *testing.T) {
	appender := &memoryAppender{}
	client, err := New("c2sp-tlog:public:https://tlog.example.com/dnsid#identity-01", WithAppender(appender))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	entity := dnsid.GenerateEd25519KeyProvider()
	operational := dnsid.GenerateEd25519KeyProvider()
	event := dnsidlog.LogEvent{Type: dnsidlog.LogEventIssuance, Domain: "agent.example", GovernanceID: "example.com", Timestamp: time.Unix(1782172800, 0).UTC(), InitialEntityPublicKey: entity.JWK(), InitialOperationalPublicKey: operational.JWK()}
	prepared, err := client.PrepareEvent(event)
	if err != nil {
		t.Fatalf("PrepareEvent: %v", err)
	}
	prepared, err = client.SignPreparedEvent(context.Background(), prepared, SignerEntity, entity)
	if err != nil {
		t.Fatalf("SignPreparedEvent entity: %v", err)
	}
	partial, err := prepared.Bytes()
	if err != nil {
		t.Fatalf("prepared Bytes: %v", err)
	}
	prepared, err = client.ParsePreparedEvent(partial)
	if err != nil {
		t.Fatalf("ParsePreparedEvent: %v", err)
	}
	prepared, err = client.SignPreparedEvent(context.Background(), prepared, SignerOperationalCountersignature, operational)
	if err != nil {
		t.Fatalf("SignPreparedEvent operational: %v", err)
	}
	entry, err := client.PreparedEntryBytes(context.Background(), prepared)
	if err != nil {
		t.Fatalf("PreparedEntryBytes: %v", err)
	}
	if len(appender.entries) != 0 {
		t.Fatal("EntryBytes appended the entry")
	}
	for _, field := range []string{`"method":"c2sp-tlog"`, `"stream_id":"identity-01"`, `"seq":0`} {
		if !strings.Contains(string(entry), field) {
			t.Fatalf("prepared entry missing %s: %s", field, entry)
		}
	}
	ref, err := client.WritePreparedEvent(context.Background(), prepared)
	if err != nil {
		t.Fatalf("AppendPreparedEntry: %v", err)
	}
	if ref != "c2sp-tlog:public:https://tlog.example.com/dnsid#identity-01@0" {
		t.Fatalf("ref = %q", ref)
	}
	if len(appender.entries) != 1 || !bytes.Equal(appender.entries[0], entry) {
		t.Fatal("AppendPreparedEntry did not preserve exact entry bytes")
	}
}

func TestIdentityManagerGeneratesPublicIssuanceThroughPreparedValidation(t *testing.T) {
	appender := &memoryAppender{}
	registry := dnsidlog.NewLogRegistry()
	if err := Register(registry, WithAppender(appender)); err != nil {
		t.Fatalf("Register: %v", err)
	}
	entity := dnsid.GenerateEd25519KeyProvider()
	operational := dnsid.GenerateEd25519KeyProvider()
	manager, err := dnsid.NewIdentityManager(dnsid.Config{Identity: &dnsid.IdentityConfig{
		Domain:       "agent.example",
		GovernanceID: "example.com",
		LogRef:       "c2sp-tlog:public:https://tlog.example.com/dnsid#identity-01",
		StatusURL:    "https://agent.example/status.json",
	}}, operational, dnsid.WithEntityKeyProvider(entity), dnsid.WithLogRegistry(registry))
	if err != nil {
		t.Fatalf("NewIdentityManager: %v", err)
	}
	ref, err := manager.GenerateIssuanceEvent(context.Background())
	if err != nil {
		t.Fatalf("GenerateIssuanceEvent: %v", err)
	}
	if ref != "c2sp-tlog:public:https://tlog.example.com/dnsid#identity-01@0" {
		t.Fatalf("ref = %q", ref)
	}
	if len(appender.entries) != 1 {
		t.Fatalf("appended entries = %d, want 1", len(appender.entries))
	}
	entry := string(appender.entries[0])
	for _, field := range []string{`"method":"c2sp-tlog"`, `"seq":0`, `"ae":`, `"op":`} {
		if !strings.Contains(entry, field) {
			t.Fatalf("generated ISSUANCE missing %s: %s", field, entry)
		}
	}
}

func TestPrepareEventNormalizesTimestampToWholeSeconds(t *testing.T) {
	client, err := New("c2sp-tlog:public:https://tlog.example.com/dnsid#identity-01")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	entity := dnsid.GenerateEd25519KeyProvider()
	operational := dnsid.GenerateEd25519KeyProvider()
	event := dnsidlog.LogEvent{
		Type:                        dnsidlog.LogEventIssuance,
		Domain:                      "agent.example",
		GovernanceID:                "example.com",
		Timestamp:                   time.Unix(1782172800, 123456789).UTC(),
		InitialEntityPublicKey:      entity.JWK(),
		InitialOperationalPublicKey: operational.JWK(),
	}
	prepared, err := client.PrepareEvent(event)
	if err != nil {
		t.Fatalf("PrepareEvent: %v", err)
	}
	got, err := prepared.Event()
	if err != nil {
		t.Fatalf("Event: %v", err)
	}
	want := time.Unix(1782172800, 0).UTC()
	if !got.Timestamp.Equal(want) {
		t.Fatalf("Timestamp = %s, want %s", got.Timestamp, want)
	}
}

func TestPreparedEventPreservesUnknownSignedFieldsAndRejectsTamperedPriorSignature(t *testing.T) {
	client, err := New("c2sp-tlog:public:https://tlog.example.com/dnsid#identity-01")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	entity := dnsid.GenerateEd25519KeyProvider()
	operational := dnsid.GenerateEd25519KeyProvider()
	event := dnsidlog.LogEvent{Type: dnsidlog.LogEventIssuance, Domain: "agent.example", GovernanceID: "example.com", Timestamp: time.Unix(1782172800, 0).UTC(), InitialEntityPublicKey: entity.JWK(), InitialOperationalPublicKey: operational.JWK()}
	prepared, err := client.PrepareEvent(event)
	if err != nil {
		t.Fatalf("PrepareEvent: %v", err)
	}
	prepared.envelope["extension.example"] = map[string]any{"covered": true}
	prepared, err = client.preparedFromEnvelope(prepared.envelope)
	if err != nil {
		t.Fatalf("preparedFromEnvelope: %v", err)
	}
	prepared, err = client.SignPreparedEvent(context.Background(), prepared, SignerEntity, entity)
	if err != nil {
		t.Fatalf("SignPreparedEvent entity: %v", err)
	}
	partial, err := prepared.Bytes()
	if err != nil {
		t.Fatalf("Bytes: %v", err)
	}
	parsed, err := client.ParsePreparedEvent(partial)
	if err != nil {
		t.Fatalf("ParsePreparedEvent: %v", err)
	}
	parsed, err = client.SignPreparedEvent(context.Background(), parsed, SignerOperationalCountersignature, operational)
	if err != nil {
		t.Fatalf("SignPreparedEvent operational: %v", err)
	}
	entry, err := client.PreparedEntryBytes(context.Background(), parsed)
	if err != nil {
		t.Fatalf("PreparedEntryBytes: %v", err)
	}
	if !strings.Contains(string(entry), `"extension.example":{"covered":true}`) {
		t.Fatalf("entry lost unknown signed field: %s", entry)
	}

	tampered, err := client.ParsePreparedEvent(partial)
	if err != nil {
		t.Fatalf("ParsePreparedEvent tampered base: %v", err)
	}
	sigs := tampered.envelope["sigs"].(map[string]any)
	sigs["ae"].(map[string]any)["sig"] = "AA"
	tampered, err = client.preparedFromEnvelope(tampered.envelope)
	if err != nil {
		t.Fatalf("preparedFromEnvelope tampered: %v", err)
	}
	if _, err := client.SignPreparedEvent(context.Background(), tampered, SignerOperationalCountersignature, operational); err == nil || !strings.Contains(err.Error(), "invalid") {
		t.Fatalf("SignPreparedEvent tampered error = %v, want prior-signature rejection", err)
	}
}

func TestClientRebuildHistoryAndWriteEvent(t *testing.T) {
	source := memorySource{
		complete: true,
		entries: []ProvenEntry{
			{Index: 2, Entry: []byte(revocationEntry)},
			{Index: 0, Entry: []byte(issuanceEntry)},
			{Index: 1, Entry: []byte(keyRotationEntry)},
		},
	}
	appender := &memoryAppender{}
	now := time.Unix(1782345601, 0).UTC()
	source.freshness = now
	client, err := New("c2sp-tlog:testnet:http://dnsid-ledger:8080/log#identity-01", WithSource(source), WithAppender(appender), WithPolicy(Policy{MaxCheckpointAge: time.Hour, Now: func() time.Time { return now }}), withProofVerifySkipped())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	events, err := client.RebuildHistory(context.Background(), "agent.example")
	if err != nil {
		t.Fatalf("RebuildHistory: %v", err)
	}
	if len(events) != 3 || events[0].Type != dnsidlog.LogEventIssuance || events[1].Type != dnsidlog.LogEventKeyRotation || events[2].Type != dnsidlog.LogEventRevocation {
		t.Fatalf("events = %#v", events)
	}
	_, err = client.VerifyBilateralBinding(context.Background(), dnsidlog.BilateralBindingInput{
		Domain:         "agent.example",
		GovernanceID:   "example.com",
		EntityKey:      mustKey(t, aeJWK),
		OperationalKey: mustKey(t, op2JWK),
	})
	var verificationErr *dnsid.VerificationError
	if !errors.As(err, &verificationErr) || verificationErr.Code() != dnsid.VerificationCodeTerminalState {
		t.Fatalf("VerifyBilateralBinding error = %v, want TERMINAL_STATE", err)
	}
	initialThumbprint := mustThumbprint(t, op1JWK)
	if err := client.VerifyOperationalContinuity(context.Background(), "agent.example", initialThumbprint, mustThumbprint(t, op2JWK)); !errors.As(err, &verificationErr) || verificationErr.Code() != dnsid.VerificationCodeTerminalState {
		t.Fatalf("VerifyOperationalContinuity error = %v, want TERMINAL_STATE", err)
	}
	if _, err := client.KeyTimestamp(context.Background(), "agent.example", mustThumbprint(t, op2JWK)); !errors.As(err, &verificationErr) || verificationErr.Code() != dnsid.VerificationCodeTerminalState {
		t.Fatalf("KeyTimestamp error = %v, want TERMINAL_STATE", err)
	}
	if _, err := client.VerifyNonRevocation(context.Background(), "agent.example", time.Unix(1782345600, 0)); !errors.As(err, &verificationErr) || verificationErr.Code() != dnsid.VerificationCodeTerminalState {
		t.Fatalf("VerifyNonRevocation error = %v, want TERMINAL_STATE", err)
	}

	ref, err := client.WriteEvent(context.Background(), events[0])
	if err != nil {
		t.Fatalf("WriteEvent: %v", err)
	}
	if ref != "c2sp-tlog:testnet:http://dnsid-ledger:8080/log#identity-01@0" {
		t.Fatalf("ref = %q", ref)
	}
	if string(appender.entries[0]) != issuanceEntry {
		t.Fatalf("appended entry = %s", appender.entries[0])
	}
}

func TestVerifyBilateralBindingAndOperationalContinuity(t *testing.T) {
	source := basicSource{entries: []ProvenEntry{{Index: 0, Entry: []byte(issuanceEntry)}, {Index: 1, Entry: []byte(keyRotationEntry)}}}
	client, err := New("c2sp-tlog:testnet:http://dnsid-ledger:8080/log#identity-01", WithSource(source), WithPolicy(Policy{Now: func() time.Time { return time.Unix(1782259201, 0).UTC() }}), withProofVerifySkipped())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	input := dnsidlog.BilateralBindingInput{
		Domain:         "agent.example",
		GovernanceID:   "example.com",
		EntityKey:      mustKey(t, aeJWK),
		OperationalKey: mustKey(t, op2JWK),
	}
	binding, err := client.VerifyBilateralBinding(context.Background(), input)
	if err != nil {
		t.Fatalf("VerifyBilateralBinding: %v", err)
	}
	if binding.InitialOperationalThumbprint != mustThumbprint(t, op1JWK) || binding.InitialEntityThumbprint != mustThumbprint(t, aeJWK) {
		t.Fatalf("binding = %#v", binding)
	}
	if err := client.VerifyOperationalContinuity(context.Background(), input.Domain, binding.InitialOperationalThumbprint, mustThumbprint(t, op1JWK)); err == nil || !strings.Contains(err.Error(), "active") {
		t.Fatalf("VerifyOperationalContinuity old key error = %v, want inactive key", err)
	}
	if err := client.VerifyOperationalContinuity(context.Background(), input.Domain, binding.InitialOperationalThumbprint, mustThumbprint(t, op2JWK)); err != nil {
		t.Fatalf("VerifyOperationalContinuity rotated key: %v", err)
	}

	input.GovernanceID = "tampered.example"
	if _, err := client.VerifyBilateralBinding(context.Background(), input); err == nil || !strings.Contains(err.Error(), "gi") {
		t.Fatalf("VerifyBilateralBinding tampered gi error = %v, want gi mismatch", err)
	}
	input.GovernanceID = "example.com"
	input.EntityKey = mustKey(t, op1JWK)
	if _, err := client.VerifyBilateralBinding(context.Background(), input); err == nil || !strings.Contains(err.Error(), "entity key") {
		t.Fatalf("VerifyBilateralBinding mismatched ek error = %v, want entity key mismatch", err)
	}
}

func TestVerifyLifecycleBindingRebuildsHistoryOnce(t *testing.T) {
	source := &countingSource{entries: []ProvenEntry{{Index: 0, Entry: []byte(issuanceEntry)}, {Index: 1, Entry: []byte(keyRotationEntry)}}}
	client, err := New("c2sp-tlog:testnet:http://dnsid-ledger:8080/log#identity-01", WithSource(source), WithPolicy(Policy{Now: func() time.Time { return time.Unix(1782259201, 0).UTC() }}), withProofVerifySkipped())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	input := dnsidlog.BilateralBindingInput{
		Domain:         "agent.example",
		GovernanceID:   "example.com",
		EntityKey:      mustKey(t, aeJWK),
		OperationalKey: mustKey(t, op2JWK),
	}
	if _, err := client.VerifyLifecycleBinding(context.Background(), input, mustThumbprint(t, op2JWK)); err != nil {
		t.Fatalf("VerifyLifecycleBinding: %v", err)
	}
	if source.rebuilds != 1 {
		t.Fatalf("RebuildHistory calls = %d, want 1", source.rebuilds)
	}
}

func mustThumbprint(t *testing.T, data string) string {
	t.Helper()
	thumb, err := thumbprint(mustKey(t, data))
	if err != nil {
		t.Fatalf("thumbprint: %v", err)
	}
	return thumb
}

func TestVerifyNonRevocationRequiresCompleteSource(t *testing.T) {
	source := basicSource{entries: []ProvenEntry{{Index: 0, Entry: []byte(issuanceEntry)}}}
	client, err := New("c2sp-tlog:testnet:http://dnsid-ledger:8080/log#identity-01", WithSource(source), withProofVerifySkipped())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	_, err = client.VerifyNonRevocation(context.Background(), "agent.example", time.Now())
	var verificationErr *dnsid.VerificationError
	if !errors.As(err, &verificationErr) || verificationErr.Code() != dnsid.VerificationCodeIncompleteStream {
		t.Fatalf("VerifyNonRevocation error = %v, want INCOMPLETE_STREAM", err)
	}
}

func TestVerifyNonRevocationRequiresCheckpointFreshnessPolicy(t *testing.T) {
	freshness := time.Unix(1782259200, 0).UTC()
	source := memorySource{
		complete:  true,
		freshness: freshness,
		entries:   []ProvenEntry{{Index: 0, Entry: []byte(issuanceEntry)}},
	}
	client, err := New(
		"c2sp-tlog:testnet:http://dnsid-ledger:8080/log#identity-01",
		WithSource(source),
		WithPolicy(Policy{Now: func() time.Time { return freshness }}),
		withProofVerifySkipped(),
	)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	_, err = client.VerifyNonRevocation(context.Background(), "agent.example", freshness)
	var verificationErr *dnsid.VerificationError
	if !errors.As(err, &verificationErr) || verificationErr.Code() != dnsid.VerificationCodeInvalidEvidence || !strings.Contains(err.Error(), "maximum checkpoint age") {
		t.Fatalf("VerifyNonRevocation error = %v, want INVALID_EVIDENCE freshness-policy failure", err)
	}
}

func TestVerifyNonRevocationRejectsStaleCheckpoint(t *testing.T) {
	freshness := time.Unix(1782259200, 0).UTC()
	source := memorySource{
		complete:  true,
		freshness: freshness,
		entries:   []ProvenEntry{{Index: 0, Entry: []byte(issuanceEntry)}},
	}
	client, err := New(
		"c2sp-tlog:testnet:http://dnsid-ledger:8080/log#identity-01",
		WithSource(source),
		WithPolicy(Policy{MaxCheckpointAge: time.Hour, Now: func() time.Time { return freshness.Add(2 * time.Hour) }}),
		withProofVerifySkipped(),
	)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	_, err = client.VerifyNonRevocation(context.Background(), "agent.example", freshness.Add(2*time.Hour))
	var verificationErr *dnsid.VerificationError
	if !errors.As(err, &verificationErr) || verificationErr.Code() != dnsid.VerificationCodeInvalidEvidence || !strings.Contains(err.Error(), "stale") {
		t.Fatalf("VerifyNonRevocation error = %v, want INVALID_EVIDENCE stale-checkpoint failure", err)
	}
}

func TestReadEventRequiresFinalRefIndex(t *testing.T) {
	source := memorySource{entries: []ProvenEntry{{Index: 0, Entry: []byte(issuanceEntry)}}}
	client, err := New("c2sp-tlog:testnet:http://dnsid-ledger:8080/log#identity-01", WithSource(source), withProofVerifySkipped())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	_, err = client.ReadEvent(context.Background(), "c2sp-tlog:testnet:http://dnsid-ledger:8080/log#identity-01@1")
	if err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("ReadEvent error = %v, want index binding failure", err)
	}
	if _, err := client.ReadEvent(context.Background(), "bad"); err == nil {
		t.Fatal("ReadEvent accepted malformed reference")
	} else {
		var parseErr *dnsid.ParseError
		if !errors.As(err, &parseErr) {
			t.Fatalf("malformed reference error = %T, want *dnsid.ParseError", err)
		}
	}
}

func TestLogEventFromEntryAllowsUnknownSignedFields(t *testing.T) {
	entry := []byte(strings.Replace(issuanceEntry, `"fqdn"`, `"extra":true,"fqdn"`, 1))
	if _, err := LogEventFromEntry(entry); err != nil {
		t.Fatalf("LogEventFromEntry unknown field error = %v", err)
	}
	entry = []byte(`{"v":1,"type":"ISSUANCE","ts":1,"kind":"dnsid.lifecycle","fqdn":"agent.example"}`)
	if _, err := LogEventFromEntry(entry); err == nil || !strings.Contains(err.Error(), "canonical") {
		t.Fatalf("LogEventFromEntry error = %v, want non-canonical entry rejection", err)
	}
	entry = []byte(`{"fqdn":"agent.example","kind":"dnsid.lifecycle","ts":1,"type":"ISSUANCE","v":1.0}`)
	if _, err := LogEventFromEntry(entry); err == nil || !strings.Contains(err.Error(), "non-canonical") {
		t.Fatalf("LogEventFromEntry error = %v, want non-canonical number rejection", err)
	}
}

func TestKeyTimestampUsesSignedEventTime(t *testing.T) {
	logTime := time.Unix(1782172801, 0).UTC()
	proof, verifier := signedSingleEntryProof(t, "dnsid-ledger:8080/log", []byte(issuanceEntry), 0)
	policy := Policy{LogVerifier: verifier, CheckpointTime: func(*formatlog.Checkpoint, *note.Note) (time.Time, error) { return logTime, nil }}
	client, err := New("c2sp-tlog:testnet:http://dnsid-ledger:8080/log#identity-01", WithSource(basicSource{entries: []ProvenEntry{{Index: 0, Entry: []byte(issuanceEntry), Proof: proof}}}), WithPolicy(policy))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	got, err := client.KeyTimestamp(context.Background(), "agent.example", "aVBtapLd11SUVKIMGJfPzOEDuN0sXcmzJQNVT-_sKEU")
	if err != nil {
		t.Fatalf("KeyTimestamp: %v", err)
	}
	eventTime := time.Unix(1782172800, 0).UTC()
	if !got.Equal(eventTime) {
		t.Fatalf("KeyTimestamp = %s, want %s", got, eventTime)
	}
}

func TestVerifyProofSingleEntryAndNegatives(t *testing.T) {
	logTime := time.Unix(1782172801, 0).UTC()
	proof, verifier := signedSingleEntryProof(t, "dnsid-ledger:8080/log", []byte(issuanceEntry), 0)
	policy := Policy{LogVerifier: verifier, CheckpointTime: func(*formatlog.Checkpoint, *note.Note) (time.Time, error) { return logTime, nil }}
	ref, err := ParseReference("c2sp-tlog:testnet:http://dnsid-ledger:8080/log#identity-01")
	if err != nil {
		t.Fatalf("ParseReference: %v", err)
	}
	got, err := policy.VerifyProof(ref, []byte(issuanceEntry), proof)
	if err != nil {
		t.Fatalf("VerifyProof: %v", err)
	}
	if got.Index != 0 || !got.LogTime.Equal(logTime) {
		t.Fatalf("proof = %#v, want index/log time", got)
	}
	wrongRef, _ := ParseReference("c2sp-tlog:testnet:http://other.example/log#agent.example")
	if _, err := policy.VerifyProof(wrongRef, []byte(issuanceEntry), proof); err == nil {
		t.Fatal("VerifyProof accepted wrong origin")
	}
	if _, err := policy.VerifyProof(ref, []byte(keyRotationEntry), proof); err == nil {
		t.Fatal("VerifyProof accepted wrong leaf hash")
	}
	badIndexProof := []byte(strings.Replace(string(proof), "index 0\n", "index 1\n", 1))
	if _, err := policy.VerifyProof(ref, []byte(issuanceEntry), badIndexProof); err == nil || !strings.Contains(err.Error(), "outside") {
		t.Fatalf("VerifyProof bad index error = %v, want outside", err)
	}
	stale := Policy{LogVerifier: verifier, MaxCheckpointAge: time.Hour, Now: func() time.Time { return logTime.Add(2 * time.Hour) }, CheckpointTime: func(*formatlog.Checkpoint, *note.Note) (time.Time, error) { return logTime, nil }}
	if _, err := stale.VerifyProof(ref, []byte(issuanceEntry), proof); err == nil || !strings.Contains(err.Error(), "stale") {
		t.Fatalf("VerifyProof stale error = %v, want stale", err)
	}
	missingTime := Policy{LogVerifier: verifier, MaxCheckpointAge: time.Hour, Now: func() time.Time { return logTime }}
	if _, err := missingTime.VerifyProof(ref, []byte(issuanceEntry), proof); err == nil || !strings.Contains(err.Error(), "timestamp") {
		t.Fatalf("VerifyProof missing time error = %v, want timestamp requirement", err)
	}
}

func TestAcceptedCheckpointTimeUsesQuorumThreshold(t *testing.T) {
	_, logVKey, err := note.GenerateKey(rand.Reader, "log")
	if err != nil {
		t.Fatalf("GenerateKey log: %v", err)
	}
	logVerifier, err := note.NewVerifier(logVKey)
	if err != nil {
		t.Fatalf("NewVerifier log: %v", err)
	}
	_, vkey1, err := note.GenerateKey(rand.Reader, "w1")
	if err != nil {
		t.Fatalf("GenerateKey w1: %v", err)
	}
	_, vkey2, err := note.GenerateKey(rand.Reader, "w2")
	if err != nil {
		t.Fatalf("GenerateKey w2: %v", err)
	}
	_, vkey3, err := note.GenerateKey(rand.Reader, "w3")
	if err != nil {
		t.Fatalf("GenerateKey w3: %v", err)
	}
	w1, err := note.NewVerifier(vkey1)
	if err != nil {
		t.Fatalf("NewVerifier w1: %v", err)
	}
	w2, err := note.NewVerifier(vkey2)
	if err != nil {
		t.Fatalf("NewVerifier w2: %v", err)
	}
	w3, err := note.NewVerifier(vkey3)
	if err != nil {
		t.Fatalf("NewVerifier w3: %v", err)
	}
	t1 := time.Unix(100, 0)
	t2 := time.Unix(200, 0)
	t3 := time.Unix(300, 0)
	policy := Policy{LogVerifier: logVerifier, WitnessVerifiers: []note.Verifier{w1, w2, w3}, WitnessQuorum: 2, Now: func() time.Time { return time.Unix(400, 0) }}
	got, err := policy.acceptedCheckpointTime(nil, &note.Note{Sigs: []note.Signature{fakeWitnessSig(w3, t3), fakeWitnessSig(w1, t1), fakeWitnessSig(w2, t2)}})
	if err != nil {
		t.Fatalf("acceptedCheckpointTime: %v", err)
	}
	if !got.Equal(t2) {
		t.Fatalf("acceptedCheckpointTime = %s, want quorum threshold %s", got, t2)
	}
}

func verifyLifecycle(indexed []verifiedEvent) ([]dnsidlog.LogEvent, error) {
	accepted, _, err := verifyLifecycleVerifiedWithMigration(context.Background(), indexed, nil, "")
	if err != nil {
		return nil, err
	}
	out := make([]dnsidlog.LogEvent, 0, len(accepted))
	for _, item := range accepted {
		out = append(out, item.event)
	}
	return out, nil
}

func verifiedFromEntry(t *testing.T, index uint64, entry string) verifiedEvent {
	t.Helper()
	parsed, err := parseEventFromEntry([]byte(entry))
	if err != nil {
		t.Fatalf("parseEventFromEntry: %v", err)
	}
	signed, err := CanonicalFromEntry([]byte(entry))
	if err != nil {
		t.Fatalf("CanonicalFromEntry: %v", err)
	}
	return verifiedEvent{event: parsed.event, chain: parsed.chain, index: index, signed: signed, parseError: parsed.validationError}
}

func signedIssuanceCandidate(t *testing.T, index uint64, timestamp time.Time, entity, operational dnsid.KeyProvider) verifiedEvent {
	t.Helper()
	client, err := New("c2sp-tlog:testnet:http://dnsid-ledger:8080/log#identity-01")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	prepared, err := client.PrepareEvent(dnsidlog.LogEvent{
		Type:                        dnsidlog.LogEventIssuance,
		Domain:                      "agent.example",
		GovernanceID:                "example.com",
		Timestamp:                   timestamp,
		InitialEntityPublicKey:      entity.JWK(),
		InitialOperationalPublicKey: operational.JWK(),
	})
	if err != nil {
		t.Fatalf("PrepareEvent: %v", err)
	}
	prepared, err = client.SignPreparedEvent(context.Background(), prepared, SignerEntity, entity)
	if err != nil {
		t.Fatalf("SignPreparedEvent entity: %v", err)
	}
	prepared, err = client.SignPreparedEvent(context.Background(), prepared, SignerOperationalCountersignature, operational)
	if err != nil {
		t.Fatalf("SignPreparedEvent operational: %v", err)
	}
	entry, err := client.PreparedEntryBytes(context.Background(), prepared)
	if err != nil {
		t.Fatalf("PreparedEntryBytes: %v", err)
	}
	return verifiedFromEntry(t, index, string(entry))
}

func canonicalEntryMutation(t *testing.T, entry string, mutate func(map[string]any)) []byte {
	t.Helper()
	payload, err := decodeJSONObject([]byte(entry))
	if err != nil {
		t.Fatalf("decodeJSONObject: %v", err)
	}
	mutate(payload)
	canonical, err := canonicalJSON(payload)
	if err != nil {
		t.Fatalf("canonicalJSON: %v", err)
	}
	return canonical
}

type failingSource struct{}

func (failingSource) ReadEvent(context.Context, dnsidlog.LogRef) (ProvenEntry, error) {
	return ProvenEntry{}, errors.New("log unavailable")
}
func (failingSource) RebuildHistory(context.Context, Reference, string) ([]ProvenEntry, error) {
	return nil, errors.New("log unavailable")
}

type basicSource struct {
	entries []ProvenEntry
}

func (s basicSource) ReadEvent(context.Context, dnsidlog.LogRef) (ProvenEntry, error) {
	return s.entries[0], nil
}

func (s basicSource) RebuildHistory(context.Context, Reference, string) ([]ProvenEntry, error) {
	return append([]ProvenEntry(nil), s.entries...), nil
}

type countingSource struct {
	entries  []ProvenEntry
	rebuilds int
}

func (s *countingSource) ReadEvent(context.Context, dnsidlog.LogRef) (ProvenEntry, error) {
	return s.entries[0], nil
}

func (s *countingSource) RebuildHistory(context.Context, Reference, string) ([]ProvenEntry, error) {
	s.rebuilds++
	return append([]ProvenEntry(nil), s.entries...), nil
}

type memorySource struct {
	entries   []ProvenEntry
	complete  bool
	freshness time.Time
}

type globalMemorySource struct{ memorySource }

func (globalMemorySource) GlobalCandidates() bool { return true }

func (s memorySource) ReadEvent(context.Context, dnsidlog.LogRef) (ProvenEntry, error) {
	return s.entries[0], nil
}

func (s memorySource) RebuildHistory(context.Context, Reference, string) ([]ProvenEntry, error) {
	return append([]ProvenEntry(nil), s.entries...), nil
}

func (s memorySource) RebuildCompleteHistory(context.Context, Reference, string) (CompleteHistoryResult, error) {
	if !s.complete {
		return CompleteHistoryResult{}, errIncompleteHistory{}
	}
	return CompleteHistoryResult{
		Entries:          append([]ProvenEntry(nil), s.entries...),
		CompleteThrough:  uint64(len(s.entries)),
		CompletenessMode: "test-complete",
		FreshnessTime:    s.freshness,
	}, nil
}

type errIncompleteHistory struct{}

func (errIncompleteHistory) Error() string { return "dnsid: incomplete c2sp-tlog history" }

type memoryAppender struct {
	entries [][]byte
}

func (a *memoryAppender) Append(_ context.Context, entry []byte) (uint64, error) {
	index := uint64(len(a.entries))
	a.entries = append(a.entries, append([]byte(nil), entry...))
	return index, nil
}

func fakeWitnessSig(verifier note.Verifier, ts time.Time) note.Signature {
	raw := make([]byte, 4+8+64)
	binary.BigEndian.PutUint64(raw[4:12], uint64(ts.Unix()))
	return note.Signature{Name: verifier.Name(), Hash: verifier.KeyHash(), Base64: base64.StdEncoding.EncodeToString(raw)}
}

func signedSingleEntryProof(t *testing.T, origin string, entry []byte, index uint64) ([]byte, note.Verifier) {
	t.Helper()
	skey, vkey, err := note.GenerateKey(rand.Reader, origin)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	signer, err := note.NewSigner(skey)
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}
	verifier, err := note.NewVerifier(vkey)
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	root := LeafHash(entry)
	checkpoint := formatlog.Checkpoint{Origin: origin, Size: 1, Hash: root[:]}
	signed, err := note.Sign(&note.Note{Text: string(checkpoint.Marshal())}, signer)
	if err != nil {
		t.Fatalf("Sign checkpoint: %v", err)
	}
	proof := formatproof.TLogProof{Index: index, Checkpoint: signed}
	return proof.Marshal(), verifier
}

func mustKey(t *testing.T, data string) jwk.Key {
	t.Helper()
	key, err := jwk.ParseKey([]byte(data))
	if err != nil {
		t.Fatalf("ParseKey: %v", err)
	}
	return key
}
