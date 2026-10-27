package c2sptlog

import (
	"bytes"
	"context"
	"errors"
	"testing"

	dnsid "github.com/dnsid-ai/dnsid-go"
)

func TestParsePreparedIssuance_Countersigning(t *testing.T) {
	configured, entity, operational := managedIssuanceFixture(t)
	registry := &managedIssuanceRegistry{client: configured, entity: entity, operational: operational.JWK(), governanceID: "example.com"}
	raw, err := registry.PrepareIssuance(context.Background(), "agent.example.com", "issuance-1")
	if err != nil {
		t.Fatal(err)
	}
	original := bytes.Clone(raw.EntryBytes)
	client, prepared, err := ParsePreparedIssuance(raw.EntryBytes)
	if err != nil {
		t.Fatalf("ParsePreparedIssuance: %v", err)
	}
	if prepared.Reference() != configured.ref || client.ref != configured.ref {
		t.Fatalf("bound reference = %v, want %v", prepared.Reference(), configured.ref)
	}
	preserved, err := prepared.Bytes()
	if err != nil || !bytes.Equal(preserved, original) || !bytes.Equal(raw.EntryBytes, original) {
		t.Fatalf("prepared response bytes changed: %v", err)
	}
	prepared, err = client.SignPreparedEvent(context.Background(), prepared, SignerOperationalCountersignature, operational)
	if err != nil {
		t.Fatalf("SignPreparedEvent: %v", err)
	}
	if _, err := client.PreparedEntryBytes(context.Background(), prepared); err != nil {
		t.Fatalf("PreparedEntryBytes: %v", err)
	}
}

func TestParsePreparedIssuance_PreservesUnknownSignedFields(t *testing.T) {
	payload, err := payloadObjectFromEntry([]byte(issuanceEntry))
	if err != nil {
		t.Fatal(err)
	}
	payload["extension.example"] = map[string]any{"covered": true}
	entry := []byte(signFixturePayload(payload))
	client, prepared, err := ParsePreparedIssuance(entry)
	if err != nil {
		t.Fatalf("ParsePreparedIssuance: %v", err)
	}
	preserved, err := client.PreparedEntryBytes(context.Background(), prepared)
	if err != nil || !bytes.Equal(preserved, entry) {
		t.Fatalf("signed extension was not preserved: %v", err)
	}
	signed, err := CanonicalFromEntry(entry)
	if err != nil || !bytes.Equal(prepared.SignedBytes(), signed) || prepared.EventID() != EventID(signed) {
		t.Fatalf("signed bytes or event ID changed: %v", err)
	}
}

func TestParsePreparedIssuance_RejectsInvalidEntry(t *testing.T) {
	mutate := func(fn func(map[string]any)) []byte {
		return canonicalEntryMutation(t, issuanceEntry, fn)
	}
	for _, tc := range []struct {
		name  string
		entry []byte
	}{
		{"empty", nil},
		{"malformed JSON", []byte(`{`)},
		{"non-canonical JSON", []byte(issuanceEntry + "\n")},
		{"missing lr", mutate(func(p map[string]any) { delete(p, "lr") })},
		{"malformed lr", mutate(func(p map[string]any) { p["lr"] = "invalid" })},
		{"wrong lr type", mutate(func(p map[string]any) { p["lr"] = 1 })},
		{"duplicate lr", []byte(`{"lr":"c2sp-tlog:testnet:http://dnsid-ledger:8080/log#identity-01",` + issuanceEntry[1:])},
		{"conflicting lr", []byte(`{"lr":"c2sp-tlog:testnet:https://other.example#other",` + issuanceEntry[1:])},
		{"wrong method", mutate(func(p map[string]any) { p["method"] = "other" })},
		{"wrong origin", mutate(func(p map[string]any) { p["log_origin"] = "other.example" })},
		{"wrong stream", mutate(func(p map[string]any) { p["stream_id"] = "other" })},
		{"missing seq", mutate(func(p map[string]any) { delete(p, "seq") })},
		{"nonzero seq", mutate(func(p map[string]any) { p["seq"] = 1 })},
		{"predecessor", mutate(func(p map[string]any) { p["prev_event_id"] = EventID([]byte("previous")) })},
		{"unsupported version", mutate(func(p map[string]any) { p["v"] = 2 })},
		{"malformed key", mutate(func(p map[string]any) { p["ek"].(map[string]any)["x"] = "invalid" })},
		{"wrong signature kid", mutate(func(p map[string]any) { p["sigs"].(map[string]any)["ae"].(map[string]any)["kid"] = "other" })},
		{"invalid signature", mutate(func(p map[string]any) { p["sigs"].(map[string]any)["ae"].(map[string]any)["sig"] = "AA" })},
		{"tampered payload", mutate(func(p map[string]any) { p["gi"] = "other.example" })},
		{"key rotation", []byte(keyRotationEntry)},
		{"revocation", []byte(revocationEntry)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client, prepared, err := ParsePreparedIssuance(tc.entry)
			if err == nil || client != nil || prepared != nil {
				t.Fatalf("ParsePreparedIssuance = %v, %v, %v; want only an error", client, prepared, err)
			}
			var parseErr *dnsid.ParseError
			var validationErr *dnsid.ValidationError
			if !errors.As(err, &parseErr) && !errors.As(err, &validationErr) {
				t.Fatalf("untyped error: %T %v", err, err)
			}
		})
	}
}
