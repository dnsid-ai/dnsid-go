package dnsid

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	dnsidlog "github.com/dnsid-ai/dnsid-go/log"
)

type splitWriteLog struct{ testWriteLog }

func (l *splitWriteLog) Canonical(event dnsidlog.LogEvent) ([]byte, error) {
	return []byte(fmt.Sprintf("%s:%s:%s", event.Type, event.Domain, event.GovernanceID)), nil
}

func TestSplitLogSigning_Issuance(t *testing.T) {
	wl := &splitWriteLog{}
	registry := dnsidlog.NewLogRegistry()
	if err := registry.Register("test", func(string) dnsidlog.LogReader { return wl }); err != nil {
		t.Fatalf("Register: %v", err)
	}

	entityKP := GenerateES256KeyProvider()
	opKP := GenerateES256KeyProvider()
	baseConfig := IdentityConfig{
		Domain:       "agent.example.com",
		GovernanceID: "example.com",
		LogRef:       "test:agent",
		StatusURL:    "https://agent.example.com/status.json",
	}
	opManager, err := NewIdentityManager(Config{Identity: &baseConfig}, opKP, WithLogRegistry(registry))
	if err != nil {
		t.Fatalf("NewIdentityManager operational: %v", err)
	}

	event := dnsidlog.LogEvent{
		Type:                        dnsidlog.LogEventIssuance,
		Domain:                      baseConfig.Domain,
		Timestamp:                   time.Unix(1783987200, 0).UTC(),
		GovernanceID:                baseConfig.GovernanceID,
		InitialOperationalPublicKey: opKP.JWK(),
		InitialEntityPublicKey:      entityKP.JWK(),
	}
	unsigned, err := opManager.CanonicalizeLogEvent(event)
	if err != nil {
		t.Fatalf("CanonicalizeLogEvent unsigned: %v", err)
	}

	event, err = SignLogEventWithKey(event, LogSignerEntity, entityKP, wl)
	if err != nil {
		t.Fatalf("SignLogEvent entity: %v", err)
	}
	event, err = opManager.SignLogEvent(event, LogSignerOperationalCountersignature)
	if err != nil {
		t.Fatalf("SignLogEvent operational: %v", err)
	}
	if event.InitialEntityKid == "" || event.InitialEntitySignature == "" {
		t.Fatal("missing accountable-entity signature")
	}
	if event.InitialOperationalKid == "" || event.InitialOperationalSignature == "" {
		t.Fatal("missing operational countersignature")
	}

	signed, err := opManager.CanonicalizeLogEvent(event)
	if err != nil {
		t.Fatalf("CanonicalizeLogEvent signed: %v", err)
	}
	if !bytes.Equal(signed, unsigned) {
		t.Fatal("adding signatures changed canonical signed bytes")
	}

	ref, err := opManager.WriteSignedEvent(context.Background(), event)
	if err != nil {
		t.Fatalf("WriteSignedEvent: %v", err)
	}
	if ref != "test:1" {
		t.Fatalf("ref = %q, want test:1", ref)
	}
	if len(wl.events) != 1 {
		t.Fatalf("written events = %d, want 1", len(wl.events))
	}
}

func TestSplitLogSigning_KeyRotationUsesNamedKeys(t *testing.T) {
	wl := &splitWriteLog{}
	kp := GenerateES256KeyProvider()
	previousKid := kp.ListKeyIds()[0]
	newKid, err := kp.GenerateKey(JoseAlgES256)
	if err != nil {
		t.Fatal(err)
	}
	previousThumb, err := (&JWK{key: kp.JWK(previousKid)}).Thumbprint()
	if err != nil {
		t.Fatal(err)
	}
	event := dnsidlog.LogEvent{
		Type:                          dnsidlog.LogEventKeyRotation,
		Domain:                        "agent.example.com",
		Timestamp:                     time.Unix(1783987200, 0).UTC(),
		PreviousOperationalKid:        previousKid,
		PreviousOperationalThumbprint: previousThumb,
		NewOperationalKid:             newKid,
		NewOperationalPublicKey:       kp.JWK(newKid),
	}
	event, err = SignLogEventWithKey(event, LogSignerPreviousOperational, kp, wl)
	if err != nil {
		t.Fatalf("sign previous key: %v", err)
	}
	event, err = SignLogEventWithKey(event, LogSignerNewOperational, kp, wl)
	if err != nil {
		t.Fatalf("sign new key: %v", err)
	}
	if event.PreviousOperationalKid != previousKid || event.PreviousOperationalSignature == "" {
		t.Fatal("missing previous-key authorization")
	}
	if event.NewOperationalKid != newKid || event.NewOperationalSignature == "" {
		t.Fatal("missing new-key proof")
	}
}

func TestWriteSignedEvent_KeyRotationNeedsOnlyPreviousSignature(t *testing.T) {
	wl := &splitWriteLog{}
	registry := dnsidlog.NewLogRegistry()
	if err := registry.Register("test", func(string) dnsidlog.LogReader { return wl }); err != nil {
		t.Fatal(err)
	}
	manager, err := NewIdentityManager(Config{Identity: &IdentityConfig{
		Domain: "agent.example.com", GovernanceID: "example.com", LogRef: "test:agent",
		StatusURL: "https://agent.example.com/status.json",
	}}, GenerateES256KeyProvider(), WithLogRegistry(registry))
	if err != nil {
		t.Fatal(err)
	}
	_, err = manager.WriteSignedEvent(context.Background(), dnsidlog.LogEvent{
		Type: dnsidlog.LogEventKeyRotation, PreviousOperationalKid: "previous", PreviousOperationalSignature: "signature",
	})
	if err != nil {
		t.Fatalf("WriteSignedEvent: %v", err)
	}
	if len(wl.events) != 1 {
		t.Fatalf("written events = %d, want 1", len(wl.events))
	}
}

func TestWriteSignedEvent_RejectsIncompleteIssuance(t *testing.T) {
	wl := &splitWriteLog{}
	registry := dnsidlog.NewLogRegistry()
	if err := registry.Register("test", func(string) dnsidlog.LogReader { return wl }); err != nil {
		t.Fatalf("Register: %v", err)
	}
	entityKP := GenerateES256KeyProvider()
	opKP := GenerateES256KeyProvider()
	manager, err := NewIdentityManager(Config{Identity: &IdentityConfig{
		Domain:       "agent.example.com",
		GovernanceID: "example.com",
		LogRef:       "test:agent",
		StatusURL:    "https://agent.example.com/status.json",
	}}, opKP, WithEntityKeyProvider(entityKP), WithLogRegistry(registry))
	if err != nil {
		t.Fatalf("NewIdentityManager: %v", err)
	}

	event := dnsidlog.LogEvent{
		Type:                        dnsidlog.LogEventIssuance,
		Domain:                      "agent.example.com",
		Timestamp:                   time.Unix(1783987200, 0).UTC(),
		GovernanceID:                "example.com",
		InitialOperationalPublicKey: opKP.JWK(),
		InitialEntityPublicKey:      entityKP.JWK(),
		InitialEntityKid:            "entity",
		InitialEntitySignature:      "signature",
	}
	_, err = manager.WriteSignedEvent(context.Background(), event)
	if err == nil || !strings.Contains(err.Error(), "operational countersignature") {
		t.Fatalf("WriteSignedEvent error = %v, want missing operational countersignature", err)
	}
	var argumentErr *ArgumentError
	if !errors.As(err, &argumentErr) {
		t.Fatalf("WriteSignedEvent error = %T, want *ArgumentError", err)
	}
	if len(wl.events) != 0 {
		t.Fatalf("written events = %d, want 0", len(wl.events))
	}
}

func TestSignLogEvent_RejectsMismatchedRoleKey(t *testing.T) {
	wl := &splitWriteLog{}
	registry := dnsidlog.NewLogRegistry()
	if err := registry.Register("test", func(string) dnsidlog.LogReader { return wl }); err != nil {
		t.Fatalf("Register: %v", err)
	}
	opKP := GenerateES256KeyProvider()
	otherKP := GenerateES256KeyProvider()
	manager, err := NewIdentityManager(Config{Identity: &IdentityConfig{
		Domain:       "agent.example.com",
		GovernanceID: "example.com",
		LogRef:       "test:agent",
		StatusURL:    "https://agent.example.com/status.json",
	}}, opKP, WithLogRegistry(registry))
	if err != nil {
		t.Fatalf("NewIdentityManager: %v", err)
	}

	_, err = manager.SignLogEvent(dnsidlog.LogEvent{
		Type:                        dnsidlog.LogEventIssuance,
		Domain:                      "agent.example.com",
		Timestamp:                   time.Unix(1783987200, 0).UTC(),
		InitialOperationalPublicKey: otherKP.JWK(),
	}, LogSignerOperationalCountersignature)
	if err == nil || !strings.Contains(err.Error(), "does not match event key") {
		t.Fatalf("SignLogEvent error = %v, want key mismatch", err)
	}
}

func TestSignLogEvent_RequiresLocalLogReference(t *testing.T) {
	event := dnsidlog.LogEvent{Type: dnsidlog.LogEventIssuance}
	if _, err := (*IdentityManager)(nil).SignLogEvent(event, LogSignerEntity); err == nil || !strings.Contains(err.Error(), "local log reference") {
		t.Fatalf("nil manager error = %v, want local log reference", err)
	}

	manager := &IdentityManager{}
	if _, err := manager.SignLogEvent(event, LogSignerEntity); err == nil || !strings.Contains(err.Error(), "local log reference") {
		t.Fatalf("unconfigured manager error = %v, want local log reference", err)
	}
}
