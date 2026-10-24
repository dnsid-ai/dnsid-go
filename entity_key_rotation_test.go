package dnsid

import (
	"context"
	"testing"
	"time"

	dnsidlog "github.com/dnsid-ai/dnsid-go/log"
	"github.com/lestrrat-go/jwx/v3/jwk"
)

func entityRotationEvent(t *testing.T, domain, previousThumb string, next jwk.Key, timestamp time.Time) dnsidlog.LogEvent {
	t.Helper()
	thumb, err := (&JWK{key: next}).Thumbprint()
	if err != nil {
		t.Fatalf("new entity thumbprint: %v", err)
	}
	return dnsidlog.LogEvent{Type: dnsidlog.LogEventEntityKeyRotation, Domain: domain, PreviousEntityThumbprint: previousThumb, NewEntityPublicKey: next, NewEntityThumbprint: thumb, Timestamp: timestamp}
}

func TestDomainLogEntityKeyRotationConformance(t *testing.T) {
	now := time.Now()
	op1 := GenerateES256KeyProvider().JWK()
	issuance := lifecycleIssuance(t, "agent.example.com", op1, now.Add(-4*time.Hour))
	e2 := GenerateES256KeyProvider().JWK()
	e3 := GenerateES256KeyProvider().JWK()
	rotation := entityRotationEvent(t, "agent.example.com", issuance.InitialEntityThumbprint, e2, now.Add(-3*time.Hour))
	second := entityRotationEvent(t, "agent.example.com", rotation.NewEntityThumbprint, e3, now.Add(-2*time.Hour))
	opRotation := lifecycleRotation(t, "agent.example.com", issuance.InitialOperationalThumbprint, GenerateES256KeyProvider().JWK(), now.Add(-time.Hour))
	retirement := dnsidlog.LogEvent{Type: dnsidlog.LogEventRetirement, Domain: "agent.example.com", Timestamp: now.Add(-90 * time.Minute)}
	mismatched := rotation
	mismatched.NewEntityThumbprint = issuance.InitialEntityThumbprint

	cases := []struct {
		name   string
		events []dnsidlog.LogEvent
		code   string
		entity jwk.Key
	}{
		{name: "rotation", events: []dnsidlog.LogEvent{issuance, rotation}, entity: e2},
		{name: "chained rotations", events: []dnsidlog.LogEvent{issuance, rotation, second}, entity: e3},
		{name: "interleaved operational rotation", events: []dnsidlog.LogEvent{issuance, rotation, opRotation}, entity: e2},
		{name: "rotation before genesis", events: []dnsidlog.LogEvent{rotation}, code: dnsidlog.VerificationCodeGenesisRequired},
		{name: "stale previous entity key", events: []dnsidlog.LogEvent{issuance, rotation, entityRotationEvent(t, "agent.example.com", issuance.InitialEntityThumbprint, e3, now.Add(-time.Hour))}, code: dnsidlog.VerificationCodeKeyContinuity},
		{name: "new entity key is operational key", events: []dnsidlog.LogEvent{issuance, entityRotationEvent(t, "agent.example.com", issuance.InitialEntityThumbprint, op1, now.Add(-time.Hour))}, code: dnsidlog.VerificationCodeKeyContinuity},
		{name: "new entity thumbprint mismatch", events: []dnsidlog.LogEvent{issuance, mismatched}, code: dnsidlog.VerificationCodeKeyContinuity},
		{name: "after terminal", events: []dnsidlog.LogEvent{issuance, retirement, second}, code: dnsidlog.VerificationCodeTerminalState},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			snapshot, err := dnsidlog.NewDomainLog("agent.example.com", tc.events).SnapshotAt(now)
			if got := verificationCode(err); got != tc.code {
				t.Fatalf("SnapshotAt code = %q (%v), want %q", got, err, tc.code)
			}
			if tc.code != "" {
				return
			}
			if snapshot.HistoricalState != dnsidlog.AgentStateActive {
				t.Fatalf("snapshot state = %s", snapshot.HistoricalState)
			}
			current, err := dnsidlog.CurrentEntityKey(tc.events)
			if err != nil {
				t.Fatalf("CurrentEntityKey: %v", err)
			}
			got, _ := (&JWK{key: current}).Thumbprint()
			want, _ := (&JWK{key: tc.entity}).Thumbprint()
			if got != want {
				t.Fatalf("CurrentEntityKey = %s, want %s", got, want)
			}
		})
	}

	t.Run("CurrentEntityKey without rotation is ISSUANCE key", func(t *testing.T) {
		current, err := dnsidlog.CurrentEntityKey([]dnsidlog.LogEvent{issuance, opRotation})
		if err != nil {
			t.Fatal(err)
		}
		if got, _ := (&JWK{key: current}).Thumbprint(); got != issuance.InitialEntityThumbprint {
			t.Fatalf("CurrentEntityKey = %s, want ISSUANCE key", got)
		}
	})
	t.Run("CurrentEntityKey follows a migration genesis", func(t *testing.T) {
		migration := dnsidlog.LogEvent{Type: dnsidlog.LogEventMigration, Domain: "agent.example.com", InitialEntityPublicKey: e2, Timestamp: now.Add(-time.Hour)}
		current, err := dnsidlog.CurrentEntityKey([]dnsidlog.LogEvent{issuance, rotation, migration, entityRotationEvent(t, "agent.example.com", rotation.NewEntityThumbprint, e3, now)})
		if err != nil {
			t.Fatal(err)
		}
		if got, _ := (&JWK{key: current}).Thumbprint(); got != second.NewEntityThumbprint {
			t.Fatalf("CurrentEntityKey = %s, want E3", got)
		}
		if _, err := dnsidlog.CurrentEntityKey([]dnsidlog.LogEvent{issuance, migration}); verificationCode(err) != dnsidlog.VerificationCodeKeyContinuity {
			t.Fatalf("CurrentEntityKey with discontinuous migration = %v, want KEY_CONTINUITY", err)
		}
		destinationOnly, err := dnsidlog.CurrentEntityKey([]dnsidlog.LogEvent{migration})
		if err != nil {
			t.Fatal(err)
		}
		if got, _ := (&JWK{key: destinationOnly}).Thumbprint(); got != rotation.NewEntityThumbprint {
			t.Fatalf("CurrentEntityKey destination-only = %s, want E2", got)
		}
	})
	t.Run("CurrentEntityKey rejects empty and ungrounded history", func(t *testing.T) {
		if _, err := dnsidlog.CurrentEntityKey(nil); err == nil {
			t.Fatal("CurrentEntityKey accepted empty history")
		}
		if _, err := dnsidlog.CurrentEntityKey([]dnsidlog.LogEvent{retirement}); err == nil {
			t.Fatal("CurrentEntityKey accepted history without genesis")
		}
	})
}

func TestRequiredLogSignatures_EntityKeyRotation(t *testing.T) {
	roles, err := RequiredLogSignatures(dnsidlog.LogEvent{Type: dnsidlog.LogEventEntityKeyRotation})
	if err != nil {
		t.Fatal(err)
	}
	if len(roles) != 2 || roles[0] != LogSignerPreviousEntity || roles[1] != LogSignerNewEntity {
		t.Fatalf("roles = %v, want [previous_entity new_entity]", roles)
	}
}

func TestSplitLogSigning_EntityKeyRotationUsesNamedKeys(t *testing.T) {
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
	newThumb, err := (&JWK{key: kp.JWK(newKid)}).Thumbprint()
	if err != nil {
		t.Fatal(err)
	}
	event := dnsidlog.LogEvent{
		Type:                     dnsidlog.LogEventEntityKeyRotation,
		Domain:                   "agent.example.com",
		Timestamp:                time.Unix(1783987200, 0).UTC(),
		PreviousEntityKid:        previousKid,
		PreviousEntityThumbprint: previousThumb,
		NewEntityKid:             newKid,
		NewEntityPublicKey:       kp.JWK(newKid),
		NewEntityThumbprint:      newThumb,
	}
	if _, err := SignLogEventWithKey(event, LogSignerPreviousEntity, GenerateES256KeyProvider(), wl); err == nil {
		t.Fatal("previous-entity signature accepted an unrelated key provider")
	}
	wrong := event
	wrong.PreviousEntityThumbprint = newThumb
	if _, err := SignLogEventWithKey(wrong, LogSignerPreviousEntity, kp, wl); err == nil {
		t.Fatal("previous-entity signature accepted a key that is not the previous thumbprint")
	}
	event, err = SignLogEventWithKey(event, LogSignerPreviousEntity, kp, wl)
	if err != nil {
		t.Fatalf("sign previous entity key: %v", err)
	}
	event, err = SignLogEventWithKey(event, LogSignerNewEntity, kp, wl)
	if err != nil {
		t.Fatalf("sign new entity key: %v", err)
	}
	if event.PreviousEntityKid != previousKid || event.PreviousEntitySignature == "" {
		t.Fatal("missing previous-entity authorization")
	}
	if event.NewEntityKid != newKid || event.NewEntitySignature == "" {
		t.Fatal("missing new-entity proof")
	}
	if event.InitialEntitySignature != "" || event.PreviousOperationalSignature != "" {
		t.Fatal("entity rotation populated another role")
	}
}

func TestWriteSignedEvent_EntityKeyRotationNeedsBothSignatures(t *testing.T) {
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
	complete := dnsidlog.LogEvent{
		Type: dnsidlog.LogEventEntityKeyRotation, NewEntityPublicKey: GenerateES256KeyProvider().JWK(),
		PreviousEntityKid: "previous", PreviousEntitySignature: "signature",
		NewEntityKid: "next", NewEntitySignature: "signature",
	}
	for name, mutate := range map[string]func(*dnsidlog.LogEvent){
		"missing previous": func(e *dnsidlog.LogEvent) { e.PreviousEntitySignature = "" },
		"missing new":      func(e *dnsidlog.LogEvent) { e.NewEntitySignature = "" },
		"missing key":      func(e *dnsidlog.LogEvent) { e.NewEntityPublicKey = nil },
	} {
		event := complete
		mutate(&event)
		if _, err := manager.WriteSignedEvent(context.Background(), event); err == nil {
			t.Fatalf("WriteSignedEvent accepted %s", name)
		}
	}
	if _, err := manager.WriteSignedEvent(context.Background(), complete); err != nil {
		t.Fatalf("WriteSignedEvent: %v", err)
	}
	if len(wl.events) != 1 {
		t.Fatalf("written events = %d, want 1", len(wl.events))
	}
}
