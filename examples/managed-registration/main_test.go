package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
	"time"

	dnsid "github.com/dnsid-ai/dnsid-go"
	dnsidlog "github.com/dnsid-ai/dnsid-go/log"
	"github.com/dnsid-ai/dnsid-go/log/c2sptlog"
	"github.com/lestrrat-go/jwx/v3/jwk"
)

func TestIssue_ValidatesBindingsAndResumesExactBytes(t *testing.T) {
	ctx := context.Background()
	entity, operational := dnsid.GenerateEd25519KeyProvider(), dnsid.GenerateEd25519KeyProvider()
	client, err := c2sptlog.New("c2sp-tlog:public:https://log.dev.dnsid.ai#ag-example")
	if err != nil {
		t.Fatal(err)
	}
	r := &dnsid.AgentRegistration{Domain: "agent.sandbox.dev.dnsid.ai", PublicationConfig: dnsid.PublicationConfig{GovernanceID: "dev.dnsid.ai"}}
	prepared, err := client.PrepareEvent(dnsidlog.LogEvent{
		Type: dnsidlog.LogEventIssuance, Domain: r.Domain, GovernanceID: r.PublicationConfig.GovernanceID,
		Timestamp: time.Now().UTC(), InitialEntityPublicKey: entity.JWK(), InitialOperationalPublicKey: operational.JWK(),
	})
	if err != nil {
		t.Fatal(err)
	}
	prepared, err = client.SignPreparedEvent(ctx, prepared, c2sptlog.SignerEntity, entity)
	if err != nil {
		t.Fatal(err)
	}
	prepared, err = client.SignPreparedEvent(ctx, prepared, c2sptlog.SignerOperationalCountersignature, operational)
	if err != nil {
		t.Fatal(err)
	}
	entry, err := client.PreparedEntryBytes(ctx, prepared)
	if err != nil {
		t.Fatal(err)
	}
	for _, tt := range []struct {
		name                string
		domain, governance  string
		entity, operational jwk.Key
	}{
		{"domain", "other.dev.dnsid.ai", "dev.dnsid.ai", entity.JWK(), operational.JWK()},
		{"governance", r.Domain, "other.dnsid.ai", entity.JWK(), operational.JWK()},
		{"entity", r.Domain, "dev.dnsid.ai", dnsid.GenerateEd25519KeyProvider().JWK(), operational.JWK()},
		{"operational", r.Domain, "dev.dnsid.ai", entity.JWK(), dnsid.GenerateEd25519KeyProvider().JWK()},
	} {
		t.Run(tt.name, func(t *testing.T) {
			expected := &dnsid.AgentRegistration{Domain: tt.domain, PublicationConfig: dnsid.PublicationConfig{GovernanceID: tt.governance}}
			if _, err := parseIssuance(client, entry, expected, tt.entity, tt.operational); err == nil {
				t.Fatal("accepted mismatched binding")
			}
		})
	}
	sum := sha256.Sum256(entry)
	index := uint64(3)
	s := &state{Registration: r, Entry: entry, Submission: &dnsid.SubmissionResult{
		State: dnsid.SubmissionStateAccepted, Index: &index, EntryHash: hex.EncodeToString(sum[:]), LogRef: string(prepared.Reference().FinalEventRef(index)),
	}}
	// A nil registry proves accepted recovery performs no prepare or submit calls.
	if err := issue(ctx, nil, client, entity.JWK(), operational, filepath.Join(t.TempDir(), "recovery.json"), s); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(s.Entry, entry) {
		t.Fatal("changed persisted entry bytes")
	}
	s.Submission.EntryHash = "wrong"
	if err := issue(ctx, nil, client, entity.JWK(), operational, "unused", s); err == nil {
		t.Fatal("accepted wrong submission hash")
	}
	s.Submission.State = dnsid.SubmissionStateRejected
	if err := issue(ctx, nil, client, entity.JWK(), operational, "unused", s); err == nil {
		t.Fatal("accepted rejected submission")
	}
	// Drop the entity signature. No incomplete event may reach submission.
	unsigned, err := client.PrepareEvent(dnsidlog.LogEvent{
		Type: dnsidlog.LogEventIssuance, Domain: r.Domain, GovernanceID: r.PublicationConfig.GovernanceID,
		Timestamp: time.Now().UTC(), InitialEntityPublicKey: entity.JWK(), InitialOperationalPublicKey: operational.JWK(),
	})
	if err != nil {
		t.Fatal(err)
	}
	s.Entry, err = unsigned.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	s.Submission = nil
	if err := issue(ctx, nil, client, entity.JWK(), operational, "unused", s); err == nil {
		t.Fatal("submitted unsigned event")
	}
}

func TestLoadState_PreservesRequestAndRequiresOriginalKey(t *testing.T) {
	directory := t.TempDir()
	initial, key, err := loadState(directory)
	if err != nil {
		t.Fatal(err)
	}
	initial.Entry = []byte("exact completed bytes")
	path := filepath.Join(directory, "recovery.json")
	if err := saveState(path, initial); err != nil {
		t.Fatal(err)
	}
	resumed, resumedKey, err := loadState(directory)
	if err != nil {
		t.Fatal(err)
	}
	initialKid, _ := key.JWK().KeyID()
	resumedKid, _ := resumedKey.JWK().KeyID()
	if initial.RegistrationKey != resumed.RegistrationKey || initial.IssuanceKey != resumed.IssuanceKey || initialKid != resumedKid || !bytes.Equal(initial.Entry, resumed.Entry) {
		t.Fatal("changed recovery facts")
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm()&0077 != 0 {
		t.Fatal("state is not owner-only")
	}
	keyPath := filepath.Join(directory, "operational-key.json")
	if err := os.Remove(keyPath); err != nil {
		t.Fatal(err)
	}
	if _, _, err := loadState(directory); err == nil {
		t.Fatal("replaced missing registered private key")
	}
	if _, err := os.Stat(keyPath); !os.IsNotExist(err) {
		t.Fatal("created a replacement key")
	}
}
