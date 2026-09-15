package c2sptlog

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	dnsid "github.com/dnsid-ai/dnsid-go"
	dnsidlog "github.com/dnsid-ai/dnsid-go/log"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"golang.org/x/mod/sumdb/note"
)

func TestMigration_ExactLaterCopyCutoffAndDestinationID(t *testing.T) {
	v := streamBundleWithCopies(t)
	verifier, err := note.NewVerifier(v.Trust.BundleVerifierKey)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(v.Trust.Now, 0)
	bundle, err := VerifyStreamBundle(context.Background(), []byte(v.Bundle), StreamBundleTrust{PolicyDocument: []byte(v.Policy), BundleVerifier: verifier, Now: func() time.Time { return now }, MaxBundleLifetime: time.Duration(v.Trust.MaxBundleLifetime) * time.Millisecond, MaxCheckpointAge: time.Duration(v.Trust.CheckpointFreshness) * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	policy, err := ParsePolicy([]byte(v.Policy))
	if err != nil {
		t.Fatal(err)
	}
	policy.Now = func() time.Time { return now }
	policy.MaxCheckpointAge = time.Minute * 2
	source, err := New(bundle.Reference.String(), WithSource(bundle.Source), WithPolicy(policy))
	if err != nil {
		t.Fatal(err)
	}
	key, err := jwk.Import(ed25519.NewKeyFromSeed(bytes.Repeat([]byte{1}, 32)))
	if err != nil {
		t.Fatal(err)
	}
	if err := key.Set(jwk.KeyIDKey, "entity-1"); err != nil {
		t.Fatal(err)
	}
	if err := key.Set(jwk.AlgorithmKey, "EdDSA"); err != nil {
		t.Fatal(err)
	}
	private, err := json.Marshal(key)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "key.jwk")
	if err := os.WriteFile(path, private, 0600); err != nil {
		t.Fatal(err)
	}
	entity, err := dnsid.NewLocalKeyProvider(path)
	if err != nil {
		t.Fatal(err)
	}
	const destination = "c2sp-tlog:testnet:https://destination.example#new-instance"
	transport := &memorySource{}
	resolve := func(ctx context.Context, event dnsidlog.LogEvent) (MigrationVerificationResult, error) {
		return source.RebuildHistoryThrough(ctx, event.Domain, dnsidlog.LogRef(event.FinalEntryRef))
	}
	dest, err := New(destination, WithSource(transport), WithMigrationVerifier(resolve), withProofVerifySkipped())
	if err != nil {
		t.Fatal(err)
	}
	event := dnsidlog.LogEvent{Type: dnsidlog.LogEventMigration, Domain: bundle.FQDN, Timestamp: now, PreviousLog: bundle.Reference.String(), NewLog: destination, FinalEntryRef: string(bundle.Reference.FinalEventRef(2))}
	prepared, err := dest.PrepareEvent(event)
	if err != nil {
		t.Fatal(err)
	}
	prepared, err = dest.SignPreparedEvent(context.Background(), prepared, SignerEntity, entity)
	if err != nil {
		t.Fatal(err)
	}
	entry, err := dest.PreparedEntryBytes(context.Background(), prepared)
	if err != nil {
		t.Fatal(err)
	}
	transport.entries = []ProvenEntry{{Index: 0, Entry: entry}}
	history, err := dest.RebuildHistory(context.Background(), bundle.FQDN)
	if err != nil || len(history) != 3 {
		t.Fatalf("migration history: %v, %v", history, err)
	}
	successor := dnsidlog.LogEvent{Type: dnsidlog.LogEventRetirement, Domain: bundle.FQDN, Timestamp: now.Add(time.Second)}
	chain, err := dest.ChainForWrite(context.Background(), successor)
	if err != nil {
		t.Fatal(err)
	}
	if chain.Sequence != 1 || chain.PreviousEventID != prepared.EventID() {
		t.Fatal("destination successor did not name migration logical ID")
	}
	issuance := history[0]
	issuance.InitialEntityPublicKey = key
	if _, err := dest.PrepareEvent(issuance); err == nil {
		t.Fatal("private key accepted in lifecycle payload")
	}
	regressing := event
	regressing.Timestamp = history[1].Timestamp.Add(-time.Second)
	unsigned, err := dest.PrepareEvent(regressing)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := dest.SignPreparedEvent(context.Background(), unsigned, SignerEntity, entity); err == nil {
		t.Fatal("migration predates imported source history")
	}
	// Invalid signed copies cannot be used as source cutoffs even with otherwise valid history.
	event.FinalEntryRef = string(bundle.Reference.FinalEventRef(3))
	invalid, err := dest.PrepareEvent(event)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := dest.SignPreparedEvent(context.Background(), invalid, SignerEntity, entity); err == nil {
		t.Fatal("signed migration from invalid occurrence")
	}
}
