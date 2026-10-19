package registration

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"

	dnsid "github.com/dnsid-ai/dnsid-go"
	dnsidlog "github.com/dnsid-ai/dnsid-go/log"
	"github.com/dnsid-ai/dnsid-go/log/c2sptlog"
	"github.com/lestrrat-go/jwx/v3/jwk"
)

type entryReader interface {
	ReadEntry(context.Context, dnsidlog.LogRef) ([]byte, error)
}

func acceptedEntry(ctx context.Context, reader dnsidlog.LogReader, issuance *c2sptlog.ManagedIssuanceState) ([]byte, error) {
	if issuance == nil || issuance.Submission == nil || issuance.Submission.State != dnsid.SubmissionStateAccepted || issuance.Submission.EntryHash != issuance.EntryHash {
		return nil, fmt.Errorf("issuance lacks bound acceptance")
	}
	ref, index, err := c2sptlog.ParseFinalEventRef(dnsidlog.LogRef(issuance.Submission.LogRef))
	if err != nil || ref.String() != issuance.LogReference || issuance.Submission.Index == nil || index != *issuance.Submission.Index {
		return nil, fmt.Errorf("issuance acceptance reference conflicts with assigned stream")
	}
	source, ok := reader.(entryReader)
	if !ok {
		return nil, dnsid.NewArgumentError("dnsid: managed issuance compaction requires a trusted reader with ReadEntry support", nil)
	}
	entry, err := source.ReadEntry(ctx, dnsidlog.LogRef(issuance.Submission.LogRef))
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(entry)
	if hex.EncodeToString(sum[:]) != issuance.EntryHash {
		return nil, fmt.Errorf("historical issuance entry differs from accepted hash")
	}
	return entry, nil
}

func recoverIssuance(ctx context.Context, reader dnsidlog.LogReader, state *State) (*c2sptlog.ManagedIssuanceState, error) {
	if !state.IssuanceCompacted {
		return state.Issuance, nil
	}
	entry, err := acceptedEntry(ctx, reader, state.Issuance)
	if err != nil {
		return nil, err
	}
	issuance, err := clone(state.Issuance)
	if err != nil {
		return nil, err
	}
	issuance.EntryBytes = entry
	_, issuance.IdempotencyKey, err = state.replayKeys()
	if err != nil {
		return nil, err
	}
	return issuance, nil
}

func compactIssuance(ctx context.Context, reader dnsidlog.LogReader, state *State) error {
	entry, err := acceptedEntry(ctx, reader, state.Issuance)
	if err != nil {
		return err
	}
	if !bytes.Equal(entry, state.Issuance.EntryBytes) {
		return fmt.Errorf("included issuance differs from saved completed bytes")
	}
	state.Issuance.Prepared, state.Issuance.EntryBytes = nil, nil
	state.Issuance.IdempotencyKey = ""
	state.IssuanceCompacted = true
	return nil
}

func openIssuance(ctx context.Context, reader dnsidlog.LogReader, client *c2sptlog.Client, state *State, entity jwk.Key, provider dnsid.KeyProvider, key string) error {
	history, err := reader.RebuildHistory(ctx, state.Registration.Domain)
	if err != nil {
		return err
	}
	if len(history) == 0 {
		return nil
	}
	if history[0].Type != dnsidlog.LogEventIssuance || history[0].Domain != state.Registration.Domain || history[0].GovernanceID != state.Loaded.Registration.GovernanceID || !sameKey(history[0].InitialEntityPublicKey, entity) {
		return fmt.Errorf("existing lifecycle genesis differs from assigned identity/account")
	}
	initial, err := parsePublic(state.OperationalKey)
	if err != nil || !sameKey(history[0].InitialOperationalPublicKey, initial) {
		return fmt.Errorf("existing issuance differs from initial key")
	}
	evidence, err := reader.VerifyNonRevocation(ctx, state.Registration.Domain, time.Now())
	if err != nil {
		return err
	}
	ref, index, err := c2sptlog.ParseFinalEventRef(evidence.HistoryStart)
	if err != nil || ref.String() != state.Registration.PublicationConfig.LogRef {
		return fmt.Errorf("existing issuance reference differs from assigned log instance")
	}
	source, ok := reader.(entryReader)
	if !ok {
		return dnsid.NewArgumentError("dnsid: opening existing issuance requires a trusted ReadEntry reader", nil)
	}
	entry, err := source.ReadEntry(ctx, evidence.HistoryStart)
	if err != nil {
		return err
	}
	sum := sha256.Sum256(entry)
	pin, err := thumbprint(initial)
	if err != nil {
		return err
	}
	kid, _ := initial.KeyID()
	issuance := &c2sptlog.ManagedIssuanceState{
		Domain: state.Registration.Domain, GovernanceID: state.Loaded.Registration.GovernanceID,
		LogReference: ref.String(), EntityThumbprint: state.EntityThumbprint,
		OperationalKid: kid, OperationalThumbprint: pin, IdempotencyKey: key,
		EntryBytes: entry, EntryHash: hex.EncodeToString(sum[:]), Complete: true,
	}
	issuance.Submission = &dnsid.SubmissionResult{State: dnsid.SubmissionStateAccepted, EntryHash: issuance.EntryHash, LogRef: string(evidence.HistoryStart), Index: &index}
	if err := c2sptlog.ValidateManagedIssuanceState(ctx, client, issuance, entity, provider); err != nil {
		return err
	}
	state.Issuance = issuance
	return nil
}
