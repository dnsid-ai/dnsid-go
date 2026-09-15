package c2sptlog

import (
	"context"
	"encoding/json"
	"strconv"

	dnsid "github.com/dnsid-ai/dnsid-go"
	dnsidlog "github.com/dnsid-ai/dnsid-go/log"
)

// RebuildHistoryThrough verifies an exact signed migration cutoff. It can be
// called by an injected MigrationVerifier after selecting the source's trust
// configuration. Later source events are not imported. A valid later copy of
// the final logical event is allowed; its exact occurrence evidence is retained.
func (c *Client) RebuildHistoryThrough(ctx context.Context, domain string, finalRef dnsidlog.LogRef) (result MigrationVerificationResult, err error) {
	ctx, cancel := dnsid.VerificationContext(ctx)
	defer cancel()
	defer func() {
		if err == nil {
			err = ctx.Err()
		}
		if err != nil {
			result = MigrationVerificationResult{}
			err = logVerificationError(err, false)
		}
	}()
	ref, index, err := ParseFinalEventRef(finalRef)
	if err != nil {
		return result, err
	}
	if c == nil || ref.String() != c.ref.String() {
		return result, dnsid.NewArgumentError("dnsid: migration cutoff does not match client", nil)
	}
	source, ok := c.source.(CompleteSource)
	if !ok {
		return result, invalidMigration("dnsid: migration requires complete source history", nil)
	}
	history, err := source.RebuildCompleteHistory(ctx, c.ref, domain)
	if err != nil {
		return result, invalidMigration("dnsid: migration source unavailable", err)
	}
	if err := validateHistorySize(history.Entries); err != nil {
		return result, err
	}
	checkpoint, err := c.verifyCompleteCheckpoint(history)
	if err != nil {
		return result, err
	}
	if index >= history.CompleteThrough {
		return result, invalidMigration("dnsid: migration cutoff exceeds complete history", nil)
	}
	var prefix []ProvenEntry
	var occurrence *ProvenEntry
	for _, entry := range history.Entries {
		if entry.Index <= index {
			prefix = append(prefix, entry)
		}
		if entry.Index == index {
			copy := entry
			occurrence = &copy
		}
	}
	if occurrence == nil {
		// Trusted bundles may omit later copies. Discovery still has to prove this
		// exact occurrence against the accepted completeness checkpoint.
		entry, err := c.source.ReadEvent(ctx, finalRef)
		if err != nil {
			return result, err
		}
		if entry.Index != index {
			return result, invalidMigration("dnsid: wrong migration cutoff occurrence", nil)
		}
		occurrence = &entry
		prefix = append(prefix, entry)
	}
	verified, events, err := c.verifyHistoryEntries(ctx, domain, prefix, checkpoint)
	if err != nil {
		return result, err
	}
	last := verified[len(verified)-1]
	parsed, err := c.parseCandidateEntry(occurrence.Entry)
	if err != nil {
		return result, err
	}
	signed, err := CanonicalFromEntry(occurrence.Entry)
	if err != nil {
		return result, err
	}
	if string(signed) != string(last.signed) || !candidateAuthorizedByCurrentHistory(parsed.event, signed, last.authorityEntity, last.authorityOperational) {
		return result, invalidMigration("dnsid: cutoff is not a fully signed occurrence of the final logical event", nil)
	}
	entity, operational, state, err := lifecycleStateFromVerified(verified, domain)
	if err != nil {
		return result, err
	}
	if state["status"] != "ACTIVE" {
		return result, invalidMigration("dnsid: cannot migrate terminal history", nil)
	}
	var priorEvidence []dnsidlog.LoggedStateEvidence
	var references []dnsidlog.LogRef
	if verified[0].migration != nil {
		priorEvidence, references, err = validatedPriorEvidence(verified[0].event, verified[0].migration)
		if err != nil {
			return result, err
		}
	}
	for _, event := range verified {
		references = append(references, c.ref.FinalEventRef(event.index))
	}
	references[len(references)-1] = finalRef
	evidence := dnsidlog.LoggedStateEvidence{LogReference: dnsidlog.LogRef(c.ref.String()), LoggedState: dnsidlog.AgentStateActive, HistoryStart: references[0], HistoryEnd: finalRef, CompleteThrough: strconv.FormatUint(history.CompleteThrough, 10), CompletenessMode: history.CompletenessMode, Checkpoint: append([]byte(nil), history.Checkpoint...), FreshnessTime: checkpoint.CheckpointFreshnessTime, PriorEvidence: priorEvidence}
	result = MigrationVerificationResult{EntityKey: entity, ActiveOperationalKey: operational, PriorHistory: events, PriorHistoryReferences: references, PriorEvidence: &evidence, FinalOccurrence: &ProvenEntry{Index: index, Entry: append([]byte(nil), occurrence.Entry...), Proof: append([]byte(nil), occurrence.Proof...)}}
	limits := migrationLimitsForContext(ctx, c.migrationLimits)
	if len(events) > limits.MaxHistoryEvents {
		return MigrationVerificationResult{}, invalidMigration("dnsid: migration history exceeds event limit", nil)
	}
	encoded, err := json.Marshal(result)
	if err != nil {
		return MigrationVerificationResult{}, err
	}
	if int64(len(encoded)) > limits.MaxResponseBytes {
		return MigrationVerificationResult{}, invalidMigration("dnsid: migration history exceeds byte limit", nil)
	}
	return result, nil
}
