package c2sptlog

import (
	"context"
	"errors"
	"fmt"

	dnsid "github.com/dnsid-ai/dnsid-go"
	dnsidlog "github.com/dnsid-ai/dnsid-go/log"
)

// LifecycleState is a stream's computed state after a logical event (method
// Section 13). Its Hash is the next event's prev_state_hash.
type LifecycleState struct {
	FQDN             string
	Status           string // ACTIVE, REVOKED, or RETIRED
	EntityThumb      string
	OperationalThumb string
}

func (s LifecycleState) object() map[string]any {
	return map[string]any{
		"fqdn":              s.FQDN,
		"status":            s.Status,
		"entity_thumb":      s.EntityThumb,
		"operational_thumb": s.OperationalThumb,
	}
}

// Hash returns base64url-no-pad(SHA-256("dnsid-c2sp-state-v1" || JCS(state))).
func (s LifecycleState) Hash() string { return lifecycleStateHash(s.object()) }

// StreamHead is the last applied logical event of a stream and the state it
// leaves.
type StreamHead struct {
	Seq     uint64
	EventID string
	Type    dnsidlog.LogEventType
	State   LifecycleState
	// GovernanceID is the gi recorded by the stream's genesis.
	GovernanceID string
}

// CheckAppend reports whether candidate, appended after history, is applied
// as the stream's next logical event, and returns the head after it. history
// is the stream's entries in log order. Replay uses the same rules as
// verification, without inclusion proofs, checkpoints, or inbound MIGRATION
// support: a MIGRATION candidate is never applied.
//
// Errors are *dnsid.ParseError or *dnsid.ValidationError for malformed
// entries or entries for another stream, and *dnsid.VerificationError
// otherwise: VerificationCodeSignatureInvalid when the candidate is not
// authorized by the stream's keys, VerificationCodeChainContinuity for a
// stale or unknown predecessor, VerificationCodeTerminalState,
// VerificationCodeDuplicateIssuance, or VerificationCodeKeyContinuity for an
// invalid transition, and VerificationCodeInvalidEvidence for other invalid
// candidates. History that does not replay cleanly is an error.
func (c *Client) CheckAppend(ctx context.Context, history [][]byte, candidate []byte) (StreamHead, error) {
	if c == nil {
		return StreamHead{}, dnsid.NewArgumentError("dnsid: c2sp-tlog client is required", nil)
	}
	entries := append(history[:len(history):len(history)], candidate)
	proven := make([]ProvenEntry, len(entries))
	for i, entry := range entries {
		proven[i] = ProvenEntry{Index: uint64(i), Entry: entry}
	}
	if err := validateHistorySize(proven); err != nil {
		return StreamHead{}, dnsid.NewValidationError("dnsid: c2sp-tlog stream", err)
	}
	verified := make([]verifiedEvent, 0, len(entries))
	var domain string
	for i, entry := range entries {
		which := "candidate"
		if i < len(history) {
			which = fmt.Sprintf("history entry %d", i)
		}
		if err := c.validateEntryMetadata(entry); err != nil {
			return StreamHead{}, dnsid.NewValidationError("dnsid: c2sp-tlog "+which+" context", err)
		}
		parsed, err := parseEventFromEntry(entry)
		if err != nil {
			return StreamHead{}, dnsid.NewParseError("dnsid: parsing c2sp-tlog "+which, err)
		}
		if parsed.validationError != nil {
			return StreamHead{}, dnsid.NewValidationError("dnsid: invalid c2sp-tlog "+which, parsed.validationError)
		}
		if i == 0 {
			domain = parsed.event.Domain
		} else if parsed.event.Domain != domain {
			return StreamHead{}, dnsid.NewValidationError("dnsid: c2sp-tlog "+which+" fqdn differs from the stream's", nil)
		}
		signed, err := CanonicalFromEntry(entry)
		if err != nil {
			return StreamHead{}, err
		}
		verified = append(verified, verifiedEvent{event: parsed.event, chain: parsed.chain, index: uint64(i), signed: signed})
	}

	applied, _, err := verifyLifecycleVerifiedWithMigration(ctx, verified, nil, c.ref.String())
	var verr *dnsid.VerificationError
	switch {
	case errors.As(err, &verr):
		return StreamHead{}, err
	case err != nil && ctx.Err() != nil:
		return StreamHead{}, err
	}
	if len(applied) < len(history) {
		return StreamHead{}, fmt.Errorf("dnsid: c2sp-tlog history does not replay: %d of %d entries applied", len(applied), len(history))
	}
	if len(applied) == len(history) {
		return StreamHead{}, notApplied(verified[len(verified)-1], applied)
	}
	last := applied[len(applied)-1]
	_, _, state, err := lifecycleStateFromVerified(applied, domain)
	if err != nil {
		return StreamHead{}, err
	}
	fqdn, fqdnOK := state["fqdn"].(string)
	status, statusOK := state["status"].(string)
	entityThumb, entityOK := state["entity_thumb"].(string)
	operationalThumb, operationalOK := state["operational_thumb"].(string)
	if !fqdnOK || !statusOK || !entityOK || !operationalOK {
		return StreamHead{}, fmt.Errorf("dnsid: c2sp-tlog computed lifecycle state has invalid field types")
	}
	return StreamHead{
		Seq:     *last.chain.sequence,
		EventID: EventID(last.signed),
		Type:    last.event.Type,
		State: LifecycleState{
			FQDN:             fqdn,
			Status:           status,
			EntityThumb:      entityThumb,
			OperationalThumb: operationalThumb,
		},
		GovernanceID: applied[0].event.GovernanceID,
	}, nil
}

// notApplied explains why replay skipped candidate after the applied history.
func notApplied(candidate verifiedEvent, applied []verifiedEvent) error {
	event := candidate.event
	if len(applied) == 0 {
		switch event.Type {
		case dnsidlog.LogEventIssuance:
			if !candidateAuthorizedByCurrentHistory(event, candidate.signed, event.InitialEntityPublicKey, event.InitialOperationalPublicKey) {
				return dnsid.NewVerificationError(dnsid.VerificationCodeSignatureInvalid, false, "dnsid: c2sp-tlog ISSUANCE signatures do not verify", nil)
			}
			return dnsid.NewVerificationError(dnsid.VerificationCodeInvalidEvidence, false, "dnsid: c2sp-tlog ISSUANCE key bindings are invalid", nil)
		case dnsidlog.LogEventMigration:
			return dnsid.NewVerificationError(dnsid.VerificationCodeInvalidMigration, false, "dnsid: inbound c2sp-tlog MIGRATION is not supported", nil)
		default:
			return dnsid.NewVerificationError(dnsid.VerificationCodeChainContinuity, false, "dnsid: c2sp-tlog stream has no genesis", nil)
		}
	}
	entity, operational, _, err := lifecycleStateFromVerified(applied, event.Domain)
	if err != nil {
		return err
	}
	if !candidateAuthorizedByCurrentHistory(event, candidate.signed, entity, operational) {
		return dnsid.NewVerificationError(dnsid.VerificationCodeSignatureInvalid, false, "dnsid: c2sp-tlog candidate is not authorized by the stream's keys", nil)
	}
	return dnsid.NewVerificationError(dnsid.VerificationCodeInvalidEvidence, false, "dnsid: c2sp-tlog candidate is not applied", nil)
}
