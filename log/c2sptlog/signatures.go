package c2sptlog

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"fmt"

	dnsid "github.com/dnsid-ai/dnsid-go"
	"github.com/dnsid-ai/dnsid-go/internal/cryptoutil"
	dnsidlog "github.com/dnsid-ai/dnsid-go/log"
	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
)

func verifyLifecycleVerifiedWithMigration(ctx context.Context, indexed []verifiedEvent, verifyMigration MigrationVerifier, currentLog string) ([]verifiedEvent, []dnsidlog.LogEvent, error) {
	var out []verifiedEvent
	var priorHistory []dnsidlog.LogEvent
	var entityKey jwk.Key
	var currentOperationalKey jwk.Key
	var currentOperationalThumb string
	started := false
	terminal := false
	seen := make(map[string][]byte, len(indexed))
	type authority struct{ entity, operational jwk.Key }
	postStates := make(map[string]authority, len(indexed))
	var lastEventID string
	var nextSeq uint64
	var previousState map[string]any
	for _, item := range indexed {
		if err := ctx.Err(); err != nil {
			return nil, nil, err
		}
		if lastEventID != "" {
			postStates[lastEventID] = authority{entityKey, currentOperationalKey}
		}
		event := item.event
		if len(item.signed) == 0 {
			continue
		}
		canonical := item.signed
		key := EventID(canonical)
		if signed, ok := seen[key]; ok {
			if string(signed) != string(canonical) {
				return nil, nil, dnsid.NewVerificationError(dnsid.VerificationCodeInvalidEvidence, false, "dnsid: logical event ID collision", nil)
			}
			continue
		}
		if started {
			auth := authority{entityKey, currentOperationalKey}
			if prior, ok := postStates[item.chain.previousEventID]; ok {
				auth = prior
			}
			if !candidateAuthorizedByCurrentHistory(event, canonical, auth.entity, auth.operational) {
				continue
			}
			item.authorityEntity, item.authorityOperational = auth.entity, auth.operational
			if terminal {
				return nil, nil, dnsid.NewVerificationError(dnsid.VerificationCodeTerminalState, false, "dnsid: authenticated c2sp-tlog lifecycle event after terminal state", nil)
			}
			if event.Type == dnsidlog.LogEventIssuance {
				return nil, nil, dnsid.NewVerificationError(dnsid.VerificationCodeDuplicateIssuance, false, "dnsid: authenticated additional ISSUANCE", nil)
			}
			if !validChainFields(item, nextSeq, lastEventID, previousState) {
				return nil, nil, dnsid.NewVerificationError(dnsid.VerificationCodeChainContinuity, false, "dnsid: authenticated logical chain conflict", nil)
			}
			if event.Timestamp.Before(out[len(out)-1].event.Timestamp) {
				return nil, nil, dnsid.NewVerificationError(dnsid.VerificationCodeChainContinuity, false, "dnsid: lifecycle timestamps regress", nil)
			}
			if item.parseError != nil {
				return nil, nil, dnsid.NewVerificationError(dnsid.VerificationCodeInvalidEvidence, false, "dnsid: authenticated invalid lifecycle payload", item.parseError)
			}
		}
		if !started {
			// A stream begins with an ISSUANCE, or with a migration-in genesis
			// that re-anchors the identity's keys in the new log and references
			// the prior log for historical continuity.
			if event.Type != dnsidlog.LogEventIssuance && event.Type != dnsidlog.LogEventMigration {
				continue
			}
			if event.Type == dnsidlog.LogEventMigration {
				if verifyMigration == nil {
					return nil, nil, invalidMigration("dnsid: inbound MIGRATION requires verified prior-log history", nil)
				}
				if event.PreviousLog == "" || event.NewLog == "" || event.FinalEntryRef == "" || event.PreviousLog == event.NewLog || (currentLog != "" && event.NewLog != currentLog) {
					return nil, nil, invalidMigration("dnsid: inbound MIGRATION log references are invalid", nil)
				}
				if method, _, err := dnsidlog.ParseLogRef(event.PreviousLog); err != nil {
					return nil, nil, invalidMigration("dnsid: inbound MIGRATION previous log reference is invalid", err)
				} else if method == Method {
					previous, _, err := ParseFinalEventRef(dnsidlog.LogRef(event.FinalEntryRef))
					if err != nil || previous.String() != event.PreviousLog {
						return nil, nil, invalidMigration("dnsid: inbound MIGRATION cutoff does not belong to the previous log", err)
					}
				}
				migration, err := verifyMigration(ctx, event)
				if err != nil {
					return nil, nil, invalidMigration("dnsid: inbound MIGRATION prior history verification failed", err)
				}
				if err := validateMigrationResult(event, migration); err != nil {
					return nil, nil, err
				}
				entityKey = migration.EntityKey
				currentOperationalKey = migration.ActiveOperationalKey
				currentOperationalThumb, _ = thumbprint(currentOperationalKey)
				event.InitialEntityPublicKey = entityKey
				event.InitialEntityThumbprint, _ = thumbprint(entityKey)
				event.InitialOperationalPublicKey = currentOperationalKey
				event.InitialOperationalThumbprint = currentOperationalThumb
				entityKid, _ := entityKey.KeyID()
				if event.InitialEntityKid == "" || event.InitialEntityKid != entityKid {
					return nil, nil, invalidMigration("dnsid: inbound MIGRATION signature kid does not match the verified entity key", nil)
				}
				if err := verifyEventSignature(entityKey, canonical, event.InitialEntitySignature); err != nil {
					return nil, nil, invalidMigration("dnsid: inbound MIGRATION entity signature is invalid", err)
				}
				if item.parseError != nil {
					return nil, nil, invalidMigration("dnsid: invalid authenticated migration payload", item.parseError)
				}
				if !validGenesisChain(item.chain) {
					return nil, nil, dnsid.NewVerificationError(dnsid.VerificationCodeChainContinuity, false, "dnsid: invalid c2sp-tlog migration genesis chain", nil)
				}
				nextSeq = 1
				entityThumb, _ := thumbprint(entityKey)
				previousState = activeLifecycleState(event.Domain, entityThumb, currentOperationalThumb)
				lastEventID = key
				started = true
				seen[key] = canonical
				item.authorityEntity, item.authorityOperational = entityKey, currentOperationalKey
				item.event = event
				item.migration = &migration
				out = append(out, item)
				priorHistory = append([]dnsidlog.LogEvent(nil), migration.PriorHistory...)
				continue
			}
			if !candidateAuthorizedByCurrentHistory(event, canonical, event.InitialEntityPublicKey, event.InitialOperationalPublicKey) {
				continue
			}
			if event.InitialOperationalThumbprint == "" {
				thumb, err := thumbprint(event.InitialOperationalPublicKey)
				if err != nil {
					continue
				}
				event.InitialOperationalThumbprint = thumb
			}
			if item.parseError != nil {
				return nil, nil, dnsid.NewVerificationError(dnsid.VerificationCodeInvalidEvidence, false, "dnsid: invalid authenticated genesis", item.parseError)
			}
			if !validGenesisChain(item.chain) {
				return nil, nil, dnsid.NewVerificationError(dnsid.VerificationCodeChainContinuity, false, "dnsid: invalid c2sp-tlog genesis chain", nil)
			}
			nextSeq = 1
			entityKey = event.InitialEntityPublicKey
			currentOperationalKey = event.InitialOperationalPublicKey
			currentOperationalThumb = event.InitialOperationalThumbprint
			entityThumb, err := thumbprint(entityKey)
			if err != nil || event.InitialEntityThumbprint == "" || entityThumb != event.InitialEntityThumbprint || entityThumb == currentOperationalThumb {
				continue
			}
			previousState = activeLifecycleState(event.Domain, entityThumb, currentOperationalThumb)
			lastEventID = key
			started = true
			seen[key] = canonical
			item.authorityEntity, item.authorityOperational = entityKey, currentOperationalKey
			item.event = event
			out = append(out, item)
			continue
		}
		switch event.Type {
		case dnsidlog.LogEventKeyRotation:
			if event.PreviousOperationalThumbprint != currentOperationalThumb || event.NewOperationalPublicKey == nil || event.NewOperationalThumbprint == "" {
				return nil, nil, dnsid.NewVerificationError(dnsid.VerificationCodeKeyContinuity, false, "dnsid: authenticated KEY_ROTATION does not continue from the active key", nil)
			}
			newThumb, err := thumbprint(event.NewOperationalPublicKey)
			if err != nil || newThumb != event.NewOperationalThumbprint || newThumb == currentOperationalThumb || newThumb == previousState["entity_thumb"] {
				return nil, nil, dnsid.NewVerificationError(dnsid.VerificationCodeKeyContinuity, false, "dnsid: authenticated KEY_ROTATION new key binding is invalid", err)
			}
			currentOperationalKey = event.NewOperationalPublicKey
			currentOperationalThumb = event.NewOperationalThumbprint
			entityThumb, err := thumbprint(entityKey)
			if err != nil {
				continue
			}
			previousState = activeLifecycleState(event.Domain, entityThumb, currentOperationalThumb)
		case dnsidlog.LogEventRevocation, dnsidlog.LogEventRetirement, dnsidlog.LogEventMigration, dnsidlog.LogEventDelegation:
			if event.Type == dnsidlog.LogEventRevocation && !dnsidlog.ValidRevocationReason(event.Reason) {
				return nil, nil, dnsid.NewVerificationError(dnsid.VerificationCodeInvalidEvidence, false, "dnsid: authenticated REVOCATION reason is invalid", nil)
			}
			if event.Type == dnsidlog.LogEventMigration {
				return nil, nil, invalidMigration("dnsid: c2sp-tlog MIGRATION must be destination genesis", nil)
			}
			if event.Type == dnsidlog.LogEventDelegation && (event.Delegatee == "" || event.Scope == "" || event.Expiry.IsZero()) {
				return nil, nil, dnsid.NewVerificationError(dnsid.VerificationCodeInvalidEvidence, false, "dnsid: authenticated DELEGATION is invalid", nil)
			}
			if event.Type != dnsidlog.LogEventDelegation {
				entityThumb, err := thumbprint(entityKey)
				if err != nil {
					continue
				}
				previousState = activeLifecycleState(event.Domain, entityThumb, currentOperationalThumb)
				switch event.Type {
				case dnsidlog.LogEventRevocation:
					previousState["status"] = "REVOKED"
				case dnsidlog.LogEventRetirement:
					previousState["status"] = "RETIRED"
				}
			}
			if event.Type == dnsidlog.LogEventRevocation || event.Type == dnsidlog.LogEventRetirement {
				terminal = true
			}
		default:
			continue
		}
		seen[key] = canonical
		item.event = event
		out = append(out, item)
		lastEventID = key
		nextSeq++
	}
	if len(out) == 0 {
		return nil, nil, fmt.Errorf("dnsid: no valid c2sp-tlog lifecycle events")
	}
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}
	return out, priorHistory, nil
}

func candidateAuthorizedByCurrentHistory(event dnsidlog.LogEvent, canonical []byte, entityKey, operationalKey jwk.Key) bool {
	key := entityKey
	kid, signature := event.InitialEntityKid, event.InitialEntitySignature
	switch event.Type {
	case dnsidlog.LogEventKeyRotation:
		key = operationalKey
		kid, signature = event.PreviousOperationalKid, event.PreviousOperationalSignature
	case dnsidlog.LogEventIssuance, dnsidlog.LogEventRevocation, dnsidlog.LogEventRetirement,
		dnsidlog.LogEventMigration, dnsidlog.LogEventDelegation:
	default:
		return false
	}
	if key == nil {
		return false
	}
	expectedKid, _ := key.KeyID()
	if kid == "" || kid != expectedKid || verifyEventSignature(key, canonical, signature) != nil {
		return false
	}
	var counterKey jwk.Key
	var counterKid, counterSignature string
	switch event.Type {
	case dnsidlog.LogEventIssuance:
		counterKey, counterKid, counterSignature = event.InitialOperationalPublicKey, event.InitialOperationalKid, event.InitialOperationalSignature
	case dnsidlog.LogEventKeyRotation:
		counterKey, counterKid, counterSignature = event.NewOperationalPublicKey, event.NewOperationalKid, event.NewOperationalSignature
	default:
		return true
	}
	if counterKey == nil {
		return false
	}
	want, _ := counterKey.KeyID()
	return counterKid != "" && counterKid == want && verifyEventSignature(counterKey, canonical, counterSignature) == nil
}

func validateMigrationResult(event dnsidlog.LogEvent, migration MigrationVerificationResult) error {
	if migration.EntityKey == nil || migration.ActiveOperationalKey == nil || len(migration.PriorHistory) == 0 {
		return invalidMigration("dnsid: inbound MIGRATION prior history and keys are required", nil)
	}
	entityThumb, err := thumbprint(migration.EntityKey)
	if err != nil {
		return invalidMigration("dnsid: inbound MIGRATION entity key is invalid", err)
	}
	operationalThumb, err := thumbprint(migration.ActiveOperationalKey)
	if err != nil || entityThumb == operationalThumb {
		return invalidMigration("dnsid: inbound MIGRATION operational key is invalid", err)
	}
	for _, prior := range migration.PriorHistory {
		if prior.Type == dnsidlog.LogEventMigration && prior.PreviousLog == event.PreviousLog && prior.NewLog == event.NewLog && prior.FinalEntryRef == event.FinalEntryRef {
			return invalidMigration("dnsid: inbound MIGRATION must appear exactly once in stitched history", nil)
		}
	}
	latest := migration.PriorHistory[0].Timestamp
	for _, prior := range migration.PriorHistory[1:] {
		if prior.Timestamp.After(latest) {
			latest = prior.Timestamp
		}
	}
	if event.Timestamp.Before(latest) {
		return invalidMigration("dnsid: migration timestamp precedes imported history", nil)
	}
	snapshot, err := dnsidlog.NewDomainLog(event.Domain, migration.PriorHistory).SnapshotAt(latest)
	if err != nil || snapshot.HistoricalState != dnsidlog.AgentStateActive || snapshot.ActiveKeyThumbprint != operationalThumb {
		return invalidMigration("dnsid: inbound MIGRATION prior history does not establish the active operational key", err)
	}
	var priorEntityKey jwk.Key
	for _, prior := range migration.PriorHistory {
		if prior.Type == dnsidlog.LogEventIssuance {
			priorEntityKey = prior.InitialEntityPublicKey
			break
		}
	}
	priorEntityThumb, err := thumbprint(priorEntityKey)
	if err != nil || priorEntityThumb != entityThumb {
		return invalidMigration("dnsid: inbound MIGRATION prior history does not establish the entity key", err)
	}
	return nil
}

func invalidMigration(message string, cause error) error {
	return dnsid.NewVerificationError(dnsid.VerificationCodeInvalidMigration, false, message, cause)
}

func validGenesisChain(chain chainFields) bool {
	return !chain.invalid && chain.sequence != nil && *chain.sequence == 0 && chain.previousEventID == "" && chain.previousStateHash == ""
}

func validChainFields(event verifiedEvent, seq uint64, previousEventID string, previousState map[string]any) bool {
	return !event.chain.invalid && event.chain.sequence != nil && *event.chain.sequence == seq &&
		validHash(event.chain.previousEventID) &&
		event.chain.previousEventID == previousEventID && event.chain.previousStateHash == lifecycleStateHash(previousState)
}

func activeLifecycleState(domain, entityThumb, operationalThumb string) map[string]any {
	return map[string]any{
		"fqdn":              domain,
		"status":            "ACTIVE",
		"entity_thumb":      entityThumb,
		"operational_thumb": operationalThumb,
	}
}

func lifecycleStateHash(state map[string]any) string {
	canonical, err := canonicalJSON(state)
	if err != nil {
		return ""
	}
	digest := sha256.New()
	_, _ = digest.Write([]byte("dnsid-c2sp-state-v1"))
	_, _ = digest.Write(canonical)
	return base64.RawURLEncoding.EncodeToString(digest.Sum(nil))
}

func verifyEventSignature(key jwk.Key, payload []byte, sigValue string) error {
	if key == nil {
		return fmt.Errorf("dnsid: missing c2sp-tlog signature key")
	}
	if sigValue == "" {
		return fmt.Errorf("dnsid: missing c2sp-tlog signature")
	}
	sig, err := base64.RawURLEncoding.DecodeString(sigValue)
	if err != nil {
		return fmt.Errorf("dnsid: invalid c2sp-tlog signature encoding: %w", err)
	}
	switch key.KeyType() {
	case jwa.OKP():
		crv, ok := jwkCurve(key)
		if !ok || crv != jwa.Ed25519() {
			return fmt.Errorf("dnsid: unsupported OKP c2sp-tlog signature key")
		}
		var pub ed25519.PublicKey
		if err := jwk.Export(key, &pub); err != nil {
			return fmt.Errorf("dnsid: exporting Ed25519 key: %w", err)
		}
		if !ed25519.Verify(pub, payload, sig) {
			return fmt.Errorf("dnsid: invalid Ed25519 c2sp-tlog signature")
		}
		return nil
	case jwa.EC():
		crv, ok := jwkCurve(key)
		if !ok || crv != jwa.P256() {
			return fmt.Errorf("dnsid: unsupported EC c2sp-tlog signature key")
		}
		var pub ecdsa.PublicKey
		if err := jwk.Export(key, &pub); err != nil {
			return fmt.Errorf("dnsid: exporting P-256 key: %w", err)
		}
		// C2SP accepts both ECDSA S representatives. Preserve the exact entry
		// bytes for inclusion verification; logical IDs provide replay identity.
		if len(sig) != cryptoutil.ES256SignatureSize || cryptoutil.ValidateP256PublicKey(&pub) != nil {
			return fmt.Errorf("dnsid: invalid ES256 c2sp-tlog signature")
		}
		r, s := cryptoutil.ES256RawRS(sig)
		digest := sha256.Sum256(payload)
		if !ecdsa.Verify(&pub, digest[:], r, s) {
			return fmt.Errorf("dnsid: invalid ES256 c2sp-tlog signature")
		}
		return nil
	default:
		return fmt.Errorf("dnsid: unsupported c2sp-tlog signature key type")
	}
}

func jwkCurve(key jwk.Key) (jwa.EllipticCurveAlgorithm, bool) {
	type curveKey interface {
		Crv() (jwa.EllipticCurveAlgorithm, bool)
	}
	if k, ok := key.(curveKey); ok {
		return k.Crv()
	}
	return jwa.EmptyEllipticCurveAlgorithm(), false
}
