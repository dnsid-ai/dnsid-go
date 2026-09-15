package c2sptlog

import (
	"bytes"
	"crypto"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	dnsid "github.com/dnsid-ai/dnsid-go"
	dnsidlog "github.com/dnsid-ai/dnsid-go/log"
	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
)

type signatureValue struct {
	Kid string `json:"kid"`
	Sig string `json:"sig"`
}

// Chain is c2sp-tlog logical predecessor metadata for every scope.
// Sequence is zero for genesis; successors name the preceding event's ID
// (excluding signatures) and computed state hash. Derive values with
// Client.ChainForWrite; log indexes and leaf hashes are inclusion evidence only.
type Chain struct {
	Sequence          uint64
	PreviousEventID   string
	PreviousStateHash string
}

type chainFields struct {
	sequence          *uint64
	previousEventID   string
	invalid           bool
	previousStateHash string
}

func chainFieldsFromChain(event dnsidlog.LogEvent, chain Chain) *chainFields {
	fields := &chainFields{sequence: &chain.Sequence}
	if chain.Sequence != 0 || event.Type != dnsidlog.LogEventIssuance {
		fields.previousEventID = chain.PreviousEventID
		fields.previousStateHash = chain.PreviousStateHash
	}
	return fields
}

type parsedEvent struct {
	event           dnsidlog.LogEvent
	chain           chainFields
	validationError error
}

// Canonical returns the canonical JCS bytes that lifecycle signatures for
// event are computed over, contextualized with the client's reference and
// excluding signatures. ISSUANCE and inbound MIGRATION events derive
// seq=0; later events require CanonicalWithChain.
func (c *Client) Canonical(event dnsidlog.LogEvent) ([]byte, error) {
	chain, err := c.chainForWrite(event)
	if err != nil {
		return nil, err
	}
	return c.canonicalWithChain(event, chain)
}

// CanonicalWithChain is Canonical with caller-supplied logical stream-chain
// metadata, as required for non-genesis events in every scope.
func (c *Client) CanonicalWithChain(event dnsidlog.LogEvent, chain Chain) ([]byte, error) {
	if err := c.validateChain(event, chain); err != nil {
		return nil, err
	}
	return c.canonicalWithChain(event, chainFieldsFromChain(event, chain))
}

func (c *Client) canonicalWithChain(event dnsidlog.LogEvent, chain *chainFields) ([]byte, error) {
	if err := c.validateWritableStream(event); err != nil {
		return nil, err
	}
	payload, err := payloadFromEventWithChain(event, false, &c.ref, chain)
	if err != nil {
		return nil, err
	}
	return canonicalJSON(payload)
}

// Canonical returns the canonical JCS signing bytes for event without any
// stream context. Use Client.Canonical when the event is destined for a
// specific stream, since all streams contextualize the signed payload.
func Canonical(event dnsidlog.LogEvent) ([]byte, error) {
	payload, err := payloadFromEvent(event, false, nil)
	if err != nil {
		return nil, err
	}
	return canonicalJSON(payload)
}

// EntryBytes returns the canonical entry bytes for event, including its
// signatures, without any stream context. It returns an error if the event
// has no signatures or exceeds the maximum entry size. Use Client.EntryBytes
// for stream-contextualized entries.
func EntryBytes(event dnsidlog.LogEvent) ([]byte, error) {
	return entryBytes(event, nil)
}

func entryBytes(event dnsidlog.LogEvent, ref *Reference) ([]byte, error) {
	return entryBytesWithChain(event, ref, nil)
}

func entryBytesWithChain(event dnsidlog.LogEvent, ref *Reference, chain *chainFields) ([]byte, error) {
	payload, err := payloadFromEventWithChain(event, true, ref, chain)
	if err != nil {
		return nil, err
	}
	body, err := canonicalJSON(payload)
	if err != nil {
		return nil, err
	}
	if len(body) > maxEntrySize {
		return nil, fmt.Errorf("dnsid: c2sp-tlog entry is %d bytes, maximum is %d", len(body), maxEntrySize)
	}
	return body, nil
}

// CanonicalFromEntry recovers the signed bytes from stored entry bytes by
// stripping the signatures and re-canonicalizing. It returns an error if
// entry is empty, oversized, or not canonical JCS.
func CanonicalFromEntry(entry []byte) (canonicalResult []byte, errResult error) {
	defer func() {
		if errResult != nil {
			errResult = dnsid.NewParseError("dnsid: parsing c2sp-tlog entry", errResult)
		}
	}()
	payload, err := payloadObjectFromEntry(entry)
	if err != nil {
		return nil, err
	}
	delete(payload, "sigs")
	return canonicalJSON(payload)
}

// LogEventFromEntry parses stored entry bytes into the shared lifecycle
// event representation. The entry must be canonical JCS with a complete,
// well-formed signature set and valid lifecycle fields; the signatures
// themselves are not cryptographically verified.
func LogEventFromEntry(entry []byte) (eventResult dnsidlog.LogEvent, errResult error) {
	payload, err := payloadObjectFromEntry(entry)
	if err != nil {
		return dnsidlog.LogEvent{}, dnsid.NewParseError("dnsid: parsing c2sp-tlog lifecycle entry", err)
	}
	parsed, err := eventFromPayload(payload)
	if err != nil {
		return dnsidlog.LogEvent{}, dnsid.NewValidationError("dnsid: validating c2sp-tlog lifecycle entry", err)
	}
	if parsed.validationError != nil {
		return dnsidlog.LogEvent{}, dnsid.NewValidationError("dnsid: invalid lifecycle event", parsed.validationError)
	}
	required, err := requiredSignerRoles(parsed.event.Type)
	if err != nil {
		return dnsidlog.LogEvent{}, dnsid.NewValidationError("dnsid: validating c2sp-tlog lifecycle entry", err)
	}
	if err := validateSignatureShape(payload, required, true); err != nil {
		return dnsidlog.LogEvent{}, dnsid.NewValidationError("dnsid: validating c2sp-tlog lifecycle entry", err)
	}
	if err := validateEmbeddedSignatureKids(parsed.event); err != nil {
		return dnsidlog.LogEvent{}, dnsid.NewValidationError("dnsid: validating c2sp-tlog lifecycle entry", err)
	}
	return parsed.event, nil
}

func parseEventFromEntry(entry []byte) (parsedEvent, error) {
	payload, err := payloadObjectFromEntry(entry)
	if err != nil {
		return parsedEvent{}, err
	}
	parsed, err := eventFromPayload(payload)
	if err != nil {
		return parsedEvent{}, err
	}
	required, err := requiredSignerRoles(parsed.event.Type)
	if err != nil {
		return parsedEvent{}, err
	}
	if err := validateSignatureShape(payload, required, true); err != nil {
		return parsedEvent{}, err
	}
	parsed.validationError = errors.Join(parsed.validationError, validateEmbeddedSignatureKids(parsed.event))
	return parsed, nil
}

func payloadObjectFromEntry(entry []byte) (map[string]any, error) {
	if len(entry) == 0 {
		return nil, fmt.Errorf("dnsid: c2sp-tlog entry must be between 1 and %d bytes", maxEntrySize)
	}
	if len(entry) > maxEntrySize {
		return nil, fmt.Errorf("dnsid: c2sp-tlog entry is %d bytes, maximum is %d", len(entry), maxEntrySize)
	}
	payload, err := decodeJSONObject(entry)
	if err != nil {
		return nil, err
	}
	if err := validatePayloadJSON(payload); err != nil {
		return nil, err
	}
	canonical, err := canonicalJSON(payload)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(entry, canonical) {
		return nil, fmt.Errorf("dnsid: c2sp-tlog entry is not canonical JCS")
	}
	return payload, nil
}

func payloadFromEvent(event dnsidlog.LogEvent, includeSigs bool, ref *Reference) (map[string]any, error) {
	return payloadFromEventWithChain(event, includeSigs, ref, nil)
}

func payloadFromEventWithChain(event dnsidlog.LogEvent, includeSigs bool, ref *Reference, chain *chainFields) (map[string]any, error) {
	if event.Type == "" {
		return nil, fmt.Errorf("dnsid: c2sp-tlog event type is required")
	}
	if event.Domain == "" {
		return nil, fmt.Errorf("dnsid: c2sp-tlog event domain is required")
	}
	if event.Timestamp.IsZero() {
		return nil, fmt.Errorf("dnsid: c2sp-tlog event timestamp is required")
	}
	if err := validateLifecycleFields(event); err != nil {
		return nil, err
	}
	ts := event.Timestamp.Unix()
	if ts < 0 || ts > maxJSONInteger {
		return nil, fmt.Errorf("dnsid: c2sp-tlog event timestamp out of range")
	}
	payload := map[string]any{
		"v":    1,
		"kind": Kind,
		"type": string(event.Type),
		"fqdn": event.Domain,
		"ts":   ts,
	}
	if ref != nil {
		origin, err := ref.Origin()
		if err != nil {
			return nil, err
		}
		payload["method"] = Method
		payload["log_origin"] = origin
		payload["stream_id"] = ref.StreamID
		payload["lr"] = ref.String()
	}
	if chain != nil {
		if chain.sequence != nil {
			payload["seq"] = *chain.sequence
		}
		if chain.previousEventID != "" {
			payload["prev_event_id"] = chain.previousEventID
		}
		if chain.previousStateHash != "" {
			payload["prev_state_hash"] = chain.previousStateHash
		}
	}
	switch event.Type {
	case dnsidlog.LogEventIssuance:
		if event.GovernanceID != "" {
			payload["gi"] = event.GovernanceID
		}
		if event.InitialOperationalPublicKey != nil {
			ku, err := keyAsJSON(event.InitialOperationalPublicKey)
			if err != nil {
				return nil, err
			}
			payload["ku"] = ku
		}
		if event.InitialEntityPublicKey != nil {
			ek, err := keyAsJSON(event.InitialEntityPublicKey)
			if err != nil {
				return nil, err
			}
			payload["ek"] = ek
		}
	case dnsidlog.LogEventKeyRotation:
		if event.PreviousOperationalThumbprint != "" {
			payload["prev_thumb"] = event.PreviousOperationalThumbprint
		}
		if event.NewOperationalThumbprint != "" {
			payload["new_thumb"] = event.NewOperationalThumbprint
		}
		if event.NewOperationalPublicKey != nil {
			newKU, err := keyAsJSON(event.NewOperationalPublicKey)
			if err != nil {
				return nil, err
			}
			payload["new_ku"] = newKU
		}
	case dnsidlog.LogEventRevocation:
		if event.Reason != "" {
			payload["reason"] = event.Reason
		}
	case dnsidlog.LogEventRetirement:
	case dnsidlog.LogEventMigration:
		if event.PreviousLog != "" {
			payload["prev_lr"] = event.PreviousLog
		}
		if event.NewLog != "" {
			payload["new_lr"] = event.NewLog
		}
		if event.FinalEntryRef != "" {
			payload["prev_ref"] = event.FinalEntryRef
		}
	case dnsidlog.LogEventDelegation:
		if event.Delegatee != "" {
			payload["delegatee"] = event.Delegatee
		}
		if event.Scope != "" {
			payload["scope"] = event.Scope
		}
		if !event.Expiry.IsZero() {
			payload["expiry"] = event.Expiry.Unix()
		}
	default:
		return nil, fmt.Errorf("dnsid: unsupported c2sp-tlog event type %q", event.Type)
	}
	if includeSigs {
		sigs := signaturesFromEvent(event)
		if len(sigs) == 0 {
			return nil, fmt.Errorf("dnsid: c2sp-tlog event has no signatures")
		}
		payload["sigs"] = sigs
	}
	return payload, nil
}

func signaturesFromEvent(event dnsidlog.LogEvent) map[string]any {
	sigs := make(map[string]any)
	switch event.Type {
	case dnsidlog.LogEventIssuance:
		if event.InitialEntityKid != "" && event.InitialEntitySignature != "" {
			sigs["ae"] = map[string]any{"kid": event.InitialEntityKid, "sig": event.InitialEntitySignature}
		}
		if event.InitialOperationalKid != "" && event.InitialOperationalSignature != "" {
			sigs["op"] = map[string]any{"kid": event.InitialOperationalKid, "sig": event.InitialOperationalSignature}
		}
	case dnsidlog.LogEventKeyRotation:
		if event.PreviousOperationalKid != "" && event.PreviousOperationalSignature != "" {
			sigs["prev_op"] = map[string]any{"kid": event.PreviousOperationalKid, "sig": event.PreviousOperationalSignature}
		}
		if event.NewOperationalKid != "" && event.NewOperationalSignature != "" {
			sigs["new_op"] = map[string]any{"kid": event.NewOperationalKid, "sig": event.NewOperationalSignature}
		}
	default:
		if event.InitialEntityKid != "" && event.InitialEntitySignature != "" {
			sigs["ae"] = map[string]any{"kid": event.InitialEntityKid, "sig": event.InitialEntitySignature}
		}
	}
	return sigs
}

func keyAsJSON(key jwk.Key) (any, error) {
	data, err := json.Marshal(key)
	if err != nil {
		return nil, fmt.Errorf("dnsid: marshal JWK: %w", err)
	}
	decoded, err := decodeJSONObject(data)
	if err != nil {
		return nil, fmt.Errorf("dnsid: decode JWK: %w", err)
	}
	return decoded, nil
}

func eventFromPayload(payload map[string]any) (parsedEvent, error) {
	version, err := intField(payload, "v")
	if err != nil {
		return parsedEvent{}, err
	}
	if version != 1 {
		return parsedEvent{}, fmt.Errorf("dnsid: unsupported c2sp-tlog event version %d", version)
	}
	kind, err := stringField(payload, "kind")
	if err != nil {
		return parsedEvent{}, err
	}
	if kind != Kind {
		return parsedEvent{}, fmt.Errorf("dnsid: unsupported c2sp-tlog event kind %q", kind)
	}
	typeStr, err := stringField(payload, "type")
	if err != nil {
		return parsedEvent{}, err
	}
	fqdn, err := stringField(payload, "fqdn")
	if err != nil {
		return parsedEvent{}, err
	}
	// Retain semantic errors until required signatures have been checked.
	// A signed contradiction must not disappear as unauthenticated noise.
	ts, fieldErr := int64Field(payload, "ts")
	if ts < 0 || ts > maxJSONInteger {
		fieldErr = fmt.Errorf("dnsid: c2sp-tlog event timestamp out of range")
	}
	event := dnsidlog.LogEvent{
		Type:      dnsidlog.LogEventType(typeStr),
		Domain:    fqdn,
		Timestamp: time.Unix(ts, 0).UTC(),
	}
	var chain chainFields
	if seq, ok, err := optionalUint64(payload, "seq"); err != nil {
		chain.invalid = true
	} else if ok {
		chain.sequence = &seq
	}
	for _, name := range []string{"prev_index", "prev_leaf_hash", "event_id"} {
		if _, exists := payload[name]; exists {
			chain.invalid = true
		}
	}
	chain.previousEventID, _ = optionalString(payload, "prev_event_id")
	chain.previousStateHash, _ = optionalString(payload, "prev_state_hash")
	for _, name := range []string{"prev_event_id", "prev_state_hash"} {
		if value, exists := payload[name]; exists {
			s, ok := value.(string)
			if !ok || !validHash(s) {
				chain.invalid = true
			}
		}
	}
	switch event.Type {
	case dnsidlog.LogEventIssuance:
		event.GovernanceID, _ = optionalString(payload, "gi")
		if key, ok, err := optionalJWK(payload, "ku"); err != nil {
			fieldErr = errors.Join(fieldErr, err)
		} else if ok {
			event.InitialOperationalPublicKey = key
			event.InitialOperationalThumbprint, _ = thumbprint(key)
		}
		if key, ok, err := optionalJWK(payload, "ek"); err != nil {
			fieldErr = errors.Join(fieldErr, err)
		} else if ok {
			event.InitialEntityPublicKey = key
			event.InitialEntityThumbprint, _ = thumbprint(key)
		}
	case dnsidlog.LogEventKeyRotation:
		event.PreviousOperationalThumbprint, _ = optionalString(payload, "prev_thumb")
		event.NewOperationalThumbprint, _ = optionalString(payload, "new_thumb")
		if key, ok, err := optionalJWK(payload, "new_ku"); err != nil {
			fieldErr = errors.Join(fieldErr, err)
		} else if ok {
			event.NewOperationalPublicKey = key
		}
	case dnsidlog.LogEventRevocation:
		event.Reason, _ = optionalString(payload, "reason")
	case dnsidlog.LogEventRetirement:
	case dnsidlog.LogEventMigration:
		event.PreviousLog, _ = optionalString(payload, "prev_lr")
		event.NewLog, _ = optionalString(payload, "new_lr")
		event.FinalEntryRef, _ = optionalString(payload, "prev_ref")
	case dnsidlog.LogEventDelegation:
		event.Delegatee, _ = optionalString(payload, "delegatee")
		event.Scope, _ = optionalString(payload, "scope")
		if exp, ok, err := optionalInt64(payload, "expiry"); err != nil {
			fieldErr = errors.Join(fieldErr, err)
		} else if ok {
			event.Expiry = time.Unix(exp, 0).UTC()
		}
	default:
		return parsedEvent{}, fmt.Errorf("dnsid: unsupported c2sp-tlog event type %q", event.Type)
	}
	applySignatures(&event, payload)
	return parsedEvent{event: event, chain: chain, validationError: errors.Join(fieldErr, validateLifecycleFields(event))}, nil
}

func validateLifecycleFields(event dnsidlog.LogEvent) error {
	normalized, err := dnsid.NormalizeFQDN(event.Domain)
	if err != nil || normalized != event.Domain {
		return fmt.Errorf("dnsid: c2sp-tlog fqdn must be normalized")
	}
	switch event.Type {
	case dnsidlog.LogEventIssuance:
		if event.GovernanceID == "" || event.InitialOperationalPublicKey == nil || event.InitialEntityPublicKey == nil {
			return fmt.Errorf("dnsid: c2sp-tlog ISSUANCE requires gi, ek, and ku")
		}
		if err := validateSigningJWK(event.InitialEntityPublicKey, "ek"); err != nil {
			return err
		}
		if err := validateSigningJWK(event.InitialOperationalPublicKey, "ku"); err != nil {
			return err
		}
		entityThumb, err := thumbprint(event.InitialEntityPublicKey)
		if err != nil {
			return fmt.Errorf("dnsid: c2sp-tlog ek thumbprint: %w", err)
		}
		operationalThumb, err := thumbprint(event.InitialOperationalPublicKey)
		if err != nil {
			return fmt.Errorf("dnsid: c2sp-tlog ku thumbprint: %w", err)
		}
		if entityThumb == operationalThumb {
			return fmt.Errorf("dnsid: c2sp-tlog ek and ku must be distinct")
		}
	case dnsidlog.LogEventKeyRotation:
		if event.PreviousOperationalThumbprint == "" || event.NewOperationalThumbprint == "" || event.NewOperationalPublicKey == nil {
			return fmt.Errorf("dnsid: c2sp-tlog KEY_ROTATION requires prev_thumb, new_thumb, and new_ku")
		}
		if err := validateSigningJWK(event.NewOperationalPublicKey, "new_ku"); err != nil {
			return err
		}
		thumb, err := thumbprint(event.NewOperationalPublicKey)
		if err != nil || thumb != event.NewOperationalThumbprint {
			return fmt.Errorf("dnsid: c2sp-tlog new_thumb does not match new_ku")
		}
	case dnsidlog.LogEventRevocation:
		if !dnsidlog.ValidRevocationReason(event.Reason) {
			return fmt.Errorf("dnsid: invalid c2sp-tlog REVOCATION reason %q", event.Reason)
		}
	case dnsidlog.LogEventRetirement:
	case dnsidlog.LogEventMigration:
		if event.PreviousLog == "" || event.NewLog == "" || event.FinalEntryRef == "" {
			return fmt.Errorf("dnsid: c2sp-tlog MIGRATION requires prev_lr, new_lr, and prev_ref")
		}
		if event.PreviousLog == event.NewLog {
			return fmt.Errorf("dnsid: c2sp-tlog MIGRATION must change log reference")
		}
	case dnsidlog.LogEventDelegation:
		if event.Delegatee == "" || event.Scope == "" || event.Expiry.IsZero() {
			return fmt.Errorf("dnsid: c2sp-tlog DELEGATION requires delegatee, scope, and expiry")
		}
		if event.Expiry.Nanosecond() != 0 {
			return fmt.Errorf("dnsid: c2sp-tlog DELEGATION expiry must have whole-second precision")
		}
	default:
		return fmt.Errorf("dnsid: unsupported c2sp-tlog event type %q", event.Type)
	}
	return nil
}

func validateSigningJWK(key jwk.Key, field string) error {
	if key == nil {
		return fmt.Errorf("dnsid: missing %s public JWK", field)
	}
	if private, err := jwk.IsPrivateKey(key); err != nil || private {
		return fmt.Errorf("dnsid: %s JWK must be public", field)
	}
	if use, ok := key.KeyUsage(); ok && use != string(jwk.ForSignature) {
		return fmt.Errorf("dnsid: %s JWK must be for signatures", field)
	}
	kid, ok := key.KeyID()
	if !ok || kid == "" {
		return fmt.Errorf("dnsid: c2sp-tlog %s JWK is missing kid", field)
	}
	alg, ok := key.Algorithm()
	if !ok || alg == nil || alg.String() == "" {
		return fmt.Errorf("dnsid: c2sp-tlog %s JWK is missing alg", field)
	}
	switch key.KeyType() {
	case jwa.OKP():
		curve, curveOK := jwkCurve(key)
		if alg.String() != jwa.EdDSA().String() || !curveOK || curve != jwa.Ed25519() {
			return fmt.Errorf("dnsid: c2sp-tlog %s JWK must use EdDSA with Ed25519", field)
		}
	case jwa.EC():
		curve, curveOK := jwkCurve(key)
		if alg.String() != jwa.ES256().String() || !curveOK || curve != jwa.P256() {
			return fmt.Errorf("dnsid: c2sp-tlog %s JWK must use ES256 with P-256", field)
		}
	default:
		return fmt.Errorf("dnsid: c2sp-tlog %s JWK uses unsupported key type", field)
	}
	return nil
}

func validateEmbeddedSignatureKids(event dnsidlog.LogEvent) error {
	switch event.Type {
	case dnsidlog.LogEventIssuance:
		if event.InitialEntityPublicKey == nil || event.InitialOperationalPublicKey == nil {
			return fmt.Errorf("dnsid: ISSUANCE requires entity and operational keys")
		}
		entityKid, _ := event.InitialEntityPublicKey.KeyID()
		operationalKid, _ := event.InitialOperationalPublicKey.KeyID()
		if event.InitialEntityKid != entityKid || event.InitialOperationalKid != operationalKid {
			return fmt.Errorf("dnsid: c2sp-tlog ISSUANCE signature kid does not match recorded key")
		}
	case dnsidlog.LogEventKeyRotation:
		if event.NewOperationalPublicKey == nil {
			return fmt.Errorf("dnsid: KEY_ROTATION requires new operational key")
		}
		newKid, _ := event.NewOperationalPublicKey.KeyID()
		if event.NewOperationalKid != newKid {
			return fmt.Errorf("dnsid: c2sp-tlog KEY_ROTATION new_op kid does not match new_ku")
		}
	}
	return nil
}

func applySignatures(event *dnsidlog.LogEvent, payload map[string]any) {
	sigs, ok := payload["sigs"].(map[string]any)
	if !ok {
		return
	}
	if ae, ok := parseSig(sigs["ae"]); ok {
		event.InitialEntityKid = ae.Kid
		event.InitialEntitySignature = ae.Sig
	}
	if op, ok := parseSig(sigs["op"]); ok {
		event.InitialOperationalKid = op.Kid
		event.InitialOperationalSignature = op.Sig
	}
	if prev, ok := parseSig(sigs["prev_op"]); ok {
		event.PreviousOperationalKid = prev.Kid
		event.PreviousOperationalSignature = prev.Sig
	}
	if next, ok := parseSig(sigs["new_op"]); ok {
		event.NewOperationalKid = next.Kid
		event.NewOperationalSignature = next.Sig
	}
}

func parseSig(v any) (signatureValue, bool) {
	obj, ok := v.(map[string]any)
	if !ok {
		return signatureValue{}, false
	}
	kid, kidOK := obj["kid"].(string)
	sig, sigOK := obj["sig"].(string)
	return signatureValue{Kid: kid, Sig: sig}, kidOK && sigOK
}

func stringField(payload map[string]any, key string) (string, error) {
	value, ok := payload[key].(string)
	if !ok || value == "" {
		return "", fmt.Errorf("dnsid: c2sp-tlog event missing string field %q", key)
	}
	return value, nil
}

func optionalString(payload map[string]any, key string) (string, bool) {
	value, ok := payload[key].(string)
	return value, ok
}

func intField(payload map[string]any, key string) (int, error) {
	value, err := int64Field(payload, key)
	return int(value), err
}

func int64Field(payload map[string]any, key string) (int64, error) {
	value, ok, err := optionalInt64(payload, key)
	if err != nil {
		return 0, err
	}
	if !ok {
		return 0, fmt.Errorf("dnsid: c2sp-tlog event missing integer field %q", key)
	}
	return value, nil
}

func optionalUint64(payload map[string]any, key string) (uint64, bool, error) {
	value, ok, err := optionalInt64(payload, key)
	if err != nil || !ok {
		return 0, ok, err
	}
	if value < 0 {
		return 0, true, fmt.Errorf("dnsid: c2sp-tlog field %q is negative", key)
	}
	if value > maxJSONInteger {
		return 0, true, fmt.Errorf("dnsid: c2sp-tlog field %q exceeds maximum JSON integer", key)
	}
	return uint64(value), true, nil
}

func optionalInt64(payload map[string]any, key string) (int64, bool, error) {
	switch value := payload[key].(type) {
	case nil:
		return 0, false, nil
	case json.Number:
		i, err := value.Int64()
		if err != nil {
			return 0, true, fmt.Errorf("dnsid: c2sp-tlog field %q is not an integer: %w", key, err)
		}
		return i, true, nil
	case float64:
		i := int64(value)
		if float64(i) != value {
			return 0, true, fmt.Errorf("dnsid: c2sp-tlog field %q is not an integer", key)
		}
		return i, true, nil
	default:
		return 0, true, fmt.Errorf("dnsid: c2sp-tlog field %q is not an integer", key)
	}
}

func optionalJWK(payload map[string]any, key string) (jwk.Key, bool, error) {
	value, ok := payload[key]
	if !ok {
		return nil, false, nil
	}
	data, err := canonicalJSON(value)
	if err != nil {
		return nil, true, err
	}
	parsed, err := jwk.ParseKey(data)
	if err != nil {
		return nil, true, fmt.Errorf("dnsid: parsing %s JWK: %w", key, err)
	}
	return parsed, true, nil
}

// EventID derives logical identity from canonical signing bytes, not signatures or leaf evidence.
func EventID(signedBytes []byte) string {
	h := sha256.New()
	_, _ = h.Write([]byte("dnsid-c2sp-event-v1\x00"))
	_, _ = h.Write(signedBytes)
	return base64.RawURLEncoding.EncodeToString(h.Sum(nil))
}

func validHash(value string) bool {
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(value)
	return err == nil && len(decoded) == sha256.Size && base64.RawURLEncoding.EncodeToString(decoded) == value
}

func thumbprint(key jwk.Key) (string, error) {
	sum, err := key.Thumbprint(crypto.SHA256)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(sum), nil
}
