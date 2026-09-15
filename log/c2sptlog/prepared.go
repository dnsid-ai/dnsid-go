package c2sptlog

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"

	dnsid "github.com/dnsid-ai/dnsid-go"
	dnsidlog "github.com/dnsid-ai/dnsid-go/log"
	"github.com/lestrrat-go/jwx/v3/jwk"
)

// SignerRole identifies a DNSid lifecycle signature in a C2SP event envelope.
type SignerRole string

const (
	// SignerEntity is the accountable entity key: it signs ISSUANCE and
	// every post-issuance event other than KEY_ROTATION.
	SignerEntity SignerRole = "entity"
	// SignerOperationalCountersignature is the operational key's
	// countersignature on ISSUANCE.
	SignerOperationalCountersignature SignerRole = "operational_countersignature"
	// SignerPreviousOperational is the outgoing operational key's signature
	// on KEY_ROTATION.
	SignerPreviousOperational SignerRole = "previous_operational"
	// SignerNewOperational is the incoming operational key's signature on
	// KEY_ROTATION.
	SignerNewOperational SignerRole = "new_operational"
)

// PreparedEvent preserves the complete method-specific envelope while its
// lifecycle signatures are collected. Its accessors return copies.
type PreparedEvent struct {
	reference          Reference
	envelope           map[string]any
	signedBytes        []byte
	requiredSignatures []SignerRole
}

// Reference returns the stream reference the event was prepared for. It
// returns the zero Reference on a nil receiver.
func (p *PreparedEvent) Reference() Reference {
	if p == nil {
		return Reference{}
	}
	return p.reference
}

// SignedBytes returns a copy of the canonical bytes each SignerRole signs
// (the envelope without its signatures). It returns nil on a nil receiver.
func (p *PreparedEvent) SignedBytes() []byte {
	if p == nil {
		return nil
	}
	return bytes.Clone(p.signedBytes)
}

// EventID returns the derived logical event identity, unchanged by signatures.
func (p *PreparedEvent) EventID() string {
	if p == nil {
		return ""
	}
	return EventID(p.signedBytes)
}

// RequiredSignatures returns a copy of the signer roles this event type
// requires before it can be written. It returns nil on a nil receiver.
func (p *PreparedEvent) RequiredSignatures() []SignerRole {
	if p == nil {
		return nil
	}
	return append([]SignerRole(nil), p.requiredSignatures...)
}

// Bytes returns the current canonical envelope, including any signatures
// already collected. It may be incomplete and is intended for signer handoff.
func (p *PreparedEvent) Bytes() ([]byte, error) {
	if p == nil {
		return nil, fmt.Errorf("dnsid: prepared c2sp-tlog event is required")
	}
	return canonicalJSON(p.envelope)
}

// Event returns the envelope parsed as the shared lifecycle event
// representation, including any signatures collected so far. It returns an
// error on a nil receiver.
func (p *PreparedEvent) Event() (dnsidlog.LogEvent, error) {
	if p == nil {
		return dnsidlog.LogEvent{}, fmt.Errorf("dnsid: prepared c2sp-tlog event is required")
	}
	parsed, err := eventFromPayload(p.envelope)
	if err != nil {
		return dnsidlog.LogEvent{}, err
	}
	return parsed.event, nil
}

// PrepareEvent builds an unsigned method-specific envelope. ISSUANCE
// and inbound MIGRATION derive seq=0; later events use
// PrepareEventWithChain.
func (c *Client) PrepareEvent(event dnsidlog.LogEvent) (*PreparedEvent, error) {
	if c == nil {
		return nil, fmt.Errorf("dnsid: c2sp-tlog client is required")
	}
	chain, err := c.chainForWrite(event)
	if err != nil {
		return nil, err
	}
	return c.prepareEvent(event, chain)
}

// PrepareEventWithChain is PrepareEvent with caller-supplied public
// stream-chain metadata, as required for non-genesis events in every scope.
func (c *Client) PrepareEventWithChain(event dnsidlog.LogEvent, chain Chain) (*PreparedEvent, error) {
	if c == nil {
		return nil, fmt.Errorf("dnsid: c2sp-tlog client is required")
	}
	if err := c.validateChain(event, chain); err != nil {
		return nil, err
	}
	return c.prepareEvent(event, chainFieldsFromChain(event, chain))
}

func (c *Client) prepareEvent(event dnsidlog.LogEvent, chain *chainFields) (*PreparedEvent, error) {
	if err := c.validateWritableStream(event); err != nil {
		return nil, err
	}
	envelope, err := payloadFromEventWithChain(event, false, &c.ref, chain)
	if err != nil {
		return nil, err
	}
	if sigs := signaturesFromEvent(event); len(sigs) != 0 {
		envelope["sigs"] = sigs
	}
	return c.preparedFromEnvelope(envelope)
}

// ParsePreparedEvent treats received bytes as untrusted, canonicalizes the
// envelope independently, and preserves unknown signed fields.
func (c *Client) ParsePreparedEvent(entry []byte) (*PreparedEvent, error) {
	if c == nil {
		return nil, dnsid.NewArgumentError("dnsid: c2sp-tlog client is required", nil)
	}
	envelope, err := payloadObjectFromEntry(entry)
	if err != nil {
		return nil, dnsid.NewParseError("dnsid: parsing c2sp-tlog prepared event", err)
	}
	prepared, err := c.preparedFromEnvelope(envelope)
	if err != nil {
		return nil, dnsid.NewValidationError("dnsid: validating c2sp-tlog prepared event", err)
	}
	return prepared, nil
}

func (c *Client) preparedFromEnvelope(envelope map[string]any) (*PreparedEvent, error) {
	copy, err := cloneJSONObject(envelope)
	if err != nil {
		return nil, err
	}
	parsed, err := eventFromPayload(copy)
	if err != nil {
		return nil, err
	}
	if parsed.validationError != nil {
		return nil, parsed.validationError
	}
	if err := c.validateWritableStream(parsed.event); err != nil {
		return nil, err
	}
	encoded, err := canonicalJSON(copy)
	if err != nil {
		return nil, err
	}
	if len(encoded) == 0 || len(encoded) > maxEntrySize {
		return nil, fmt.Errorf("dnsid: c2sp-tlog entry must be between 1 and %d bytes", maxEntrySize)
	}
	if err := c.validateEntryMetadata(encoded); err != nil {
		return nil, err
	}
	if err := c.validatePreparedChain(parsed); err != nil {
		return nil, err
	}
	required, err := requiredSignerRoles(parsed.event.Type)
	if err != nil {
		return nil, err
	}
	if err := validateSignatureShape(copy, required, false); err != nil {
		return nil, err
	}
	unsigned, err := cloneJSONObject(copy)
	if err != nil {
		return nil, err
	}
	delete(unsigned, "sigs")
	signedBytes, err := canonicalJSON(unsigned)
	if err != nil {
		return nil, err
	}
	return &PreparedEvent{reference: c.ref, envelope: copy, signedBytes: signedBytes, requiredSignatures: required}, nil
}

func (c *Client) validateWritableStream(event dnsidlog.LogEvent) error {
	normalizedDomain, err := dnsid.NormalizeFQDN(event.Domain)
	if err != nil {
		return err
	}
	if c.ref.StreamID == normalizedDomain {
		return fmt.Errorf("dnsid: c2sp-tlog stream ID must identify an identity instance and must not equal the normalized event fqdn")
	}
	return nil
}

// SignPreparedEvent validates every signature already present and adds exactly
// one role signature. ctx is used when historical stream keys are required.
func (c *Client) SignPreparedEvent(ctx context.Context, prepared *PreparedEvent, role SignerRole, kp dnsid.KeyProvider) (*PreparedEvent, error) {
	return c.signPreparedEvent(ctx, prepared, role, kp, "")
}

// SignPreparedEventWithKey validates every signature already present and adds
// role using the named active or pending key. It is intended for transitions
// such as KEY_ROTATION whose new-key proof must be made before activation.
func (c *Client) SignPreparedEventWithKey(ctx context.Context, prepared *PreparedEvent, role SignerRole, kp dnsid.KeyProvider, kid string) (*PreparedEvent, error) {
	if kid == "" {
		return nil, dnsid.NewArgumentError("dnsid: c2sp-tlog signer kid is required", nil)
	}
	return c.signPreparedEvent(ctx, prepared, role, kp, kid)
}

func (c *Client) signPreparedEvent(ctx context.Context, prepared *PreparedEvent, role SignerRole, kp dnsid.KeyProvider, namedKid string) (result *PreparedEvent, err error) {
	ctx, cancel := dnsid.VerificationContext(ctx)
	defer cancel()
	defer func() {
		if err == nil && ctx.Err() != nil {
			result, err = nil, ctx.Err()
		}
	}()
	if err := c.validatePrepared(prepared); err != nil {
		return nil, dnsid.NewValidationError("dnsid: invalid prepared event", err)
	}
	if !containsRole(prepared.requiredSignatures, role) {
		return nil, dnsid.NewArgumentError(fmt.Sprintf("dnsid: signer role %q is not valid for this c2sp-tlog event", role), nil)
	}
	if kp == nil {
		return nil, dnsid.NewArgumentError(fmt.Sprintf("dnsid: signer role %q key provider is required", role), nil)
	}
	keys, err := c.preparedSignerKeys(ctx, prepared)
	if err != nil {
		return nil, err
	}
	if err := verifyPresentSignatures(prepared, keys); err != nil {
		return nil, dnsid.NewValidationError("dnsid: invalid prepared event signatures", err)
	}
	expected := keys[role]
	if expected == nil {
		return nil, dnsid.NewArgumentError(fmt.Sprintf("dnsid: no verified key is available for signer role %q", role), nil)
	}
	signingKey := kp.JWK()
	if namedKid != "" {
		signingKey = kp.JWK(namedKid)
	}
	if signingKey == nil {
		return nil, dnsid.NewArgumentError(fmt.Sprintf("dnsid: signer role %q key provider has no matching key", role), nil)
	}
	signingThumb, err := thumbprint(signingKey)
	if err != nil {
		return nil, dnsid.NewArgumentError(fmt.Sprintf("dnsid: signer role %q signing key thumbprint", role), err)
	}
	expectedThumb, err := thumbprint(expected)
	if err != nil {
		return nil, dnsid.NewArgumentError(fmt.Sprintf("dnsid: signer role %q expected key thumbprint", role), err)
	}
	if signingThumb != expectedThumb {
		return nil, dnsid.NewArgumentError(fmt.Sprintf("dnsid: signer role %q key does not match event key", role), nil)
	}
	kid, ok := signingKey.KeyID()
	if !ok || kid == "" {
		return nil, dnsid.NewArgumentError(fmt.Sprintf("dnsid: signer role %q key is missing kid", role), nil)
	}
	expectedKid, _ := expected.KeyID()
	if kid != expectedKid {
		return nil, dnsid.NewArgumentError(fmt.Sprintf("dnsid: signer role %q kid %q does not match event key kid %q", role, kid, expectedKid), nil)
	}
	activeAlg, activeAlgOK := signingKey.Algorithm()
	expectedAlg, expectedAlgOK := expected.Algorithm()
	if !activeAlgOK || !expectedAlgOK || activeAlg.String() != expectedAlg.String() {
		return nil, dnsid.NewArgumentError(fmt.Sprintf("dnsid: signer role %q algorithm does not match event key", role), nil)
	}
	name := signatureName(role)
	if sigs, ok := prepared.envelope["sigs"].(map[string]any); ok {
		if existing, ok := sigs[name]; ok {
			value, valid := parseSig(existing)
			if !valid || value.Kid != kid {
				return nil, dnsid.NewArgumentError(fmt.Sprintf("dnsid: signer role %q already has a different signature", role), nil)
			}
			return prepared, nil
		}
	}
	var signed *dnsid.KeySignature
	if namedKid == "" {
		signed, err = kp.Sign(prepared.signedBytes)
	} else {
		signed, err = kp.SignKey(namedKid, prepared.signedBytes)
	}
	if err != nil {
		return nil, dnsid.NewArgumentError(fmt.Sprintf("dnsid: signer role %q signing failed", role), err)
	}
	if signed == nil {
		return nil, dnsid.NewArgumentError(fmt.Sprintf("dnsid: signer role %q key provider returned no signature", role), nil)
	}
	if signed.Kid != kid {
		return nil, dnsid.NewArgumentError(fmt.Sprintf("dnsid: signer role %q signed with kid %q, want %q", role, signed.Kid, kid), nil)
	}
	if string(signed.Alg) != expectedAlg.String() {
		return nil, dnsid.NewArgumentError(fmt.Sprintf("dnsid: signer role %q signed with algorithm %q, want %q", role, signed.Alg, expectedAlg), nil)
	}
	copy, err := cloneJSONObject(prepared.envelope)
	if err != nil {
		return nil, dnsid.NewValidationError("dnsid: cloning prepared event", err)
	}
	sigs, _ := copy["sigs"].(map[string]any)
	if sigs == nil {
		sigs = make(map[string]any)
		copy["sigs"] = sigs
	}
	sigs[name] = map[string]any{"kid": kid, "sig": base64.RawURLEncoding.EncodeToString(signed.Signature)}
	return c.preparedFromEnvelope(copy)
}

// PreparedEntryBytes returns exact canonical bytes after validating all
// required signatures. It never appends.
func (c *Client) PreparedEntryBytes(ctx context.Context, prepared *PreparedEvent) (result []byte, err error) {
	ctx, cancel := dnsid.VerificationContext(ctx)
	defer cancel()
	defer func() {
		if err == nil && ctx.Err() != nil {
			result, err = nil, ctx.Err()
		}
	}()
	if err := c.validatePrepared(prepared); err != nil {
		return nil, dnsid.NewValidationError("dnsid: invalid prepared event", err)
	}
	if err := validateSignatureShape(prepared.envelope, prepared.requiredSignatures, true); err != nil {
		return nil, dnsid.NewValidationError("dnsid: invalid prepared event signatures", err)
	}
	keys, err := c.preparedSignerKeys(ctx, prepared)
	if err != nil {
		return nil, err
	}
	if err := verifyPresentSignatures(prepared, keys); err != nil {
		return nil, dnsid.NewValidationError("dnsid: invalid prepared event signatures", err)
	}
	entry, err := canonicalJSON(prepared.envelope)
	if err != nil {
		return nil, err
	}
	if len(entry) == 0 || len(entry) > maxEntrySize {
		return nil, dnsid.NewValidationError(fmt.Sprintf("dnsid: c2sp-tlog entry must be between 1 and %d bytes", maxEntrySize), nil)
	}
	return entry, nil
}

// WritePreparedEvent validates and appends the exact prepared bytes unchanged.
func (c *Client) WritePreparedEvent(ctx context.Context, prepared *PreparedEvent) (dnsidlog.LogRef, error) {
	if c == nil || c.appender == nil {
		return "", dnsid.NewArgumentError("dnsid: c2sp-tlog appender is required", nil)
	}
	entry, err := c.PreparedEntryBytes(ctx, prepared)
	if err != nil {
		return "", err
	}
	parsed, err := parseEventFromEntry(entry)
	if err != nil {
		return "", dnsid.NewValidationError("dnsid: invalid prepared event", err)
	}
	if err := c.validatePreparedChainAgainstHistory(ctx, parsed); err != nil {
		return "", err
	}
	index, err := c.appender.Append(ctx, entry)
	if err != nil {
		return "", err
	}
	return c.ref.FinalEventRef(index), nil
}

func (c *Client) validatePrepared(prepared *PreparedEvent) error {
	if c == nil || prepared == nil {
		return fmt.Errorf("dnsid: prepared c2sp-tlog event is required")
	}
	if prepared.reference != c.ref {
		return fmt.Errorf("dnsid: prepared c2sp-tlog event belongs to a different reference")
	}
	unsigned, err := cloneJSONObject(prepared.envelope)
	if err != nil {
		return err
	}
	delete(unsigned, "sigs")
	canonical, err := canonicalJSON(unsigned)
	if err != nil {
		return err
	}
	if !bytes.Equal(canonical, prepared.signedBytes) {
		return fmt.Errorf("dnsid: prepared c2sp-tlog signed bytes do not match envelope")
	}
	return nil
}

func (c *Client) preparedSignerKeys(ctx context.Context, prepared *PreparedEvent) (map[SignerRole]jwk.Key, error) {
	event, err := prepared.Event()
	if err != nil {
		return nil, err
	}
	keys := make(map[SignerRole]jwk.Key)
	switch event.Type {
	case dnsidlog.LogEventIssuance:
		keys[SignerEntity] = event.InitialEntityPublicKey
		keys[SignerOperationalCountersignature] = event.InitialOperationalPublicKey
	case dnsidlog.LogEventKeyRotation:
		_, operational, state, err := c.currentLifecycleState(ctx, event.Domain)
		if err != nil {
			return nil, err
		}
		if event.NewOperationalThumbprint == state["entity_thumb"] {
			return nil, fmt.Errorf("dnsid: operational key must remain distinct from entity key")
		}
		keys[SignerPreviousOperational] = operational
		keys[SignerNewOperational] = event.NewOperationalPublicKey
	case dnsidlog.LogEventMigration:
		if !c.isInboundMigration(event) || c.verifyMigration == nil {
			return nil, invalidMigration("dnsid: migration signing requires verified source history", nil)
		}
		migration, err := c.verifyBoundedMigration(ctx, event)
		if err != nil {
			return nil, err
		}
		if err := validateMigrationResult(event, migration); err != nil {
			return nil, err
		}
		keys[SignerEntity] = migration.EntityKey
	default:
		entity, _, _, err := c.currentLifecycleState(ctx, event.Domain)
		if err != nil {
			return nil, err
		}
		keys[SignerEntity] = entity
	}
	return keys, nil
}

func (c *Client) currentLifecycleState(ctx context.Context, domain string) (jwk.Key, jwk.Key, map[string]any, error) {
	verified, _, err := c.rebuildVerifiedHistory(ctx, domain)
	if err != nil {
		return nil, nil, nil, err
	}
	return lifecycleStateFromVerified(verified, domain)
}

func lifecycleStateFromVerified(verified []verifiedEvent, domain string) (jwk.Key, jwk.Key, map[string]any, error) {
	if len(verified) == 0 {
		return nil, nil, nil, fmt.Errorf("dnsid: c2sp-tlog lifecycle history is empty")
	}
	entity := verified[0].event.InitialEntityPublicKey
	operational := verified[0].event.InitialOperationalPublicKey
	entityThumb, err := thumbprint(entity)
	if err != nil {
		return nil, nil, nil, err
	}
	operationalThumb, err := thumbprint(operational)
	if err != nil {
		return nil, nil, nil, err
	}
	state := activeLifecycleState(domain, entityThumb, operationalThumb)
	for _, item := range verified[1:] {
		switch item.event.Type {
		case dnsidlog.LogEventKeyRotation:
			operational = item.event.NewOperationalPublicKey
			operationalThumb = item.event.NewOperationalThumbprint
			state = activeLifecycleState(domain, entityThumb, operationalThumb)
		case dnsidlog.LogEventRevocation:
			state = activeLifecycleState(domain, entityThumb, operationalThumb)
			state["status"] = "REVOKED"
		case dnsidlog.LogEventRetirement:
			state = activeLifecycleState(domain, entityThumb, operationalThumb)
			state["status"] = "RETIRED"
		case dnsidlog.LogEventDelegation:
		default:
			state = activeLifecycleState(domain, entityThumb, operationalThumb)
		}
	}
	return entity, operational, state, nil
}

// ChainForWrite derives the logical stream-chain metadata for event from the
// client's verified history. ISSUANCE derives seq=0 without reading history.
func (c *Client) ChainForWrite(ctx context.Context, event dnsidlog.LogEvent) (Chain, error) {
	if c == nil {
		return Chain{}, fmt.Errorf("dnsid: c2sp-tlog client is required")
	}
	if event.Type == dnsidlog.LogEventIssuance || c.isInboundMigration(event) {
		return Chain{Sequence: 0}, nil
	}
	verified, _, err := c.rebuildVerifiedHistory(ctx, event.Domain)
	if err != nil {
		return Chain{}, err
	}
	_, _, state, err := lifecycleStateFromVerified(verified, event.Domain)
	if err != nil {
		return Chain{}, err
	}
	last := verified[len(verified)-1]
	if last.chain.sequence == nil {
		return Chain{}, fmt.Errorf("dnsid: verified c2sp-tlog history is missing sequence metadata")
	}
	return Chain{
		Sequence:          *last.chain.sequence + 1,
		PreviousEventID:   EventID(last.signed),
		PreviousStateHash: lifecycleStateHash(state),
	}, nil
}

func (c *Client) validatePreparedChainAgainstHistory(ctx context.Context, parsed parsedEvent) error {
	if parsed.event.Type == dnsidlog.LogEventIssuance || c.isInboundMigration(parsed.event) {
		return c.validatePreparedChain(parsed)
	}
	verified, _, err := c.rebuildVerifiedHistory(ctx, parsed.event.Domain)
	if err != nil {
		return err
	}
	if len(verified) == 0 {
		return fmt.Errorf("dnsid: c2sp-tlog event requires prior verified state")
	}
	_, _, state, err := c.currentLifecycleState(ctx, parsed.event.Domain)
	if err != nil {
		return err
	}
	last := verified[len(verified)-1]
	seq := uint64(0)
	if last.chain.sequence != nil {
		seq = *last.chain.sequence + 1
	}
	candidate := verifiedEvent{chain: parsed.chain}
	if !validChainFields(candidate, seq, EventID(last.signed), state) {
		return fmt.Errorf("dnsid: invalid c2sp-tlog logical lifecycle chain")
	}
	return nil
}

func verifyPresentSignatures(prepared *PreparedEvent, keys map[SignerRole]jwk.Key) error {
	sigs, _ := prepared.envelope["sigs"].(map[string]any)
	for _, role := range prepared.requiredSignatures {
		raw, ok := sigs[signatureName(role)]
		if !ok {
			continue
		}
		value, ok := parseSig(raw)
		if !ok || value.Kid == "" || value.Sig == "" {
			return fmt.Errorf("dnsid: malformed c2sp-tlog signature for role %q", role)
		}
		key := keys[role]
		if key == nil {
			return fmt.Errorf("dnsid: no verified key is available for signer role %q", role)
		}
		kid, ok := key.KeyID()
		if !ok || kid == "" || kid != value.Kid {
			return fmt.Errorf("dnsid: c2sp-tlog signature kid does not match signer role %q key", role)
		}
		if err := verifyEventSignature(key, prepared.signedBytes, value.Sig); err != nil {
			return fmt.Errorf("dnsid: invalid c2sp-tlog signature for role %q: %w", role, err)
		}
	}
	return nil
}

func requiredSignerRoles(eventType dnsidlog.LogEventType) ([]SignerRole, error) {
	switch eventType {
	case dnsidlog.LogEventIssuance:
		return []SignerRole{SignerEntity, SignerOperationalCountersignature}, nil
	case dnsidlog.LogEventKeyRotation:
		return []SignerRole{SignerPreviousOperational, SignerNewOperational}, nil
	case dnsidlog.LogEventRevocation, dnsidlog.LogEventRetirement, dnsidlog.LogEventMigration, dnsidlog.LogEventDelegation:
		return []SignerRole{SignerEntity}, nil
	default:
		return nil, fmt.Errorf("dnsid: unsupported c2sp-tlog event type %q", eventType)
	}
}

func signatureName(role SignerRole) string {
	switch role {
	case SignerEntity:
		return "ae"
	case SignerOperationalCountersignature:
		return "op"
	case SignerPreviousOperational:
		return "prev_op"
	case SignerNewOperational:
		return "new_op"
	default:
		return ""
	}
}

func validateSignatureShape(envelope map[string]any, required []SignerRole, complete bool) error {
	sigs, exists := envelope["sigs"]
	if !exists {
		if complete {
			return fmt.Errorf("dnsid: c2sp-tlog event missing signatures")
		}
		return nil
	}
	obj, ok := sigs.(map[string]any)
	if !ok {
		return fmt.Errorf("dnsid: c2sp-tlog sigs field must be an object")
	}
	allowed := make(map[string]struct{}, len(required))
	for _, role := range required {
		allowed[signatureName(role)] = struct{}{}
	}
	for name := range obj {
		if _, ok := allowed[name]; !ok {
			return fmt.Errorf("dnsid: unexpected c2sp-tlog signature role %q", name)
		}
		value, ok := parseSig(obj[name])
		if !ok || value.Kid == "" || value.Sig == "" {
			return fmt.Errorf("dnsid: malformed c2sp-tlog signature role %q", name)
		}
		decoded, err := base64.RawURLEncoding.DecodeString(value.Sig)
		if err != nil || base64.RawURLEncoding.EncodeToString(decoded) != value.Sig {
			return fmt.Errorf("dnsid: c2sp-tlog signature role %q is not unpadded base64url", name)
		}
	}
	if complete {
		for name := range allowed {
			if _, ok := obj[name]; !ok {
				return fmt.Errorf("dnsid: c2sp-tlog event missing signature role %q", name)
			}
		}
	}
	return nil
}

func containsRole(roles []SignerRole, role SignerRole) bool {
	for _, candidate := range roles {
		if candidate == role {
			return true
		}
	}
	return false
}

func cloneJSONObject(value map[string]any) (map[string]any, error) {
	encoded, err := canonicalJSON(value)
	if err != nil {
		return nil, err
	}
	return decodeJSONObject(encoded)
}
