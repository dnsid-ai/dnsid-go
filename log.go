package dnsid

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	dnsidlog "github.com/dnsid-ai/dnsid-go/log"
	"github.com/lestrrat-go/jwx/v3/jwk"
)

// ParseLogRef splits an lr= log reference of the form "method:entryRef" into
// its method and entry-reference parts. It returns a *ParseError for
// malformed references or invalid method names.
func ParseLogRef(lr string) (method, entryRef string, err error) {
	method, entryRef, err = dnsidlog.ParseLogRef(lr)
	if err != nil {
		return "", "", NewParseError(err.Error(), nil)
	}
	return method, entryRef, nil
}

// LogSignerRole identifies a DNSid lifecycle-event signer. Signatures from all
// roles cover the same log-method canonical bytes.
type LogSignerRole string

// The lifecycle-event signer roles: the accountable entity signature, the
// operational countersignature on ISSUANCE, and the previous- and
// new-operational signatures on KEY_ROTATION.
const (
	LogSignerEntity                      LogSignerRole = "entity"
	LogSignerOperationalCountersignature LogSignerRole = "operational_countersignature"
	LogSignerPreviousOperational         LogSignerRole = "previous_operational"
	LogSignerNewOperational              LogSignerRole = "new_operational"
)

// LogEventCanonicalizer produces the exact bytes covered by lifecycle-event
// signatures for one bound log method and reference.
type LogEventCanonicalizer interface {
	Canonical(event dnsidlog.LogEvent) ([]byte, error)
}

// CanonicalizeLogEvent returns the log-method-specific bytes covered by every
// lifecycle-event signature. It requires a bound log reader, but not a
// write-capable log or access to any private key.
func (m *IdentityManager) CanonicalizeLogEvent(event dnsidlog.LogEvent) ([]byte, error) {
	if m == nil || m.identity.LogRef == "" {
		return nil, NewArgumentError("dnsid: local log reference is required", nil)
	}
	reader, err := m.logReaderFor(m.identity.LogRef)
	if err != nil {
		return nil, err
	}
	return reader.Canonical(event)
}

// SignLogEvent adds one lifecycle signature without writing the event. This
// supports split signing where the accountable entity and operational key are
// held by different SDK instances or machines.
func (m *IdentityManager) SignLogEvent(event dnsidlog.LogEvent, role LogSignerRole) (dnsidlog.LogEvent, error) {
	if m == nil || m.identity.LogRef == "" {
		return event, NewArgumentError("dnsid: local log reference is required", nil)
	}
	var kp KeyProvider
	switch role {
	case LogSignerEntity:
		kp = m.entityKeys
	case LogSignerOperationalCountersignature, LogSignerPreviousOperational, LogSignerNewOperational:
		kp = m.keys
	default:
		return event, NewArgumentError(fmt.Sprintf("dnsid: unsupported log signer role %q", role), nil)
	}
	reader, err := m.logReaderFor(m.identity.LogRef)
	if err != nil {
		return event, err
	}
	return SignLogEventWithKey(event, role, kp, reader)
}

// SignLogEventWithKey adds one lifecycle signature using an explicitly supplied
// key provider and bound log canonicalizer. It is suitable for accountable
// entity services that do not possess the operational private key.
func SignLogEventWithKey(event dnsidlog.LogEvent, role LogSignerRole, kp KeyProvider, canonicalizer LogEventCanonicalizer) (dnsidlog.LogEvent, error) {
	if kp == nil {
		return event, NewArgumentError(fmt.Sprintf("dnsid: log signer role %q is not configured", role), nil)
	}
	if canonicalizer == nil {
		return event, NewArgumentError("dnsid: log canonicalizer is required", nil)
	}
	var expected jwk.Key
	var kid string
	useNamedKey := false
	switch role {
	case LogSignerEntity:
		expected = event.InitialEntityPublicKey
	case LogSignerOperationalCountersignature:
		expected = event.InitialOperationalPublicKey
	case LogSignerPreviousOperational:
		kid, useNamedKey = event.PreviousOperationalKid, true
	case LogSignerNewOperational:
		expected, kid, useNamedKey = event.NewOperationalPublicKey, event.NewOperationalKid, true
	default:
		return event, NewArgumentError(fmt.Sprintf("dnsid: unsupported log signer role %q", role), nil)
	}
	if !useNamedKey {
		var err error
		kid, err = activeSigningKid(kp)
		if err != nil {
			return event, NewArgumentError(fmt.Sprintf("dnsid: invalid log signer role %q key provider", role), err)
		}
		if expected == nil && role == LogSignerEntity && event.Type != dnsidlog.LogEventIssuance {
			expected = kp.JWK(kid)
		}
	} else if kid == "" {
		return event, NewArgumentError(fmt.Sprintf("dnsid: log signer role %q has no event kid", role), nil)
	}
	if expected == nil && role != LogSignerPreviousOperational {
		return event, NewArgumentError(fmt.Sprintf("dnsid: log signer role %q has no event public key", role), nil)
	}
	key := kp.JWK(kid)
	if key == nil {
		return event, NewArgumentError(fmt.Sprintf("dnsid: log signer role %q key %q not found", role, kid), nil)
	}
	keyThumb, err := (&JWK{key: key}).Thumbprint()
	if err != nil {
		return event, NewArgumentError(fmt.Sprintf("dnsid: computing log signer role %q key thumbprint", role), err)
	}
	expectedThumb := event.PreviousOperationalThumbprint
	if expected != nil {
		expectedThumb, err = (&JWK{key: expected}).Thumbprint()
		if err != nil {
			return event, NewArgumentError(fmt.Sprintf("dnsid: computing event key thumbprint for role %q", role), err)
		}
	}
	if expectedThumb == "" {
		return event, NewArgumentError(fmt.Sprintf("dnsid: log signer role %q has no event key thumbprint", role), nil)
	}
	if keyThumb != expectedThumb {
		return event, NewArgumentError(fmt.Sprintf("dnsid: log signer role %q key does not match event key", role), nil)
	}

	switch role {
	case LogSignerEntity:
		event.InitialEntityKid = kid
		event.InitialEntitySignature = ""
	case LogSignerOperationalCountersignature:
		event.InitialOperationalKid = kid
		event.InitialOperationalSignature = ""
	case LogSignerPreviousOperational:
		event.PreviousOperationalKid = kid
		event.PreviousOperationalSignature = ""
	case LogSignerNewOperational:
		event.NewOperationalKid = kid
		event.NewOperationalSignature = ""
	}
	canonical, err := canonicalizer.Canonical(event)
	if err != nil {
		return event, NewValidationError("dnsid: canonicalizing lifecycle event", err)
	}
	var sig *KeySignature
	if useNamedKey {
		sig, err = kp.SignKey(kid, canonical)
	} else {
		sig, err = kp.Sign(canonical)
	}
	if err != nil {
		return event, NewArgumentError(fmt.Sprintf("dnsid: log signer role %q signing failed", role), err)
	}
	if sig == nil {
		return event, NewArgumentError(fmt.Sprintf("dnsid: log signer role %q KeyProvider returned no signature", role), nil)
	}
	if sig.Kid != kid {
		return event, NewArgumentError(fmt.Sprintf("dnsid: log signer role %q signed with kid %q, want %q", role, sig.Kid, kid), nil)
	}
	encoded := base64.RawURLEncoding.EncodeToString(sig.Signature)
	switch role {
	case LogSignerEntity:
		event.InitialEntitySignature = encoded
	case LogSignerOperationalCountersignature:
		event.InitialOperationalSignature = encoded
	case LogSignerPreviousOperational:
		event.PreviousOperationalSignature = encoded
	case LogSignerNewOperational:
		event.NewOperationalSignature = encoded
	}
	return event, nil
}

func validateLifecycleEvent(event dnsidlog.LogEvent) error {
	if event.Type == dnsidlog.LogEventRevocation && !dnsidlog.ValidRevocationReason(event.Reason) {
		return NewArgumentError(fmt.Sprintf("dnsid: invalid REVOCATION reason %q", event.Reason), nil)
	}
	return nil
}

// RequiredLogSignatures returns the base draft-01 signer roles for event.
func RequiredLogSignatures(event dnsidlog.LogEvent) ([]LogSignerRole, error) {
	switch event.Type {
	case dnsidlog.LogEventIssuance:
		return []LogSignerRole{LogSignerEntity, LogSignerOperationalCountersignature}, nil
	case dnsidlog.LogEventKeyRotation:
		return []LogSignerRole{LogSignerPreviousOperational}, nil
	case dnsidlog.LogEventRevocation, dnsidlog.LogEventRetirement, dnsidlog.LogEventMigration, dnsidlog.LogEventDelegation:
		return []LogSignerRole{LogSignerEntity}, nil
	default:
		return nil, NewArgumentError(fmt.Sprintf("dnsid: unsupported lifecycle event type %q", event.Type), nil)
	}
}

func logSignaturePresent(event dnsidlog.LogEvent, role LogSignerRole) bool {
	switch role {
	case LogSignerEntity:
		return event.InitialEntityKid != "" && event.InitialEntitySignature != ""
	case LogSignerOperationalCountersignature:
		return event.InitialOperationalKid != "" && event.InitialOperationalSignature != ""
	case LogSignerPreviousOperational:
		return event.PreviousOperationalKid != "" && event.PreviousOperationalSignature != ""
	case LogSignerNewOperational:
		return event.NewOperationalKid != "" && event.NewOperationalSignature != ""
	default:
		return false
	}
}

// WriteSignedEvent writes an event without adding or replacing signatures.
// It rejects events missing signatures required by the shared lifecycle role
// model. Log bindings perform method-specific cryptographic validation.
func (m *IdentityManager) WriteSignedEvent(ctx context.Context, event dnsidlog.LogEvent) (dnsidlog.LogRef, error) {
	if err := validateLifecycleEvent(event); err != nil {
		return "", err
	}
	switch event.Type {
	case dnsidlog.LogEventIssuance:
		if event.InitialOperationalPublicKey == nil || event.InitialEntityPublicKey == nil {
			return "", NewArgumentError("dnsid: ISSUANCE requires operational and accountable-entity public keys", nil)
		}
		if event.InitialEntityKid == "" || event.InitialEntitySignature == "" {
			return "", NewArgumentError("dnsid: ISSUANCE requires an accountable-entity signature", nil)
		}
		if event.InitialOperationalKid == "" || event.InitialOperationalSignature == "" {
			return "", NewArgumentError("dnsid: ISSUANCE requires an operational countersignature", nil)
		}
	case dnsidlog.LogEventKeyRotation:
		if event.PreviousOperationalKid == "" || event.PreviousOperationalSignature == "" {
			return "", NewArgumentError("dnsid: KEY_ROTATION requires a previous-operational signature", nil)
		}
	case dnsidlog.LogEventRevocation, dnsidlog.LogEventRetirement, dnsidlog.LogEventMigration, dnsidlog.LogEventDelegation:
		if event.InitialEntityKid == "" || event.InitialEntitySignature == "" {
			return "", NewArgumentError(fmt.Sprintf("dnsid: %s requires an accountable-entity signature", event.Type), nil)
		}
	default:
		return "", NewArgumentError(fmt.Sprintf("dnsid: unsupported lifecycle event type %q", event.Type), nil)
	}
	log, err := m.localWriteLog()
	if err != nil {
		return "", err
	}
	return log.WriteEvent(ctx, event)
}

// GenerateIssuanceEvent builds a draft 01 ISSUANCE event, signs it with the
// entity key, countersigns it with the operational key, and writes it locally.
func (m *IdentityManager) GenerateIssuanceEvent(ctx context.Context) (dnsidlog.LogRef, error) {
	if err := m.requireLocalIdentity(); err != nil {
		return "", err
	}

	// Snapshot the operational key at the very start so that no mid-generation
	// key rotation can mix key versions between the recorded ku thumbprint and
	// the countersignature.
	opKid, err := activeSigningKid(m.keys)
	if err != nil {
		return "", err
	}
	opPubKey := m.keys.JWK(opKid)
	if opPubKey == nil {
		return "", NewArgumentError(fmt.Sprintf("dnsid: operational key %q not found", opKid), nil)
	}
	opThumb, err := (&JWK{key: opPubKey}).Thumbprint()
	if err != nil {
		return "", NewArgumentError("dnsid: computing operational key thumbprint", err)
	}

	event := dnsidlog.LogEvent{
		Type:                         dnsidlog.LogEventIssuance,
		Domain:                       m.identity.Domain,
		Timestamp:                    time.Now().Truncate(time.Second),
		InitialOperationalKid:        opKid,
		InitialOperationalPublicKey:  opPubKey,
		InitialOperationalThumbprint: opThumb,
		GovernanceID:                 m.identity.GovernanceID,
	}

	if m.entityKeys == nil {
		return "", NewArgumentError("dnsid: DNSid1 issuance requires an entity KeyProvider", nil)
	}
	// Include the entity key and produce the DNSid1 dual signatures.
	// The operational key was snapshotted above; use it consistently for
	// both the event record and countersignature.
	ekKid, err := activeSigningKid(m.entityKeys)
	if err != nil {
		return "", NewArgumentError("dnsid: invalid entity KeyProvider", err)
	}
	ekPubKey := m.entityKeys.JWK(ekKid)
	if ekPubKey == nil {
		return "", NewArgumentError(fmt.Sprintf("dnsid: entity key %q not found", ekKid), nil)
	}
	// Enforce DNSid1 ek≠ku distinctness: the endpoints require different
	// key material for entity and operational keys.
	ekThumb, err := (&JWK{key: ekPubKey}).Thumbprint()
	if err != nil {
		return "", NewArgumentError("dnsid: computing entity key thumbprint", err)
	}
	if ekThumb == opThumb {
		return "", NewArgumentError(fmt.Sprintf("dnsid: entity key and operational key must be distinct (same thumbprint %q)", opThumb), nil)
	}
	event.InitialEntityKid = ekKid
	event.InitialEntityPublicKey = ekPubKey
	event.InitialEntityThumbprint = ekThumb
	event.InitialEntitySignature = ""
	event.InitialOperationalSignature = ""

	log, err := m.localWriteLog()
	if err != nil {
		return "", err
	}

	// Entity key signature (primary).
	canonical, err := log.Canonical(event)
	if err != nil {
		return "", NewValidationError("dnsid: canonicalizing ISSUANCE event", err)
	}
	ekSig, err := m.entityKeys.Sign(canonical)
	if err != nil {
		return "", NewArgumentError("dnsid: entity key signing failed", err)
	}
	if ekSig == nil {
		return "", NewArgumentError("dnsid: entity KeyProvider returned no signature", nil)
	}
	if ekSig.Kid != ekKid {
		return "", NewArgumentError(fmt.Sprintf("dnsid: entity key provider signed with kid %q, want %q", ekSig.Kid, ekKid), nil)
	}
	event.InitialEntitySignature = base64.RawURLEncoding.EncodeToString(ekSig.Signature)

	// Operational key countersignature — uses the snapshotted opKid.
	event.InitialOperationalSignature = ""
	canonical, err = log.Canonical(event)
	if err != nil {
		return "", NewValidationError("dnsid: canonicalizing ISSUANCE countersignature", err)
	}
	opSig, err := m.keys.Sign(canonical)
	if err != nil {
		return "", NewArgumentError("dnsid: operational key signing failed", err)
	}
	if opSig == nil {
		return "", NewArgumentError("dnsid: operational KeyProvider returned no signature", nil)
	}
	if opSig.Kid != opKid {
		return "", NewArgumentError(fmt.Sprintf("dnsid: operational key rotated mid-generation: signed with kid %q, want snapshotted %q", opSig.Kid, opKid), nil)
	}
	event.InitialOperationalSignature = base64.RawURLEncoding.EncodeToString(opSig.Signature)

	return log.WriteEvent(ctx, event)
}

// SignAndWriteEvent adds every signature the event's type requires that is
// not already present — using the entity key for entity signatures and the
// operational key otherwise — and writes the event to the local log. Roles
// whose key provider is not configured are skipped, in which case
// WriteSignedEvent rejects the still-unsigned event. A zero Timestamp is set
// to the current time truncated to seconds.
func (m *IdentityManager) SignAndWriteEvent(ctx context.Context, event dnsidlog.LogEvent) (dnsidlog.LogRef, error) {
	if err := validateLifecycleEvent(event); err != nil {
		return "", err
	}
	log, err := m.localWriteLog()
	if err != nil {
		return "", err
	}
	if event.Timestamp.IsZero() {
		event.Timestamp = time.Now().Truncate(time.Second)
	}
	roles, err := RequiredLogSignatures(event)
	if err != nil {
		return "", err
	}
	for _, role := range roles {
		if logSignaturePresent(event, role) {
			continue
		}
		var kp KeyProvider
		if role == LogSignerEntity {
			kp = m.entityKeys
		} else {
			kp = m.keys
		}
		if kp == nil {
			continue
		}
		event, err = SignLogEventWithKey(event, role, kp, log)
		if err != nil {
			return "", err
		}
	}
	return m.WriteSignedEvent(ctx, event)
}

// RegistryRevoker is the registry capability required for managed revocation.
type RegistryRevoker interface {
	RevokeAgent(ctx context.Context, fqdn string, req *RevokeAgentRequest) (*LifecycleResponse, error)
}

// RevokeViaRegistry asks the registry to revoke the immutable managed identity
// at the local domain and evicts the local verified-domain cache. The registry
// owns lifecycle persistence and the transparency-log append; this method never
// appends a second local event.
func (m *IdentityManager) RevokeViaRegistry(ctx context.Context, client RegistryRevoker, agentID string, reason RegistryRevocationReason) (*LifecycleResponse, error) {
	if err := m.requireLocalIdentity(); err != nil {
		return nil, err
	}
	if client == nil {
		return nil, NewArgumentError("dnsid: nil RegistryRevoker", nil)
	}
	if agentID == "" {
		return nil, NewArgumentError("dnsid: agent ID is required", nil)
	}
	if !validRegistryRevocationReason(reason) {
		return nil, NewArgumentError(fmt.Sprintf("dnsid: invalid registry revocation reason %q", reason), nil)
	}
	resp, err := client.RevokeAgent(ctx, m.identity.Domain, &RevokeAgentRequest{AgentID: agentID, Reason: reason})
	if err != nil {
		return nil, err
	}
	m.EvictDomain(m.identity.Domain)
	return resp, nil
}

// VerifyLogEvidence performs an operation-time complete-history and
// non-revocation check through the log reader bound during domain verification.
// A zero at value uses the current time.
func (v *VerifiedDomain) VerifyLogEvidence(ctx context.Context, at time.Time) (evidence dnsidlog.LoggedStateEvidence, err error) {
	ctx, cancel := VerificationContext(ctx)
	defer cancel()
	defer func() {
		if err == nil {
			err = ctx.Err()
		}
		if err != nil {
			evidence = dnsidlog.LoggedStateEvidence{}
		}
	}()
	if v == nil || v.logReader == nil {
		return dnsidlog.LoggedStateEvidence{}, NewVerificationError(VerificationCodeLogError, false, "dnsid: verified domain has no log reader", nil)
	}
	if at.IsZero() {
		at = time.Now()
	}
	evidence, err = v.logReader.VerifyNonRevocation(ctx, v.domain, at)
	if err != nil {
		return dnsidlog.LoggedStateEvidence{}, logVerificationError(err)
	}
	return evidence, nil
}

// VerifyLogEvidence performs an operation-time complete-history and
// non-revocation check for vd. A zero at value uses the current time.
func (m *IdentityManager) VerifyLogEvidence(ctx context.Context, vd *VerifiedDomain, at time.Time) (dnsidlog.LoggedStateEvidence, error) {
	return vd.VerifyLogEvidence(ctx, at)
}

// LoadDomainLog rebuilds the verified lifecycle event history for a verified
// domain through the log reader bound during verification. It returns a
// *VerificationError with VerificationCodeLogError when vd carries no log
// reader or history reconstruction fails.
func (m *IdentityManager) LoadDomainLog(ctx context.Context, vd *VerifiedDomain) (*dnsidlog.DomainLog, error) {
	if vd == nil || vd.logReader == nil {
		return nil, NewVerificationError(VerificationCodeLogError, false, "dnsid: verified domain has no log reader", nil)
	}
	events, err := vd.logReader.RebuildHistory(ctx, vd.domain)
	if err != nil {
		return nil, logVerificationError(err)
	}
	return dnsidlog.NewDomainLog(vd.domain, events), nil
}

func (m *IdentityManager) localWriteLog() (dnsidlog.Log, error) {
	m.localLogMu.Lock()
	defer m.localLogMu.Unlock()

	if m.localLog != nil {
		return m.localLog, nil
	}
	reader, err := m.logReaderFor(m.identity.LogRef)
	if err != nil {
		return nil, err
	}
	log, ok := reader.(dnsidlog.Log)
	if !ok {
		return nil, NewArgumentError(fmt.Sprintf("dnsid: local log %q is not write-capable", m.identity.LogRef), nil)
	}
	m.localLog = log
	return log, nil
}

func (m *IdentityManager) logReaderFor(lr string) (dnsidlog.LogReader, error) {
	if m.logRegistry == nil {
		method, _, err := ParseLogRef(lr)
		if err != nil {
			return nil, err
		}
		return dnsidlog.NoopLogReader{Method: method}, nil
	}
	return m.logRegistry.NewReader(lr)
}

func logVerificationError(err error) error {
	if err == nil {
		return nil
	}
	var verErr *VerificationError
	if errors.As(err, &verErr) {
		return err
	}
	transient := false
	var classified interface{ Transient() bool }
	if errors.As(err, &classified) {
		transient = classified.Transient()
	}
	return NewVerificationError(VerificationCodeLogError, transient, "dnsid: lifecycle log verification failed", err)
}
