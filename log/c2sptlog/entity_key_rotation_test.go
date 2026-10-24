package c2sptlog

import (
	"context"
	"encoding/base64"
	"errors"
	"strings"
	"testing"
	"time"

	dnsid "github.com/dnsid-ai/dnsid-go"
	dnsidlog "github.com/dnsid-ai/dnsid-go/log"
	"github.com/lestrrat-go/jwx/v3/jwk"
)

const ekrStreamRef = "c2sp-tlog:testnet:http://dnsid-ledger:8080/log#identity-ekr"

var ekrBase = time.Unix(1782172800, 0).UTC()

// ekrStream builds a lifecycle stream entry by entry. Chain metadata for each
// new entry is derived from the verified history so far, so skipped
// candidates do not advance the chain.
type ekrStream struct {
	t      *testing.T
	source *memorySource
	client *Client
	next   int
}

func newEKRStream(t *testing.T) *ekrStream {
	t.Helper()
	source := &memorySource{complete: true, freshness: ekrBase.Add(24 * time.Hour)}
	client, err := New(ekrStreamRef, WithSource(source), WithPolicy(Policy{MaxCheckpointAge: 48 * time.Hour, Now: func() time.Time { return ekrBase.Add(24 * time.Hour) }}), withProofVerifySkipped())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return &ekrStream{t: t, source: source, client: client}
}

func (s *ekrStream) ts() time.Time {
	s.next++
	return ekrBase.Add(time.Duration(s.next) * time.Minute)
}

func (s *ekrStream) appendEntry(entry []byte) {
	s.source.entries = append(s.source.entries, ProvenEntry{Index: uint64(len(s.source.entries)), Entry: entry})
}

func (s *ekrStream) issue(entity, operational dnsid.KeyProvider) {
	s.t.Helper()
	event := dnsidlog.LogEvent{Type: dnsidlog.LogEventIssuance, Domain: "agent.example", GovernanceID: "example.com", Timestamp: s.ts(), InitialEntityPublicKey: entity.JWK(), InitialOperationalPublicKey: operational.JWK()}
	canonical, err := s.client.Canonical(event)
	if err != nil {
		s.t.Fatalf("Canonical ISSUANCE: %v", err)
	}
	event.InitialEntityKid, event.InitialEntitySignature = ekrSign(s.t, entity, canonical)
	event.InitialOperationalKid, event.InitialOperationalSignature = ekrSign(s.t, operational, canonical)
	entry, err := s.client.EntryBytes(event)
	if err != nil {
		s.t.Fatalf("EntryBytes ISSUANCE: %v", err)
	}
	s.appendEntry(entry)
}

// signed derives the chain from verified history, lets sign fill in the
// signature fields over the canonical bytes, and appends the entry.
func (s *ekrStream) signed(event dnsidlog.LogEvent, sign func(event *dnsidlog.LogEvent, canonical []byte)) {
	s.t.Helper()
	event.Domain = "agent.example"
	event.Timestamp = s.ts()
	chain, err := s.client.ChainForWrite(context.Background(), event)
	if err != nil {
		s.t.Fatalf("ChainForWrite %s: %v", event.Type, err)
	}
	s.signedWithChain(event, chain, sign)
}

func (s *ekrStream) signedWithChain(event dnsidlog.LogEvent, chain Chain, sign func(event *dnsidlog.LogEvent, canonical []byte)) {
	s.t.Helper()
	canonical, err := s.client.CanonicalWithChain(event, chain)
	if err != nil {
		s.t.Fatalf("CanonicalWithChain %s: %v", event.Type, err)
	}
	sign(&event, canonical)
	entry, err := s.client.EntryBytesWithChain(event, chain)
	if err != nil {
		s.t.Fatalf("EntryBytesWithChain %s: %v", event.Type, err)
	}
	s.appendEntry(entry)
}

func ekrSign(t *testing.T, kp dnsid.KeyProvider, canonical []byte) (string, string) {
	t.Helper()
	sig, err := kp.Sign(canonical)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	return sig.Kid, base64.RawURLEncoding.EncodeToString(sig.Signature)
}

func ekrKid(key jwk.Key) string {
	kid, _ := key.KeyID()
	return kid
}

func ekrThumb(t *testing.T, key jwk.Key) string {
	t.Helper()
	thumb, err := thumbprint(key)
	if err != nil {
		t.Fatalf("thumbprint: %v", err)
	}
	return thumb
}

// entityRotation returns an ENTITY_KEY_ROTATION from previous to next,
// signed by prevSigner (prev_ae) and newSigner (new_ae). A nil signer omits
// that signature.
func entityRotation(t *testing.T, previous, next jwk.Key, prevSigner, newSigner dnsid.KeyProvider) (dnsidlog.LogEvent, func(*dnsidlog.LogEvent, []byte)) {
	t.Helper()
	event := dnsidlog.LogEvent{
		Type:                     dnsidlog.LogEventEntityKeyRotation,
		PreviousEntityThumbprint: ekrThumb(t, previous),
		NewEntityThumbprint:      ekrThumb(t, next),
		NewEntityPublicKey:       next,
	}
	return event, func(event *dnsidlog.LogEvent, canonical []byte) {
		if prevSigner != nil {
			_, sig := ekrSign(t, prevSigner, canonical)
			event.PreviousEntityKid, event.PreviousEntitySignature = ekrKid(previous), sig
		}
		if newSigner != nil {
			_, sig := ekrSign(t, newSigner, canonical)
			event.NewEntityKid, event.NewEntitySignature = ekrKid(next), sig
		}
	}
}

func operationalRotation(t *testing.T, previous, next dnsid.KeyProvider) (dnsidlog.LogEvent, func(*dnsidlog.LogEvent, []byte)) {
	t.Helper()
	event := dnsidlog.LogEvent{
		Type:                          dnsidlog.LogEventKeyRotation,
		PreviousOperationalThumbprint: ekrThumb(t, previous.JWK()),
		NewOperationalThumbprint:      ekrThumb(t, next.JWK()),
		NewOperationalPublicKey:       next.JWK(),
	}
	return event, func(event *dnsidlog.LogEvent, canonical []byte) {
		event.PreviousOperationalKid, event.PreviousOperationalSignature = ekrSign(t, previous, canonical)
		event.NewOperationalKid, event.NewOperationalSignature = ekrSign(t, next, canonical)
	}
}

func entitySigned(t *testing.T, eventType dnsidlog.LogEventType, signer dnsid.KeyProvider) (dnsidlog.LogEvent, func(*dnsidlog.LogEvent, []byte)) {
	t.Helper()
	event := dnsidlog.LogEvent{Type: eventType}
	if eventType == dnsidlog.LogEventRevocation {
		event.Reason = "keyCompromise"
	}
	return event, func(event *dnsidlog.LogEvent, canonical []byte) {
		event.InitialEntityKid, event.InitialEntitySignature = ekrSign(t, signer, canonical)
	}
}

func ekrBindingInput(entity, operational jwk.Key) dnsidlog.BilateralBindingInput {
	return dnsidlog.BilateralBindingInput{Domain: "agent.example", GovernanceID: "example.com", EntityKey: entity, OperationalKey: operational}
}

func ekrTypes(events []dnsidlog.LogEvent) []dnsidlog.LogEventType {
	types := make([]dnsidlog.LogEventType, 0, len(events))
	for _, event := range events {
		types = append(types, event.Type)
	}
	return types
}

func ekrWantTypes(t *testing.T, events []dnsidlog.LogEvent, want ...dnsidlog.LogEventType) {
	t.Helper()
	got := ekrTypes(events)
	if len(got) != len(want) {
		t.Fatalf("history types = %v, want %v", got, want)
	}
	for i := range got {
		if got[i] != want[i] {
			t.Fatalf("history types = %v, want %v", got, want)
		}
	}
}

func ekrWantCode(t *testing.T, err error, code dnsid.VerificationCode) {
	t.Helper()
	var verificationErr *dnsid.VerificationError
	if !errors.As(err, &verificationErr) || verificationErr.Code() != code {
		t.Fatalf("error = %v, want code %s", err, code)
	}
}

func ekrWantCurrentEntity(t *testing.T, stream *ekrStream, want jwk.Key) {
	t.Helper()
	history, err := stream.client.RebuildHistory(context.Background(), "agent.example")
	if err != nil {
		t.Fatalf("RebuildHistory: %v", err)
	}
	current, err := dnsidlog.CurrentEntityKey(history)
	if err != nil {
		t.Fatalf("CurrentEntityKey: %v", err)
	}
	if ekrThumb(t, current) != ekrThumb(t, want) {
		t.Fatalf("CurrentEntityKey = %s, want %s", ekrThumb(t, current), ekrThumb(t, want))
	}
}

// Conformance 1: the record ek must be the rotated key, not the ISSUANCE key.
func TestEntityKeyRotationBindsRecordToRotatedKey(t *testing.T) {
	e1, e2, o1 := dnsid.GenerateEd25519KeyProvider(), dnsid.GenerateEd25519KeyProvider(), dnsid.GenerateEd25519KeyProvider()
	stream := newEKRStream(t)
	stream.issue(e1, o1)
	stream.signed(entityRotation(t, e1.JWK(), e2.JWK(), e1, e2))

	history, err := stream.client.RebuildHistory(context.Background(), "agent.example")
	if err != nil {
		t.Fatalf("RebuildHistory: %v", err)
	}
	ekrWantTypes(t, history, dnsidlog.LogEventIssuance, dnsidlog.LogEventEntityKeyRotation)
	if rotated := history[1]; rotated.NewEntityPublicKey == nil || rotated.NewEntityThumbprint != ekrThumb(t, e2.JWK()) || rotated.PreviousEntityThumbprint != ekrThumb(t, e1.JWK()) || rotated.PreviousEntitySignature == "" || rotated.NewEntitySignature == "" {
		t.Fatalf("RebuildHistory rotation fields = %#v", rotated)
	}

	binding, err := stream.client.VerifyBilateralBinding(context.Background(), ekrBindingInput(e2.JWK(), o1.JWK()))
	if err != nil {
		t.Fatalf("VerifyBilateralBinding rotated ek: %v", err)
	}
	if binding.InitialEntityThumbprint != ekrThumb(t, e1.JWK()) || binding.CurrentEntityThumbprint != ekrThumb(t, e2.JWK()) || binding.InitialOperationalThumbprint != ekrThumb(t, o1.JWK()) {
		t.Fatalf("binding = %#v", binding)
	}
	if _, err := stream.client.VerifyLifecycleBinding(context.Background(), ekrBindingInput(e2.JWK(), o1.JWK()), ekrThumb(t, o1.JWK())); err != nil {
		t.Fatalf("VerifyLifecycleBinding rotated ek: %v", err)
	}
	_, err = stream.client.VerifyBilateralBinding(context.Background(), ekrBindingInput(e1.JWK(), o1.JWK()))
	if err == nil || !strings.Contains(err.Error(), "c2sp-tlog current entity key does not match record ek for agent.example") {
		t.Fatalf("VerifyBilateralBinding ISSUANCE ek error = %v, want current entity key mismatch", err)
	}
	if _, err := stream.client.VerifyNonRevocation(context.Background(), "agent.example", ekrBase.Add(time.Hour)); err != nil {
		t.Fatalf("VerifyNonRevocation: %v", err)
	}
}

// Conformance 2: chained rotations end at the latest key.
func TestEntityKeyRotationChained(t *testing.T) {
	e1, e2, e3, o1 := dnsid.GenerateEd25519KeyProvider(), dnsid.GenerateEd25519KeyProvider(), dnsid.GenerateEd25519KeyProvider(), dnsid.GenerateEd25519KeyProvider()
	stream := newEKRStream(t)
	stream.issue(e1, o1)
	stream.signed(entityRotation(t, e1.JWK(), e2.JWK(), e1, e2))
	stream.signed(entityRotation(t, e2.JWK(), e3.JWK(), e2, e3))
	ekrWantCurrentEntity(t, stream, e3.JWK())
	binding, err := stream.client.VerifyBilateralBinding(context.Background(), ekrBindingInput(e3.JWK(), o1.JWK()))
	if err != nil || binding.CurrentEntityThumbprint != ekrThumb(t, e3.JWK()) || binding.InitialEntityThumbprint != ekrThumb(t, e1.JWK()) {
		t.Fatalf("VerifyBilateralBinding E3 = %#v, %v", binding, err)
	}
	for _, stale := range []dnsid.KeyProvider{e1, e2} {
		if _, err := stream.client.VerifyBilateralBinding(context.Background(), ekrBindingInput(stale.JWK(), o1.JWK())); err == nil {
			t.Fatal("VerifyBilateralBinding accepted a superseded entity key")
		}
	}
}

// Conformance 3 and 4: rotations without valid authorization or proof of
// possession are skipped, never errors, and leave the ISSUANCE key current.
func TestEntityKeyRotationUnauthorizedCandidatesAreSkipped(t *testing.T) {
	e1, o1 := dnsid.GenerateEd25519KeyProvider(), dnsid.GenerateEd25519KeyProvider()
	attacker, victim := dnsid.GenerateEd25519KeyProvider(), dnsid.GenerateEd25519KeyProvider()
	cases := []struct {
		name  string
		build func(t *testing.T) (dnsidlog.LogEvent, func(*dnsidlog.LogEvent, []byte))
	}{
		{"prev_ae signed by attacker under E1 kid", func(t *testing.T) (dnsidlog.LogEvent, func(*dnsidlog.LogEvent, []byte)) {
			return entityRotation(t, e1.JWK(), attacker.JWK(), attacker, attacker)
		}},
		{"prev_ae under attacker kid", func(t *testing.T) (dnsidlog.LogEvent, func(*dnsidlog.LogEvent, []byte)) {
			event, _ := entityRotation(t, e1.JWK(), attacker.JWK(), nil, nil)
			return event, func(event *dnsidlog.LogEvent, canonical []byte) {
				event.PreviousEntityKid, event.PreviousEntitySignature = ekrSign(t, attacker, canonical)
				event.NewEntityKid, event.NewEntitySignature = ekrSign(t, attacker, canonical)
			}
		}},
		{"prev_ae signed by operational key", func(t *testing.T) (dnsidlog.LogEvent, func(*dnsidlog.LogEvent, []byte)) {
			return entityRotation(t, e1.JWK(), attacker.JWK(), o1, attacker)
		}},
		{"new_ae signed by attacker for victim key", func(t *testing.T) (dnsidlog.LogEvent, func(*dnsidlog.LogEvent, []byte)) {
			return entityRotation(t, e1.JWK(), victim.JWK(), e1, attacker)
		}},
		{"new_ae signed by previous entity key", func(t *testing.T) (dnsidlog.LogEvent, func(*dnsidlog.LogEvent, []byte)) {
			return entityRotation(t, e1.JWK(), victim.JWK(), e1, e1)
		}},
		{"new_ae corrupted", func(t *testing.T) (dnsidlog.LogEvent, func(*dnsidlog.LogEvent, []byte)) {
			event, sign := entityRotation(t, e1.JWK(), victim.JWK(), e1, victim)
			return event, func(event *dnsidlog.LogEvent, canonical []byte) {
				sign(event, canonical)
				raw, _ := base64.RawURLEncoding.DecodeString(event.NewEntitySignature)
				raw[0] ^= 0xff
				event.NewEntitySignature = base64.RawURLEncoding.EncodeToString(raw)
			}
		}},
		{"new_ae missing", func(t *testing.T) (dnsidlog.LogEvent, func(*dnsidlog.LogEvent, []byte)) {
			return entityRotation(t, e1.JWK(), victim.JWK(), e1, nil)
		}},
		{"prev_ae missing", func(t *testing.T) (dnsidlog.LogEvent, func(*dnsidlog.LogEvent, []byte)) {
			return entityRotation(t, e1.JWK(), victim.JWK(), nil, victim)
		}},
		{"entity-role ae instead of prev_ae", func(t *testing.T) (dnsidlog.LogEvent, func(*dnsidlog.LogEvent, []byte)) {
			event, sign := entityRotation(t, e1.JWK(), victim.JWK(), nil, victim)
			return event, func(event *dnsidlog.LogEvent, canonical []byte) {
				sign(event, canonical)
				event.InitialEntityKid, event.InitialEntitySignature = ekrSign(t, e1, canonical)
			}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			stream := newEKRStream(t)
			stream.issue(e1, o1)
			stream.signed(tc.build(t))
			history, err := stream.client.RebuildHistory(context.Background(), "agent.example")
			if err != nil {
				t.Fatalf("RebuildHistory: %v", err)
			}
			ekrWantTypes(t, history, dnsidlog.LogEventIssuance)
			ekrWantCurrentEntity(t, stream, e1.JWK())
			if _, err := stream.client.VerifyBilateralBinding(context.Background(), ekrBindingInput(e1.JWK(), o1.JWK())); err != nil {
				t.Fatalf("VerifyBilateralBinding E1: %v", err)
			}
			for _, key := range []jwk.Key{attacker.JWK(), victim.JWK()} {
				if _, err := stream.client.VerifyBilateralBinding(context.Background(), ekrBindingInput(key, o1.JWK())); err == nil {
					t.Fatal("VerifyBilateralBinding accepted an unauthorized entity key")
				}
			}
		})
	}
}

// Conformance 5 and 6: authenticated rotations that break key continuity
// fail verification.
func TestEntityKeyRotationAuthenticatedContinuityFailures(t *testing.T) {
	e1, e2, o1, other := dnsid.GenerateEd25519KeyProvider(), dnsid.GenerateEd25519KeyProvider(), dnsid.GenerateEd25519KeyProvider(), dnsid.GenerateEd25519KeyProvider()
	cases := []struct {
		name    string
		build   func(t *testing.T) (dnsidlog.LogEvent, func(*dnsidlog.LogEvent, []byte))
		message string
	}{
		{"prev_ek_thumb not the active key", func(t *testing.T) (dnsidlog.LogEvent, func(*dnsidlog.LogEvent, []byte)) {
			event, _ := entityRotation(t, e1.JWK(), e2.JWK(), nil, nil)
			event.PreviousEntityThumbprint = ekrThumb(t, other.JWK())
			return event, func(event *dnsidlog.LogEvent, canonical []byte) {
				event.PreviousEntityKid, event.PreviousEntitySignature = ekrSign(t, e1, canonical)
				event.NewEntityKid, event.NewEntitySignature = ekrSign(t, e2, canonical)
			}
		}, "authenticated ENTITY_KEY_ROTATION does not continue from the active entity key"},
		{"new_ek is the current operational key", func(t *testing.T) (dnsidlog.LogEvent, func(*dnsidlog.LogEvent, []byte)) {
			return entityRotation(t, e1.JWK(), o1.JWK(), e1, o1)
		}, "authenticated ENTITY_KEY_ROTATION new key binding is invalid"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			stream := newEKRStream(t)
			stream.issue(e1, o1)
			stream.signed(tc.build(t))
			_, err := stream.client.RebuildHistory(context.Background(), "agent.example")
			ekrWantCode(t, err, dnsid.VerificationCodeKeyContinuity)
			if !strings.Contains(err.Error(), tc.message) {
				t.Fatalf("error = %v, want %q", err, tc.message)
			}
		})
	}
}

// Conformance 7: entity-signed events after a rotation are authorized only by
// the rotated key.
func TestEntityKeyRotationAuthorizesLaterEntityEvents(t *testing.T) {
	e1, e2, o1 := dnsid.GenerateEd25519KeyProvider(), dnsid.GenerateEd25519KeyProvider(), dnsid.GenerateEd25519KeyProvider()
	for _, eventType := range []dnsidlog.LogEventType{dnsidlog.LogEventRevocation, dnsidlog.LogEventRetirement} {
		t.Run(string(eventType)+" by E2", func(t *testing.T) {
			stream := newEKRStream(t)
			stream.issue(e1, o1)
			stream.signed(entityRotation(t, e1.JWK(), e2.JWK(), e1, e2))
			stream.signed(entitySigned(t, eventType, e2))
			history, err := stream.client.RebuildHistory(context.Background(), "agent.example")
			if err != nil {
				t.Fatalf("RebuildHistory: %v", err)
			}
			ekrWantTypes(t, history, dnsidlog.LogEventIssuance, dnsidlog.LogEventEntityKeyRotation, eventType)
			_, err = stream.client.VerifyNonRevocation(context.Background(), "agent.example", ekrBase.Add(time.Hour))
			ekrWantCode(t, err, dnsid.VerificationCodeTerminalState)
		})
		t.Run(string(eventType)+" by E1", func(t *testing.T) {
			stream := newEKRStream(t)
			stream.issue(e1, o1)
			stream.signed(entityRotation(t, e1.JWK(), e2.JWK(), e1, e2))
			stream.signed(entitySigned(t, eventType, e1))
			history, err := stream.client.RebuildHistory(context.Background(), "agent.example")
			if err != nil {
				t.Fatalf("RebuildHistory: %v", err)
			}
			ekrWantTypes(t, history, dnsidlog.LogEventIssuance, dnsidlog.LogEventEntityKeyRotation)
			if _, err := stream.client.VerifyNonRevocation(context.Background(), "agent.example", ekrBase.Add(time.Hour)); err != nil {
				t.Fatalf("VerifyNonRevocation: %v", err)
			}
		})
	}
	t.Run("DELEGATION by E2", func(t *testing.T) {
		stream := newEKRStream(t)
		stream.issue(e1, o1)
		stream.signed(entityRotation(t, e1.JWK(), e2.JWK(), e1, e2))
		event, sign := entitySigned(t, dnsidlog.LogEventDelegation, e2)
		event.Delegatee, event.Scope, event.Expiry = "delegate.example", "read", ekrBase.Add(48*time.Hour)
		stream.signed(event, sign)
		event, sign = entitySigned(t, dnsidlog.LogEventDelegation, e1)
		event.Delegatee, event.Scope, event.Expiry = "stale.example", "read", ekrBase.Add(48*time.Hour)
		stream.signed(event, sign)
		history, err := stream.client.RebuildHistory(context.Background(), "agent.example")
		if err != nil {
			t.Fatalf("RebuildHistory: %v", err)
		}
		ekrWantTypes(t, history, dnsidlog.LogEventIssuance, dnsidlog.LogEventEntityKeyRotation, dnsidlog.LogEventDelegation)
		if history[2].Delegatee != "delegate.example" {
			t.Fatalf("accepted delegation = %q, want E2-signed delegation", history[2].Delegatee)
		}
	})
}

// Conformance 8: operational and entity continuity interleave.
func TestEntityKeyRotationInterleavesWithKeyRotation(t *testing.T) {
	e1, e2, o1, o2, o3 := dnsid.GenerateEd25519KeyProvider(), dnsid.GenerateEd25519KeyProvider(), dnsid.GenerateEd25519KeyProvider(), dnsid.GenerateEd25519KeyProvider(), dnsid.GenerateEd25519KeyProvider()
	stream := newEKRStream(t)
	stream.issue(e1, o1)
	stream.signed(operationalRotation(t, o1, o2))
	stream.signed(entityRotation(t, e1.JWK(), e2.JWK(), e1, e2))
	stream.signed(operationalRotation(t, o2, o3))
	history, err := stream.client.RebuildHistory(context.Background(), "agent.example")
	if err != nil {
		t.Fatalf("RebuildHistory: %v", err)
	}
	ekrWantTypes(t, history, dnsidlog.LogEventIssuance, dnsidlog.LogEventKeyRotation, dnsidlog.LogEventEntityKeyRotation, dnsidlog.LogEventKeyRotation)
	binding, err := stream.client.VerifyLifecycleBinding(context.Background(), ekrBindingInput(e2.JWK(), o3.JWK()), ekrThumb(t, o3.JWK()))
	if err != nil {
		t.Fatalf("VerifyLifecycleBinding: %v", err)
	}
	if binding.InitialOperationalThumbprint != ekrThumb(t, o1.JWK()) || binding.CurrentEntityThumbprint != ekrThumb(t, e2.JWK()) {
		t.Fatalf("binding = %#v", binding)
	}
	if err := stream.client.VerifyOperationalContinuity(context.Background(), "agent.example", ekrThumb(t, o1.JWK()), ekrThumb(t, o2.JWK())); err == nil {
		t.Fatal("VerifyOperationalContinuity accepted a superseded operational key")
	}

	t.Run("new operational key equal to rotated entity key", func(t *testing.T) {
		stream := newEKRStream(t)
		stream.issue(e1, o1)
		stream.signed(entityRotation(t, e1.JWK(), e2.JWK(), e1, e2))
		stream.signed(operationalRotation(t, o1, e2))
		_, err := stream.client.RebuildHistory(context.Background(), "agent.example")
		ekrWantCode(t, err, dnsid.VerificationCodeKeyContinuity)
	})
	t.Run("new operational key equal to superseded entity key", func(t *testing.T) {
		stream := newEKRStream(t)
		stream.issue(e1, o1)
		stream.signed(entityRotation(t, e1.JWK(), e2.JWK(), e1, e2))
		stream.signed(operationalRotation(t, o1, e1))
		history, err := stream.client.RebuildHistory(context.Background(), "agent.example")
		if err != nil {
			t.Fatalf("RebuildHistory: %v", err)
		}
		ekrWantTypes(t, history, dnsidlog.LogEventIssuance, dnsidlog.LogEventEntityKeyRotation, dnsidlog.LogEventKeyRotation)
	})
}

// Conformance 9: ENTITY_KEY_ROTATION never starts a stream.
func TestEntityKeyRotationIsNeverGenesis(t *testing.T) {
	e1, e2 := dnsid.GenerateEd25519KeyProvider(), dnsid.GenerateEd25519KeyProvider()
	stream := newEKRStream(t)
	hash := lifecycleStateHash(activeLifecycleState("agent.example", ekrThumb(t, e1.JWK()), "x"))
	for _, chain := range []Chain{{Sequence: 1, PreviousEventID: hash, PreviousStateHash: hash}, {Sequence: 0}} {
		event, sign := entityRotation(t, e1.JWK(), e2.JWK(), e1, e2)
		event.Domain, event.Timestamp = "agent.example", stream.ts()
		if chain.Sequence == 0 {
			// Encode a seq=0 candidate directly; writers refuse it.
			payload, err := payloadFromEventWithChain(event, false, &stream.client.ref, chainFieldsFromChain(event, chain))
			if err != nil {
				t.Fatalf("payloadFromEventWithChain: %v", err)
			}
			canonical, err := canonicalJSON(payload)
			if err != nil {
				t.Fatal(err)
			}
			sign(&event, canonical)
			payload["sigs"] = signaturesFromEvent(event)
			entry, err := canonicalJSON(payload)
			if err != nil {
				t.Fatal(err)
			}
			stream.appendEntry(entry)
			continue
		}
		stream.signedWithChain(event, chain, sign)
	}
	_, err := stream.client.RebuildHistory(context.Background(), "agent.example")
	if err == nil || !strings.Contains(err.Error(), "no valid c2sp-tlog lifecycle events") {
		t.Fatalf("RebuildHistory error = %v, want no valid lifecycle events", err)
	}
}

// Conformance 10: an authenticated rotation after a terminal event fails.
func TestEntityKeyRotationAfterTerminalStateFails(t *testing.T) {
	e1, e2, o1 := dnsid.GenerateEd25519KeyProvider(), dnsid.GenerateEd25519KeyProvider(), dnsid.GenerateEd25519KeyProvider()
	for _, terminal := range []dnsidlog.LogEventType{dnsidlog.LogEventRetirement, dnsidlog.LogEventRevocation} {
		t.Run(string(terminal), func(t *testing.T) {
			stream := newEKRStream(t)
			stream.issue(e1, o1)
			stream.signed(entitySigned(t, terminal, e1))
			stream.signed(entityRotation(t, e1.JWK(), e2.JWK(), e1, e2))
			_, err := stream.client.RebuildHistory(context.Background(), "agent.example")
			ekrWantCode(t, err, dnsid.VerificationCodeTerminalState)
		})
	}
}

func ekrValidEntry(t *testing.T) (string, dnsid.KeyProvider, dnsid.KeyProvider) {
	t.Helper()
	e1, e2, o1 := dnsid.GenerateEd25519KeyProvider(), dnsid.GenerateEd25519KeyProvider(), dnsid.GenerateEd25519KeyProvider()
	stream := newEKRStream(t)
	stream.issue(e1, o1)
	stream.signed(entityRotation(t, e1.JWK(), e2.JWK(), e1, e2))
	return string(stream.source.entries[1].Entry), e1, e2
}

// Conformance 11: structural validation rejects malformed rotations.
func TestEntityKeyRotationStructuralValidation(t *testing.T) {
	entry, e1, e2 := ekrValidEntry(t)
	if _, err := LogEventFromEntry([]byte(entry)); err != nil {
		t.Fatalf("LogEventFromEntry valid: %v", err)
	}
	other := dnsid.GenerateEd25519KeyProvider()
	newEK := func(payload map[string]any) map[string]any { return payload["new_ek"].(map[string]any) }
	cases := []struct {
		name   string
		mutate func(map[string]any)
	}{
		{"new_ek_thumb mismatch", func(p map[string]any) { p["new_ek_thumb"] = ekrThumb(t, other.JWK()) }},
		{"new_ek_thumb equals prev_ek_thumb", func(p map[string]any) { p["new_ek_thumb"] = p["prev_ek_thumb"] }},
		{"prev_ek_thumb equals new key", func(p map[string]any) { p["prev_ek_thumb"] = p["new_ek_thumb"] }},
		{"missing prev_ek_thumb", func(p map[string]any) { delete(p, "prev_ek_thumb") }},
		{"missing new_ek_thumb", func(p map[string]any) { delete(p, "new_ek_thumb") }},
		{"missing new_ek", func(p map[string]any) { delete(p, "new_ek") }},
		{"new_ek private", func(p map[string]any) { newEK(p)["d"] = "nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A" }},
		{"new_ek stray private member", func(p map[string]any) { newEK(p)["qi"] = "AQAB" }},
		{"new_ek symmetric member", func(p map[string]any) { newEK(p)["k"] = "AQAB" }},
		{"new_ek other-primes member", func(p map[string]any) { newEK(p)["oth"] = []any{map[string]any{"r": "AQAB", "d": "AQAB", "t": "AQAB"}} }},
		{"new_ek missing kid", func(p map[string]any) { delete(newEK(p), "kid") }},
		{"new_ek missing alg", func(p map[string]any) { delete(newEK(p), "alg") }},
		{"new_ek wrong alg", func(p map[string]any) { newEK(p)["alg"] = "ES256" }},
		{"new_ek encryption use", func(p map[string]any) { newEK(p)["use"] = "enc" }},
		{"new_ae kid does not match new_ek", func(p map[string]any) {
			p["sigs"].(map[string]any)["new_ae"].(map[string]any)["kid"] = "other-kid"
		}},
		{"extra signature role", func(p map[string]any) {
			p["sigs"].(map[string]any)["ae"] = p["sigs"].(map[string]any)["prev_ae"]
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			mutated := canonicalEntryMutation(t, entry, tc.mutate)
			if _, err := LogEventFromEntry(mutated); err == nil {
				t.Fatal("LogEventFromEntry accepted a malformed ENTITY_KEY_ROTATION")
			}
		})
	}

	// A correctly signed but structurally invalid rotation is evidence of
	// an invalid authenticated payload, not noise.
	t.Run("authenticated new_ek_thumb equals prev_ek_thumb", func(t *testing.T) {
		o1 := dnsid.GenerateEd25519KeyProvider()
		stream := newEKRStream(t)
		stream.issue(e1, o1)
		event, _ := entityRotation(t, e1.JWK(), e2.JWK(), nil, nil)
		event.Domain, event.Timestamp = "agent.example", stream.ts()
		chain, err := stream.client.ChainForWrite(context.Background(), event)
		if err != nil {
			t.Fatal(err)
		}
		payload, err := payloadFromEventWithChain(event, false, &stream.client.ref, chainFieldsFromChain(event, chain))
		if err != nil {
			t.Fatal(err)
		}
		payload["new_ek_thumb"] = payload["prev_ek_thumb"]
		canonical, err := canonicalJSON(payload)
		if err != nil {
			t.Fatal(err)
		}
		_, prevSig := ekrSign(t, e1, canonical)
		_, newSig := ekrSign(t, e2, canonical)
		payload["sigs"] = map[string]any{
			"prev_ae": map[string]any{"kid": ekrKid(e1.JWK()), "sig": prevSig},
			"new_ae":  map[string]any{"kid": ekrKid(e2.JWK()), "sig": newSig},
		}
		entry, err := canonicalJSON(payload)
		if err != nil {
			t.Fatal(err)
		}
		stream.appendEntry(entry)
		_, err = stream.client.RebuildHistory(context.Background(), "agent.example")
		ekrWantCode(t, err, dnsid.VerificationCodeInvalidEvidence)
	})

	t.Run("encode rejects invalid events", func(t *testing.T) {
		base := dnsidlog.LogEvent{Type: dnsidlog.LogEventEntityKeyRotation, Domain: "agent.example", Timestamp: ekrBase, PreviousEntityThumbprint: ekrThumb(t, e1.JWK()), NewEntityThumbprint: ekrThumb(t, e2.JWK()), NewEntityPublicKey: e2.JWK()}
		if _, err := Canonical(base); err != nil {
			t.Fatalf("Canonical valid: %v", err)
		}
		for name, mutate := range map[string]func(*dnsidlog.LogEvent){
			"missing new key":    func(e *dnsidlog.LogEvent) { e.NewEntityPublicKey = nil },
			"thumb mismatch":     func(e *dnsidlog.LogEvent) { e.NewEntityThumbprint = ekrThumb(t, other.JWK()) },
			"unchanged key":      func(e *dnsidlog.LogEvent) { e.PreviousEntityThumbprint = e.NewEntityThumbprint },
			"missing prev thumb": func(e *dnsidlog.LogEvent) { e.PreviousEntityThumbprint = "" },
		} {
			event := base
			mutate(&event)
			if _, err := Canonical(event); err == nil {
				t.Fatalf("Canonical accepted %s", name)
			}
		}
	})
}

func TestEntityKeyRotationEntryRoundTrip(t *testing.T) {
	entry, e1, e2 := ekrValidEntry(t)
	for _, field := range []string{`"type":"ENTITY_KEY_ROTATION"`, `"prev_ek_thumb":"` + ekrThumb(t, e1.JWK()) + `"`, `"new_ek_thumb":"` + ekrThumb(t, e2.JWK()) + `"`, `"new_ek":{`, `"prev_ae":{"kid":"` + ekrKid(e1.JWK()) + `"`, `"new_ae":{"kid":"` + ekrKid(e2.JWK()) + `"`, `"seq":1`, `"prev_event_id":`, `"prev_state_hash":`} {
		if !strings.Contains(entry, field) {
			t.Fatalf("entry missing %s: %s", field, entry)
		}
	}
	event, err := LogEventFromEntry([]byte(entry))
	if err != nil {
		t.Fatalf("LogEventFromEntry: %v", err)
	}
	if event.Type != dnsidlog.LogEventEntityKeyRotation || event.PreviousEntityThumbprint != ekrThumb(t, e1.JWK()) || event.NewEntityThumbprint != ekrThumb(t, e2.JWK()) || ekrThumb(t, event.NewEntityPublicKey) != ekrThumb(t, e2.JWK()) || event.PreviousEntityKid != ekrKid(e1.JWK()) || event.NewEntityKid != ekrKid(e2.JWK()) || event.PreviousEntitySignature == "" || event.NewEntitySignature == "" {
		t.Fatalf("decoded event = %#v", event)
	}
	if event.InitialEntityKid != "" || event.PreviousOperationalKid != "" || event.NewOperationalKid != "" {
		t.Fatalf("decoded event populated unrelated signature roles: %#v", event)
	}
	client, err := New(ekrStreamRef)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := parseEventFromEntry([]byte(entry))
	if err != nil {
		t.Fatal(err)
	}
	seq := *parsed.chain.sequence
	reencoded, err := client.EntryBytesWithChain(event, Chain{Sequence: seq, PreviousEventID: parsed.chain.previousEventID, PreviousStateHash: parsed.chain.previousStateHash})
	if err != nil {
		t.Fatalf("EntryBytesWithChain: %v", err)
	}
	if string(reencoded) != entry {
		t.Fatalf("round trip changed entry:\n got %s\nwant %s", reencoded, entry)
	}
	signed, err := CanonicalFromEntry([]byte(entry))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(signed), `"sigs"`) {
		t.Fatal("canonical signing bytes include signatures")
	}
}

func TestEntityKeyRotationPreparedSigning(t *testing.T) {
	e1, e2, o1 := dnsid.GenerateEd25519KeyProvider(), dnsid.GenerateEd25519KeyProvider(), dnsid.GenerateEd25519KeyProvider()
	stream := newEKRStream(t)
	appender := &memoryAppender{}
	stream.client.appender = appender
	stream.issue(e1, o1)
	ctx := context.Background()

	event, _ := entityRotation(t, e1.JWK(), e2.JWK(), nil, nil)
	event.Domain, event.Timestamp = "agent.example", stream.ts()
	chain, err := stream.client.ChainForWrite(ctx, event)
	if err != nil {
		t.Fatalf("ChainForWrite: %v", err)
	}
	prepared, err := stream.client.PrepareEventWithChain(event, chain)
	if err != nil {
		t.Fatalf("PrepareEventWithChain: %v", err)
	}
	roles := prepared.RequiredSignatures()
	if len(roles) != 2 || roles[0] != SignerPreviousEntity || roles[1] != SignerNewEntity {
		t.Fatalf("RequiredSignatures = %v, want [previous_entity new_entity]", roles)
	}
	for _, bad := range []struct {
		role SignerRole
		kp   dnsid.KeyProvider
	}{
		{SignerEntity, e1},
		{SignerPreviousOperational, o1},
		{SignerPreviousEntity, e2},
		{SignerPreviousEntity, o1},
		{SignerNewEntity, e1},
	} {
		if _, err := stream.client.SignPreparedEvent(ctx, prepared, bad.role, bad.kp); err == nil {
			t.Fatalf("SignPreparedEvent accepted role %s with the wrong key", bad.role)
		}
	}
	if _, err := stream.client.PreparedEntryBytes(ctx, prepared); err == nil {
		t.Fatal("PreparedEntryBytes accepted an unsigned rotation")
	}
	// Collect the roles in either order across a serialized handoff.
	prepared, err = stream.client.SignPreparedEvent(ctx, prepared, SignerNewEntity, e2)
	if err != nil {
		t.Fatalf("SignPreparedEvent new_entity: %v", err)
	}
	if _, err := stream.client.PreparedEntryBytes(ctx, prepared); err == nil {
		t.Fatal("PreparedEntryBytes accepted a rotation without prev_ae")
	}
	partial, err := prepared.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	prepared, err = stream.client.ParsePreparedEvent(partial)
	if err != nil {
		t.Fatalf("ParsePreparedEvent: %v", err)
	}
	prepared, err = stream.client.SignPreparedEvent(ctx, prepared, SignerPreviousEntity, e1)
	if err != nil {
		t.Fatalf("SignPreparedEvent previous_entity: %v", err)
	}
	ref, err := stream.client.WritePreparedEvent(ctx, prepared)
	if err != nil {
		t.Fatalf("WritePreparedEvent: %v", err)
	}
	if !strings.HasSuffix(string(ref), "@0") || len(appender.entries) != 1 {
		t.Fatalf("WritePreparedEvent ref = %q entries = %d", ref, len(appender.entries))
	}
	stream.appendEntry(appender.entries[0])
	ekrWantCurrentEntity(t, stream, e2.JWK())

	// The rotated key now signs later entity events; the old key cannot.
	revocation := dnsidlog.LogEvent{Type: dnsidlog.LogEventRevocation, Domain: "agent.example", Timestamp: stream.ts(), Reason: "superseded"}
	chain, err = stream.client.ChainForWrite(ctx, revocation)
	if err != nil {
		t.Fatalf("ChainForWrite revocation: %v", err)
	}
	wantState := lifecycleStateHash(activeLifecycleState("agent.example", ekrThumb(t, e2.JWK()), ekrThumb(t, o1.JWK())))
	if chain.PreviousStateHash != wantState {
		t.Fatalf("ChainForWrite state hash = %s, want rotated entity state %s", chain.PreviousStateHash, wantState)
	}
	preparedRevocation, err := stream.client.PrepareEventWithChain(revocation, chain)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := stream.client.SignPreparedEvent(ctx, preparedRevocation, SignerEntity, e1); err == nil {
		t.Fatal("SignPreparedEvent accepted the superseded entity key")
	}
	if _, err := stream.client.SignPreparedEvent(ctx, preparedRevocation, SignerEntity, e2); err != nil {
		t.Fatalf("SignPreparedEvent rotated entity key: %v", err)
	}

	t.Run("writer refuses discontinuous rotations", func(t *testing.T) {
		e3 := dnsid.GenerateEd25519KeyProvider()
		for name, event := range map[string]dnsidlog.LogEvent{
			"stale previous key":     {Type: dnsidlog.LogEventEntityKeyRotation, PreviousEntityThumbprint: ekrThumb(t, e1.JWK()), NewEntityThumbprint: ekrThumb(t, e3.JWK()), NewEntityPublicKey: e3.JWK()},
			"new key is operational": {Type: dnsidlog.LogEventEntityKeyRotation, PreviousEntityThumbprint: ekrThumb(t, e2.JWK()), NewEntityThumbprint: ekrThumb(t, o1.JWK()), NewEntityPublicKey: o1.JWK()},
		} {
			event.Domain, event.Timestamp = "agent.example", stream.ts()
			chain, err := stream.client.ChainForWrite(ctx, event)
			if err != nil {
				t.Fatal(err)
			}
			prepared, err := stream.client.PrepareEventWithChain(event, chain)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := stream.client.SignPreparedEvent(ctx, prepared, SignerPreviousEntity, e2); err == nil {
				t.Fatalf("SignPreparedEvent accepted %s", name)
			}
		}
	})
}

// Inbound MIGRATION imports, and is authorized by, the entity key current at
// the end of the verified prior history.
func TestEntityKeyRotationMigrationImportsCurrentEntityKey(t *testing.T) {
	e1, e2, o1 := dnsid.GenerateEd25519KeyProvider(), dnsid.GenerateEd25519KeyProvider(), dnsid.GenerateEd25519KeyProvider()
	stream := newEKRStream(t)
	stream.issue(e1, o1)
	stream.signed(entityRotation(t, e1.JWK(), e2.JWK(), e1, e2))
	prior, err := stream.client.RebuildHistory(context.Background(), "agent.example")
	if err != nil {
		t.Fatalf("RebuildHistory: %v", err)
	}
	migration := dnsidlog.LogEvent{Type: dnsidlog.LogEventMigration, Domain: "agent.example", Timestamp: stream.ts(), PreviousLog: ekrStreamRef, NewLog: ekrStreamRef + "-next", FinalEntryRef: ekrStreamRef + "@1"}
	if err := validateMigrationResult(migration, MigrationVerificationResult{EntityKey: e2.JWK(), ActiveOperationalKey: o1.JWK(), PriorHistory: prior}); err != nil {
		t.Fatalf("validateMigrationResult rotated entity key: %v", err)
	}
	err = validateMigrationResult(migration, MigrationVerificationResult{EntityKey: e1.JWK(), ActiveOperationalKey: o1.JWK(), PriorHistory: prior})
	ekrWantCode(t, err, dnsid.VerificationCodeInvalidMigration)

	// The destination genesis must be signed by the imported (rotated) key.
	destination, err := New(ekrStreamRef+"-next", WithSource(&memorySource{}), withProofVerifySkipped())
	if err != nil {
		t.Fatal(err)
	}
	verifier := func(context.Context, dnsidlog.LogEvent) (MigrationVerificationResult, error) {
		return MigrationVerificationResult{EntityKey: e2.JWK(), ActiveOperationalKey: o1.JWK(), PriorHistory: prior}, nil
	}
	for _, tc := range []struct {
		signer   dnsid.KeyProvider
		accepted bool
	}{{e2, true}, {e1, false}} {
		canonical, err := destination.Canonical(migration)
		if err != nil {
			t.Fatalf("Canonical MIGRATION: %v", err)
		}
		signedMigration := migration
		signedMigration.InitialEntityKid, signedMigration.InitialEntitySignature = ekrSign(t, tc.signer, canonical)
		entry, err := destination.EntryBytes(signedMigration)
		if err != nil {
			t.Fatalf("EntryBytes MIGRATION: %v", err)
		}
		accepted, history, err := verifyLifecycleVerifiedWithMigration(context.Background(), []verifiedEvent{verifiedFromEntry(t, 0, string(entry))}, verifier, ekrStreamRef+"-next")
		if !tc.accepted {
			ekrWantCode(t, err, dnsid.VerificationCodeInvalidMigration)
			continue
		}
		if err != nil || len(accepted) != 1 {
			t.Fatalf("verify migration = %v, %v", accepted, err)
		}
		stitched := append(history, accepted[0].event)
		current, err := dnsidlog.CurrentEntityKey(stitched)
		if err != nil || ekrThumb(t, current) != ekrThumb(t, e2.JWK()) {
			t.Fatalf("CurrentEntityKey stitched = %v, %v; want E2", current, err)
		}
		if _, err := verifyBilateralBinding(stitched, ekrBindingInput(e2.JWK(), o1.JWK())); err != nil {
			t.Fatalf("verifyBilateralBinding stitched: %v", err)
		}
	}
}

// Streams without ENTITY_KEY_ROTATION keep the ISSUANCE key as current.
func TestEntityKeyRotationAbsentKeepsIssuanceBinding(t *testing.T) {
	source := basicSource{entries: []ProvenEntry{{Index: 0, Entry: []byte(issuanceEntry)}, {Index: 1, Entry: []byte(keyRotationEntry)}}}
	client, err := New("c2sp-tlog:testnet:http://dnsid-ledger:8080/log#identity-01", WithSource(source), WithPolicy(Policy{Now: func() time.Time { return time.Unix(1782259201, 0).UTC() }}), withProofVerifySkipped())
	if err != nil {
		t.Fatal(err)
	}
	binding, err := client.VerifyBilateralBinding(context.Background(), ekrBindingInput(mustKey(t, aeJWK), mustKey(t, op2JWK)))
	if err != nil {
		t.Fatalf("VerifyBilateralBinding: %v", err)
	}
	if binding.CurrentEntityThumbprint != binding.InitialEntityThumbprint || binding.InitialEntityThumbprint != mustThumbprint(t, aeJWK) {
		t.Fatalf("binding = %#v, want current entity = ISSUANCE entity", binding)
	}
	_, err = client.VerifyBilateralBinding(context.Background(), ekrBindingInput(mustKey(t, op1JWK), mustKey(t, op2JWK)))
	if err == nil || !strings.Contains(err.Error(), "c2sp-tlog current entity key does not match record ek for agent.example") {
		t.Fatalf("VerifyBilateralBinding mismatch error = %v", err)
	}
}

func TestEntityKeyRotationEdgeCases(t *testing.T) {
	e1, e2, o1 := dnsid.GenerateEd25519KeyProvider(), dnsid.GenerateEd25519KeyProvider(), dnsid.GenerateEd25519KeyProvider()

	t.Run("exact duplicate is ignored", func(t *testing.T) {
		stream := newEKRStream(t)
		stream.issue(e1, o1)
		stream.signed(entityRotation(t, e1.JWK(), e2.JWK(), e1, e2))
		stream.appendEntry(stream.source.entries[1].Entry)
		history, err := stream.client.RebuildHistory(context.Background(), "agent.example")
		if err != nil {
			t.Fatalf("RebuildHistory: %v", err)
		}
		ekrWantTypes(t, history, dnsidlog.LogEventIssuance, dnsidlog.LogEventEntityKeyRotation)
		ekrWantCurrentEntity(t, stream, e2.JWK())
	})

	t.Run("rotate back to a superseded key", func(t *testing.T) {
		stream := newEKRStream(t)
		stream.issue(e1, o1)
		stream.signed(entityRotation(t, e1.JWK(), e2.JWK(), e1, e2))
		stream.signed(entityRotation(t, e2.JWK(), e1.JWK(), e2, e1))
		ekrWantCurrentEntity(t, stream, e1.JWK())
		if _, err := stream.client.VerifyBilateralBinding(context.Background(), ekrBindingInput(e1.JWK(), o1.JWK())); err != nil {
			t.Fatalf("VerifyBilateralBinding E1: %v", err)
		}
	})

	t.Run("new key sharing the previous kid label", func(t *testing.T) {
		shared, err := e2.JWK().Clone()
		if err != nil {
			t.Fatal(err)
		}
		if err := shared.Set(jwk.KeyIDKey, ekrKid(e1.JWK())); err != nil {
			t.Fatal(err)
		}
		stream := newEKRStream(t)
		stream.issue(e1, o1)
		stream.signed(entityRotation(t, e1.JWK(), shared, e1, e2))
		labelled := func(signer dnsid.KeyProvider) (dnsidlog.LogEvent, func(*dnsidlog.LogEvent, []byte)) {
			return dnsidlog.LogEvent{Type: dnsidlog.LogEventRevocation, Reason: "keyCompromise"}, func(event *dnsidlog.LogEvent, canonical []byte) {
				_, sig := ekrSign(t, signer, canonical)
				event.InitialEntityKid, event.InitialEntitySignature = ekrKid(e1.JWK()), sig
			}
		}
		stream.signed(labelled(e1))
		history, err := stream.client.RebuildHistory(context.Background(), "agent.example")
		if err != nil {
			t.Fatalf("RebuildHistory: %v", err)
		}
		ekrWantTypes(t, history, dnsidlog.LogEventIssuance, dnsidlog.LogEventEntityKeyRotation)
		stream.signed(labelled(e2))
		history, err = stream.client.RebuildHistory(context.Background(), "agent.example")
		if err != nil {
			t.Fatalf("RebuildHistory: %v", err)
		}
		ekrWantTypes(t, history, dnsidlog.LogEventIssuance, dnsidlog.LogEventEntityKeyRotation, dnsidlog.LogEventRevocation)
	})

	// Authority is taken from an event's chain predecessor. A holder of a
	// superseded entity key can therefore sign a fork off a pre-rotation
	// predecessor; it is never accepted, but it is an authenticated chain
	// conflict and fails verification, exactly as for KEY_ROTATION today.
	t.Run("superseded key fork from pre-rotation predecessor", func(t *testing.T) {
		stream := newEKRStream(t)
		stream.issue(e1, o1)
		forkEvent, forkSign := entitySigned(t, dnsidlog.LogEventRevocation, e1)
		forkEvent.Domain, forkEvent.Timestamp = "agent.example", stream.ts()
		forkChain, err := stream.client.ChainForWrite(context.Background(), forkEvent)
		if err != nil {
			t.Fatal(err)
		}
		stream.signed(entityRotation(t, e1.JWK(), e2.JWK(), e1, e2))
		forkEvent.Timestamp = stream.ts()
		stream.signedWithChain(forkEvent, forkChain, forkSign)
		_, err = stream.client.RebuildHistory(context.Background(), "agent.example")
		ekrWantCode(t, err, dnsid.VerificationCodeChainContinuity)
	})
}

func TestEntityKeyRotationRebuildHistoryThroughExportsRotatedKey(t *testing.T) {
	e1, e2, o1 := dnsid.GenerateEd25519KeyProvider(), dnsid.GenerateEd25519KeyProvider(), dnsid.GenerateEd25519KeyProvider()
	stream := newEKRStream(t)
	stream.issue(e1, o1)
	stream.signed(entityRotation(t, e1.JWK(), e2.JWK(), e1, e2))
	for _, tc := range []struct {
		index uint64
		want  jwk.Key
	}{{0, e1.JWK()}, {1, e2.JWK()}} {
		result, err := stream.client.RebuildHistoryThrough(context.Background(), "agent.example", stream.client.ref.FinalEventRef(tc.index))
		if err != nil {
			t.Fatalf("RebuildHistoryThrough @%d: %v", tc.index, err)
		}
		if ekrThumb(t, result.EntityKey) != ekrThumb(t, tc.want) || ekrThumb(t, result.ActiveOperationalKey) != ekrThumb(t, o1.JWK()) {
			t.Fatalf("RebuildHistoryThrough @%d entity = %s, want %s", tc.index, ekrThumb(t, result.EntityKey), ekrThumb(t, tc.want))
		}
		migration := dnsidlog.LogEvent{Type: dnsidlog.LogEventMigration, Domain: "agent.example", Timestamp: stream.ts(), PreviousLog: ekrStreamRef, NewLog: ekrStreamRef + "-next", FinalEntryRef: string(stream.client.ref.FinalEventRef(tc.index))}
		if err := validateMigrationResult(migration, result); err != nil {
			t.Fatalf("validateMigrationResult @%d: %v", tc.index, err)
		}
	}
}

// A rotation after an inbound MIGRATION genesis continues from the imported
// entity key. ES256 keys exercise the second supported algorithm end to end.
func TestEntityKeyRotationAfterMigrationGenesisES256(t *testing.T) {
	e1, e2, e3 := dnsid.GenerateES256KeyProvider(), dnsid.GenerateES256KeyProvider(), dnsid.GenerateES256KeyProvider()
	o1 := dnsid.GenerateES256KeyProvider()
	previous := newEKRStream(t)
	previous.issue(e1, o1)
	previous.signed(entityRotation(t, e1.JWK(), e2.JWK(), e1, e2))
	prior, err := previous.client.RebuildHistory(context.Background(), "agent.example")
	if err != nil {
		t.Fatalf("RebuildHistory prior: %v", err)
	}

	destinationRef := ekrStreamRef + "-next"
	source := &memorySource{complete: true, freshness: ekrBase.Add(24 * time.Hour)}
	verifier := func(context.Context, dnsidlog.LogEvent) (MigrationVerificationResult, error) {
		return MigrationVerificationResult{EntityKey: e2.JWK(), ActiveOperationalKey: o1.JWK(), PriorHistory: prior}, nil
	}
	client, err := New(destinationRef, WithSource(source), WithMigrationVerifier(verifier), WithPolicy(Policy{MaxCheckpointAge: 48 * time.Hour, Now: func() time.Time { return ekrBase.Add(24 * time.Hour) }}), withProofVerifySkipped())
	if err != nil {
		t.Fatal(err)
	}
	stream := &ekrStream{t: t, source: source, client: client, next: previous.next}
	migration := dnsidlog.LogEvent{Type: dnsidlog.LogEventMigration, Domain: "agent.example", Timestamp: stream.ts(), PreviousLog: ekrStreamRef, NewLog: destinationRef, FinalEntryRef: string(previous.client.ref.FinalEventRef(1))}
	canonical, err := client.Canonical(migration)
	if err != nil {
		t.Fatalf("Canonical MIGRATION: %v", err)
	}
	migration.InitialEntityKid, migration.InitialEntitySignature = ekrSign(t, e2, canonical)
	entry, err := client.EntryBytes(migration)
	if err != nil {
		t.Fatalf("EntryBytes MIGRATION: %v", err)
	}
	stream.appendEntry(entry)
	stream.signed(entityRotation(t, e2.JWK(), e3.JWK(), e2, e3))
	stream.signed(entitySigned(t, dnsidlog.LogEventRevocation, e2))

	history, err := client.RebuildHistory(context.Background(), "agent.example")
	if err != nil {
		t.Fatalf("RebuildHistory destination: %v", err)
	}
	ekrWantTypes(t, history, dnsidlog.LogEventIssuance, dnsidlog.LogEventEntityKeyRotation, dnsidlog.LogEventMigration, dnsidlog.LogEventEntityKeyRotation)
	ekrWantCurrentEntity(t, stream, e3.JWK())
	binding, err := client.VerifyBilateralBinding(context.Background(), ekrBindingInput(e3.JWK(), o1.JWK()))
	if err != nil {
		t.Fatalf("VerifyBilateralBinding E3: %v", err)
	}
	if binding.InitialEntityThumbprint != ekrThumb(t, e1.JWK()) || binding.CurrentEntityThumbprint != ekrThumb(t, e3.JWK()) {
		t.Fatalf("binding = %#v", binding)
	}
	if _, err := client.VerifyBilateralBinding(context.Background(), ekrBindingInput(e2.JWK(), o1.JWK())); err == nil {
		t.Fatal("VerifyBilateralBinding accepted the imported key after rotation")
	}

	stream.signed(entitySigned(t, dnsidlog.LogEventRevocation, e3))
	history, err = client.RebuildHistory(context.Background(), "agent.example")
	if err != nil {
		t.Fatalf("RebuildHistory after revocation: %v", err)
	}
	ekrWantTypes(t, history, dnsidlog.LogEventIssuance, dnsidlog.LogEventEntityKeyRotation, dnsidlog.LogEventMigration, dnsidlog.LogEventEntityKeyRotation, dnsidlog.LogEventRevocation)
}

// Amendment 3: a new_ek carrying any private member is never used to verify
// new_ae, so the rotation is unauthenticated noise and is skipped.
func TestEntityKeyRotationPrivateNewKeyIsSkipped(t *testing.T) {
	for _, alg := range []string{"EdDSA", "ES256"} {
		for _, member := range []string{"d", "p", "q", "dp", "dq", "qi", "k", "oth"} {
			t.Run(alg+" "+member, func(t *testing.T) {
				e1, o1 := dnsid.GenerateEd25519KeyProvider(), dnsid.GenerateEd25519KeyProvider()
				e2 := dnsid.GenerateEd25519KeyProvider()
				if alg == "ES256" {
					e2 = dnsid.GenerateES256KeyProvider()
				}
				stream := newEKRStream(t)
				stream.issue(e1, o1)
				event, _ := entityRotation(t, e1.JWK(), e2.JWK(), nil, nil)
				event.Domain, event.Timestamp = "agent.example", stream.ts()
				chain, err := stream.client.ChainForWrite(context.Background(), event)
				if err != nil {
					t.Fatal(err)
				}
				payload, err := payloadFromEventWithChain(event, false, &stream.client.ref, chainFieldsFromChain(event, chain))
				if err != nil {
					t.Fatal(err)
				}
				value := base64.RawURLEncoding.EncodeToString(append([]byte{1}, make([]byte, 31)...))
				payload["new_ek"].(map[string]any)[member] = value
				canonical, err := canonicalJSON(payload)
				if err != nil {
					t.Fatal(err)
				}
				_, prevSig := ekrSign(t, e1, canonical)
				_, newSig := ekrSign(t, e2, canonical)
				payload["sigs"] = map[string]any{
					"prev_ae": map[string]any{"kid": ekrKid(e1.JWK()), "sig": prevSig},
					"new_ae":  map[string]any{"kid": ekrKid(e2.JWK()), "sig": newSig},
				}
				entry, err := canonicalJSON(payload)
				if err != nil {
					t.Fatal(err)
				}
				stream.appendEntry(entry)
				history, err := stream.client.RebuildHistory(context.Background(), "agent.example")
				if err != nil {
					t.Fatalf("RebuildHistory = %v, want private new_ek rotation skipped", err)
				}
				ekrWantTypes(t, history, dnsidlog.LogEventIssuance)
				ekrWantCurrentEntity(t, stream, e1.JWK())
			})
		}
	}
}

// Amendments 3 and 4: authenticated rotations that fail structural
// validation are fatal invalid evidence. Rotations that cannot authenticate
// (new_ek without a kid, new_ae naming another kid, unsupported curve) are
// skipped even though structural validation would also reject them.
func TestEntityKeyRotationAuthenticatedMalformedIsFatal(t *testing.T) {
	cases := map[string]func(payload map[string]any, other jwk.Key){
		"thumb mismatch":       func(p map[string]any, other jwk.Key) { p["new_ek_thumb"] = ekrThumb(t, other) },
		"thumb unchanged":      func(p map[string]any, _ jwk.Key) { p["new_ek_thumb"] = p["prev_ek_thumb"] },
		"missing alg":          func(p map[string]any, _ jwk.Key) { delete(p["new_ek"].(map[string]any), "alg") },
		"unsupported alg":      func(p map[string]any, _ jwk.Key) { p["new_ek"].(map[string]any)["alg"] = "ES384" },
		"unsupported crv":      func(p map[string]any, _ jwk.Key) { p["new_ek"].(map[string]any)["crv"] = "X25519" },
		"missing new_ek_thumb": func(p map[string]any, _ jwk.Key) { delete(p, "new_ek_thumb") },
		"missing kid":          func(p map[string]any, _ jwk.Key) { delete(p["new_ek"].(map[string]any), "kid") },
		"empty kid":            func(p map[string]any, _ jwk.Key) { p["new_ek"].(map[string]any)["kid"] = "" },
		"new_ae kid mismatch":  func(map[string]any, jwk.Key) {},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			e1, e2, o1, other := dnsid.GenerateEd25519KeyProvider(), dnsid.GenerateEd25519KeyProvider(), dnsid.GenerateEd25519KeyProvider(), dnsid.GenerateEd25519KeyProvider()
			stream := newEKRStream(t)
			stream.issue(e1, o1)
			event, _ := entityRotation(t, e1.JWK(), e2.JWK(), nil, nil)
			event.Domain, event.Timestamp = "agent.example", stream.ts()
			chain, err := stream.client.ChainForWrite(context.Background(), event)
			if err != nil {
				t.Fatal(err)
			}
			payload, err := payloadFromEventWithChain(event, false, &stream.client.ref, chainFieldsFromChain(event, chain))
			if err != nil {
				t.Fatal(err)
			}
			mutate(payload, other.JWK())
			canonical, err := canonicalJSON(payload)
			if err != nil {
				t.Fatal(err)
			}
			_, prevSig := ekrSign(t, e1, canonical)
			_, newSig := ekrSign(t, e2, canonical)
			newKid := ekrKid(e2.JWK())
			if name == "new_ae kid mismatch" {
				newKid = "other-kid"
			}
			payload["sigs"] = map[string]any{
				"prev_ae": map[string]any{"kid": ekrKid(e1.JWK()), "sig": prevSig},
				"new_ae":  map[string]any{"kid": newKid, "sig": newSig},
			}
			entry, err := canonicalJSON(payload)
			if err != nil {
				t.Fatal(err)
			}
			stream.appendEntry(entry)
			_, err = stream.client.RebuildHistory(context.Background(), "agent.example")
			if name == "unsupported crv" || name == "missing kid" || name == "empty kid" || name == "new_ae kid mismatch" {
				// The rotation cannot authenticate: an X25519 new_ek can
				// never verify new_ae, and new_ae must name kid(new_ek),
				// which must be non-empty. It is skipped, never fatal.
				if err != nil {
					t.Fatalf("RebuildHistory = %v, want unauthenticated rotation skipped", err)
				}
				ekrWantCurrentEntity(t, stream, e1.JWK())
				return
			}
			ekrWantCode(t, err, dnsid.VerificationCodeInvalidEvidence)
		})
	}
}

// Under a global-candidate source, spam at the tip from an attacker without
// the current entity key is skipped and the binding stays on E2.
func TestEntityKeyRotationGlobalCandidateSpamIsSkipped(t *testing.T) {
	e1, e2, o1, attacker := dnsid.GenerateEd25519KeyProvider(), dnsid.GenerateEd25519KeyProvider(), dnsid.GenerateEd25519KeyProvider(), dnsid.GenerateEd25519KeyProvider()
	stream := newEKRStream(t)
	stream.issue(e1, o1)
	stream.signed(entityRotation(t, e1.JWK(), e2.JWK(), e1, e2))
	legitimate := stream.source.entries[1].Entry
	stream.signed(entityRotation(t, e2.JWK(), attacker.JWK(), attacker, attacker))
	stream.signed(entityRotation(t, e2.JWK(), attacker.JWK(), nil, attacker))
	stream.signed(entitySigned(t, dnsidlog.LogEventRevocation, attacker))
	stream.signed(entitySigned(t, dnsidlog.LogEventRevocation, e1))
	// Move the legitimate rotation's signatures onto a rotation to the attacker's key.
	moved := canonicalEntryMutation(t, string(legitimate), func(p map[string]any) {
		attackerKey, _ := keyAsJSON(attacker.JWK())
		p["new_ek"] = attackerKey
		p["new_ek_thumb"] = ekrThumb(t, attacker.JWK())
	})
	stream.appendEntry(moved)
	stream.appendEntry(legitimate)

	global := &globalMemorySource{memorySource: *stream.source}
	client, err := New(ekrStreamRef, WithSource(global), WithPolicy(Policy{Now: func() time.Time { return ekrBase.Add(24 * time.Hour) }}), withProofVerifySkipped())
	if err != nil {
		t.Fatal(err)
	}
	history, err := client.RebuildHistory(context.Background(), "agent.example")
	if err != nil {
		t.Fatalf("RebuildHistory: %v", err)
	}
	ekrWantTypes(t, history, dnsidlog.LogEventIssuance, dnsidlog.LogEventEntityKeyRotation)
	if _, err := client.VerifyBilateralBinding(context.Background(), ekrBindingInput(e2.JWK(), o1.JWK())); err != nil {
		t.Fatalf("VerifyBilateralBinding E2: %v", err)
	}
	for _, key := range []jwk.Key{e1.JWK(), attacker.JWK()} {
		if _, err := client.VerifyBilateralBinding(context.Background(), ekrBindingInput(key, o1.JWK())); err == nil {
			t.Fatal("VerifyBilateralBinding accepted a key other than E2")
		}
	}
}

// One entity provider holding both keys signs new_entity with the pending key
// through SignPreparedEventWithKey; the writer refuses a new key that reuses
// the current entity kid.
func TestEntityKeyRotationPreparedSigningWithPendingKey(t *testing.T) {
	ctx := context.Background()
	entityKeys := dnsid.GenerateES256KeyProvider()
	previousKid := entityKeys.ListKeyIds()[0]
	o1 := dnsid.GenerateES256KeyProvider()
	stream := newEKRStream(t)
	stream.issue(entityKeys, o1)
	newKid, err := entityKeys.GenerateKey(dnsid.JoseAlgES256)
	if err != nil {
		t.Fatal(err)
	}
	newKey := entityKeys.JWK(newKid)
	event, _ := entityRotation(t, entityKeys.JWK(previousKid), newKey, nil, nil)
	event.Domain, event.Timestamp = "agent.example", stream.ts()
	chain, err := stream.client.ChainForWrite(ctx, event)
	if err != nil {
		t.Fatal(err)
	}
	prepared, err := stream.client.PrepareEventWithChain(event, chain)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := stream.client.SignPreparedEvent(ctx, prepared, SignerNewEntity, entityKeys); err == nil {
		t.Fatal("SignPreparedEvent signed new_entity with the active key")
	}
	prepared, err = stream.client.SignPreparedEventWithKey(ctx, prepared, SignerNewEntity, entityKeys, newKid)
	if err != nil {
		t.Fatalf("SignPreparedEventWithKey new_entity: %v", err)
	}
	prepared, err = stream.client.SignPreparedEvent(ctx, prepared, SignerPreviousEntity, entityKeys)
	if err != nil {
		t.Fatalf("SignPreparedEvent previous_entity: %v", err)
	}
	entry, err := stream.client.PreparedEntryBytes(ctx, prepared)
	if err != nil {
		t.Fatalf("PreparedEntryBytes: %v", err)
	}
	stream.appendEntry(entry)
	ekrWantCurrentEntity(t, stream, newKey)

	t.Run("writer refuses kid reuse", func(t *testing.T) {
		other := dnsid.GenerateES256KeyProvider()
		reused, err := other.JWK().Clone()
		if err != nil {
			t.Fatal(err)
		}
		if err := reused.Set(jwk.KeyIDKey, newKid); err != nil {
			t.Fatal(err)
		}
		event, _ := entityRotation(t, newKey, reused, nil, nil)
		event.Domain, event.Timestamp = "agent.example", stream.ts()
		chain, err := stream.client.ChainForWrite(ctx, event)
		if err != nil {
			t.Fatal(err)
		}
		prepared, err := stream.client.PrepareEventWithChain(event, chain)
		if err != nil {
			t.Fatal(err)
		}
		_, err = stream.client.SignPreparedEventWithKey(ctx, prepared, SignerPreviousEntity, entityKeys, newKid)
		if err == nil || !strings.Contains(err.Error(), "duplicate c2sp-tlog kid") {
			t.Fatalf("SignPreparedEventWithKey kid reuse error = %v, want duplicate kid", err)
		}
	})
}

// Amendment 5: a malformed ISSUANCE authenticated by its own keys is fatal
// invalid genesis evidence, not skipped.
func TestEntityKeyRotationMalformedAuthenticatedGenesisIsFatal(t *testing.T) {
	e1, o1 := dnsid.GenerateEd25519KeyProvider(), dnsid.GenerateEd25519KeyProvider()
	stream := newEKRStream(t)
	stream.issue(e1, o1)
	entry := stream.source.entries[0].Entry
	payload, err := decodeJSONObject(entry)
	if err != nil {
		t.Fatal(err)
	}
	delete(payload, "sigs")
	delete(payload, "gi")
	canonical, err := canonicalJSON(payload)
	if err != nil {
		t.Fatal(err)
	}
	_, entitySig := ekrSign(t, e1, canonical)
	_, operationalSig := ekrSign(t, o1, canonical)
	payload["sigs"] = map[string]any{
		"ae": map[string]any{"kid": ekrKid(e1.JWK()), "sig": entitySig},
		"op": map[string]any{"kid": ekrKid(o1.JWK()), "sig": operationalSig},
	}
	malformed, err := canonicalJSON(payload)
	if err != nil {
		t.Fatal(err)
	}
	stream.source.entries = nil
	stream.appendEntry(malformed)
	_, err = stream.client.RebuildHistory(context.Background(), "agent.example")
	ekrWantCode(t, err, dnsid.VerificationCodeInvalidEvidence)
	if !strings.Contains(err.Error(), "invalid authenticated genesis") {
		t.Fatalf("RebuildHistory error = %v, want invalid authenticated genesis", err)
	}
}

// Amendment 5: a holder of a superseded key cannot revive a revoked identity
// with a fresh ISSUANCE; the first authenticated genesis decides.
func TestEntityKeyRotationRevokedIdentityCannotBeRevivedBySupersededKey(t *testing.T) {
	e1, e2, e3, o1, o2 := dnsid.GenerateEd25519KeyProvider(), dnsid.GenerateEd25519KeyProvider(), dnsid.GenerateEd25519KeyProvider(), dnsid.GenerateEd25519KeyProvider(), dnsid.GenerateEd25519KeyProvider()
	for _, global := range []bool{false, true} {
		t.Run(map[bool]string{false: "per-stream source", true: "global-candidate source"}[global], func(t *testing.T) {
			stream := newEKRStream(t)
			stream.issue(e1, o1)
			stream.signed(entityRotation(t, e1.JWK(), e2.JWK(), e1, e2))
			stream.signed(entityRotation(t, e2.JWK(), e3.JWK(), e2, e3))
			stream.signed(entitySigned(t, dnsidlog.LogEventRevocation, e3))
			stream.issue(e2, o2)
			client := stream.client
			if global {
				var err error
				client, err = New(ekrStreamRef, WithSource(&globalMemorySource{memorySource: *stream.source}), WithPolicy(Policy{Now: func() time.Time { return ekrBase.Add(24 * time.Hour) }}), withProofVerifySkipped())
				if err != nil {
					t.Fatal(err)
				}
			}
			for _, operational := range []jwk.Key{o1.JWK(), o2.JWK()} {
				if _, err := client.VerifyBilateralBinding(context.Background(), ekrBindingInput(e2.JWK(), operational)); err == nil {
					t.Fatal("VerifyBilateralBinding revived a revoked identity with a fresh ISSUANCE")
				}
				if _, err := client.VerifyLifecycleBinding(context.Background(), ekrBindingInput(e2.JWK(), operational), ekrThumb(t, operational)); err == nil {
					t.Fatal("VerifyLifecycleBinding revived a revoked identity with a fresh ISSUANCE")
				}
			}
		})
	}
}
