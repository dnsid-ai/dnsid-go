package c2sptlog

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"testing"

	dnsid "github.com/dnsid-ai/dnsid-go"
	dnsidlog "github.com/dnsid-ai/dnsid-go/log"
)

const fixtureLR = "c2sp-tlog:testnet:http://dnsid-ledger:8080/log#identity-01"

// resignedFixture mutates a fixture entry and signs it again with the
// fixture keys named by its sigs.
func resignedFixture(t *testing.T, entry string, mutate func(map[string]any)) string {
	t.Helper()
	payload, err := decodeJSONObject([]byte(entry))
	if err != nil {
		t.Fatalf("decodeJSONObject: %v", err)
	}
	mutate(payload)
	return signFixturePayload(payload)
}

func entries(list ...string) [][]byte {
	out := make([][]byte, len(list))
	for i, e := range list {
		out[i] = []byte(e)
	}
	return out
}

func fixtureEventID(t *testing.T, entry string) string {
	t.Helper()
	signed, err := CanonicalFromEntry([]byte(entry))
	if err != nil {
		t.Fatalf("CanonicalFromEntry: %v", err)
	}
	return EventID(signed)
}

func TestLifecycleStateHash_MatchesMethodDefinition(t *testing.T) {
	state := LifecycleState{FQDN: "agent.example", Status: "ACTIVE", EntityThumb: "ent", OperationalThumb: "op"}
	// base64url-no-pad(SHA-256("dnsid-c2sp-state-v1" || JCS(state))), with
	// the JCS written out by hand.
	sum := sha256.Sum256([]byte(`dnsid-c2sp-state-v1{"entity_thumb":"ent","fqdn":"agent.example","operational_thumb":"op","status":"ACTIVE"}`))
	if got, want := state.Hash(), base64.RawURLEncoding.EncodeToString(sum[:]); got != want {
		t.Fatalf("Hash = %s, want %s", got, want)
	}
	revoked := state
	revoked.Status = "REVOKED"
	if revoked.Hash() == state.Hash() {
		t.Fatal("Hash does not depend on Status")
	}
}

func TestClientCheckAppend_AppliesCandidate(t *testing.T) {
	ae, op1, op2 := fixtureThumb(aeJWK), fixtureThumb(op1JWK), fixtureThumb(op2JWK)
	tests := []struct {
		name      string
		history   []string
		candidate string
		want      StreamHead
	}{
		{
			name:      "genesis",
			candidate: issuanceEntry,
			want:      StreamHead{Seq: 0, Type: dnsidlog.LogEventIssuance, State: LifecycleState{FQDN: "agent.example", Status: "ACTIVE", EntityThumb: ae, OperationalThumb: op1}},
		},
		{
			name:      "key rotation",
			history:   []string{issuanceEntry},
			candidate: keyRotationEntry,
			want:      StreamHead{Seq: 1, Type: dnsidlog.LogEventKeyRotation, State: LifecycleState{FQDN: "agent.example", Status: "ACTIVE", EntityThumb: ae, OperationalThumb: op2}},
		},
		{
			name:      "revocation",
			history:   []string{issuanceEntry, keyRotationEntry},
			candidate: revocationEntry,
			want:      StreamHead{Seq: 2, Type: dnsidlog.LogEventRevocation, State: LifecycleState{FQDN: "agent.example", Status: "REVOKED", EntityThumb: ae, OperationalThumb: op2}},
		},
	}
	client, err := New(fixtureLR)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			head, err := client.CheckAppend(context.Background(), entries(tt.history...), []byte(tt.candidate))
			if err != nil {
				t.Fatalf("CheckAppend: %v", err)
			}
			tt.want.EventID = fixtureEventID(t, tt.candidate)
			tt.want.GovernanceID = "example.com"
			if head != tt.want {
				t.Fatalf("head = %+v, want %+v", head, tt.want)
			}
		})
	}
}

func TestClientCheckAppend_HeadStateHashIsNextPredecessor(t *testing.T) {
	client, err := New(fixtureLR)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	head, err := client.CheckAppend(context.Background(), nil, []byte(issuanceEntry))
	if err != nil {
		t.Fatalf("CheckAppend: %v", err)
	}
	rotation, err := decodeJSONObject([]byte(keyRotationEntry))
	if err != nil {
		t.Fatalf("decodeJSONObject: %v", err)
	}
	if rotation["prev_event_id"] != head.EventID || rotation["prev_state_hash"] != head.State.Hash() {
		t.Fatalf("successor chain = %v, %v; head = %s, %s", rotation["prev_event_id"], rotation["prev_state_hash"], head.EventID, head.State.Hash())
	}
}

func TestClientCheckAppend_RejectsCandidate(t *testing.T) {
	revoked := LifecycleState{FQDN: "agent.example", Status: "REVOKED", EntityThumb: fixtureThumb(aeJWK), OperationalThumb: fixtureThumb(op2JWK)}
	afterRevocation := resignedFixture(t, revocationEntry, func(p map[string]any) {
		p["seq"] = 3
		p["prev_event_id"] = fixtureEventID(t, revocationEntry)
		p["prev_state_hash"] = revoked.Hash()
		p["ts"] = 1782345700
	})
	secondIssuance := resignedFixture(t, issuanceEntry, func(p map[string]any) { p["ts"] = 1782172900 })
	wrongPrevious := resignedFixture(t, keyRotationEntry, func(p map[string]any) { p["prev_thumb"] = fixtureThumb(op2JWK) })
	tampered := string(canonicalEntryMutation(t, keyRotationEntry, func(p map[string]any) { p["ts"] = 1782259201 }))

	tests := []struct {
		name      string
		history   []string
		candidate string
		code      dnsid.VerificationCode
	}{
		{"successor without genesis", nil, keyRotationEntry, dnsid.VerificationCodeChainContinuity},
		{"stale predecessor", []string{issuanceEntry}, revocationEntry, dnsid.VerificationCodeChainContinuity},
		{"after terminal state", []string{issuanceEntry, keyRotationEntry, revocationEntry}, afterRevocation, dnsid.VerificationCodeTerminalState},
		{"second issuance", []string{issuanceEntry}, secondIssuance, dnsid.VerificationCodeDuplicateIssuance},
		{"rotation from another key", []string{issuanceEntry}, wrongPrevious, dnsid.VerificationCodeKeyContinuity},
		{"invalid signature", []string{issuanceEntry}, tampered, dnsid.VerificationCodeSignatureInvalid},
		{"exact duplicate", []string{issuanceEntry}, issuanceEntry, dnsid.VerificationCodeInvalidEvidence},
	}
	client, err := New(fixtureLR)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := client.CheckAppend(context.Background(), entries(tt.history...), []byte(tt.candidate))
			var verr *dnsid.VerificationError
			if !errors.As(err, &verr) || verr.Code() != tt.code {
				t.Fatalf("CheckAppend error = %v, want %s", err, tt.code)
			}
		})
	}
}

func TestClientCheckAppend_RejectsMalformedOrForeignEntries(t *testing.T) {
	client, err := New(fixtureLR)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	otherStream, err := New("c2sp-tlog:testnet:http://dnsid-ledger:8080/log#identity-02")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	otherFQDN := resignedFixture(t, keyRotationEntry, func(p map[string]any) { p["fqdn"] = "other.example" })
	tests := []struct {
		name      string
		client    *Client
		history   []string
		candidate string
	}{
		{"malformed JSON", client, nil, "{"},
		{"another stream", otherStream, nil, issuanceEntry},
		{"another fqdn", client, []string{issuanceEntry}, otherFQDN},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := tt.client.CheckAppend(context.Background(), entries(tt.history...), []byte(tt.candidate))
			var parseErr *dnsid.ParseError
			var validationErr *dnsid.ValidationError
			if !errors.As(err, &parseErr) && !errors.As(err, &validationErr) {
				t.Fatalf("CheckAppend error = %T %v, want parse or validation error", err, err)
			}
		})
	}
}

func TestClientCheckAppend_HistoryThatDoesNotReplayIsAnError(t *testing.T) {
	client, err := New(fixtureLR)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	_, err = client.CheckAppend(context.Background(), entries(keyRotationEntry), []byte(revocationEntry))
	var verr *dnsid.VerificationError
	if err == nil || errors.As(err, &verr) {
		t.Fatalf("CheckAppend error = %v, want a non-verification error for the history", err)
	}
}

func TestClientCheckAppend_RequiresClient(t *testing.T) {
	var client *Client
	_, err := client.CheckAppend(context.Background(), nil, []byte(issuanceEntry))
	var argErr *dnsid.ArgumentError
	if !errors.As(err, &argErr) {
		t.Fatalf("CheckAppend error = %T %v, want argument error", err, err)
	}
}
