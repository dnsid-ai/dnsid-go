package dnsid

import (
	"testing"
	"time"
)

// Compile-time check: AgentStatus.State uses the typed lifecycle state.
var _ AgentState = AgentStatus{}.State

// TestParseAgentState verifies the root-package re-exported ParseAgentState
// helper correctly parses valid states and rejects invalid ones.
func TestParseAgentState(t *testing.T) {
	valid := []struct {
		input string
		want  AgentState
	}{
		{"PENDING", AgentStatePending},
		{"PROVISIONING", AgentStateProvisioning},
		{"VERIFYING", AgentStateVerifying},
		{"ACTIVE", AgentStateActive},
		{"RETIRED", AgentStateRetired},
		{"REVOKED", AgentStateRevoked},
	}
	for _, tc := range valid {
		got, err := ParseAgentState(tc.input)
		if err != nil {
			t.Errorf("ParseAgentState(%q) unexpected error: %v", tc.input, err)
			continue
		}
		if got != tc.want {
			t.Errorf("ParseAgentState(%q) = %q, want %q", tc.input, got, tc.want)
		}
	}

	invalid := []string{"", "pending", "UNKNOWN", "active", "publishing"}
	for _, s := range invalid {
		_, err := ParseAgentState(s)
		if err == nil {
			t.Errorf("ParseAgentState(%q) expected error, got nil", s)
		}
	}
}

// TestAgentStateIsValid verifies IsValid works on the re-exported type.
func TestAgentStateIsValid(t *testing.T) {
	if !AgentStateActive.IsValid() {
		t.Error("AgentStateActive.IsValid() = false, want true")
	}
	if AgentState("bogus").IsValid() {
		t.Error(`AgentState("bogus").IsValid() = true, want false`)
	}
}

// TestAgentStateString verifies String() returns the underlying value.
func TestAgentStateString(t *testing.T) {
	if s := AgentStateActive.String(); s != "ACTIVE" {
		t.Errorf("AgentStateActive.String() = %q, want %q", s, "ACTIVE")
	}
}

// TestAgentStatesReturnsAllSix verifies AgentStates returns all six states.
func TestAgentStatesReturnsAllSix(t *testing.T) {
	states := AgentStates()
	if len(states) != 6 {
		t.Fatalf("AgentStates() returned %d states, want 6", len(states))
	}
}

func TestAgentStatusValidateRequiresExactCanonicalState(t *testing.T) {
	now := time.Now()

	for _, state := range []AgentState{
		AgentStatePending,
		AgentStateProvisioning,
		AgentStateVerifying,
		AgentStateActive,
		AgentStateRetired,
		AgentStateRevoked,
	} {
		t.Run("accepts_"+state.String(), func(t *testing.T) {
			status := &AgentStatus{State: state, LastTransitionAt: now}
			if state == AgentStateRevoked {
				status.RevocationReason = "keyCompromise"
			}
			if err := status.Validate(); err != nil {
				t.Fatalf("Validate() = %v, want nil", err)
			}
		})
	}

	for _, raw := range []string{"active", " ACTIVE", "ACTIVE ", "\tACTIVE\n"} {
		state := AgentState(raw)
		t.Run("rejects_"+state.String(), func(t *testing.T) {
			status := &AgentStatus{State: state, LastTransitionAt: now}
			if err := status.Validate(); err == nil {
				t.Fatal("Validate() = nil, want error")
			}
			if status.State != state {
				t.Fatalf("Validate() changed State to %q, want %q", status.State, state)
			}
		})
	}
}

// TestAgentStateSourceCompat verifies that callers can round-trip between
// string and AgentState using the public helpers (source-compatibility).
func TestAgentStateSourceCompat(t *testing.T) {
	// Callers that have a string can use ParseAgentState
	s := "ACTIVE"
	state, err := ParseAgentState(s)
	if err != nil {
		t.Fatal(err)
	}
	// Callers that need a string back can use .String()
	if state.String() != s {
		t.Errorf("round-trip failed: got %q, want %q", state.String(), s)
	}
	// AgentState* constants are typed. The explicit type is the assertion:
	// it fails to compile if the constant ever stops being an AgentState.
	//nolint:staticcheck // ST1023: the explicit type is deliberate, see above.
	var st AgentState = AgentStateActive
	if st != AgentStateActive {
		t.Error("AgentStateActive != AgentState(AgentStateActive)")
	}
}
