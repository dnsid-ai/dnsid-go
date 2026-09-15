package log

import "testing"

// TestAgentStateMachine pins the fixed six-state protocol machine
// (spec §Agent States). A missing or renamed state fails compilation or here.
func TestAgentStateMachine(t *testing.T) {
	want := map[AgentState]string{
		AgentStatePending:      "PENDING",
		AgentStateProvisioning: "PROVISIONING",
		AgentStateVerifying:    "VERIFYING",
		AgentStateActive:       "ACTIVE",
		AgentStateRetired:      "RETIRED",
		AgentStateRevoked:      "REVOKED",
	}
	states := AgentStates()
	// The spec fixes exactly six states; this length is the real guard — it
	// fails if a state is added to (or removed from) the enum without updating
	// this test.
	if len(states) != 6 {
		t.Fatalf("expected 6 states, got %d", len(states))
	}
	seen := make(map[AgentState]bool, len(states))
	for _, state := range states {
		if seen[state] {
			t.Errorf("AgentStates has duplicate entry %q", state)
		}
		seen[state] = true
		str, ok := want[state]
		if !ok {
			t.Errorf("AgentStates has %q missing from want map", state)
		}
		if string(state) != str {
			t.Errorf("AgentState %q != %q", state, str)
		}
	}
	for state := range want {
		if !seen[state] {
			t.Errorf("want state %q missing from AgentStates", state)
		}
	}
}

var _ AgentState = DomainSnapshot{}.HistoricalState
