package main

import (
	"context"
	"strings"
	"testing"
)

func TestNewApplication_RequiresLocalRunPort(t *testing.T) {
	for _, port := range []string{"", "0", "65536", "not-a-port"} {
		t.Run(port, func(t *testing.T) {
			t.Setenv("DNSID_AGENT_PORT", port)
			if _, _, err := newApplication(context.Background()); err == nil || !strings.Contains(err.Error(), "DNSID_AGENT_PORT is required") {
				t.Fatalf("newApplication(DNSID_AGENT_PORT=%q) error = %v", port, err)
			}
		})
	}
}
