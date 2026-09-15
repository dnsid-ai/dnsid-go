package dnsid

import "testing"

func TestRegistrantDomain(t *testing.T) {
	tests := []struct {
		name   string
		domain string
		want   string
	}{
		{name: "subdomain", domain: "Agent.Example.COM.", want: "example.com"},
		{name: "public suffix", domain: "service.example.co.uk", want: "example.co.uk"},
		{name: "fallback single label", domain: "localhost", want: "localhost"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := RegistrantDomain(tt.domain); got != tt.want {
				t.Fatalf("RegistrantDomain(%q) = %q, want %q", tt.domain, got, tt.want)
			}
		})
	}
}
