package dnsid

import (
	"strings"
	"testing"
)

func TestNormalizeFQDNValid(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "lowercase FQDN",
			input: "example.com",
			want:  "example.com",
		},
		{
			name:  "uppercase ASCII",
			input: "EXAMPLE.COM",
			want:  "example.com",
		},
		{
			name:  "single trailing dot",
			input: "example.com.",
			want:  "example.com",
		},
		{
			name:  "ideographic trailing dot",
			input: "example.com。",
			want:  "example.com",
		},
		{
			name:  "fullwidth trailing dot",
			input: "example.com．",
			want:  "example.com",
		},
		{
			name:  "halfwidth trailing dot",
			input: "example.com｡",
			want:  "example.com",
		},
		{
			name:  "subdomain",
			input: "agent.sub.example.com",
			want:  "agent.sub.example.com",
		},
		{
			name:  "unicode IDN",
			input: "München.de",
			want:  "xn--mnchen-3ya.de",
		},
		{
			name:  "single label",
			input: "localhost",
			want:  "localhost",
		},
		{
			name:  "maximum DNSid length",
			input: strings.Repeat("aa.", 81) + "aaa",
			want:  strings.Repeat("aa.", 81) + "aaa",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NormalizeFQDN(tt.input)
			if err != nil {
				t.Fatalf("NormalizeFQDN(%q) returned error: %v", tt.input, err)
			}
			if got != tt.want {
				t.Fatalf("NormalizeFQDN(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestNormalizeFQDNInvalid(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{
			name:  "empty input",
			input: "",
		},
		{
			name:  "just dot",
			input: ".",
		},
		{
			name:  "empty label",
			input: "example..com",
		},
		{
			name:  "label too long",
			input: strings.Repeat("a", 64),
		},
		{
			name:  "fqdn too long",
			input: strings.Repeat("aa.", 82) + "a",
		},
		{
			name:  "multiple trailing dots",
			input: "example.com..",
		},
		{
			name:  "multiple unicode trailing dots",
			input: "example.com。。",
		},
		{
			name:  "mixed multiple trailing dots",
			input: "example.com｡.",
		},
		{
			name:  "leading hyphen",
			input: "-leading-hyphen.test",
		},
		{
			name:  "invalid punycode",
			input: "xn--.test",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, err := NormalizeFQDN(tt.input); err == nil {
				t.Fatalf("NormalizeFQDN(%q) = %q, want error", tt.input, got)
			}
		})
	}
}
