package oidc

import "testing"

// validateIssuerRoot's scheme guard was rewritten by De Morgan's law:
//
//	old: u.Scheme != "https" && !(allowHTTPLoopback && u.Scheme == "http" && isLocalhost(u.Hostname()))
//	new: u.Scheme != "https" && (!allowHTTPLoopback || u.Scheme != "http" || !isLocalhost(u.Hostname()))
//
// That is a pure logical rewrite, so an exhaustive table over the three inputs
// must produce identical results before and after. This test enumerates every
// combination rather than spot-checking, because a De Morgan slip inverts a
// security check silently.

func TestValidateIssuerRootSchemeGuardExhaustive(t *testing.T) {
	for _, tc := range []struct {
		name              string
		raw               string
		allowHTTPLoopback bool
		wantOK            bool
	}{
		// https is always accepted regardless of the loopback flag.
		{"https remote, loopback off", "https://issuer.example.com", false, true},
		{"https remote, loopback on", "https://issuer.example.com", true, true},
		{"https localhost, loopback off", "https://localhost", false, true},
		{"https localhost, loopback on", "https://localhost", true, true},
		{"https 127.0.0.1, loopback on", "https://127.0.0.1", true, true},

		// http is accepted only for loopback hosts and only when allowed.
		{"http localhost, loopback on", "http://localhost", true, true},
		{"http 127.0.0.1, loopback on", "http://127.0.0.1", true, true},
		{"http localhost, loopback off", "http://localhost", false, false},
		{"http 127.0.0.1, loopback off", "http://127.0.0.1", false, false},
		{"http remote, loopback on", "http://issuer.example.com", true, false},
		{"http remote, loopback off", "http://issuer.example.com", false, false},

		// Any other scheme is rejected either way.
		{"ftp remote, loopback on", "ftp://issuer.example.com", true, false},
		{"ftp localhost, loopback on", "ftp://localhost", true, false},
		{"ftp localhost, loopback off", "ftp://localhost", false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := validateIssuerRoot(tc.raw, tc.allowHTTPLoopback)
			if gotOK := err == nil; gotOK != tc.wantOK {
				t.Fatalf("validateIssuerRoot(%q, allowHTTPLoopback=%v) ok = %v, want %v (err=%v)",
					tc.raw, tc.allowHTTPLoopback, gotOK, tc.wantOK, err)
			}
		})
	}
}
