package dnsid

import (
	"errors"
	"net/http"
	"strings"
	"testing"
)

// These tests pin the host-boundary checks that bind a record's key endpoints
// to DNS names: ku= must equal the identity FQDN, ek= must sit at or under the
// gi= governance domain, and a same-host redirect must stay on the allowed
// host. Every check compares hosts in NormalizeFQDN form, the exact name the
// transport resolves and presents as TLS SNI.
//
// U+0130 (LATIN CAPITAL LETTER I WITH DOT ABOVE) is the probe used throughout.
// strings.ToLower and strings.EqualFold apply Unicode simple case mappings,
// under which U+0130 is ASCII "i"; the UTS 46 mapping that net/http applies
// before dialing turns it into "i̇", and the label is punycode-encoded
// into a different registrable domain. A comparison that folds case therefore
// accepts a host that is dialed somewhere else. Because TXT values are
// printable ASCII, the character reaches a record URL only percent-encoded,
// as %C4%B0, which url.Parse decodes in the host component.

// hostBoundaryRecord returns a record that is valid for the identity
// agent.identity.example under governance domain identity.example, with the
// ku= and ek= URLs supplied by the caller.
func hostBoundaryRecord(t *testing.T, ku, ek string) *TXTRecord {
	t.Helper()
	return &TXTRecord{
		Version:      identityRecordDNSid1,
		GovernanceID: "identity.example",
		EntityKeyURI: ek,
		KeyURI:       ku,
		LogRef:       "testlog:agent",
		StatusURI:    "https://agent.identity.example/status",
		Signature:    "placeholder",
	}
}

// assertHostBoundaryResult checks a validation result against the expected
// outcome: nil for wantErr == "", otherwise a *ValidationError whose message
// contains wantErr.
func assertHostBoundaryResult(t *testing.T, err error, wantErr string) {
	t.Helper()
	if wantErr == "" {
		if err != nil {
			t.Fatalf("error = %v, want nil", err)
		}
		return
	}
	if err == nil {
		t.Fatalf("error = nil, want error containing %q", wantErr)
	}
	var validationErr *ValidationError
	if !errors.As(err, &validationErr) {
		t.Fatalf("error = %T (%v), want *ValidationError", err, err)
	}
	if !strings.Contains(err.Error(), wantErr) {
		t.Fatalf("error = %q, want it to contain %q", err.Error(), wantErr)
	}
}

func TestTXTRecordValidate_KUHostComparedInCanonicalForm(t *testing.T) {
	const ek = "https://keys.identity.example/ek.json"
	for _, tc := range []struct {
		name    string
		ku      string
		wantErr string
	}{
		{"canonical", "https://agent.identity.example/ku.json", ""},
		{"with port", "https://agent.identity.example:8443/ku.json", ""},
		{"uppercase", "https://AGENT.Identity.EXAMPLE/ku.json", ""},
		{"trailing dot", "https://agent.identity.example./ku.json", "must not end with a dot"},
		{"other host", "https://other.identity.example/ku.json", "must equal identity FQDN"},
		{"parent domain", "https://identity.example/ku.json", "must equal identity FQDN"},
		{"identity as suffix", "https://agent.identity.example.attacker.example/ku.json", "must equal identity FQDN"},
		{"percent-encoded U+0130", "https://agent.%C4%B0dentity.example/ku.json", "without percent-escapes"},
		{"raw U+0130", "https://agent.İdentity.example/ku.json", "without percent-escapes"},
		{"leading hyphen label", "https://-agent.identity.example/ku.json", "not a valid DNS name"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := hostBoundaryRecord(t, tc.ku, ek).Validate("agent.identity.example")
			assertHostBoundaryResult(t, err, tc.wantErr)
		})
	}
}

func TestTXTRecordValidate_EKHostComparedInCanonicalForm(t *testing.T) {
	const ku = "https://agent.identity.example/ku.json"
	for _, tc := range []struct {
		name    string
		ek      string
		wantErr string
	}{
		{"at gi", "https://identity.example/ek.json", ""},
		{"under gi", "https://keys.identity.example/ek.json", ""},
		{"deeper under gi", "https://a.b.keys.identity.example/ek.json", ""},
		{"uppercase", "https://KEYS.Identity.EXAMPLE/ek.json", ""},
		{"trailing dot", "https://keys.identity.example./ek.json", "must not end with a dot"},
		{"sibling domain", "https://keys.other.example/ek.json", "must be at or under gi domain"},
		{"gi as prefix", "https://identity.example.attacker.example/ek.json", "must be at or under gi domain"},
		{"gi as label suffix", "https://notidentity.example/ek.json", "must be at or under gi domain"},
		// Before canonical comparison this host lowercased to
		// keys.identity.example and passed, while the JWKS was fetched from the
		// punycode form of keys.i̇dentity.example, outside identity.example.
		{"percent-encoded U+0130", "https://keys.%C4%B0dentity.example/ek.json", "without percent-escapes"},
		{"raw U+0130", "https://keys.İdentity.example/ek.json", "without percent-escapes"},
		{"leading hyphen label", "https://-keys.identity.example/ek.json", "not a valid DNS name"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := hostBoundaryRecord(t, ku, tc.ek).Validate("agent.identity.example")
			assertHostBoundaryResult(t, err, tc.wantErr)
		})
	}
}

// TestTXTRecordValidate_TrailingDotHostRejected pins that a trailing dot in a
// ku= or ek= host is rejected before normalization. NormalizeFQDN would accept
// and strip it, but the byte-wise comparisons that canonical comparison
// replaced never admitted one, and that rule is deliberately kept: the host as
// published is the host that is compared and dialed. The su= host is outside
// the rule, as before, since no host comparison applies to it.
func TestTXTRecordValidate_TrailingDotHostRejected(t *testing.T) {
	const ku = "https://agent.identity.example/ku.json"
	const ek = "https://keys.identity.example/ek.json"
	for _, tc := range []struct {
		name    string
		ku, ek  string
		su      string
		wantErr string
	}{
		{"no trailing dots", ku, ek, "", ""},
		{"ku trailing dot", "https://agent.identity.example./ku.json", ek, "", "ku host \"agent.identity.example.\" must not end with a dot"},
		{"ku trailing dot with port", "https://agent.identity.example.:8443/ku.json", ek, "", "ku host \"agent.identity.example.\" must not end with a dot"},
		{"ek trailing dot", ku, "https://keys.identity.example./ek.json", "", "ek host \"keys.identity.example.\" must not end with a dot"},
		{"ek at gi with trailing dot", ku, "https://identity.example./ek.json", "", "ek host \"identity.example.\" must not end with a dot"},
		{"su trailing dot is outside the rule", ku, ek, "https://agent.identity.example./status", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			record := hostBoundaryRecord(t, tc.ku, tc.ek)
			if tc.su != "" {
				record.StatusURI = tc.su
			}
			assertHostBoundaryResult(t, record.Validate("agent.identity.example"), tc.wantErr)
		})
	}
}

// TestTXTRecordValidate_U0130HostNormalizesOutsideGI documents why the folded
// comparison was unsafe: the decoded ek= host from the bypass record is a valid
// DNS name whose canonical (dialed) form lies outside the governance domain.
func TestTXTRecordValidate_U0130HostNormalizesOutsideGI(t *testing.T) {
	dialed, err := NormalizeFQDN("keys.İdentity.example")
	if err != nil {
		t.Fatalf("NormalizeFQDN: %v", err)
	}
	if isDomainOrSubdomain(dialed, "identity.example") {
		t.Fatalf("canonical form %q unexpectedly lies under identity.example", dialed)
	}
	if !strings.HasPrefix(dialed, "keys.xn--") {
		t.Fatalf("canonical form = %q, want a punycode second label", dialed)
	}
	if folded := strings.ToLower("keys.İdentity.example"); folded != "keys.identity.example" {
		t.Fatalf("strings.ToLower = %q; the premise of this test no longer holds", folded)
	}
}

func TestValidateRecordHTTPSURL_RejectsEscapedHost(t *testing.T) {
	for _, tc := range []struct {
		name    string
		raw     string
		wantErr string
	}{
		{"plain", "https://keys.example.com/ek.json", ""},
		{"with port", "https://keys.example.com:8443/ek.json", ""},
		{"escaped path", "https://keys.example.com/ek%20v1.json", ""},
		{"escaped query", "https://keys.example.com/ek.json?v=%2F1", ""},
		{"a-label host", "https://xn--mnchen-3ya.de/ek.json", ""},
		{"percent-encoded non-ascii host", "https://keys.%C4%B0dentity.example/ek.json", "without percent-escapes"},
		{"raw non-ascii host", "https://keys.İdentity.example/ek.json", "without percent-escapes"},
		{"raw u-label host", "https://münchen.de/ek.json", "without percent-escapes"},
		{"literal percent via %25", "https://keys.example.com%25/ek.json", "without percent-escapes"},
		{"ipv6 zone", "https://[fe80::1%25eth0]/ek.json", "without percent-escapes"},
		{"percent-encoded ascii host", "https://keys.example%2Ecom/ek.json", "must be an HTTPS URL"},
		{"userinfo", "https://user@keys.example.com/ek.json", "must not include userinfo"},
		{"http", "http://keys.example.com/ek.json", "must be an HTTPS URL"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			assertHostBoundaryResult(t, validateRecordHTTPSURL(tc.raw, "ek"), tc.wantErr)
		})
	}
}

// TestClientWithRedirectPolicy_SameHostComparesCanonicalForm covers the second
// way a non-ASCII host reaches the boundary check: a Location header is not
// subject to the TXT value character set, and net/http accepts both raw UTF-8
// and percent-escapes in it. A redirect from a legitimate host under gi must
// not be able to send the JWKS fetch to a look-alike domain.
func TestClientWithRedirectPolicy_SameHostComparesCanonicalForm(t *testing.T) {
	const original = "https://www.bigcorp.com/go"
	client := clientWithRedirectPolicy(&http.Client{}, original, FetchOptions{
		AllowedHost:    "bigcorp.com",
		DomainBoundary: true,
		RedirectPolicy: RedirectPolicySameHost,
	})
	first, err := http.NewRequest(http.MethodGet, original, nil)
	if err != nil {
		t.Fatal(err)
	}
	via := []*http.Request{first}

	for _, tc := range []struct {
		name    string
		target  string
		allowed bool
	}{
		{"under gi", "https://keys.bigcorp.com/ek.json", true},
		{"uppercase", "https://KEYS.BigCorp.COM/ek.json", true},
		{"trailing dot", "https://keys.bigcorp.com./ek.json", false},
		{"percent-encoded U+0130", "https://keys.b%C4%B0gcorp.com/ek.json", false},
		{"raw U+0130", "https://keys.bİgcorp.com/ek.json", false},
		{"gi as prefix", "https://bigcorp.com.attacker.example/ek.json", false},
		{"other domain", "https://notbigcorp.com/ek.json", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			next, err := http.NewRequest(http.MethodGet, tc.target, nil)
			if err != nil {
				t.Fatal(err)
			}
			err = client.CheckRedirect(next, via)
			if tc.allowed {
				if err != nil {
					t.Fatalf("CheckRedirect(%q) = %v, want nil", tc.target, err)
				}
				return
			}
			if !errors.Is(err, errTLSPolicy) || !strings.Contains(err.Error(), "redirect host") {
				t.Fatalf("CheckRedirect(%q) = %v, want errTLSPolicy redirect host error", tc.target, err)
			}
		})
	}
}
