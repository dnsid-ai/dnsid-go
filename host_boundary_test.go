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
// host. Every check compares hosts in canonical form (NormalizeFQDN for the
// identity FQDN, NormalizeDNSName for other hosts), the exact name the
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
// ku= or ek= host is rejected before normalization. NormalizeFQDN (ku) and
// NormalizeDNSName (ek) would both accept and strip it, but the byte-wise comparisons that canonical comparison
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

// TestNormalizeFQDN_U0130MapsOutsideFoldedDomain documents why the folded
// comparison was unsafe: the decoded ek= host from the bypass record is a valid
// DNS name whose canonical (dialed) form lies outside the governance domain.
func TestNormalizeFQDN_U0130MapsOutsideFoldedDomain(t *testing.T) {
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

// longDNSHost returns a valid DNS name of exactly n octets ending in suffix,
// built from labels of at most 63 octets.
func longDNSHost(t *testing.T, n int, suffix string) string {
	t.Helper()
	var labels []string
	remaining := n - len(suffix)
	for remaining > 0 {
		// Each label costs its length plus one separating dot.
		size := min(63, remaining-1)
		if size < 1 {
			t.Fatalf("cannot build a %d-octet host ending in %q", n, suffix)
		}
		labels = append(labels, strings.Repeat("a", size))
		remaining -= size + 1
	}
	host := strings.Join(labels, ".") + "." + suffix
	if len(host) != n {
		t.Fatalf("built host of %d octets, want %d", len(host), n)
	}
	return host
}

// TestFetchHostAllowed_EndpointHostsUseDNSLengthLimit pins that the 246-octet limit applies only to
// identity FQDNs (so that _dnsid.<fqdn> fits in 253 octets). Endpoint hosts
// such as status, ek and redirect targets are ordinary DNS names and may be up
// to 253 octets; canonical comparison must not shrink that.
func TestFetchHostAllowed_EndpointHostsUseDNSLengthLimit(t *testing.T) {
	// A valid 251-octet status host (labels 63.63.63.55.3): longer than the
	// agent-FQDN limit, within the DNS limit.
	statusHost := strings.Repeat("a", 63) + "." + strings.Repeat("b", 63) + "." +
		strings.Repeat("c", 63) + "." + strings.Repeat("d", 55) + ".com"
	if len(statusHost) != 251 {
		t.Fatalf("status host is %d octets, want 251", len(statusHost))
	}
	host253 := longDNSHost(t, 253, "example.com")
	host254 := longDNSHost(t, 254, "example.com")

	t.Run("NormalizeFQDN keeps the identity limit", func(t *testing.T) {
		if _, err := NormalizeFQDN(longDNSHost(t, 246, "example.com")); err != nil {
			t.Fatalf("246-octet FQDN: %v", err)
		}
		if _, err := NormalizeFQDN(longDNSHost(t, 247, "example.com")); err == nil {
			t.Fatal("247-octet FQDN accepted, want error")
		}
		if _, err := NormalizeFQDN(statusHost); err == nil {
			t.Fatal("251-octet FQDN accepted as identity FQDN, want error")
		}
	})

	t.Run("NormalizeDNSName uses the DNS limit", func(t *testing.T) {
		for _, h := range []string{statusHost, host253, host253 + "."} {
			if _, err := NormalizeDNSName(h); err != nil {
				t.Errorf("NormalizeDNSName(%d octets): %v", len(h), err)
			}
		}
		if _, err := NormalizeDNSName(host254); err == nil {
			t.Error("254-octet host accepted, want error")
		}
	})

	t.Run("status host matches itself", func(t *testing.T) {
		statusURL := "https://" + statusHost + "/status"
		if err := validateManagerFetchURL(statusURL, allowedHostFromURL(statusURL), false); err != nil {
			t.Fatalf("validateManagerFetchURL: %v", err)
		}
		if !fetchHostAllowed(strings.ToUpper(statusHost), statusHost, false) {
			t.Fatal("251-octet host does not match itself in canonical form")
		}
		if !fetchHostAllowed(host253, host253, false) {
			t.Fatal("253-octet host does not match itself")
		}
		if fetchHostAllowed(host254, host254, false) {
			t.Fatal("254-octet host allowed, want refused")
		}
	})

	t.Run("long ek host under gi", func(t *testing.T) {
		ku := "https://agent.identity.example/ku.json"
		ek := "https://" + longDNSHost(t, 251, "identity.example") + "/ek.json"
		if err := hostBoundaryRecord(t, ku, ek).Validate("agent.identity.example"); err != nil {
			t.Fatalf("Validate with 251-octet ek host: %v", err)
		}
		if !fetchHostAllowed(longDNSHost(t, 251, "identity.example"), "identity.example", true) {
			t.Fatal("251-octet ek host not allowed under gi boundary")
		}
	})

	t.Run("long gi", func(t *testing.T) {
		// A delegated record's gi need not be above the agent FQDN, so it is
		// bound only by the DNS limit, not the 246-octet agent-FQDN limit.
		gi := longDNSHost(t, 250, "example")
		record := hostBoundaryRecord(t, "https://agent.identity.example/ku.json", "https://"+gi+"/ek.json")
		record.GovernanceID = gi
		if err := record.Validate("agent.identity.example"); err != nil {
			t.Fatalf("Validate with 250-octet gi: %v", err)
		}
	})
}

// TestEnforceRecordPolicy_LongDelegatedGIRequiresGovernanceRelationship pins
// that a gi longer than the 246-octet agent-FQDN limit still goes through the
// delegated-governance check. Such a gi can never be at or above the agent
// FQDN, so the record is always delegated; normalizing gi under the identity
// limit and skipping the check on error would let it bypass the ISSUANCE
// binding. A gi with no canonical form at all must fail closed.
func TestEnforceRecordPolicy_LongDelegatedGIRequiresGovernanceRelationship(t *testing.T) {
	const domain = "agent.identity.example"
	ctx := t.Context()

	t.Run("long gi is checked", func(t *testing.T) {
		gi := longDNSHost(t, 250, "example")
		reader := &testLogReader{govErr: errors.New("no ISSUANCE binding")}
		err := (&IdentityManager{}).enforceRecordPolicy(ctx, reader, &TXTRecord{GovernanceID: gi}, domain, "", "", nil)
		if err == nil {
			t.Fatal("enforceRecordPolicy accepted a delegated gi without a governance relationship")
		}
		if reader.govID != gi || reader.govDomain != domain {
			t.Fatalf("VerifyGovernanceRelationship called with (%q, %q), want (%q, %q)", reader.govDomain, reader.govID, domain, gi)
		}
	})

	t.Run("gi without canonical form fails closed", func(t *testing.T) {
		reader := &testLogReader{}
		err := (&IdentityManager{}).enforceRecordPolicy(ctx, reader, &TXTRecord{GovernanceID: longDNSHost(t, 254, "example")}, domain, "", "", nil)
		var ve *VerificationError
		if !errors.As(err, &ve) || ve.Code() != VerificationCodeRecordInvalid {
			t.Fatalf("error = %v, want VerificationCodeRecordInvalid", err)
		}
		if reader.govID != "" {
			t.Fatal("VerifyGovernanceRelationship called for an invalid gi")
		}
	})
}

// TestGovernanceID_UsesDNSLengthLimitInRootPackage pins that the root
// package's gi and ek host checks (publication config, TrustedEntities,
// registration responses) use the same 253-octet DNS limit as
// TXTRecord.Validate, so the SDK can publish, and a verifier can allowlist,
// every record it validates. The registry GovernanceDomain selector is covered
// in registration_test.go; managed issuance and Foundry, which also use
// NormalizeDNSName for gi, are covered in their own packages.
func TestGovernanceID_UsesDNSLengthLimitInRootPackage(t *testing.T) {
	gi := longDNSHost(t, 250, "example")
	ek := "https://" + gi + "/ek.json"
	tooLong := longDNSHost(t, 254, "example")

	t.Run("publication config", func(t *testing.T) {
		cfg := IdentityConfig{
			Domain:       "agent.identity.example",
			GovernanceID: gi,
			LogRef:       "testlog:agent",
			StatusURL:    "https://agent.identity.example/status",
			KeyURL:       "https://agent.identity.example/ku.json",
			EntityKeyURL: ek,
		}
		if err := validatePublicationConfig(cfg, GenerateES256KeyProvider(), GenerateES256KeyProvider()); err != nil {
			t.Fatalf("validatePublicationConfig with 250-octet gi: %v", err)
		}
		cfg.GovernanceID = tooLong
		if err := validatePublicationConfig(cfg, GenerateES256KeyProvider(), GenerateES256KeyProvider()); err == nil {
			t.Fatal("validatePublicationConfig accepted a 254-octet gi")
		}
	})

	t.Run("trusted entities", func(t *testing.T) {
		if err := (VerificationConfig{TrustedEntities: []TrustedEntity{{GovernanceID: gi}}}).validate(); err != nil {
			t.Fatalf("TrustedEntity with 250-octet gi: %v", err)
		}
		if got := (VerificationConfig{TrustedEntities: []TrustedEntity{{GovernanceID: strings.ToUpper(gi)}}}).snapshot().TrustedEntities[0].GovernanceID; got != gi {
			t.Fatalf("snapshot gi = %q, want %q", got, gi)
		}
		if err := (VerificationConfig{TrustedEntities: []TrustedEntity{{GovernanceID: tooLong}}}).validate(); err == nil {
			t.Fatal("TrustedEntity accepted a 254-octet gi")
		}
	})

	t.Run("registration response", func(t *testing.T) {
		resp := &CreateAgentResponse{
			ID:     "agent-1",
			Domain: "agent.identity.example",
			PublicationConfig: PublicationConfig{
				PublishProfile: DefaultPublishProfile,
				GovernanceID:   gi,
				KeyURL:         "https://agent.identity.example/ku.json",
				EntityKeyURL:   ek,
				LogRef:         "testlog:agent",
				StatusURL:      "https://agent.identity.example/status",
			},
		}
		if err := validateRegistrationCreation(&CreateAgentRequest{}, resp); err != nil {
			t.Fatalf("validateRegistrationCreation with 250-octet gi: %v", err)
		}
	})
}
