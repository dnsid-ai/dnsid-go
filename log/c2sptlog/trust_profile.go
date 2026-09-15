package c2sptlog

import (
	"bytes"
	"encoding/json"
	"fmt"
	"unicode/utf8"

	dnsid "github.com/dnsid-ai/dnsid-go"
	"golang.org/x/mod/sumdb/note"
)

// TrustProfile binds one exact C2SP log to its independently distributed trust
// policy and accepted stream-bundle signers. Runtime freshness and resource
// limits remain caller configuration.
type TrustProfile struct {
	Version            int      `json:"version"`
	Scope              string   `json:"scope"`
	LogPrefix          string   `json:"log_prefix"`
	PolicyDocument     string   `json:"tlog_policy"`
	BundleVerifierKeys []string `json:"bundle_verifier_keys"`
}

// ParseTrustProfile parses and validates a DNSid C2SP trust-profile document.
func ParseTrustProfile(data []byte) (TrustProfile, error) {
	if !utf8.Valid(data) {
		return TrustProfile{}, dnsid.NewParseError("dnsid: parsing c2sp-tlog trust profile", fmt.Errorf("dnsid: trust profile must be UTF-8"))
	}
	if _, err := decodeJSONObject(data); err != nil {
		return TrustProfile{}, dnsid.NewParseError("dnsid: parsing c2sp-tlog trust profile", err)
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var profile TrustProfile
	if err := dec.Decode(&profile); err != nil {
		return TrustProfile{}, dnsid.NewParseError("dnsid: parsing c2sp-tlog trust profile", err)
	}
	if _, err := profile.validate(); err != nil {
		return TrustProfile{}, dnsid.NewParseError("dnsid: parsing c2sp-tlog trust profile", err)
	}
	return profile, nil
}

func (p TrustProfile) validate() ([]note.Verifier, error) {
	if p.Version != 1 {
		return nil, fmt.Errorf("dnsid: unsupported c2sp-tlog trust profile version %d", p.Version)
	}
	ref, err := ParseReference(Method + ":" + p.Scope + ":" + p.LogPrefix + "#trust-profile")
	if err != nil {
		return nil, fmt.Errorf("dnsid: invalid c2sp-tlog trust profile scope or log prefix: %w", err)
	}
	policy, err := ParsePolicy([]byte(p.PolicyDocument))
	if err != nil {
		return nil, err
	}
	origin, err := ref.Origin()
	if err != nil {
		return nil, err
	}
	if policy.LogVerifier == nil || policy.LogVerifier.Name() != origin {
		return nil, fmt.Errorf("dnsid: c2sp-tlog trust profile policy does not match log prefix")
	}
	if len(p.BundleVerifierKeys) == 0 {
		return nil, fmt.Errorf("dnsid: c2sp-tlog trust profile needs a bundle verifier key")
	}
	verifiers := make([]note.Verifier, 0, len(p.BundleVerifierKeys))
	seenKeys := make(map[string]bool, len(p.BundleVerifierKeys))
	seenIDs := make(map[string]bool, len(p.BundleVerifierKeys))
	for _, key := range p.BundleVerifierKeys {
		verifier, err := note.NewVerifier(key)
		publicKey, keyErr := signedNotePublicKey(key)
		if err != nil || keyErr != nil || verifier.Name() != "dnsid-stream-bundle" || len(publicKey) != 32 {
			return nil, fmt.Errorf("dnsid: invalid c2sp-tlog trust profile bundle verifier key")
		}
		kid := fmt.Sprintf("%s+%08x", verifier.Name(), verifier.KeyHash())
		if seenKeys[string(publicKey)] || seenIDs[kid] {
			return nil, fmt.Errorf("dnsid: c2sp-tlog trust profile bundle verifier keys must have distinct public keys and key IDs")
		}
		for _, checkpointKey := range policy.trustedPublicKeys {
			if bytes.Equal(publicKey, checkpointKey) {
				return nil, fmt.Errorf("dnsid: c2sp-tlog trust profile bundle signer must be independent of checkpoint policy keys")
			}
		}
		seenKeys[string(publicKey)] = true
		seenIDs[kid] = true
		verifiers = append(verifiers, verifier)
	}
	return verifiers, nil
}
