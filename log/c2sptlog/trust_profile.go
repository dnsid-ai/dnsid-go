package c2sptlog

import (
	"bytes"
	"encoding/json"
	"fmt"
	"unicode/utf8"

	dnsid "github.com/dnsid-ai/dnsid-go"
	"golang.org/x/mod/sumdb/note"
)

const (
	// TrustProfileVersionSingle is the original trust-profile format: one
	// tlog_policy and its bundle_verifier_keys at the top level.
	TrustProfileVersionSingle = 1
	// TrustProfileVersionEpochs is the epoch format: a list of complete trust
	// epochs for one log, used to rotate log, witness and bundle keys together.
	TrustProfileVersionEpochs = 2

	// maxTrustProfileEpochs bounds the epochs a profile may carry.
	maxTrustProfileEpochs = 8
	// maxTrustEpochIDBytes bounds a trust epoch identifier.
	maxTrustEpochIDBytes = 64
	// maxTrustEpochTreeSize keeps epoch tree-size bounds exactly representable
	// as IEEE 754 doubles, so every SDK parses the same profile identically.
	maxTrustEpochTreeSize = 1<<53 - 1
)

// TrustProfile binds one exact C2SP log to its independently distributed trust
// policy and accepted stream-bundle signers. Runtime freshness and resource
// limits remain caller configuration.
//
// Version 1 carries one PolicyDocument and its BundleVerifierKeys. Version 2
// leaves both empty and carries Epochs instead: each epoch is a complete
// version 1 trust (policy plus bundle keys) for the same log, and a checkpoint
// or bundle is accepted only when it satisfies one epoch completely.
type TrustProfile struct {
	Version            int                 `json:"version"`
	Scope              string              `json:"scope"`
	LogPrefix          string              `json:"log_prefix"`
	PolicyDocument     string              `json:"tlog_policy,omitempty"`
	BundleVerifierKeys []string            `json:"bundle_verifier_keys,omitempty"`
	Epochs             []TrustProfileEpoch `json:"epochs,omitempty"`
}

// TrustProfileEpoch is one epoch of a version 2 trust profile.
//
// PolicyDocument must be byte-identical to the tlog-policy document that the
// epoch's log server renders, because stream bundles bind its SHA-256 as
// policy_hash. MinTreeSize and MaxTreeSize, when set, bound the checkpoint
// tree sizes this epoch accepts (both inclusive). A nil bound is unbounded. A
// bound must be written as a JSON number token matching ^[1-9][0-9]*$ with a
// value of at most 2^53-1; decoding into *uint64 rejects fractions, exponents,
// signs, booleans and strings, and validation rejects zero and larger values.
type TrustProfileEpoch struct {
	ID                 string   `json:"id"`
	PolicyDocument     string   `json:"tlog_policy"`
	BundleVerifierKeys []string `json:"bundle_verifier_keys"`
	MinTreeSize        *uint64  `json:"min_tree_size,omitempty"`
	MaxTreeSize        *uint64  `json:"max_tree_size,omitempty"`
}

// TrustEpoch is a validated, verifier-side trust epoch: one complete
// tlog-policy document, the stream-bundle signers bound to it, and optional
// inclusive checkpoint tree-size bounds. Zero MinTreeSize and MaxTreeSize mean
// unbounded. Use NewEpochPolicy for checkpoints and StreamBundleTrust.Epochs
// for bundles.
type TrustEpoch struct {
	ID              string
	PolicyDocument  []byte
	BundleVerifiers []note.Verifier
	MinTreeSize     uint64
	MaxTreeSize     uint64
}

// ParseTrustProfile parses and validates a DNSid C2SP trust-profile document.
// Member names must match exactly, including case, at the top level and in
// every epoch; unknown members are rejected.
func ParseTrustProfile(data []byte) (TrustProfile, error) {
	if !utf8.Valid(data) {
		return TrustProfile{}, dnsid.NewParseError("dnsid: parsing c2sp-tlog trust profile", fmt.Errorf("dnsid: trust profile must be UTF-8"))
	}
	object, err := decodeJSONObject(data)
	if err != nil {
		return TrustProfile{}, dnsid.NewParseError("dnsid: parsing c2sp-tlog trust profile", err)
	}
	// encoding/json matches struct fields case-insensitively, so member names
	// are checked exactly against the raw object before the struct decode.
	if err := checkTrustProfileMembers(object); err != nil {
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

var (
	trustProfileV1Members = map[string]bool{"version": true, "scope": true, "log_prefix": true, "tlog_policy": true, "bundle_verifier_keys": true}
	trustProfileV2Members = map[string]bool{"version": true, "scope": true, "log_prefix": true, "epochs": true}
	trustEpochMembers     = map[string]bool{"id": true, "tlog_policy": true, "bundle_verifier_keys": true, "min_tree_size": true, "max_tree_size": true}
)

// checkTrustProfileMembers checks member names exactly, including case,
// against the raw decoded document: every member must be allowed for the
// document's version (or for an epoch), and every required member must be
// present. Members of the other version are rejected even when empty, so a
// document has exactly one reading in every SDK.
func checkTrustProfileMembers(object map[string]any) error {
	version, ok := object["version"].(json.Number)
	if !ok {
		return fmt.Errorf("dnsid: c2sp-tlog trust profile requires a numeric \"version\" member")
	}
	var allowed map[string]bool
	var required []string
	switch version.String() {
	case "1":
		allowed, required = trustProfileV1Members, []string{"version", "scope", "log_prefix", "tlog_policy", "bundle_verifier_keys"}
	case "2":
		allowed, required = trustProfileV2Members, []string{"version", "scope", "log_prefix", "epochs"}
	default:
		return fmt.Errorf("dnsid: unsupported c2sp-tlog trust profile version %s", version.String())
	}
	if err := checkExactMembers("trust profile", object, allowed, required); err != nil {
		return err
	}
	if version.String() != "2" {
		return nil
	}
	epochs, ok := object["epochs"].([]any)
	if !ok {
		return fmt.Errorf("dnsid: c2sp-tlog trust profile epochs must be an array")
	}
	for _, value := range epochs {
		epoch, ok := value.(map[string]any)
		if !ok {
			return fmt.Errorf("dnsid: c2sp-tlog trust profile epoch must be an object")
		}
		if err := checkExactMembers("trust profile epoch", epoch, trustEpochMembers, []string{"id", "tlog_policy", "bundle_verifier_keys"}); err != nil {
			return err
		}
	}
	return nil
}

func checkExactMembers(what string, object map[string]any, allowed map[string]bool, required []string) error {
	for member := range object {
		if !allowed[member] {
			return fmt.Errorf("dnsid: c2sp-tlog %s contains unknown member %q (member names are case-sensitive)", what, member)
		}
	}
	for _, member := range required {
		if _, ok := object[member]; !ok {
			return fmt.Errorf("dnsid: c2sp-tlog %s is missing %q", what, member)
		}
	}
	return nil
}

// TrustEpochs returns the profile's validated trust epochs in profile order.
// A version 1 profile yields one epoch with an empty ID and no tree-size
// bounds, which verifies exactly as the version 1 profile does.
func (p TrustProfile) TrustEpochs() ([]TrustEpoch, error) {
	epochs, err := p.validate()
	if err != nil {
		return nil, dnsid.NewArgumentError("dnsid: invalid c2sp-tlog trust profile", err)
	}
	return epochs, nil
}

func (p TrustProfile) validate() ([]TrustEpoch, error) {
	if p.Version != TrustProfileVersionSingle && p.Version != TrustProfileVersionEpochs {
		return nil, fmt.Errorf("dnsid: unsupported c2sp-tlog trust profile version %d", p.Version)
	}
	ref, err := ParseReference(Method + ":" + p.Scope + ":" + p.LogPrefix + "#trust-profile")
	if err != nil {
		return nil, fmt.Errorf("dnsid: invalid c2sp-tlog trust profile scope or log prefix: %w", err)
	}
	switch p.Version {
	case TrustProfileVersionSingle:
		if len(p.Epochs) != 0 {
			return nil, fmt.Errorf("dnsid: c2sp-tlog trust profile version 1 must not contain epochs")
		}
		epoch, err := validateTrustProfileEpoch(ref, TrustProfileEpoch{PolicyDocument: p.PolicyDocument, BundleVerifierKeys: p.BundleVerifierKeys})
		if err != nil {
			return nil, err
		}
		return []TrustEpoch{epoch}, nil
	case TrustProfileVersionEpochs:
		if p.PolicyDocument != "" || len(p.BundleVerifierKeys) != 0 {
			return nil, fmt.Errorf("dnsid: c2sp-tlog trust profile version 2 must carry its policies and bundle keys in epochs")
		}
		if len(p.Epochs) == 0 || len(p.Epochs) > maxTrustProfileEpochs {
			return nil, fmt.Errorf("dnsid: c2sp-tlog trust profile needs between 1 and %d epochs", maxTrustProfileEpochs)
		}
		epochs := make([]TrustEpoch, 0, len(p.Epochs))
		seenIDs := make(map[string]bool, len(p.Epochs))
		for _, profileEpoch := range p.Epochs {
			if !validTrustEpochID(profileEpoch.ID) {
				return nil, fmt.Errorf("dnsid: c2sp-tlog trust profile epoch id must be 1 to %d characters of A-Z, a-z, 0-9, '.', '_' or '-'", maxTrustEpochIDBytes)
			}
			if seenIDs[profileEpoch.ID] {
				return nil, fmt.Errorf("dnsid: c2sp-tlog trust profile epoch ids must be distinct")
			}
			seenIDs[profileEpoch.ID] = true
			epoch, err := validateTrustProfileEpoch(ref, profileEpoch)
			if err != nil {
				return nil, fmt.Errorf("dnsid: c2sp-tlog trust profile epoch %q: %w", profileEpoch.ID, err)
			}
			epochs = append(epochs, epoch)
		}
		if err := validateTrustEpochSet(epochs); err != nil {
			return nil, err
		}
		return epochs, nil
	}
	return nil, fmt.Errorf("dnsid: unsupported c2sp-tlog trust profile version %d", p.Version)
}

func validateTrustProfileEpoch(ref Reference, profileEpoch TrustProfileEpoch) (TrustEpoch, error) {
	policy, err := ParsePolicy([]byte(profileEpoch.PolicyDocument))
	if err != nil {
		return TrustEpoch{}, err
	}
	origin, err := ref.Origin()
	if err != nil {
		return TrustEpoch{}, err
	}
	if policy.LogVerifier == nil || policy.LogVerifier.Name() != origin {
		return TrustEpoch{}, fmt.Errorf("dnsid: c2sp-tlog trust profile policy does not match log prefix")
	}
	if len(profileEpoch.BundleVerifierKeys) == 0 {
		return TrustEpoch{}, fmt.Errorf("dnsid: c2sp-tlog trust profile needs a bundle verifier key")
	}
	verifiers := make([]note.Verifier, 0, len(profileEpoch.BundleVerifierKeys))
	seenKeys := make(map[string]bool, len(profileEpoch.BundleVerifierKeys))
	seenIDs := make(map[string]bool, len(profileEpoch.BundleVerifierKeys))
	for _, key := range profileEpoch.BundleVerifierKeys {
		verifier, err := note.NewVerifier(key)
		publicKey, keyErr := signedNotePublicKey(key)
		if err != nil || keyErr != nil || verifier.Name() != "dnsid-stream-bundle" || len(publicKey) != 32 {
			return TrustEpoch{}, fmt.Errorf("dnsid: invalid c2sp-tlog trust profile bundle verifier key")
		}
		kid := bundleVerifierKeyID(verifier)
		if seenKeys[string(publicKey)] || seenIDs[kid] {
			return TrustEpoch{}, fmt.Errorf("dnsid: c2sp-tlog trust profile bundle verifier keys must have distinct public keys and key IDs")
		}
		for _, checkpointKey := range policy.trustedPublicKeys {
			if bytes.Equal(publicKey, checkpointKey) {
				return TrustEpoch{}, fmt.Errorf("dnsid: c2sp-tlog trust profile bundle signer must be independent of checkpoint policy keys")
			}
		}
		seenKeys[string(publicKey)] = true
		seenIDs[kid] = true
		verifiers = append(verifiers, verifier)
	}
	epoch := TrustEpoch{ID: profileEpoch.ID, PolicyDocument: []byte(profileEpoch.PolicyDocument), BundleVerifiers: verifiers}
	for _, bound := range []struct {
		value  *uint64
		target *uint64
	}{{profileEpoch.MinTreeSize, &epoch.MinTreeSize}, {profileEpoch.MaxTreeSize, &epoch.MaxTreeSize}} {
		if bound.value == nil {
			continue
		}
		if *bound.value < 1 || *bound.value > maxTrustEpochTreeSize {
			return TrustEpoch{}, fmt.Errorf("dnsid: c2sp-tlog trust profile epoch tree-size bounds must be between 1 and 2^53-1; omit a bound to leave it open")
		}
		*bound.target = *bound.value
	}
	if epoch.MaxTreeSize != 0 && epoch.MinTreeSize > epoch.MaxTreeSize {
		return TrustEpoch{}, fmt.Errorf("dnsid: c2sp-tlog trust profile epoch min_tree_size exceeds max_tree_size")
	}
	return epoch, nil
}

// validateTrustEpochSet checks the rules that span epochs and that every
// constructor of an epoch set shares: at least one epoch, parseable policies
// naming one origin, bounds in order, and an unambiguous bundle-epoch
// selection. A bundle selects its epoch by signer key ID and then by policy
// hash, so no two epochs may share both a bundle key ID and a policy document.
func validateTrustEpochSet(epochs []TrustEpoch) error {
	if len(epochs) == 0 {
		return fmt.Errorf("dnsid: c2sp-tlog trust epoch set is empty")
	}
	var origin string
	for i, epoch := range epochs {
		policy, err := ParsePolicy(epoch.PolicyDocument)
		if err != nil {
			return fmt.Errorf("dnsid: c2sp-tlog trust epoch %q: %w", epoch.ID, err)
		}
		if i == 0 {
			origin = policy.LogVerifier.Name()
		} else if policy.LogVerifier.Name() != origin {
			return fmt.Errorf("dnsid: c2sp-tlog trust epochs must all name one log origin")
		}
		if epoch.MaxTreeSize != 0 && epoch.MinTreeSize > epoch.MaxTreeSize {
			return fmt.Errorf("dnsid: c2sp-tlog trust epoch %q min tree size exceeds max tree size", epoch.ID)
		}
		for j := range i {
			if epochs[j].ID == epoch.ID {
				return fmt.Errorf("dnsid: c2sp-tlog trust epoch ids must be distinct")
			}
			if !bytes.Equal(epochs[j].PolicyDocument, epoch.PolicyDocument) {
				continue
			}
			for _, a := range epochs[j].BundleVerifiers {
				for _, b := range epoch.BundleVerifiers {
					if a != nil && b != nil && bundleVerifierKeyID(a) == bundleVerifierKeyID(b) {
						return fmt.Errorf("dnsid: c2sp-tlog trust epochs %q and %q share a bundle key ID and policy, so bundle selection is ambiguous", epochs[j].ID, epoch.ID)
					}
				}
			}
		}
	}
	return nil
}

func validTrustEpochID(id string) bool {
	if id == "" || len(id) > maxTrustEpochIDBytes {
		return false
	}
	for _, c := range []byte(id) {
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '.', c == '_', c == '-':
		default:
			return false
		}
	}
	return true
}

func bundleVerifierKeyID(verifier note.Verifier) string {
	return fmt.Sprintf("%s+%08x", verifier.Name(), verifier.KeyHash())
}
