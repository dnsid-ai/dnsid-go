package c2sptlog

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"

	dnsid "github.com/dnsid-ai/dnsid-go"
	formatnote "github.com/transparency-dev/formats/note"
	"golang.org/x/mod/sumdb/note"
)

type checkpointQuorumRule struct {
	none      bool
	verifier  note.Verifier
	threshold int
	members   []*checkpointQuorumRule
}

// ParsePolicy parses the official line-oriented C2SP tlog-policy format for a
// verification-only client. Witness URLs are optional transport hints and are
// ignored. Definitions are ordered: groups and quorum may reference only
// preceding witnesses or groups.
func ParsePolicy(document []byte) (policyResult Policy, errResult error) {
	defer func() {
		if errResult != nil {
			errResult = dnsid.NewParseError("dnsid: parsing c2sp-tlog policy", errResult)
		}
	}()
	components := make(map[string]*checkpointQuorumRule)
	var logVerifier note.Verifier
	var witnesses []note.Verifier
	var trustedPublicKeys [][]byte
	var quorum *checkpointQuorumRule
	scanner := bufio.NewScanner(bytes.NewReader(document))
	lineNumber := 0
	for scanner.Scan() {
		lineNumber++
		line := strings.TrimSpace(scanner.Text())
		if i := strings.IndexByte(line, '#'); i >= 0 {
			line = strings.TrimSpace(line[:i])
		}
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		fail := func(message string) (Policy, error) {
			return Policy{}, fmt.Errorf("dnsid: invalid c2sp-tlog policy line %d: %s", lineNumber, message)
		}
		switch fields[0] {
		case "log":
			if len(fields) != 2 && len(fields) != 3 {
				return fail("log requires a verifier key and optional URL")
			}
			if logVerifier != nil {
				return fail("verification policy requires exactly one log key")
			}
			v, err := note.NewVerifier(fields[1])
			if err != nil {
				return fail("invalid log verifier key")
			}
			logVerifier = v
			publicKey, err := signedNotePublicKey(fields[1])
			if err != nil {
				return fail("invalid log verifier key")
			}
			trustedPublicKeys = append(trustedPublicKeys, publicKey)
		case "witness":
			if len(fields) != 3 && len(fields) != 4 {
				return fail("witness requires name, verifier key, and optional URL")
			}
			name := fields[1]
			if invalidPolicyName(name) {
				return fail("invalid witness name")
			}
			if _, exists := components[name]; exists {
				return fail("duplicate witness or group name")
			}
			v, err := formatnote.NewVerifierForCosignatureV1(fields[2])
			if err != nil {
				return fail("invalid witness verifier key")
			}
			witnesses = append(witnesses, v)
			publicKey, err := signedNotePublicKey(fields[2])
			if err != nil {
				return fail("invalid witness verifier key")
			}
			trustedPublicKeys = append(trustedPublicKeys, publicKey)
			components[name] = &checkpointQuorumRule{verifier: v}
		case "group":
			if len(fields) < 4 {
				return fail("group requires name, threshold, and members")
			}
			name := fields[1]
			if invalidPolicyName(name) {
				return fail("invalid group name")
			}
			if _, exists := components[name]; exists {
				return fail("duplicate witness or group name")
			}
			members := make([]*checkpointQuorumRule, 0, len(fields)-3)
			seen := make(map[string]bool)
			for _, memberName := range fields[3:] {
				if seen[memberName] {
					return fail("group members must be distinct")
				}
				seen[memberName] = true
				member := components[memberName]
				if member == nil {
					return fail("group references an unknown or later component")
				}
				members = append(members, member)
			}
			threshold, err := parsePolicyThreshold(fields[2], len(members))
			if err != nil {
				return fail(err.Error())
			}
			components[name] = &checkpointQuorumRule{threshold: threshold, members: members}
		case "quorum":
			if len(fields) != 2 || quorum != nil {
				return fail("policy requires exactly one quorum directive")
			}
			if fields[1] == "none" {
				quorum = &checkpointQuorumRule{none: true}
			} else {
				quorum = components[fields[1]]
				if quorum == nil {
					return fail("quorum references an unknown or later component")
				}
			}
		default:
			return fail("unknown directive")
		}
	}
	if err := scanner.Err(); err != nil {
		return Policy{}, fmt.Errorf("dnsid: reading c2sp-tlog policy: %w", err)
	}
	if logVerifier == nil || quorum == nil {
		return Policy{}, fmt.Errorf("dnsid: c2sp-tlog policy requires one log and one quorum directive")
	}
	return Policy{LogVerifier: logVerifier, WitnessVerifiers: witnesses, WitnessQuorum: quorum.minimumSignatures(), quorumRule: quorum, trustedPublicKeys: trustedPublicKeys}, nil
}

func signedNotePublicKey(key string) ([]byte, error) {
	parts := strings.SplitN(key, "+", 3)
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid signed-note verifier key")
	}
	encoded, err := base64.StdEncoding.DecodeString(parts[2])
	if err != nil || len(encoded) < 2 {
		return nil, fmt.Errorf("invalid signed-note verifier key")
	}
	return encoded[1:], nil
}

func parsePolicyThreshold(value string, memberCount int) (int, error) {
	var threshold int
	switch value {
	case "any":
		threshold = 1
	case "all":
		threshold = memberCount
	default:
		n, err := strconv.ParseUint(value, 10, 31)
		if err != nil {
			return 0, fmt.Errorf("invalid group threshold")
		}
		threshold = int(n)
	}
	if threshold < 1 || threshold > memberCount {
		return 0, fmt.Errorf("group threshold outside member count")
	}
	return threshold, nil
}

func invalidPolicyName(name string) bool {
	if name == "" {
		return true
	}
	switch name {
	case "log", "witness", "group", "quorum", "any", "all", "none":
		return true
	}
	return false
}

func (r *checkpointQuorumRule) minimumSignatures() int {
	if r == nil || r.none {
		return 0
	}
	if r.verifier != nil {
		return 1
	}
	values := make([]int, len(r.members))
	for i, member := range r.members {
		values[i] = member.minimumSignatures()
	}
	sortInts(values)
	total := 0
	for _, value := range values[:r.threshold] {
		total += value
	}
	return total
}

func sortInts(values []int) {
	for i := 1; i < len(values); i++ {
		for j := i; j > 0 && values[j] < values[j-1]; j-- {
			values[j], values[j-1] = values[j-1], values[j]
		}
	}
}
