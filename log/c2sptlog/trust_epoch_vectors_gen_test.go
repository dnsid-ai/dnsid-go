package c2sptlog

// Deterministic generator for testdata/c2sp-trust-profile-epochs-v1.json, the
// language-neutral trust profile v2 (epochs) vector shared with dnsid-ts and
// dnsid-py. The format is documented in testdata/c2sp-trust-profile-epochs.md.
//
// Regenerate with:
//
//	DNSID_UPDATE_TRUST_EPOCH_VECTORS=1 go test -run TestTrustEpochVectors ./log/c2sptlog
//
// Every key is derived from a fixed, published test seed below. None of them
// is, or protects, a DNSid deployment key.

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"testing"

	"golang.org/x/mod/sumdb/note"
	"golang.org/x/mod/sumdb/tlog"
)

const (
	trustEpochVectorPath        = "testdata/c2sp-trust-profile-epochs-v1.json"
	trustEpochVectorFormat      = "dnsid-c2sp-trust-profile-epochs@v1"
	trustEpochVectorN           = 5
	trustEpochVectorK           = 2
	trustEpochVectorWitnessTime = 1782345700
	trustEpochVectorNow         = 1782345760
	trustEpochVectorMaxAge      = 600
	trustEpochVectorLifetime    = 600
	trustEpochLegacyID          = "legacy"
	trustEpochSuccessorID       = "successor"
)

type epochVectorFile struct {
	Format          string                `json:"format"`
	Description     string                `json:"description"`
	Generator       string                `json:"generator"`
	Documentation   string                `json:"documentation"`
	ReasonCodes     map[string]string     `json:"reason_codes"`
	Parameters      epochVectorParameters `json:"parameters"`
	Keys            map[string]string     `json:"keys"`
	Tree            epochVectorTree       `json:"tree"`
	Profiles        map[string]string     `json:"profiles"`
	ProfileCases    []epochProfileCase    `json:"profile_cases"`
	CheckpointCases []epochCheckpointCase `json:"checkpoint_cases"`
	BundleCases     []epochBundleCase     `json:"bundle_cases"`
	ContinuityCases []epochContinuityCase `json:"continuity_cases"`
}

type epochVectorParameters struct {
	Scope                    string `json:"scope"`
	LogPrefix                string `json:"log_prefix"`
	Origin                   string `json:"origin"`
	LR                       string `json:"lr"`
	FQDN                     string `json:"fqdn"`
	N                        uint64 `json:"n"`
	K                        uint64 `json:"k"`
	Now                      int64  `json:"now"`
	WitnessTime              int64  `json:"witness_time"`
	CheckpointMaxAgeSeconds  int64  `json:"checkpoint_max_age_seconds"`
	MaxBundleLifetimeSeconds int64  `json:"max_bundle_lifetime_seconds"`
	ClockSkewSeconds         int64  `json:"clock_skew_seconds"`
}

type epochVectorTree struct {
	Entries     []string          `json:"entries"`
	Roots       map[string]string `json:"roots"`
	ForkEntries []string          `json:"fork_entries"`
	ForkRoots   map[string]string `json:"fork_roots"`
}

type epochExpect struct {
	Result string  `json:"result"`
	Reason string  `json:"reason,omitempty"`
	Epoch  *string `json:"epoch,omitempty"`
}

type epochProfileCase struct {
	Name     string      `json:"name"`
	Note     string      `json:"note"`
	Document string      `json:"document"`
	Expect   epochExpect `json:"expect"`
	EpochIDs []string    `json:"epoch_ids,omitempty"`
}

type epochCheckpointCase struct {
	Name       string      `json:"name"`
	Tags       []string    `json:"tags"`
	Note       string      `json:"note"`
	Profile    string      `json:"profile"`
	TreeSize   uint64      `json:"tree_size"`
	Checkpoint string      `json:"checkpoint"`
	Expect     epochExpect `json:"expect"`
}

type epochBundleCase struct {
	Name    string      `json:"name"`
	Tags    []string    `json:"tags"`
	Note    string      `json:"note"`
	Profile string      `json:"profile"`
	Bundle  string      `json:"bundle"`
	Expect  epochExpect `json:"expect"`
}

type epochContinuityCase struct {
	Name    string                `json:"name"`
	Tags    []string              `json:"tags"`
	Note    string                `json:"note"`
	Profile string                `json:"profile"`
	Steps   []epochContinuityStep `json:"steps"`
}

type epochContinuityStep struct {
	Checkpoint       string             `json:"checkpoint"`
	ConsistencyProof []string           `json:"consistency_proof"`
	Expect           epochExpect        `json:"expect"`
	TrustedAfter     *epochTrustedState `json:"trusted_after"`
}

type epochTrustedState struct {
	TreeSize uint64 `json:"tree_size"`
	RootHash string `json:"root_hash"`
}

// epochTestKey is one disposable Ed25519 test key with its signed-note name.
type epochTestKey struct {
	name    string
	private ed25519.PrivateKey
	vkey    string
	hash    uint32
}

func newEpochLogKey(t *testing.T, name string, seed byte) epochTestKey {
	t.Helper()
	private := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{seed}, ed25519.SeedSize))
	vkey, err := note.NewEd25519VerifierKey(name, private.Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := note.NewVerifier(vkey)
	if err != nil {
		t.Fatal(err)
	}
	return epochTestKey{name: name, private: private, vkey: vkey, hash: verifier.KeyHash()}
}

// newEpochWitnessKey returns a C2SP cosignature/v1 (signature type 0x04) key.
func newEpochWitnessKey(t *testing.T, name string, seed byte) epochTestKey {
	t.Helper()
	private := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{seed}, ed25519.SeedSize))
	material := append([]byte{0x04}, private.Public().(ed25519.PublicKey)...)
	sum := sha256.Sum256(append([]byte(name+"\n"), material...))
	hash := binary.BigEndian.Uint32(sum[:4])
	vkey := fmt.Sprintf("%s+%08x+%s", name, hash, base64.StdEncoding.EncodeToString(material))
	return epochTestKey{name: name, private: private, vkey: vkey, hash: hash}
}

type epochVectorKeys struct {
	legacyLog, legacyWitness, legacyBundle          epochTestKey
	successorLog, successorWitness, successorBundle epochTestKey
	strangerBundle                                  epochTestKey
}

func newEpochVectorKeys(t *testing.T) epochVectorKeys {
	t.Helper()
	// Published disposable seeds: 0x31.. legacy epoch, 0x41.. successor epoch.
	return epochVectorKeys{
		legacyLog:        newEpochLogKey(t, "log.example", 0x31),
		legacyWitness:    newEpochWitnessKey(t, "witness.example/w1", 0x32),
		legacyBundle:     newEpochLogKey(t, "dnsid-stream-bundle", 0x33),
		successorLog:     newEpochLogKey(t, "log.example", 0x41),
		successorWitness: newEpochWitnessKey(t, "witness.example/w1", 0x42),
		successorBundle:  newEpochLogKey(t, "dnsid-stream-bundle", 0x43),
		strangerBundle:   newEpochLogKey(t, "dnsid-stream-bundle", 0x51),
	}
}

// epochPolicyDocument renders a policy in the DNSid server's single-witness
// format (dnsid internal/tlog/policy.go).
func epochPolicyDocument(logKey, witnessKey epochTestKey) string {
	return fmt.Sprintf("log %s\nwitness dnsid-witness-1 %s\nquorum dnsid-witness-1\n", logKey.vkey, witnessKey.vkey)
}

// signEpochCheckpoint returns a signed-note checkpoint for the tree prefix of
// size, signed by every log key and cosigned by every witness key at witnessTime.
func signEpochCheckpoint(origin string, size uint64, root tlog.Hash, logs, witnesses []epochTestKey, witnessTime int64) string {
	body := fmt.Sprintf("%s\n%d\n%s\n", origin, size, base64.StdEncoding.EncodeToString(root[:]))
	var signatures string
	for _, key := range logs {
		sig := binary.BigEndian.AppendUint32(nil, key.hash)
		sig = append(sig, ed25519.Sign(key.private, []byte(body))...)
		signatures += fmt.Sprintf("— %s %s\n", key.name, base64.StdEncoding.EncodeToString(sig))
	}
	for _, key := range witnesses {
		message := fmt.Appendf(nil, "cosignature/v1\ntime %d\n%s", witnessTime, body)
		sig := binary.BigEndian.AppendUint32(nil, key.hash)
		sig = binary.BigEndian.AppendUint64(sig, uint64(witnessTime))
		sig = append(sig, ed25519.Sign(key.private, message)...)
		signatures += fmt.Sprintf("— %s %s\n", key.name, base64.StdEncoding.EncodeToString(sig))
	}
	return body + "\n" + signatures
}

// RFC 6962 §2.1 helpers over leaf hashes.
func epochTreeHash(leaves []tlog.Hash) tlog.Hash {
	if len(leaves) == 0 {
		return sha256.Sum256(nil)
	}
	if len(leaves) == 1 {
		return leaves[0]
	}
	k := epochSplit(len(leaves))
	return tlog.NodeHash(epochTreeHash(leaves[:k]), epochTreeHash(leaves[k:]))
}

func epochSplit(n int) int {
	k := 1
	for k<<1 < n {
		k <<= 1
	}
	return k
}

func epochInclusionPath(index int, leaves []tlog.Hash) []tlog.Hash {
	if len(leaves) <= 1 {
		return nil
	}
	k := epochSplit(len(leaves))
	if index < k {
		return append(epochInclusionPath(index, leaves[:k]), epochTreeHash(leaves[k:]))
	}
	return append(epochInclusionPath(index-k, leaves[k:]), epochTreeHash(leaves[:k]))
}

func epochConsistencyProof(m int, leaves []tlog.Hash) []tlog.Hash {
	return epochSubproof(m, leaves, true)
}

func epochSubproof(m int, leaves []tlog.Hash, complete bool) []tlog.Hash {
	n := len(leaves)
	if m == n {
		if complete {
			return nil
		}
		return []tlog.Hash{epochTreeHash(leaves)}
	}
	k := epochSplit(n)
	if m <= k {
		return append(epochSubproof(m, leaves[:k], complete), epochTreeHash(leaves[k:]))
	}
	return append(epochSubproof(m-k, leaves[k:], false), epochTreeHash(leaves[:k]))
}

func epochLeafHashes(entries [][]byte) []tlog.Hash {
	leaves := make([]tlog.Hash, len(entries))
	for i, entry := range entries {
		leaves[i] = tlog.RecordHash(entry)
	}
	return leaves
}

func encodeEpochHashes(hashes []tlog.Hash) []string {
	encoded := make([]string, len(hashes))
	for i, hash := range hashes {
		encoded[i] = base64.StdEncoding.EncodeToString(hash[:])
	}
	return encoded
}

func epochString(value string) *string { return &value }

func epochAccept(epoch string) epochExpect {
	return epochExpect{Result: "accept", Epoch: epochString(epoch)}
}

func epochReject(reason string) epochExpect {
	return epochExpect{Result: "reject", Reason: reason}
}

func epochUint(value uint64) *uint64 { return &value }

func marshalEpochProfile(t *testing.T, profile any) string {
	t.Helper()
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(profile); err != nil {
		t.Fatal(err)
	}
	return buf.String()
}

// buildTrustEpochVectors generates the whole vector file deterministically.
func buildTrustEpochVectors(t *testing.T) epochVectorFile {
	t.Helper()
	logical := loadStreamBundleVector(t)
	object, err := decodeJSONObject([]byte(logical.Bundle))
	if err != nil {
		t.Fatal(err)
	}
	lr := object["lr"].(string)
	fqdn := object["fqdn"].(string)
	ref, err := ParseReference(lr)
	if err != nil {
		t.Fatal(err)
	}
	origin, err := ref.Origin()
	if err != nil {
		t.Fatal(err)
	}
	stateObject := object["state"]

	// The tree: the two corrected lifecycle entries of the shared logical
	// bundle vector, then opaque filler entries up to N+k.
	const n, k = trustEpochVectorN, trustEpochVectorK
	var entries [][]byte
	for _, item := range object["events"].([]any) {
		entry, err := base64.RawURLEncoding.DecodeString(item.(map[string]any)["entry"].(string))
		if err != nil {
			t.Fatal(err)
		}
		entries = append(entries, entry)
	}
	lifecycleEntries := len(entries)
	for i := lifecycleEntries; i < n+k; i++ {
		entries = append(entries, fmt.Appendf(nil, "dnsid trust-epoch vector filler entry %d", i))
	}
	forkEntries := append([][]byte(nil), entries...)
	forkEntries[n-1] = fmt.Appendf(nil, "dnsid trust-epoch vector fork entry %d", n-1)
	leaves := epochLeafHashes(entries)
	forkLeaves := epochLeafHashes(forkEntries)
	root := func(size int) tlog.Hash { return epochTreeHash(leaves[:size]) }
	forkRoot := func(size int) tlog.Hash { return epochTreeHash(forkLeaves[:size]) }

	keys := newEpochVectorKeys(t)
	legacyPolicy := epochPolicyDocument(keys.legacyLog, keys.legacyWitness)
	successorPolicy := epochPolicyDocument(keys.successorLog, keys.successorWitness)
	legacyEpoch := func(max *uint64) TrustProfileEpoch {
		return TrustProfileEpoch{ID: trustEpochLegacyID, PolicyDocument: legacyPolicy, BundleVerifierKeys: []string{keys.legacyBundle.vkey}, MaxTreeSize: max}
	}
	successorEpoch := func(min *uint64) TrustProfileEpoch {
		return TrustProfileEpoch{ID: trustEpochSuccessorID, PolicyDocument: successorPolicy, BundleVerifierKeys: []string{keys.successorBundle.vkey}, MinTreeSize: min}
	}
	v2 := func(epochs ...TrustProfileEpoch) string {
		return marshalEpochProfile(t, TrustProfile{Version: 2, Scope: ref.Scope, LogPrefix: ref.LogPrefix, Epochs: epochs})
	}
	profiles := map[string]string{
		"v1-legacy":        marshalEpochProfile(t, TrustProfile{Version: 1, Scope: ref.Scope, LogPrefix: ref.LogPrefix, PolicyDocument: legacyPolicy, BundleVerifierKeys: []string{keys.legacyBundle.vkey}}),
		"v2-legacy-only":   v2(legacyEpoch(nil)),
		"v2-open":          v2(legacyEpoch(nil), successorEpoch(nil)),
		"v2-bounded":       v2(legacyEpoch(epochUint(n)), successorEpoch(epochUint(n))),
		"v2-legacy-capped": v2(legacyEpoch(epochUint(n)), successorEpoch(nil)),
		// Both epochs accept the legacy bundle key, so sig.kid alone matches
		// both and only policy_hash selects the epoch.
		"v2-shared-bundle-key": v2(legacyEpoch(nil), func() TrustProfileEpoch {
			e := successorEpoch(nil)
			e.BundleVerifierKeys = []string{keys.legacyBundle.vkey}
			return e
		}()),
	}

	legacy := []epochTestKey{keys.legacyLog}
	successor := []epochTestKey{keys.successorLog}
	both := []epochTestKey{keys.legacyLog, keys.successorLog}
	lw := []epochTestKey{keys.legacyWitness}
	sw := []epochTestKey{keys.successorWitness}
	cp := func(size int, logs, witnesses []epochTestKey) string {
		return signEpochCheckpoint(origin, uint64(size), root(size), logs, witnesses, trustEpochVectorWitnessTime)
	}
	t76 := []string{"T7-6"}
	// forged is a well-formed signature line under the legacy log key's name
	// and key hash whose signature bytes are all zero: it makes the legacy
	// epoch relevant without being a valid legacy signature.
	forged := func(checkpoint string) string {
		line := binary.BigEndian.AppendUint32(nil, keys.legacyLog.hash)
		line = append(line, make([]byte, ed25519.SignatureSize)...)
		return checkpoint + fmt.Sprintf("— %s %s\n", keys.legacyLog.name, base64.StdEncoding.EncodeToString(line))
	}

	checkpointCases := []epochCheckpointCase{
		{Name: "t7-6-legacy-below-n", Tags: t76, Profile: "v2-bounded", TreeSize: n - 1, Checkpoint: cp(n-1, legacy, lw), Expect: epochAccept(trustEpochLegacyID),
			Note: "A live legacy checkpoint (legacy log key, legacy witness) at size < N verifies under the legacy epoch."},
		{Name: "t7-6-legacy-at-n", Tags: t76, Profile: "v2-bounded", TreeSize: n, Checkpoint: cp(n, legacy, lw), Expect: epochAccept(trustEpochLegacyID),
			Note: "The last legacy checkpoint, at exactly N, verifies: max_tree_size is inclusive."},
		{Name: "t7-6-successor-at-n", Tags: t76, Profile: "v2-bounded", TreeSize: n, Checkpoint: cp(n, successor, sw), Expect: epochAccept(trustEpochSuccessorID),
			Note: "The first successor checkpoint, over the same tree at exactly N, verifies: min_tree_size is inclusive."},
		{Name: "t7-6-successor-above-n", Tags: t76, Profile: "v2-bounded", TreeSize: n + k, Checkpoint: cp(n+k, successor, sw), Expect: epochAccept(trustEpochSuccessorID),
			Note: "A successor checkpoint at N+k over the same tree verifies."},
		{Name: "t7-6-legacy-above-n-capped", Tags: t76, Profile: "v2-bounded", TreeSize: n + k, Checkpoint: cp(n+k, legacy, lw), Expect: epochReject("max_tree_size"),
			Note: "A fully valid legacy checkpoint past N fails because the legacy epoch has max_tree_size = N."},
		{Name: "t7-6-successor-below-n-floored", Tags: t76, Profile: "v2-bounded", TreeSize: n - 1, Checkpoint: cp(n-1, successor, sw), Expect: epochReject("min_tree_size"),
			Note: "A fully valid successor checkpoint below N fails because the successor epoch has min_tree_size = N."},
		{Name: "legacy-above-n-uncapped", Tags: []string{"bounds"}, Profile: "v2-open", TreeSize: n + k, Checkpoint: cp(n+k, legacy, lw), Expect: epochAccept(trustEpochLegacyID),
			Note: "Without max_tree_size the legacy epoch still accepts growth; the bound, not the epoch list, is what rejects legacy past N."},
		{Name: "successor-below-n-unfloored", Tags: []string{"bounds"}, Profile: "v2-open", TreeSize: n - 1, Checkpoint: cp(n-1, successor, sw), Expect: epochAccept(trustEpochSuccessorID),
			Note: "Without min_tree_size a stateless verifier accepts a successor checkpoint below N; only stored state (see continuity cases) would reject it."},
		{Name: "mix-legacy-log-successor-witness", Tags: []string{"cross-epoch"}, Profile: "v2-open", TreeSize: n, Checkpoint: cp(n, legacy, sw), Expect: epochReject("witness_quorum"),
			Note: "Legacy log signature plus successor witness cosignature: no single epoch is satisfied. The witness keys share a name, so only the key hash tells them apart."},
		{Name: "mix-successor-log-legacy-witness", Tags: []string{"cross-epoch"}, Profile: "v2-open", TreeSize: n, Checkpoint: cp(n, successor, lw), Expect: epochReject("witness_quorum"),
			Note: "Successor log signature plus legacy witness cosignature is rejected."},
		{Name: "dual-log-successor-witness-past-n", Tags: []string{"cross-epoch", "bounds"}, Profile: "v2-bounded", TreeSize: n + k, Checkpoint: cp(n+k, both, sw), Expect: epochAccept(trustEpochSuccessorID),
			Note: "Signed by both log keys and cosigned by the successor witness: the legacy epoch fails its bound and quorum, the successor epoch is satisfied completely."},
		{Name: "dual-log-legacy-witness-past-n", Tags: []string{"cross-epoch", "bounds"}, Profile: "v2-bounded", TreeSize: n + k, Checkpoint: cp(n+k, both, lw), Expect: epochReject("max_tree_size"),
			Note: "Signed by both log keys, cosigned only by the legacy witness: legacy fails max_tree_size, successor fails witness_quorum. The reported reason is the first epoch whose log key signed."},
		{Name: "forged-legacy-line-successor-accepts", Tags: []string{"cross-epoch", "precedence"}, Profile: "v2-bounded", TreeSize: n + k, Checkpoint: forged(cp(n+k, successor, sw)), Expect: epochAccept(trustEpochSuccessorID),
			Note: "A valid successor checkpoint plus an invalid signature line under the legacy log key hash: the legacy epoch fails on its log signature, the successor epoch still accepts completely. Do not reject the whole note because a line under another epoch's key is invalid."},
		{Name: "forged-legacy-line-precedence", Tags: []string{"cross-epoch", "precedence", "bounds"}, Profile: "v2-bounded", TreeSize: n - 1, Checkpoint: forged(cp(n-1, successor, sw)), Expect: epochReject("log_signature"),
			Note: "The same forged legacy line on a successor checkpoint below the successor's min_tree_size: neither epoch accepts. The legacy epoch is relevant (its name and key hash appear) and comes first, so the reason is its failure, log_signature, not the successor's min_tree_size."},
		{Name: "no-epoch-log-key", Tags: []string{"cross-epoch"}, Profile: "v2-legacy-only", TreeSize: n, Checkpoint: cp(n, successor, sw), Expect: epochReject("log_signature"),
			Note: "A profile that only knows the legacy epoch rejects a successor checkpoint: no epoch's log key signed it."},
		{Name: "stale-successor", Tags: []string{"freshness"}, Profile: "v2-bounded", TreeSize: n + k,
			Checkpoint: signEpochCheckpoint(origin, n+k, root(n+k), successor, sw, trustEpochVectorNow-trustEpochVectorMaxAge-1), Expect: epochReject("stale"),
			Note: "Epochs do not relax freshness: a cosignature older than checkpoint_max_age_seconds is rejected."},
		{Name: "v1-legacy-at-n", Tags: []string{"v1"}, Profile: "v1-legacy", TreeSize: n, Checkpoint: cp(n, legacy, lw), Expect: epochAccept(""),
			Note: "Version 1 back-compat: the legacy checkpoint verifies, reported under the unnamed epoch \"\"."},
		{Name: "v1-legacy-above-n", Tags: []string{"v1"}, Profile: "v1-legacy", TreeSize: n + k, Checkpoint: cp(n+k, legacy, lw), Expect: epochAccept(""),
			Note: "Version 1 has no tree-size bounds."},
		{Name: "v1-rejects-successor", Tags: []string{"v1"}, Profile: "v1-legacy", TreeSize: n, Checkpoint: cp(n, successor, sw), Expect: epochReject("log_signature"),
			Note: "An un-upgraded version 1 profile fails closed on successor keys."},
		{Name: "v2-legacy-only-matches-v1", Tags: []string{"v1"}, Profile: "v2-legacy-only", TreeSize: n, Checkpoint: cp(n, legacy, lw), Expect: epochAccept(trustEpochLegacyID),
			Note: "A single-epoch version 2 profile accepts what the version 1 profile accepts."},
	}

	type bundleSpec struct {
		signer    epochTestKey
		policy    string
		size      int
		logs      []epochTestKey
		witnesses []epochTestKey
	}
	bundle := func(spec bundleSpec) string {
		checkpoint := cp(spec.size, spec.logs, spec.witnesses)
		sizeLeaves := leaves[:spec.size]
		var events []any
		for i := 0; i < lifecycleEntries; i++ {
			var proof []byte
			for _, hash := range epochInclusionPath(i, sizeLeaves) {
				proof = append(proof, hash[:]...)
			}
			events = append(events, map[string]any{
				"entry": base64.RawURLEncoding.EncodeToString(entries[i]),
				"index": json.Number(strconv.Itoa(i)),
				"proof": base64.RawURLEncoding.EncodeToString(proof),
			})
		}
		policyHash := sha256.Sum256([]byte(spec.policy))
		unsigned := map[string]any{
			"checkpoint":            base64.RawURLEncoding.EncodeToString([]byte(checkpoint)),
			"complete_through_size": json.Number(strconv.Itoa(spec.size)),
			"completeness_mode":     StreamBundleTrustedIndex,
			"events":                events,
			"expires":               json.Number(strconv.Itoa(trustEpochVectorWitnessTime + 300)),
			"fqdn":                  fqdn,
			"lr":                    lr,
			"policy_hash":           base64.RawURLEncoding.EncodeToString(policyHash[:]),
			"state":                 stateObject,
			"type":                  StreamBundleType,
			"v":                     json.Number(strconv.Itoa(StreamBundleVersion)),
		}
		message, err := canonicalJSON(unsigned)
		if err != nil {
			t.Fatal(err)
		}
		unsigned["sig"] = map[string]any{
			"alg":   "EdDSA",
			"kid":   fmt.Sprintf("%s+%08x", spec.signer.name, spec.signer.hash),
			"value": base64.RawURLEncoding.EncodeToString(ed25519.Sign(spec.signer.private, message)),
		}
		signed, err := canonicalJSON(unsigned)
		if err != nil {
			t.Fatal(err)
		}
		return string(signed)
	}
	legacyBundle := bundleSpec{signer: keys.legacyBundle, policy: legacyPolicy, size: n, logs: legacy, witnesses: lw}
	successorBundle := bundleSpec{signer: keys.successorBundle, policy: successorPolicy, size: n + k, logs: successor, witnesses: sw}
	with := func(spec bundleSpec, edit func(*bundleSpec)) bundleSpec { edit(&spec); return spec }

	bundleCases := []epochBundleCase{
		{Name: "bundle-legacy-epoch-at-n", Tags: []string{"T7-6", "bundle"}, Profile: "v2-bounded", Bundle: bundle(legacyBundle), Expect: epochAccept(trustEpochLegacyID),
			Note: "Legacy bundle key, legacy policy_hash, legacy checkpoint at N: accepted under the legacy epoch."},
		{Name: "bundle-successor-epoch-above-n", Tags: []string{"T7-6", "bundle"}, Profile: "v2-bounded", Bundle: bundle(successorBundle), Expect: epochAccept(trustEpochSuccessorID),
			Note: "Successor bundle key, successor policy_hash, successor checkpoint at N+k: accepted under the successor epoch."},
		{Name: "bundle-successor-epoch-at-n", Tags: []string{"T7-6", "bundle"}, Profile: "v2-bounded", Bundle: bundle(with(successorBundle, func(s *bundleSpec) { s.size = n })), Expect: epochAccept(trustEpochSuccessorID),
			Note: "Successor bundle over the same tree at exactly N."},
		{Name: "bundle-legacy-epoch-above-n-capped", Tags: []string{"T7-6", "bundle", "bounds"}, Profile: "v2-bounded", Bundle: bundle(with(legacyBundle, func(s *bundleSpec) { s.size = n + k })), Expect: epochReject("max_tree_size"),
			Note: "A legacy bundle whose checkpoint is past N fails the selected epoch's max_tree_size."},
		{Name: "bundle-successor-epoch-below-n-floored", Tags: []string{"T7-6", "bundle", "bounds"}, Profile: "v2-bounded", Bundle: bundle(with(successorBundle, func(s *bundleSpec) { s.size = n - 1 })), Expect: epochReject("min_tree_size"),
			Note: "A successor bundle whose checkpoint is below N fails the selected epoch's min_tree_size."},
		{Name: "bundle-policy-hash-mismatch", Tags: []string{"bundle", "policy-hash"}, Profile: "v2-open", Bundle: bundle(with(successorBundle, func(s *bundleSpec) { s.policy = legacyPolicy })), Expect: epochReject("policy_hash"),
			Note: "Successor bundle key with the legacy policy_hash: the kid selects the successor epoch, whose policy does not hash to policy_hash."},
		{Name: "bundle-policy-hash-combined-document", Tags: []string{"bundle", "policy-hash"}, Profile: "v2-open", Bundle: bundle(with(successorBundle, func(s *bundleSpec) { s.policy = legacyPolicy + successorPolicy })), Expect: epochReject("policy_hash"),
			Note: "policy_hash over any other document, here the two epoch policies concatenated, is rejected."},
		{Name: "bundle-cross-epoch-checkpoint", Tags: []string{"bundle", "cross-epoch"}, Profile: "v2-open", Bundle: bundle(with(legacyBundle, func(s *bundleSpec) { s.logs, s.witnesses = successor, sw })), Expect: epochReject("log_signature"),
			Note: "Legacy bundle key and policy_hash, but the embedded checkpoint is the successor's: it must satisfy the selected legacy epoch and does not."},
		{Name: "bundle-cross-epoch-witness", Tags: []string{"bundle", "cross-epoch"}, Profile: "v2-open", Bundle: bundle(with(legacyBundle, func(s *bundleSpec) { s.witnesses = sw })), Expect: epochReject("witness_quorum"),
			Note: "Legacy bundle, legacy log signature, successor witness cosignature: the selected epoch's quorum is not met."},
		{Name: "bundle-shared-kid-selects-legacy", Tags: []string{"bundle", "shared-kid"}, Profile: "v2-shared-bundle-key", Bundle: bundle(legacyBundle), Expect: epochAccept(trustEpochLegacyID),
			Note: "The legacy bundle key is in both epochs; policy_hash equals the legacy policy, so the legacy epoch is selected."},
		{Name: "bundle-shared-kid-selects-successor", Tags: []string{"bundle", "shared-kid"}, Profile: "v2-shared-bundle-key", Bundle: bundle(with(successorBundle, func(s *bundleSpec) { s.signer = keys.legacyBundle })), Expect: epochAccept(trustEpochSuccessorID),
			Note: "Signed by the shared legacy bundle key with the successor policy_hash and a successor checkpoint: the successor epoch is selected. Picking the first epoch whose keys contain the kid would wrongly reject this."},
		{Name: "bundle-shared-kid-policy-hash-mismatch", Tags: []string{"bundle", "shared-kid", "policy-hash"}, Profile: "v2-shared-bundle-key", Bundle: bundle(with(legacyBundle, func(s *bundleSpec) { s.policy = legacyPolicy + successorPolicy })), Expect: epochReject("policy_hash"),
			Note: "Signed by the shared key, but policy_hash matches neither epoch holding that kid."},
		{Name: "bundle-unknown-signer", Tags: []string{"bundle"}, Profile: "v2-open", Bundle: bundle(with(successorBundle, func(s *bundleSpec) { s.signer = keys.strangerBundle })), Expect: epochReject("bundle_signer"),
			Note: "A bundle key in no epoch is rejected before any other check."},
		{Name: "v1-bundle-legacy", Tags: []string{"bundle", "v1"}, Profile: "v1-legacy", Bundle: bundle(legacyBundle), Expect: epochAccept(""),
			Note: "Version 1 back-compat: the legacy bundle verifies unchanged."},
		{Name: "v1-bundle-successor", Tags: []string{"bundle", "v1"}, Profile: "v1-legacy", Bundle: bundle(successorBundle), Expect: epochReject("bundle_signer"),
			Note: "A version 1 profile does not know the successor bundle key."},
	}

	stored := func(size int, hash tlog.Hash) *epochTrustedState {
		return &epochTrustedState{TreeSize: uint64(size), RootHash: base64.StdEncoding.EncodeToString(hash[:])}
	}
	legacyAtN := epochContinuityStep{Checkpoint: cp(n, legacy, lw), ConsistencyProof: []string{}, Expect: epochAccept(trustEpochLegacyID), TrustedAfter: stored(n, root(n))}
	continuityCases := []epochContinuityCase{
		{Name: "continuity-equal-root-at-n", Tags: []string{"T7-6", "continuity"}, Profile: "v2-bounded",
			Note:  "Stored legacy state at N, then the successor checkpoint at N with the same root: an equal-size, equal-root no-op. No consistency proof is needed.",
			Steps: []epochContinuityStep{legacyAtN, {Checkpoint: cp(n, successor, sw), ConsistencyProof: []string{}, Expect: epochAccept(trustEpochSuccessorID), TrustedAfter: stored(n, root(n))}}},
		{Name: "continuity-advance-to-n-plus-k", Tags: []string{"T7-6", "continuity"}, Profile: "v2-bounded",
			Note:  "Stored legacy state at N, then the successor checkpoint at N+k: advances with an RFC 6962 consistency proof from N to N+k, exactly as within one epoch.",
			Steps: []epochContinuityStep{legacyAtN, {Checkpoint: cp(n+k, successor, sw), ConsistencyProof: encodeEpochHashes(epochConsistencyProof(n, leaves[:n+k])), Expect: epochAccept(trustEpochSuccessorID), TrustedAfter: stored(n+k, root(n+k))}}},
		{Name: "continuity-bad-consistency-proof", Tags: []string{"continuity"}, Profile: "v2-bounded",
			Note:  "The successor checkpoint at N+k with a consistency proof for a different tree is rejected and trusted state stays at N.",
			Steps: []epochContinuityStep{legacyAtN, {Checkpoint: cp(n+k, successor, sw), ConsistencyProof: encodeEpochHashes(epochConsistencyProof(n, forkLeaves[:n+k])), Expect: epochReject("consistency_failed"), TrustedAfter: stored(n, root(n))}}},
		{Name: "continuity-root-conflict-at-n", Tags: []string{"continuity", "cross-epoch"}, Profile: "v2-bounded",
			Note:  "A successor checkpoint at N over a forked tree is validly signed but conflicts with the stored legacy root at N.",
			Steps: []epochContinuityStep{legacyAtN, {Checkpoint: signEpochCheckpoint(origin, n, forkRoot(n), successor, sw, trustEpochVectorWitnessTime), ConsistencyProof: []string{}, Expect: epochReject("root_conflict"), TrustedAfter: stored(n, root(n))}}},
		{Name: "continuity-successor-below-n-rollback", Tags: []string{"continuity"}, Profile: "v2-open",
			Note:  "Without min_tree_size, a successor checkpoint below stored legacy state is still refused as a rollback.",
			Steps: []epochContinuityStep{legacyAtN, {Checkpoint: cp(n-1, successor, sw), ConsistencyProof: []string{}, Expect: epochReject("rollback"), TrustedAfter: stored(n, root(n))}}},
		{Name: "continuity-legacy-after-successor-rollback", Tags: []string{"continuity"}, Profile: "v2-open",
			Note: "After the successor advanced to N+k, a legacy checkpoint at N (for example a stale edge still serving legacy) is a rollback.",
			Steps: []epochContinuityStep{
				legacyAtN,
				{Checkpoint: cp(n+k, successor, sw), ConsistencyProof: encodeEpochHashes(epochConsistencyProof(n, leaves[:n+k])), Expect: epochAccept(trustEpochSuccessorID), TrustedAfter: stored(n+k, root(n+k))},
				{Checkpoint: cp(n, legacy, lw), ConsistencyProof: []string{}, Expect: epochReject("rollback"), TrustedAfter: stored(n+k, root(n+k))},
			}},
		{Name: "continuity-rejected-checkpoint-leaves-state", Tags: []string{"continuity", "bounds"}, Profile: "v2-bounded",
			Note:  "A checkpoint that fails epoch verification never reaches the store: state stays at N.",
			Steps: []epochContinuityStep{legacyAtN, {Checkpoint: cp(n+k, legacy, lw), ConsistencyProof: encodeEpochHashes(epochConsistencyProof(n, leaves[:n+k])), Expect: epochReject("max_tree_size"), TrustedAfter: stored(n, root(n))}}},
	}

	profileCases := buildTrustEpochProfileCases(t, ref, keys, legacyPolicy, successorPolicy, profiles)

	roots := map[string]string{}
	forkRoots := map[string]string{}
	for size := 1; size <= n+k; size++ {
		r, f := root(size), forkRoot(size)
		roots[strconv.Itoa(size)] = base64.StdEncoding.EncodeToString(r[:])
		if f != r {
			forkRoots[strconv.Itoa(size)] = base64.StdEncoding.EncodeToString(f[:])
		}
	}
	encodeEntries := func(values [][]byte) []string {
		encoded := make([]string, len(values))
		for i, value := range values {
			encoded[i] = base64.StdEncoding.EncodeToString(value)
		}
		return encoded
	}

	return epochVectorFile{
		Format:        trustEpochVectorFormat,
		Description:   "DNSid C2SP trust profile v2 (epochs) conformance vectors: one log origin whose log, witness and bundle keys rotate at tree size N. All keys are disposable test keys from published seeds.",
		Generator:     "dnsid-go log/c2sptlog/trust_epoch_vectors_gen_test.go; regenerate with DNSID_UPDATE_TRUST_EPOCH_VECTORS=1 go test -run TestTrustEpochVectors ./log/c2sptlog",
		Documentation: "log/c2sptlog/testdata/c2sp-trust-profile-epochs.md",
		ReasonCodes: map[string]string{
			"log_signature":      "No epoch's log key (name and key hash) signed the checkpoint, or the selected epoch's log key did not.",
			"witness_quorum":     "An epoch's log key signed the checkpoint, but that same epoch's witness quorum is not met.",
			"max_tree_size":      "The checkpoint size is above the epoch's max_tree_size.",
			"min_tree_size":      "The checkpoint size is below the epoch's min_tree_size.",
			"stale":              "The accepted witness time is older than checkpoint_max_age_seconds.",
			"policy_hash":        "The bundle's policy_hash is not the SHA-256 of the tlog_policy of an epoch that accepts its signer.",
			"bundle_signer":      "The bundle's sig.kid is in no epoch's bundle_verifier_keys.",
			"rollback":           "The checkpoint is smaller than the trusted checkpoint stored for the origin.",
			"root_conflict":      "The checkpoint has the stored size but a different root.",
			"consistency_failed": "The consistency proof from the stored checkpoint does not verify.",
			"profile_invalid":    "The trust profile document is rejected at parse time.",
		},
		Parameters: epochVectorParameters{
			Scope: ref.Scope, LogPrefix: ref.LogPrefix, Origin: origin, LR: lr, FQDN: fqdn,
			N: n, K: k, Now: trustEpochVectorNow, WitnessTime: trustEpochVectorWitnessTime,
			CheckpointMaxAgeSeconds: trustEpochVectorMaxAge, MaxBundleLifetimeSeconds: trustEpochVectorLifetime, ClockSkewSeconds: 0,
		},
		Keys: map[string]string{
			"legacy_log":        keys.legacyLog.vkey,
			"legacy_witness":    keys.legacyWitness.vkey,
			"legacy_bundle":     keys.legacyBundle.vkey,
			"successor_log":     keys.successorLog.vkey,
			"successor_witness": keys.successorWitness.vkey,
			"successor_bundle":  keys.successorBundle.vkey,
			"stranger_bundle":   keys.strangerBundle.vkey,
		},
		Tree:            epochVectorTree{Entries: encodeEntries(entries), Roots: roots, ForkEntries: encodeEntries(forkEntries), ForkRoots: forkRoots},
		Profiles:        profiles,
		ProfileCases:    profileCases,
		CheckpointCases: checkpointCases,
		BundleCases:     bundleCases,
		ContinuityCases: continuityCases,
	}
}

func buildTrustEpochProfileCases(t *testing.T, ref Reference, keys epochVectorKeys, legacyPolicy, successorPolicy string, profiles map[string]string) []epochProfileCase {
	t.Helper()
	epoch := func(id, policy string, bundleKeys ...string) map[string]any {
		return map[string]any{"id": id, "tlog_policy": policy, "bundle_verifier_keys": bundleKeys}
	}
	doc := func(members map[string]any) string {
		profile := map[string]any{"version": 2, "scope": ref.Scope, "log_prefix": ref.LogPrefix}
		for key, value := range members {
			profile[key] = value
		}
		return marshalEpochProfile(t, profile)
	}
	legacy := func() map[string]any { return epoch(trustEpochLegacyID, legacyPolicy, keys.legacyBundle.vkey) }
	successor := func() map[string]any { return epoch(trustEpochSuccessorID, successorPolicy, keys.successorBundle.vkey) }
	edited := func(base map[string]any, key string, value any) map[string]any { base[key] = value; return base }
	otherLog := newEpochLogKey(t, "other.example", 0x61)
	overlap, err := note.NewEd25519VerifierKey("dnsid-stream-bundle", keys.legacyLog.private.Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatal(err)
	}
	// boundLiteral renders a legacy-only profile whose bound member carries
	// the exact JSON token literal, so ports test the token, not its value.
	const sentinel = 424242
	boundLiteral := func(member, literal string) string {
		document := doc(map[string]any{"epochs": []any{edited(legacy(), member, sentinel)}})
		token := fmt.Sprintf("%q: %d", member, sentinel)
		if strings.Count(document, token) != 1 {
			t.Fatalf("bound sentinel %q not found once", token)
		}
		return strings.Replace(document, token, fmt.Sprintf("%q: %s", member, literal), 1)
	}
	// rawReplace edits one exact token in a generated document, so a case
	// carries member names Go's encoder would never emit.
	rawReplace := func(document, token, replacement string) string {
		if strings.Count(document, token) != 1 {
			t.Fatalf("token %q not found once", token)
		}
		return strings.Replace(document, token, replacement, 1)
	}
	valid := func(name, note, document string, ids ...string) epochProfileCase {
		return epochProfileCase{Name: name, Note: note, Document: document, Expect: epochExpect{Result: "accept"}, EpochIDs: ids}
	}
	invalid := func(name, note, document string) epochProfileCase {
		return epochProfileCase{Name: name, Note: note, Document: document, Expect: epochReject("profile_invalid")}
	}
	return []epochProfileCase{
		valid("v1-legacy", "Version 1 parses as one unnamed epoch.", profiles["v1-legacy"], ""),
		valid("v2-bounded", "Legacy capped at N, successor floored at N.", profiles["v2-bounded"], trustEpochLegacyID, trustEpochSuccessorID),
		valid("v2-null-bounds", "An explicit null bound is the same as an absent one.", doc(map[string]any{"epochs": []any{edited(legacy(), "max_tree_size", nil), edited(successor(), "min_tree_size", nil)}}), trustEpochLegacyID, trustEpochSuccessorID),
		valid("v2-shared-bundle-key-distinct-policies", "One bundle key may serve two epochs whose policies differ; policy_hash then selects the epoch.",
			doc(map[string]any{"epochs": []any{legacy(), epoch(trustEpochSuccessorID, successorPolicy, keys.legacyBundle.vkey)}}), trustEpochLegacyID, trustEpochSuccessorID),
		invalid("v2-top-level-policy", "Version 2 must not carry tlog_policy at the top level.", doc(map[string]any{"tlog_policy": legacyPolicy, "epochs": []any{legacy()}})),
		invalid("v2-top-level-bundle-keys", "Version 2 must not carry bundle_verifier_keys at the top level, even empty.", doc(map[string]any{"bundle_verifier_keys": []string{}, "epochs": []any{legacy()}})),
		invalid("v1-with-epochs", "Version 1 must not carry epochs, even empty.", marshalEpochProfile(t, map[string]any{"version": 1, "scope": ref.Scope, "log_prefix": ref.LogPrefix, "tlog_policy": legacyPolicy, "bundle_verifier_keys": []string{keys.legacyBundle.vkey}, "epochs": []any{}})),
		invalid("v2-no-epochs", "Version 2 needs at least one epoch.", doc(map[string]any{"epochs": []any{}})),
		invalid("v2-missing-epochs", "Version 2 needs the epochs member.", doc(map[string]any{})),
		invalid("unsupported-version", "Only versions 1 and 2 exist.", marshalEpochProfile(t, map[string]any{"version": 3, "scope": ref.Scope, "log_prefix": ref.LogPrefix, "epochs": []any{legacy()}})),
		invalid("duplicate-epoch-id", "Epoch ids are unique.", doc(map[string]any{"epochs": []any{legacy(), edited(successor(), "id", trustEpochLegacyID)}})),
		invalid("invalid-epoch-id", "Epoch ids are 1-64 characters of A-Z a-z 0-9 . _ -.", doc(map[string]any{"epochs": []any{edited(legacy(), "id", "legacy epoch")}})),
		invalid("missing-epoch-id", "Every epoch needs an id.", doc(map[string]any{"epochs": []any{func() map[string]any { e := legacy(); delete(e, "id"); return e }()}})),
		invalid("epoch-origin-mismatch", "Every epoch's log key must be named for the profile's origin.", doc(map[string]any{"epochs": []any{legacy(), epoch(trustEpochSuccessorID, epochPolicyDocument(otherLog, keys.successorWitness), keys.successorBundle.vkey)}})),
		invalid("epoch-two-log-lines", "An epoch policy has exactly one log line; rotation is expressed with epochs.", doc(map[string]any{"epochs": []any{epoch(trustEpochLegacyID, "log "+keys.legacyLog.vkey+"\n"+successorPolicy, keys.legacyBundle.vkey)}})),
		invalid("epoch-no-bundle-keys", "Every epoch needs a bundle verifier key.", doc(map[string]any{"epochs": []any{epoch(trustEpochLegacyID, legacyPolicy)}})),
		invalid("epoch-bundle-key-not-independent", "An epoch's bundle key must not reuse one of that epoch's checkpoint keys.", doc(map[string]any{"epochs": []any{epoch(trustEpochLegacyID, legacyPolicy, overlap)}})),
		invalid("ambiguous-bundle-selection", "Two epochs with the same bundle key and the same policy cannot be told apart.", doc(map[string]any{"epochs": []any{legacy(), edited(legacy(), "id", trustEpochSuccessorID)}})),
		invalid("zero-max-tree-size", "Bounds are at least 1; omit a bound to leave it open.", doc(map[string]any{"epochs": []any{edited(legacy(), "max_tree_size", 0)}})),
		invalid("unsafe-max-tree-size", "Bounds are at most 2^53-1 so every language reads them exactly.", doc(map[string]any{"epochs": []any{edited(legacy(), "max_tree_size", uint64(1)<<53)}})),
		invalid("fractional-max-tree-size", "Bounds are integers.", doc(map[string]any{"epochs": []any{edited(legacy(), "max_tree_size", json.Number("5.5"))}})),
		valid("max-tree-size-largest", "2^53-1 is the largest bound, written as a digits-only token.", boundLiteral("max_tree_size", "9007199254740991"), trustEpochLegacyID),
		invalid("max-tree-size-decimal-point", "The bound token must match ^[1-9][0-9]*$: 5.0 is rejected even though its value is 5.", boundLiteral("max_tree_size", "5.0")),
		invalid("max-tree-size-exponent", "The bound token must match ^[1-9][0-9]*$: 5e0 is rejected even though its value is 5.", boundLiteral("max_tree_size", "5e0")),
		invalid("min-tree-size-exponent", "The digits-only rule applies to min_tree_size too.", boundLiteral("min_tree_size", "5E0")),
		invalid("max-tree-size-boolean", "true is not a bound (a language that treats booleans as integers must still reject it).", boundLiteral("max_tree_size", "true")),
		invalid("max-tree-size-string", "\"5\" is a string, not a bound.", boundLiteral("max_tree_size", `"5"`)),
		invalid("max-tree-size-negative", "-1 is rejected: no sign is allowed.", boundLiteral("max_tree_size", "-1")),
		invalid("member-case-max-tree-size", "Member names match exactly, including case: Max_Tree_Size is an unknown epoch member, not a bound.", rawReplace(profiles["v2-bounded"], `"max_tree_size":`, `"Max_Tree_Size":`)),
		invalid("member-case-min-tree-size", "Min_Tree_Size is an unknown epoch member, not a bound.", rawReplace(profiles["v2-bounded"], `"min_tree_size":`, `"Min_Tree_Size":`)),
		invalid("member-case-scope-v2", "Scope is an unknown member; the required scope is then missing.", rawReplace(profiles["v2-bounded"], `"scope":`, `"Scope":`)),
		invalid("member-case-scope-v1", "The exact-case rule applies to version 1 too.", rawReplace(profiles["v1-legacy"], `"scope":`, `"Scope":`)),
		invalid("member-case-epochs", "Epochs is an unknown member; the required epochs is then missing.", rawReplace(profiles["v2-bounded"], `"epochs":`, `"Epochs":`)),
		invalid("member-case-duplicate", "max_tree_size and MAX_TREE_SIZE together: the case variant is an unknown member, so the document is rejected (a case-insensitive decoder would let the second silently win).", rawReplace(profiles["v2-bounded"], `"max_tree_size": 5`, `"max_tree_size": 5,
      "MAX_TREE_SIZE": 9`)),
		invalid("max-tree-size-leading-zero", "05 is rejected: no leading zeros (it is also not valid JSON).", boundLiteral("max_tree_size", "05")),
		invalid("min-above-max", "min_tree_size must not exceed max_tree_size.", doc(map[string]any{"epochs": []any{edited(edited(legacy(), "min_tree_size", 6), "max_tree_size", 5)}})),
		invalid("unknown-epoch-member", "Unknown epoch members are rejected.", doc(map[string]any{"epochs": []any{edited(legacy(), "not_before", 1)}})),
	}
}
