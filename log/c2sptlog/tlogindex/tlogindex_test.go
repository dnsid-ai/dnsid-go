package tlogindex

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand/v2"
	"os"
	"strings"
	"testing"
)

// testdata/vectors.json was produced outside this module by the reference
// implementations: filippo.io/torchwood/mpt v0.10.0 (MPT roots and lookup
// proofs) and golang.org/x/mod/sumdb/tlog (RFC 6962 value log roots). See the
// file's "comment" field.
type vectorFile struct {
	ValueLogs []struct {
		Indices []uint64 `json:"indices"`
		Root    string   `json:"root"`
	} `json:"value_logs"`
	MPT []struct {
		Name    string `json:"name"`
		Entries []struct {
			Key   string `json:"key"`
			Value string `json:"value"`
		} `json:"entries"`
		Root    string `json:"root"`
		Lookups []struct {
			Key     string `json:"key"`
			Present bool   `json:"present"`
			Proof   string `json:"proof"`
		} `json:"lookups"`
	} `json:"mpt"`
}

func loadVectors(t *testing.T) vectorFile {
	t.Helper()
	data, err := os.ReadFile("testdata/vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var v vectorFile
	if err := json.Unmarshal(data, &v); err != nil {
		t.Fatal(err)
	}
	if len(v.ValueLogs) == 0 || len(v.MPT) == 0 {
		t.Fatal("empty vector file")
	}
	return v
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func mustHash(t *testing.T, s string) Hash {
	t.Helper()
	b := mustHex(t, s)
	if len(b) != HashSize {
		t.Fatalf("hash %q has %d bytes", s, len(b))
	}
	return Hash(b)
}

func TestValueRoot_MatchesReferenceVectors(t *testing.T) {
	for _, vector := range loadVectors(t).ValueLogs {
		got, err := ValueRoot(vector.Indices)
		if err != nil {
			t.Fatal(err)
		}
		if got != mustHash(t, vector.Root) {
			t.Errorf("ValueRoot(%v) = %x, want %s", vector.Indices, got, vector.Root)
		}
	}
}

func TestValueRoot_RejectsEmptyAndUnorderedIndices(t *testing.T) {
	for _, indices := range [][]uint64{nil, {}, {2, 1}, {1, 1}, {0, 5, 5}} {
		if _, err := ValueRoot(indices); err == nil {
			t.Errorf("ValueRoot(%v) accepted", indices)
		}
	}
}

func TestTrie_MatchesReferenceVectors(t *testing.T) {
	for _, vector := range loadVectors(t).MPT {
		t.Run(vector.Name, func(t *testing.T) {
			values := make(map[string]Hash)
			for _, entry := range vector.Entries {
				values[entry.Key] = mustHash(t, entry.Value)
			}
			trie, err := NewTrie(values)
			if err != nil {
				t.Fatal(err)
			}
			root := mustHash(t, vector.Root)
			if trie.Root() != root {
				t.Fatalf("root = %x, want %x", trie.Root(), root)
			}
			for _, lookup := range vector.Lookups {
				want := mustHex(t, lookup.Proof)
				if lookup.Present {
					got, err := trie.ProveInclusion(lookup.Key)
					if err != nil || !bytes.Equal(got, want) {
						t.Fatalf("ProveInclusion(%q) = %x, %v; want %x", lookup.Key, got, err, want)
					}
					if err := VerifyInclusion(root, lookup.Key, values[lookup.Key], want); err != nil {
						t.Fatalf("VerifyInclusion(%q): %v", lookup.Key, err)
					}
					continue
				}
				got, err := trie.ProveNonInclusion(lookup.Key)
				if err != nil || !bytes.Equal(got, want) {
					t.Fatalf("ProveNonInclusion(%q) = %x, %v; want %x", lookup.Key, got, err, want)
				}
				if err := VerifyNonInclusion(root, lookup.Key, want); err != nil {
					t.Fatalf("VerifyNonInclusion(%q): %v", lookup.Key, err)
				}
			}
		})
	}
}

func randomKey(rng *rand.Rand) string {
	// A small alphabet makes shared prefixes and prefix keys common.
	const alphabet = "!ab.~"
	b := make([]byte, 1+rng.IntN(6))
	for i := range b {
		b[i] = alphabet[rng.IntN(len(alphabet))]
	}
	return string(b)
}

func valueFor(key string) Hash { return sha256.Sum256([]byte("v:" + key)) }

// referenceRoot computes the MPT root straight from the topology definition:
// the minimum pairwise split bit divides the set.
func referenceRoot(keys []string) Hash {
	switch len(keys) {
	case 0:
		return EmptyMPTRoot
	case 1:
		return LeafHash(keys[0], valueFor(keys[0]))
	}
	minimum := uint64(MaxSplitBit + 1)
	for i := range keys {
		for j := i + 1; j < len(keys); j++ {
			minimum = min(minimum, splitBit(keys[i], keys[j]))
		}
	}
	var left, right []string
	for _, key := range keys {
		if bit(key, minimum) == 0 {
			left = append(left, key)
		} else {
			right = append(right, key)
		}
	}
	return InnerHash(minimum, referenceRoot(left), referenceRoot(right))
}

func TestTrie_ProofRoundTripsOnRandomKeySets(t *testing.T) {
	rng := rand.New(rand.NewPCG(7, 11))
	for round := 0; round < 200; round++ {
		values := make(map[string]Hash)
		for i := rng.IntN(20); i > 0; i-- {
			key := randomKey(rng)
			values[key] = valueFor(key)
		}
		trie, err := NewTrie(values)
		if err != nil {
			t.Fatal(err)
		}
		keys := make([]string, 0, len(values))
		for key := range values {
			keys = append(keys, key)
		}
		if want := referenceRoot(keys); trie.Root() != want {
			t.Fatalf("round %d: root %x, definition gives %x", round, trie.Root(), want)
		}
		for key, value := range values {
			proof, err := trie.ProveInclusion(key)
			if err != nil {
				t.Fatal(err)
			}
			if err := VerifyInclusion(trie.Root(), key, value, proof); err != nil {
				t.Fatalf("round %d key %q: %v", round, key, err)
			}
			if err := VerifyInclusion(trie.Root(), key, valueFor(key+"x"), proof); err == nil {
				t.Fatalf("round %d key %q: wrong value accepted", round, key)
			}
			if _, err := trie.ProveNonInclusion(key); err == nil {
				t.Fatalf("round %d key %q: non-inclusion proof for a present key", round, key)
			}
		}
		for i := 0; i < 20; i++ {
			key := randomKey(rng)
			if _, ok := values[key]; ok {
				continue
			}
			proof, err := trie.ProveNonInclusion(key)
			if err != nil {
				t.Fatal(err)
			}
			if err := VerifyNonInclusion(trie.Root(), key, proof); err != nil {
				t.Fatalf("round %d absent %q: %v", round, key, err)
			}
			if _, err := trie.ProveInclusion(key); err == nil {
				t.Fatalf("round %d absent %q: inclusion proof produced", round, key)
			}
		}
	}
}

func TestVerifyNonInclusion_EmptyTrie(t *testing.T) {
	trie, err := NewTrie(nil)
	if err != nil {
		t.Fatal(err)
	}
	if trie.Root() != EmptyMPTRoot || trie.Len() != 0 {
		t.Fatalf("empty trie root %x", trie.Root())
	}
	proof, err := trie.ProveNonInclusion("agent.example")
	if err != nil || len(proof) != 0 {
		t.Fatalf("empty trie proof %x, %v", proof, err)
	}
	if err := VerifyNonInclusion(EmptyMPTRoot, "agent.example", nil); err != nil {
		t.Fatal(err)
	}
	// A leaf-shaped proof must not be accepted against the empty root.
	single, _ := NewTrie(map[string]Hash{"b": valueFor("b")})
	forged, _ := single.ProveNonInclusion("a")
	if err := VerifyNonInclusion(EmptyMPTRoot, "a", forged); err == nil {
		t.Fatal("non-empty proof accepted for the empty trie")
	}
	if err := VerifyInclusion(EmptyMPTRoot, "a", valueFor("a"), nil); err == nil {
		t.Fatal("inclusion accepted against the empty trie")
	}
}

func TestVerifyNonInclusion_SingleKey(t *testing.T) {
	trie, _ := NewTrie(map[string]Hash{"agent.example": valueFor("agent.example")})
	inclusion, err := trie.ProveInclusion("agent.example")
	if err != nil || len(inclusion) != 0 {
		t.Fatalf("single-key inclusion proof %x, %v", inclusion, err)
	}
	if trie.Root() != LeafHash("agent.example", valueFor("agent.example")) {
		t.Fatal("single-key root is not the leaf hash")
	}
	for _, absent := range []string{"agent.exampl", "agent.example.", "b"} {
		proof, err := trie.ProveNonInclusion(absent)
		if err != nil {
			t.Fatal(err)
		}
		if err := VerifyNonInclusion(trie.Root(), absent, proof); err != nil {
			t.Fatalf("%q: %v", absent, err)
		}
	}
}

func TestVerifyNonInclusion_KeyThatIsAPrefixOfAnother(t *testing.T) {
	// "ab" is absent but is a byte prefix of the present "abc"; "abcd"
	// extends it. Padding with 0x00 then 0xFF keeps all three distinct.
	trie, _ := NewTrie(map[string]Hash{"abc": valueFor("abc"), "a": valueFor("a")})
	for _, absent := range []string{"ab", "abcd", "abc!"} {
		proof, err := trie.ProveNonInclusion(absent)
		if err != nil {
			t.Fatal(err)
		}
		if err := VerifyNonInclusion(trie.Root(), absent, proof); err != nil {
			t.Fatalf("%q: %v", absent, err)
		}
	}
	// And the prefix key itself, when present, still has its own leaf.
	both, _ := NewTrie(map[string]Hash{"ab": valueFor("ab"), "abc": valueFor("abc")})
	for _, key := range []string{"ab", "abc"} {
		proof, _ := both.ProveInclusion(key)
		if err := VerifyInclusion(both.Root(), key, valueFor(key), proof); err != nil {
			t.Fatalf("%q: %v", key, err)
		}
	}
}

func TestVerifyNonInclusion_RejectsPathKeyEqualToTarget(t *testing.T) {
	trie, _ := NewTrie(map[string]Hash{"a": valueFor("a"), "b": valueFor("b"), "c": valueFor("c")})
	// Re-encode b's real inclusion path as if b were the "other" terminal
	// leaf: everything hashes correctly, so only path_key != target stops it.
	steps, _ := trie.ProveInclusion("b")
	forged := append(appendUvarint(nil, 1), 'b')
	forged = appendUvarint(forged, HashSize)
	value := valueFor("b")
	forged = append(append(forged, value[:]...), steps...)
	if err := VerifyNonInclusion(trie.Root(), "b", forged); err == nil {
		t.Fatal("non-inclusion accepted with path_key == target")
	}
}

func TestVerifyNonInclusion_RejectsBitMismatchOnPath(t *testing.T) {
	// "a" (0x61) and "q" (0x71) split at bit 3. A non-inclusion proof for
	// "c" (0x63, bit 3 = 0) ends at "a"'s leaf.
	trie, _ := NewTrie(map[string]Hash{"a": valueFor("a"), "q": valueFor("q")})
	proof, err := trie.ProveNonInclusion("c")
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyNonInclusion(trie.Root(), "c", proof); err != nil {
		t.Fatal(err)
	}
	// Replay that proof for "s" (0x73, bit 3 = 1) against the root a
	// verifier would compute if it skipped the bit check: "s" puts the
	// running hash on the right. Only the bit-agreement rule rejects it.
	pathKey, pathVal, steps, err := ParseNonInclusionProof(proof)
	if err != nil || pathKey != "a" || len(steps) != 1 {
		t.Fatalf("unexpected proof shape %q %d %v", pathKey, len(steps), err)
	}
	forgedRoot := InnerHash(steps[0].Bit, steps[0].Sibling, LeafHash(pathKey, pathVal))
	if err := VerifyNonInclusion(forgedRoot, "s", proof); err == nil {
		t.Fatal("non-inclusion accepted where target and path key disagree at a split bit")
	}
}

func TestParseProofSteps_DecoderRules(t *testing.T) {
	sib := bytes.Repeat([]byte{0xaa}, HashSize)
	step := func(prefix ...byte) []byte { return append(append([]byte(nil), prefix...), sib...) }
	cases := map[string][]byte{
		"uvarint longer than 10 bytes": step(0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x01),
		"uvarint overflowing 64 bits":  step(0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x02),
		"non-minimal uvarint":          step(0x85, 0x00),
		"truncated uvarint":            {0x80},
		"split bit above 8192":         step(0x81, 0x40), // 8193
		"equal split bits":             append(step(0x05), step(0x05)...),
		"increasing split bits":        append(step(0x05), step(0x06)...),
		"truncated sibling hash":       append([]byte{0x05}, sib[:31]...),
		"trailing bytes":               append(step(0x05), 0x01),
	}
	for name, data := range cases {
		if _, err := ParseProofSteps(data); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	valid := append(step(0x80, 0x40), step(0x05)...) // 8192 then 5
	if steps, err := ParseProofSteps(valid); err != nil || len(steps) != 2 || steps[0].Bit != MaxSplitBit {
		t.Fatalf("valid steps rejected: %v %v", steps, err)
	}
}

func TestParseNonInclusionProof_DecoderRules(t *testing.T) {
	val := bytes.Repeat([]byte{0xbb}, HashSize)
	leaf := func(key string, valLen uint64, value []byte) []byte {
		p := appendUvarint(nil, uint64(len(key)))
		p = append(p, key...)
		p = appendUvarint(p, valLen)
		return append(p, value...)
	}
	cases := map[string][]byte{
		"empty key":             leaf("", HashSize, val),
		"key over 1024 bytes":   leaf(strings.Repeat("a", 1025), HashSize, val),
		"key with space":        leaf("a b", HashSize, val),
		"key with NUL":          leaf("a\x00", HashSize, val),
		"value not 32 bytes":    leaf("a", 31, val[:31]),
		"value length 33":       leaf("a", 33, append(val, 0)),
		"value length 31 of 32": leaf("a", 31, val),
		"truncated value":       leaf("a", HashSize, val[:20]),
		"truncated key":         {0x05, 'a'},
		"non-minimal key len":   append([]byte{0x81, 0x00}, leaf("a", HashSize, val)[1:]...),
		"trailing after steps":  append(leaf("a", HashSize, val), 0x05),
	}
	for name, data := range cases {
		if _, _, _, err := ParseNonInclusionProof(data); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestValidKey(t *testing.T) {
	for _, key := range []string{"!", "~", "agent.example", strings.Repeat("x", MaxKeyLen)} {
		if err := ValidKey(key); err != nil {
			t.Errorf("ValidKey(%q): %v", key, err)
		}
	}
	for _, key := range []string{"", " ", "a b", "a\x7f", "\x20", "é", strings.Repeat("x", MaxKeyLen+1)} {
		if err := ValidKey(key); !errors.Is(err, ErrInvalidKey) {
			t.Errorf("ValidKey(%q) = %v", key, err)
		}
	}
	if _, err := NewTrie(map[string]Hash{"a b": {}}); !errors.Is(err, ErrInvalidKey) {
		t.Errorf("NewTrie accepted a non-canonical key: %v", err)
	}
}

func TestStateEntry_RoundTrip(t *testing.T) {
	s := StateEntry{InputSize: 98765, InputRoot: sha256.Sum256([]byte("in")), MPTRoot: sha256.Sum256([]byte("mpt"))}
	text := s.Marshal()
	want := "dnsid.org/tlog-index-state@v1\ninput-size 98765\ninput-root " +
		"WClnU00PkJ0Za5f55pITQnd66oe0b6Ut8WU4nbH7jM8=\nmpt-root " +
		"lmkQNHRXYsSLydlmsNw9Tvg4dA3dHBreQLU97+rToL8=\n"
	if string(text) != want {
		t.Fatalf("Marshal =\n%s\nwant\n%s", text, want)
	}
	if !IsStateEntry(text) {
		t.Fatal("IsStateEntry rejected a state entry")
	}
	parsed, err := ParseStateEntry(text)
	if err != nil || parsed != s {
		t.Fatalf("ParseStateEntry = %+v, %v", parsed, err)
	}
	zero := StateEntry{MPTRoot: EmptyMPTRoot}
	if parsed, err := ParseStateEntry(zero.Marshal()); err != nil || parsed != zero {
		t.Fatalf("zero state round trip: %+v %v", parsed, err)
	}
}

func TestParseStateEntry_RejectsNonCanonicalForms(t *testing.T) {
	good := string(StateEntry{InputSize: 12, InputRoot: sha256.Sum256([]byte("in")), MPTRoot: sha256.Sum256([]byte("mpt"))}.Marshal())
	lines := strings.Split(strings.TrimSuffix(good, "\n"), "\n")
	join := func(l ...string) string { return strings.Join(l, "\n") + "\n" }
	root := strings.TrimPrefix(lines[2], "input-root ")
	cases := map[string]string{
		"missing final newline": strings.TrimSuffix(good, "\n"),
		"CRLF line endings":     strings.ReplaceAll(good, "\n", "\r\n"),
		"trailing data":         good + "x",
		"trailing blank line":   good + "\n",
		"five lines":            join(lines[0], lines[1], lines[2], lines[3], "extra 1"),
		"three lines":           join(lines[0], lines[1], lines[2]),
		"wrong header":          join("c2sp.org/tlog-vindex-state@v1", lines[1], lines[2], lines[3]),
		"reordered lines":       join(lines[0], lines[1], lines[3], lines[2]),
		"leading zero":          join(lines[0], "input-size 012", lines[2], lines[3]),
		"signed size":           join(lines[0], "input-size +12", lines[2], lines[3]),
		"empty size":            join(lines[0], "input-size ", lines[2], lines[3]),
		"size overflow":         join(lines[0], "input-size 18446744073709551616", lines[2], lines[3]),
		"double space":          join(lines[0], "input-size  12", lines[2], lines[3]),
		"trailing space":        join(lines[0], lines[1]+" ", lines[2], lines[3]),
		"unpadded base64":       join(lines[0], lines[1], "input-root "+strings.TrimRight(root, "="), lines[3]),
		"base64url alphabet":    join(lines[0], lines[1], "input-root "+strings.NewReplacer("+", "-", "/", "_").Replace(root)+"-", lines[3]),
		"non-canonical bits":    join(lines[0], lines[1], "input-root "+root[:42]+"d=", lines[3]),
		"short hash":            join(lines[0], lines[1], "input-root AAAA", lines[3]),
		"embedded CR in base64": join(lines[0], lines[1], "input-root "+root[:10]+"\r"+root[10:], lines[3]),
	}
	for name, text := range cases {
		if _, err := ParseStateEntry([]byte(text)); err == nil {
			t.Errorf("%s: accepted %q", name, text)
		}
	}
}

func TestReplay_BuildsValueLogsFromMappedEntries(t *testing.T) {
	entries := [][]byte{[]byte("a"), []byte("-"), []byte("b"), []byte("a"), []byte(StateEntryHeader + "\n")}
	mapFn := func(entry []byte) (string, bool, error) {
		if string(entry) == "-" || IsStateEntry(entry) {
			return "", false, nil
		}
		return string(entry), true, nil
	}
	root, err := Replay(entries, mapFn)
	if err != nil {
		t.Fatal(err)
	}
	a, _ := ValueRoot([]uint64{0, 3})
	b, _ := ValueRoot([]uint64{2})
	want, _ := NewTrie(map[string]Hash{"a": a, "b": b})
	if root != want.Root() {
		t.Fatalf("Replay root %x, want %x", root, want.Root())
	}
	r := NewReplayer(mapFn)
	for _, entry := range entries {
		if err := r.Append(entry); err != nil {
			t.Fatal(err)
		}
	}
	if r.Size() != 5 || fmt.Sprint(r.Entries("a")) != "[0 3]" || r.Entries("missing") != nil {
		t.Fatalf("replayer state size=%d a=%v", r.Size(), r.Entries("a"))
	}
	if _, err := Replay([][]byte{[]byte("x")}, func([]byte) (string, bool, error) { return "a b", true, nil }); !errors.Is(err, ErrInvalidKey) || !strings.Contains(err.Error(), "entry 0") {
		t.Fatalf("invalid mapped key accepted: %v", err)
	}
	boom := errors.New("boom")
	if _, err := Replay([][]byte{[]byte("x")}, func([]byte) (string, bool, error) { return "", false, boom }); !errors.Is(err, boom) {
		t.Fatalf("map error not propagated: %v", err)
	}
}
