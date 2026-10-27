package c2sptlog

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/dnsid-ai/dnsid-go/log/c2sptlog/tlogindex"
	formatproof "github.com/transparency-dev/formats/proof"
	"golang.org/x/mod/sumdb/note"
	"golang.org/x/mod/sumdb/tlog"
)

const ciFQDN = "agent.example.com"

// committedIndexFixture is a synthetic log that holds the two real lifecycle
// events of the logical bundle vector at chosen indices among noise entries
// and index state entries.
type committedIndexFixture struct {
	vector   streamBundleVector
	policy   Policy
	ref      Reference
	log      IndexedLog
	raw      [][]byte
	issuance []byte
	rotation []byte
}

func newCommittedIndexFixture(t *testing.T) *committedIndexFixture {
	t.Helper()
	v := loadStreamBundleVector(t)
	object, err := decodeJSONObject([]byte(v.Bundle))
	if err != nil {
		t.Fatal(err)
	}
	var lifecycle [][]byte
	for _, item := range object["events"].([]any) {
		entry, err := base64.RawURLEncoding.DecodeString(item.(map[string]any)["entry"].(string))
		if err != nil {
			t.Fatal(err)
		}
		lifecycle = append(lifecycle, entry)
	}
	policy, err := ParsePolicy([]byte(v.Policy))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(v.Trust.Now, 0)
	policy.Now = func() time.Time { return now }
	ref, err := ParseReference(object["lr"].(string))
	if err != nil {
		t.Fatal(err)
	}
	return &committedIndexFixture{
		vector: v, policy: policy, ref: ref,
		log:      IndexedLog{Scope: ref.Scope, LogPrefix: ref.LogPrefix},
		issuance: lifecycle[0], rotation: lifecycle[1],
	}
}

func (f *committedIndexFixture) add(entries ...[]byte) uint64 {
	f.raw = append(f.raw, entries...)
	return uint64(len(f.raw) - 1)
}

func (f *committedIndexFixture) addNoise(n int) {
	for i := 0; i < n; i++ {
		f.raw = append(f.raw, fmt.Appendf(nil, `{"n":%d}`, len(f.raw)))
	}
}

func (f *committedIndexFixture) replay(t *testing.T, inputSize uint64) *tlogindex.Replayer {
	t.Helper()
	r := tlogindex.NewReplayer(IndexMapFunc(f.log))
	for _, entry := range f.raw[:inputSize] {
		if err := r.Append(entry); err != nil {
			t.Fatal(err)
		}
	}
	return r
}

// addState appends an honest state entry over [0, inputSize).
func (f *committedIndexFixture) addState(t *testing.T, inputSize uint64) uint64 {
	t.Helper()
	trie, err := f.replay(t, inputSize).Trie()
	if err != nil {
		t.Fatal(err)
	}
	return f.addStateEntry(tlogindex.StateEntry{InputSize: inputSize, InputRoot: tlogindex.Hash(merkleRoot(f.raw[:inputSize])), MPTRoot: trie.Root()})
}

func (f *committedIndexFixture) addStateEntry(state tlogindex.StateEntry) uint64 {
	return f.add(state.Marshal())
}

func (f *committedIndexFixture) checkpoint() []byte {
	return signTestCheckpoint(f.policy, fmt.Sprintf("log.example\n%d\n%s\n", len(f.raw), base64.StdEncoding.EncodeToString(merkleRoot(f.raw))))
}

func (f *committedIndexFixture) proofHashes(t *testing.T, checkpoint []byte, index uint64) string {
	t.Helper()
	scan := completeScan{checkpoint: checkpoint, entries: f.raw, levels: merkleLevels(f.raw)}
	var proof formatproof.TLogProof
	if err := proof.Unmarshal(scan.provenEntry(index).Proof); err != nil {
		t.Fatal(err)
	}
	var hashes []byte
	for _, hash := range proof.Hashes {
		hashes = append(hashes, hash[:]...)
	}
	return base64.RawURLEncoding.EncodeToString(hashes)
}

func (f *committedIndexFixture) proven(t *testing.T, checkpoint []byte, index uint64) map[string]any {
	t.Helper()
	return map[string]any{"entry": base64.RawURLEncoding.EncodeToString(f.raw[index]), "index": index, "proof": f.proofHashes(t, checkpoint, index)}
}

// bundle builds the honest version 2 bundle a server would serve for
// ciFQDN, using the state entry at stateIndex and the current log as the
// checkpoint.
func (f *committedIndexFixture) bundle(t *testing.T, stateIndex uint64) map[string]any {
	t.Helper()
	state, err := tlogindex.ParseStateEntry(f.raw[stateIndex])
	if err != nil {
		t.Fatal(err)
	}
	return f.bundleFor(t, stateIndex, f.replay(t, state.InputSize))
}

func (f *committedIndexFixture) bundleFor(t *testing.T, stateIndex uint64, r *tlogindex.Replayer) map[string]any {
	t.Helper()
	checkpoint := f.checkpoint()
	trie, err := r.Trie()
	if err != nil {
		t.Fatal(err)
	}
	indices := r.Entries(ciFQDN)
	var proof []byte
	if len(indices) > 0 {
		proof, err = trie.ProveInclusion(ciFQDN)
	} else {
		proof, err = trie.ProveNonInclusion(ciFQDN)
	}
	if err != nil {
		t.Fatal(err)
	}
	events := []any{}
	for _, index := range indices {
		events = append(events, f.proven(t, checkpoint, index))
	}
	count, lastType := 0, ""
	for _, entry := range f.raw {
		switch {
		case bytes.Equal(entry, f.issuance):
			count, lastType = count+1, "ISSUANCE"
		case bytes.Equal(entry, f.rotation):
			count, lastType = count+1, "KEY_ROTATION"
		}
	}
	policyHash := sha256.Sum256([]byte(f.vector.Policy))
	return map[string]any{
		"checkpoint":            base64.RawURLEncoding.EncodeToString(checkpoint),
		"complete_through_size": len(f.raw),
		"completeness_mode":     StreamBundleCommittedIndex,
		"events":                events,
		"expires":               f.vector.Trust.Now + 200,
		"fqdn":                  ciFQDN,
		"index_proof":           base64.RawURLEncoding.EncodeToString(proof),
		"index_state":           f.proven(t, checkpoint, stateIndex),
		"lr":                    f.ref.String(),
		"policy_hash":           base64.RawURLEncoding.EncodeToString(policyHash[:]),
		"state":                 map[string]any{"event_count": count, "last_event_type": lastType, "logged_state": "ACTIVE"},
		"type":                  StreamBundleType,
		"v":                     StreamBundleCommittedIndexVersion,
	}
}

// tiles serves the log's entry bundles and hash tiles at every level.
func (f *committedIndexFixture) tiles() map[string][]byte {
	resources := make(map[string][]byte)
	path := func(kind string, n, width int) string {
		p := "/tile/" + kind + "/" + tileNumber(uint64(n))
		if width < 256 {
			p += ".p/" + fmt.Sprint(width)
		}
		return p
	}
	level := make([]tlog.Hash, len(f.raw))
	for i, entry := range f.raw {
		level[i] = tlog.RecordHash(entry)
	}
	for n := 0; n*256 < len(f.raw); n++ {
		chunk := f.raw[n*256 : min(len(f.raw), n*256+256)]
		var data []byte
		for _, entry := range chunk {
			data = binary.BigEndian.AppendUint16(data, uint16(len(entry)))
			data = append(data, entry...)
		}
		resources[path("entries", n, len(chunk))] = data
	}
	for l := 0; len(level) > 0; l++ {
		var next []tlog.Hash
		for n := 0; n*256 < len(level); n++ {
			chunk := level[n*256 : min(len(level), n*256+256)]
			var data []byte
			for _, hash := range chunk {
				data = append(data, hash[:]...)
			}
			resources[path(fmt.Sprint(l), n, len(chunk))] = data
			if len(chunk) == 256 {
				next = append(next, hashTileRoot(chunk))
			}
		}
		level = next
	}
	return resources
}

type ciFetcher struct {
	resources map[string][]byte
	reads     []string
}

func (f *ciFetcher) FetchBounded(_ context.Context, rawURL string, maximum int64) ([]byte, error) {
	path := strings.TrimPrefix(rawURL, "https://log.example")
	f.reads = append(f.reads, path)
	body, ok := f.resources[path]
	if !ok {
		return nil, &ResourceFetchError{Kind: ResourceFetchHTTPStatus, HTTPStatus: http.StatusNotFound}
	}
	if int64(len(body)) > maximum {
		return nil, &ResourceFetchError{Kind: ResourceFetchResponseLimit}
	}
	return append([]byte(nil), body...), nil
}

func (*ciFetcher) SecurityGuarantees() ResourceFetchGuarantees {
	return ResourceFetchGuarantees{HTTPSOnly: true, RejectsRedirects: true, ValidatesAllResolvedAddresses: true, ConnectsToValidatedAddress: true, BoundsResponseDuringRead: true}
}

func (f *committedIndexFixture) trust(fetcher BoundedResourceFetcher) StreamBundleTrust {
	return StreamBundleTrust{
		PolicyDocument:    []byte(f.vector.Policy),
		Now:               f.policy.Now,
		MaxBundleLifetime: time.Duration(f.vector.Trust.MaxBundleLifetime) * time.Millisecond,
		MaxCheckpointAge:  time.Duration(f.vector.Trust.CheckpointFreshness) * time.Millisecond,
		CommittedIndex:    &CommittedIndexTrust{Fetcher: fetcher},
	}
}

func encodeBundle(t *testing.T, object map[string]any) []byte {
	t.Helper()
	data, err := canonicalJSON(object)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func (f *committedIndexFixture) verify(t *testing.T, object map[string]any) (*VerifiedStreamBundle, error) {
	t.Helper()
	return VerifyStreamBundle(context.Background(), encodeBundle(t, object), f.trust(&ciFetcher{resources: f.tiles()}))
}

// Layout: noise, ISSUANCE, other-FQDN copy, KEY_ROTATION, noise, state over
// [0, 5), noise. Both lifecycle events are in the committed index.
func indexedFixture(t *testing.T) (*committedIndexFixture, uint64) {
	t.Helper()
	f := newCommittedIndexFixture(t)
	f.addNoise(1)
	f.add(f.issuance)
	f.add(canonicalEntryMutation(t, string(f.issuance), func(p map[string]any) { p["fqdn"] = "other.example.com" }))
	f.add(f.rotation)
	f.addNoise(1)
	state := f.addState(t, 5)
	f.addNoise(1)
	return f, state
}

func TestCommittedIndexBundle_AcceptsIndexedEvents(t *testing.T) {
	f, state := indexedFixture(t)
	verified, err := f.verify(t, f.bundle(t, state))
	if err != nil {
		t.Fatal(err)
	}
	if len(verified.Events) != 2 || verified.CompletenessMode != StreamBundleCommittedIndex || verified.CompleteThroughSize != uint64(len(f.raw)) || verified.SignerKeyID != "" {
		t.Fatalf("verified = %d events, mode %q, through %d, signer %q", len(verified.Events), verified.CompletenessMode, verified.CompleteThroughSize, verified.SignerKeyID)
	}
	complete, err := verified.Source.RebuildCompleteHistory(context.Background(), verified.Reference, ciFQDN)
	if err != nil || complete.CompletenessMode != StreamBundleCommittedIndex || complete.CompleteThrough != uint64(len(f.raw)) {
		t.Fatalf("complete history %+v, %v", complete, err)
	}
}

func TestCommittedIndexBundle_TailScanAddsEventsAfterTheState(t *testing.T) {
	// The state covers [0, 2): only ISSUANCE is indexed; KEY_ROTATION is in
	// the tail, which the bundle does not list and the verifier scans.
	f := newCommittedIndexFixture(t)
	f.addNoise(1)
	f.add(f.issuance)
	state := f.addState(t, 2)
	f.add(f.rotation)
	f.addNoise(1)
	object := f.bundle(t, state)
	if n := len(object["events"].([]any)); n != 1 {
		t.Fatalf("bundle lists %d events, want only the indexed one", n)
	}
	verified, err := f.verify(t, object)
	if err != nil {
		t.Fatal(err)
	}
	if len(verified.Events) != 2 || verified.Events[1].Type != "KEY_ROTATION" {
		t.Fatalf("events = %+v", verified.Events)
	}
	// A server that hides the tail event in its summary is caught, because
	// the verifier's own tail scan found the event.
	object["state"] = map[string]any{"event_count": 1, "last_event_type": "ISSUANCE", "logged_state": "ACTIVE"}
	if _, err := f.verify(t, object); err == nil || !strings.Contains(err.Error(), "state does not match") {
		t.Fatalf("omitted tail event accepted: %v", err)
	}
}

func TestCommittedIndexBundle_NonInclusionWithAllEventsInTail(t *testing.T) {
	f := newCommittedIndexFixture(t)
	f.addNoise(3)
	f.add(canonicalEntryMutation(t, string(f.issuance), func(p map[string]any) { p["fqdn"] = "other.example.com" }))
	state := f.addState(t, 4)
	f.add(f.issuance)
	f.add(f.rotation)
	object := f.bundle(t, state)
	if len(object["events"].([]any)) != 0 || object["index_proof"] == "" {
		t.Fatalf("expected a non-inclusion bundle, got %v", object)
	}
	verified, err := f.verify(t, object)
	if err != nil || len(verified.Events) != 2 {
		t.Fatalf("verified %v, %v", verified, err)
	}
}

func TestCommittedIndexBundle_TailAcrossTiles(t *testing.T) {
	// 600 entries: the tail [300, 600) spans a full and a partial entry
	// bundle, and authenticating it needs a level-1 hash tile.
	f := newCommittedIndexFixture(t)
	f.addNoise(100)
	f.add(f.issuance)
	f.addNoise(198)
	state := f.addState(t, 299)
	f.addNoise(289)
	f.add(f.rotation)
	f.addNoise(10)
	if state != 299 || len(f.raw) != 600 {
		t.Fatalf("layout state=%d size=%d", state, len(f.raw))
	}
	fetcher := &ciFetcher{resources: f.tiles()}
	verified, err := VerifyStreamBundle(context.Background(), encodeBundle(t, f.bundle(t, state)), f.trust(fetcher))
	if err != nil {
		t.Fatal(err)
	}
	if len(verified.Events) != 2 {
		t.Fatalf("events = %d", len(verified.Events))
	}
	for _, want := range []string{"/tile/entries/001", "/tile/entries/002.p/88", "/tile/1/000.p/2"} {
		if !strings.Contains(strings.Join(fetcher.reads, " "), want) {
			t.Errorf("tail scan did not read %s; reads %v", want, fetcher.reads)
		}
	}
	if strings.Contains(strings.Join(fetcher.reads, " "), "/tile/entries/000") {
		t.Errorf("tail scan read entries before input-size: %v", fetcher.reads)
	}
}

func TestCommittedIndexBundle_RejectsOmittedIndexedEvent(t *testing.T) {
	f, state := indexedFixture(t)
	object := f.bundle(t, state)
	events := object["events"].([]any)
	object["events"] = events[:1]
	if _, err := f.verify(t, object); err == nil || !strings.Contains(err.Error(), "inclusion proof") {
		t.Fatalf("omitted indexed event accepted: %v", err)
	}
	// Dropping every event turns the claim into non-inclusion, which the
	// inclusion-shaped proof cannot satisfy.
	object["events"] = []any{}
	if _, err := f.verify(t, object); err == nil || !strings.Contains(err.Error(), "non-inclusion proof") {
		t.Fatalf("bundle claiming non-inclusion for an indexed key accepted: %v", err)
	}
}

func TestCommittedIndexBundle_RejectsTamperedStateEntry(t *testing.T) {
	f, state := indexedFixture(t)
	object := f.bundle(t, state)
	parsed, _ := tlogindex.ParseStateEntry(f.raw[state])
	tampered := parsed
	tampered.MPTRoot[0] ^= 1
	object["index_state"].(map[string]any)["entry"] = base64.RawURLEncoding.EncodeToString(tampered.Marshal())
	if _, err := f.verify(t, object); err == nil || !strings.Contains(err.Error(), "state entry inclusion") {
		t.Fatalf("tampered state entry accepted: %v", err)
	}
	// A state proven at a different index than claimed is also rejected.
	object = f.bundle(t, state)
	object["index_state"].(map[string]any)["index"] = state - 1
	if _, err := f.verify(t, object); err == nil {
		t.Fatal("state entry index mismatch accepted")
	}
}

func TestCommittedIndexBundle_RejectsStateCoveringItself(t *testing.T) {
	f := newCommittedIndexFixture(t)
	f.addNoise(1)
	f.add(f.issuance)
	f.add(f.rotation)
	// A state at index 3 claiming input-size 4 would cover its own index.
	trie, err := f.replay(t, 3).Trie()
	if err != nil {
		t.Fatal(err)
	}
	state := f.addStateEntry(tlogindex.StateEntry{InputSize: 4, InputRoot: tlogindex.Hash(merkleRoot(f.raw[:3])), MPTRoot: trie.Root()})
	if _, err := f.verify(t, f.bundleFor(t, state, f.replay(t, 3))); err == nil || !strings.Contains(err.Error(), "exceeds state entry index") {
		t.Fatalf("input-size beyond the state entry accepted: %v", err)
	}
}

func TestCommittedIndexBundle_RejectsIndexedEventAtOrAfterInputSize(t *testing.T) {
	// A dishonest indexer commits index 3 for the key while claiming
	// input-size 2. The MPT proof verifies; the bound check must refuse it.
	f := newCommittedIndexFixture(t)
	f.addNoise(1)
	f.add(f.issuance)
	f.addNoise(1)
	f.add(f.rotation)
	lying := f.replay(t, 4)
	trie, err := lying.Trie()
	if err != nil {
		t.Fatal(err)
	}
	state := f.addStateEntry(tlogindex.StateEntry{InputSize: 2, InputRoot: tlogindex.Hash(merkleRoot(f.raw[:2])), MPTRoot: trie.Root()})
	if _, err := f.verify(t, f.bundleFor(t, state, lying)); err == nil || !strings.Contains(err.Error(), "not below input-size") {
		t.Fatalf("indexed event at or after input-size accepted: %v", err)
	}
}

func TestCommittedIndexBundle_RejectsIndexedEntryThatDoesNotMapToTheKey(t *testing.T) {
	// A dishonest indexer lists the noise entry 0 under the key. Its value
	// log and MPT proof verify, but entry 0 maps to no key.
	f := newCommittedIndexFixture(t)
	f.addNoise(1)
	f.add(f.issuance)
	lying := tlogindex.NewReplayer(func(entry []byte) (string, bool, error) {
		if bytes.HasPrefix(entry, []byte(`{"n":`)) {
			return ciFQDN, true, nil
		}
		return IndexKey(entry, f.log)
	})
	for _, entry := range f.raw {
		if err := lying.Append(entry); err != nil {
			t.Fatal(err)
		}
	}
	trie, _ := lying.Trie()
	state := f.addStateEntry(tlogindex.StateEntry{InputSize: 2, InputRoot: tlogindex.Hash(merkleRoot(f.raw[:2])), MPTRoot: trie.Root()})
	if _, err := f.verify(t, f.bundleFor(t, state, lying)); err == nil || !strings.Contains(err.Error(), "does not map to the bundle fqdn") {
		t.Fatalf("indexed entry for another key accepted: %v", err)
	}
}

func TestCommittedIndexBundle_RejectsTamperedEventAndCheckpoint(t *testing.T) {
	f, state := indexedFixture(t)
	object := f.bundle(t, state)
	event := object["events"].([]any)[1].(map[string]any)
	event["entry"] = base64.RawURLEncoding.EncodeToString(append(append([]byte(nil), f.rotation...), ' '))
	if _, err := f.verify(t, object); err == nil {
		t.Fatal("tampered event accepted")
	}
	// A valid entry with a wrong inclusion proof fails at the event check,
	// before replay could skip it as noise.
	object = f.bundle(t, state)
	event = object["events"].([]any)[0].(map[string]any)
	event["proof"] = f.proofHashes(t, f.checkpoint(), 2)
	if _, err := f.verify(t, object); err == nil || !strings.Contains(err.Error(), "committed-index event inclusion") {
		t.Fatalf("event with a wrong inclusion proof accepted: %v", err)
	}
	object = f.bundle(t, state)
	checkpoint, _ := base64.RawURLEncoding.DecodeString(object["checkpoint"].(string))
	object["checkpoint"] = base64.RawURLEncoding.EncodeToString(bytes.Replace(checkpoint, []byte("log.example\n7\n"), []byte("log.example\n8\n"), 1))
	if _, err := f.verify(t, object); err == nil {
		t.Fatal("checkpoint with a broken signature accepted")
	}
}

func TestCommittedIndexBundle_RejectsTamperedTail(t *testing.T) {
	f := newCommittedIndexFixture(t)
	f.add(f.issuance)
	state := f.addState(t, 1)
	f.add(f.rotation)
	object := f.bundle(t, state)
	resources := f.tiles()
	// Serve an entry bundle whose tail entry differs from the logged one:
	// the authenticated leaf hashes must catch it.
	bundlePath := "/tile/entries/000.p/3"
	resources[bundlePath] = bytes.Replace(resources[bundlePath], f.rotation, append(f.rotation[:len(f.rotation)-1:len(f.rotation)-1], ' '), 1)
	if _, err := VerifyStreamBundle(context.Background(), encodeBundle(t, object), f.trust(&ciFetcher{resources: resources})); err == nil || !strings.Contains(err.Error(), "authenticated leaf hash") {
		t.Fatalf("tampered tail entry accepted: %v", err)
	}
	// And a level-zero tile that disagrees with the checkpoint root.
	resources = f.tiles()
	resources["/tile/0/000.p/3"][0] ^= 1
	if _, err := VerifyStreamBundle(context.Background(), encodeBundle(t, object), f.trust(&ciFetcher{resources: resources})); err == nil {
		t.Fatal("hash tile contradicting the checkpoint accepted")
	}
}

func TestCommittedIndexBundle_RejectsTailOverLimitAndMissingFetcher(t *testing.T) {
	f := newCommittedIndexFixture(t)
	f.add(f.issuance)
	state := f.addState(t, 1)
	f.addNoise(5)
	data := encodeBundle(t, f.bundle(t, state))
	trust := f.trust(&ciFetcher{resources: f.tiles()})
	trust.CommittedIndex.MaxTailEntries = 5
	if _, err := VerifyStreamBundle(context.Background(), data, trust); err == nil || !strings.Contains(err.Error(), "exceeds limit") {
		t.Fatalf("tail over limit accepted: %v", err)
	}
	trust.CommittedIndex = &CommittedIndexTrust{}
	if _, err := VerifyStreamBundle(context.Background(), data, trust); err == nil {
		t.Fatal("committed-index bundle verified without a tail fetcher")
	}
}

func TestCommittedIndexBundle_RejectsShapeViolations(t *testing.T) {
	f, state := indexedFixture(t)
	cases := map[string]func(map[string]any){
		"signature present":     func(o map[string]any) { o["sig"] = map[string]any{"alg": "EdDSA", "kid": "x", "value": "AA"} },
		"missing index_proof":   func(o map[string]any) { delete(o, "index_proof") },
		"extra state field":     func(o map[string]any) { o["index_state"].(map[string]any)["extra"] = 1 },
		"trusted-index mode":    func(o map[string]any) { o["completeness_mode"] = StreamBundleTrustedIndex },
		"padded base64 proof":   func(o map[string]any) { o["index_proof"] = o["index_proof"].(string) + "=" },
		"wrong complete size":   func(o map[string]any) { o["complete_through_size"] = len(f.raw) - 1 },
		"wrong policy hash":     func(o map[string]any) { o["policy_hash"] = base64.RawURLEncoding.EncodeToString(make([]byte, 32)) },
		"lifetime beyond limit": func(o map[string]any) { o["expires"] = f.vector.Trust.Now + 100000 },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			object := f.bundle(t, state)
			mutate(object)
			if _, err := f.verify(t, object); err == nil {
				t.Fatal("accepted")
			}
		})
	}
	data := encodeBundle(t, f.bundle(t, state))
	if _, err := VerifyStreamBundle(context.Background(), append([]byte(" "), data...), f.trust(&ciFetcher{resources: f.tiles()})); err == nil {
		t.Fatal("non-canonical JSON accepted")
	}
	for _, fqdn := range []string{"Agent.Example.com", "agent.example.com."} {
		object := f.bundle(t, state)
		object["fqdn"] = fqdn
		if _, err := f.verify(t, object); err == nil || !strings.Contains(err.Error(), "normalized FQDN") {
			t.Fatalf("fqdn %q: %v", fqdn, err)
		}
	}
}

func TestCommittedIndexBundle_RequiresOptIn(t *testing.T) {
	f, state := indexedFixture(t)
	data := encodeBundle(t, f.bundle(t, state))
	trust := f.trust(&ciFetcher{resources: f.tiles()})
	trust.CommittedIndex = nil
	verifier, err := note.NewVerifier(f.vector.Trust.BundleVerifierKey)
	if err != nil {
		t.Fatal(err)
	}
	trust.BundleVerifier = verifier
	if _, err := VerifyStreamBundle(context.Background(), data, trust); err == nil || !strings.Contains(err.Error(), "unknown or missing fields") {
		t.Fatalf("v2 bundle accepted without opt-in: %v", err)
	}
}

func TestCommittedIndexBundle_OptInKeepsVersion1Behavior(t *testing.T) {
	f := newCommittedIndexFixture(t)
	verifier, err := note.NewVerifier(f.vector.Trust.BundleVerifierKey)
	if err != nil {
		t.Fatal(err)
	}
	trust := f.trust(&ciFetcher{})
	trust.BundleVerifier = verifier
	verified, err := VerifyStreamBundle(context.Background(), []byte(f.vector.Bundle), trust)
	if err != nil || verified.CompletenessMode != StreamBundleTrustedIndex || verified.SignerKeyID == "" || verified.Source.GlobalCandidates() {
		t.Fatalf("v1 bundle with opt-in: %+v, %v", verified, err)
	}
}

func TestIndexKey_MatchesScanCandidateSelection(t *testing.T) {
	f := newCommittedIndexFixture(t)
	fqdns := []string{"agent.example.com", "AGENT.Example.COM", "K.example", "k.example", "ſs.example", "straße.example", "İ.example", "a b.example", "agent.example.com."}
	domains := []string{"agent.example.com", "k.example", "ss.example", "strasse.example", "i.example", "a b.example", "agent.example.com."}
	for _, fqdn := range fqdns {
		entry := canonicalEntryMutation(t, string(f.issuance), func(p map[string]any) { p["fqdn"] = fqdn })
		key, ok, err := IndexKey(entry, f.log)
		if err != nil {
			t.Fatal(err)
		}
		for _, domain := range domains {
			candidate, err := candidateFQDN(entry, domain)
			if err != nil {
				t.Fatal(err)
			}
			indexed := ok && key == domain
			// "a b.example" is a scan candidate but not a canonical key; the
			// index cannot hold it, and no normalized FQDN contains a space.
			if domain == "a b.example" {
				if indexed {
					t.Fatalf("non-canonical key %q indexed", key)
				}
				continue
			}
			if candidate != indexed {
				t.Errorf("fqdn %q domain %q: scan candidate %v, index key %q ok=%v", fqdn, domain, candidate, key, ok)
			}
		}
	}
}

func TestIndexKey_StreamReferenceRules(t *testing.T) {
	f := newCommittedIndexFixture(t)
	key, ok, err := IndexKey(f.issuance, f.log)
	if err != nil || !ok || key != ciFQDN {
		t.Fatalf("IndexKey(issuance) = %q %v %v", key, ok, err)
	}
	otherStream := "c2sp-tlog:public:https://log.example#IiIiIiIiIiIiIiIiIiIiIg"
	cases := map[string][]byte{
		"state entry":        tlogindex.StateEntry{InputSize: 1}.Marshal(),
		"not json":           []byte("hello"),
		"no fqdn":            []byte(`{"n":1}`),
		"other log prefix":   canonicalEntryMutation(t, string(f.issuance), func(p map[string]any) { p["lr"] = "c2sp-tlog:public:https://other.example#EREREREREREREREREREREQ" }),
		"other scope":        canonicalEntryMutation(t, string(f.issuance), func(p map[string]any) { p["lr"] = "c2sp-tlog:testnet:https://log.example#EREREREREREREREREREREQ" }),
		"stream id mismatch": canonicalEntryMutation(t, string(f.issuance), func(p map[string]any) { p["lr"] = otherStream }),
		"wrong method":       canonicalEntryMutation(t, string(f.issuance), func(p map[string]any) { p["method"] = "other" }),
		"wrong log origin":   canonicalEntryMutation(t, string(f.issuance), func(p map[string]any) { p["log_origin"] = "other.example" }),
		"unparseable lr":     canonicalEntryMutation(t, string(f.issuance), func(p map[string]any) { p["lr"] = "nonsense" }),
	}
	for name, entry := range cases {
		if key, ok, err := IndexKey(entry, f.log); ok || err != nil {
			t.Errorf("%s: IndexKey = %q %v %v", name, key, ok, err)
		}
	}
	// Another stream for the same FQDN on this log is still indexed: the
	// Client, not the index, selects the stream.
	sibling := canonicalEntryMutation(t, string(f.issuance), func(p map[string]any) {
		p["lr"] = otherStream
		p["stream_id"] = "IiIiIiIiIiIiIiIiIiIiIg"
	})
	if key, ok, err := IndexKey(sibling, f.log); !ok || err != nil || key != ciFQDN {
		t.Fatalf("sibling stream: %q %v %v", key, ok, err)
	}
	nested := []byte(`{"fqdn":"a.example","x":` + strings.Repeat("[", 200) + strings.Repeat("]", 200) + `}`)
	if _, _, err := IndexKey(nested, f.log); err == nil {
		t.Fatal("nesting-limit entry did not fail like the raw scanner")
	}
}

func TestAuditIndexState(t *testing.T) {
	f, stateIndex := indexedFixture(t)
	state, err := tlogindex.ParseStateEntry(f.raw[stateIndex])
	if err != nil {
		t.Fatal(err)
	}
	if err := AuditIndexState(f.raw, state, f.log); err != nil {
		t.Fatal(err)
	}
	root, err := ReplayIndex(f.raw[:state.InputSize], f.log)
	if err != nil || root != state.MPTRoot {
		t.Fatalf("ReplayIndex = %x, %v", root, err)
	}
	// A committed root that omits the rotation is caught by the audit even
	// though a bundle against it would verify.
	omitting := tlogindex.NewReplayer(func(entry []byte) (string, bool, error) {
		if bytes.Equal(entry, f.rotation) {
			return "", false, nil
		}
		return IndexKey(entry, f.log)
	})
	for _, entry := range f.raw[:state.InputSize] {
		_ = omitting.Append(entry)
	}
	trie, _ := omitting.Trie()
	lying := state
	lying.MPTRoot = trie.Root()
	if err := AuditIndexState(f.raw, lying, f.log); err == nil || !strings.Contains(err.Error(), "mpt-root") {
		t.Fatalf("audit accepted a root that omits an entry: %v", err)
	}
	wrongInput := state
	wrongInput.InputRoot[0] ^= 1
	if err := AuditIndexState(f.raw, wrongInput, f.log); err == nil || !strings.Contains(err.Error(), "input-root") {
		t.Fatalf("audit accepted a wrong input root: %v", err)
	}
	if err := AuditIndexState(f.raw[:2], state, f.log); err == nil {
		t.Fatal("audit accepted too few entries")
	}
}

func TestFetchedStreamBundleSource_RequestsCommittedIndexBundle(t *testing.T) {
	f, state := indexedFixture(t)
	resources := f.tiles()
	resources["/streams/"+ciFQDN+"?format=bundle&v=2"] = encodeBundle(t, f.bundle(t, state))
	fetcher := &ciFetcher{resources: resources}
	trust := f.trust(fetcher)
	source := &fetchedStreamBundleSource{fetcher: fetcher, fallback: failingSource{}, committedIndex: true, trust: trust}
	entries, err := source.RebuildHistory(context.Background(), f.ref, ciFQDN)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 || fetcher.reads[0] != "/streams/"+ciFQDN+"?format=bundle&v=2" {
		t.Fatalf("entries %d, reads %v", len(entries), fetcher.reads)
	}
	// A 404 for the v2 bundle falls back exactly as for version 1.
	fallback := &countingSource{}
	source = &fetchedStreamBundleSource{fetcher: &ciFetcher{resources: map[string][]byte{}}, fallback: fallback, committedIndex: true, trust: trust}
	if _, err := source.RebuildHistory(context.Background(), f.ref, ciFQDN); err != nil || fallback.rebuilds != 1 {
		t.Fatalf("fallback rebuilds=%d err=%v", fallback.rebuilds, err)
	}
	source.requireBundle = true
	if _, err := source.RebuildHistory(context.Background(), f.ref, ciFQDN); err == nil {
		t.Fatal("required bundle fell back")
	}
}

func TestNewVerificationRegistry_CommittedIndexOptIn(t *testing.T) {
	f := newCommittedIndexFixture(t)
	base := VerificationRegistryConfig{PolicyDocument: []byte(f.vector.Policy), ResourceFetcher: &ciFetcher{}, CommittedIndexBundles: true}
	if _, err := NewVerificationRegistry(context.Background(), base); err == nil {
		t.Fatal("committed-index bundles accepted without a maximum lifetime")
	}
	base.MaxBundleLifetime = time.Minute
	base.RequireStreamBundle = true
	if _, err := NewVerificationRegistry(context.Background(), base); err != nil {
		t.Fatalf("committed-index registry without bundle verifiers: %v", err)
	}
	if _, err := NewVerificationRegistry(context.Background(), VerificationRegistryConfig{PolicyDocument: []byte(f.vector.Policy), ResourceFetcher: &ciFetcher{}, RequireStreamBundle: true}); err == nil {
		t.Fatal("required bundles accepted with neither verifiers nor committed-index opt-in")
	}
}
