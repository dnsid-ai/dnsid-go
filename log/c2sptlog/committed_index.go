package c2sptlog

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"sort"
	"time"
	"unicode"

	dnsid "github.com/dnsid-ai/dnsid-go"
	"github.com/dnsid-ai/dnsid-go/internal/jsonutil"
	dnsidlog "github.com/dnsid-ai/dnsid-go/log"
	"github.com/dnsid-ai/dnsid-go/log/c2sptlog/tlogindex"
	formatproof "github.com/transparency-dev/formats/proof"
	"golang.org/x/mod/sumdb/tlog"
)

const (
	// StreamBundleCommittedIndex is the completeness mode of a version 2
	// stream bundle. Completeness through the checkpoint comes from an index
	// state entry committed in the log itself plus a verifier-side scan of the
	// entries after it, not from a bundle signature.
	StreamBundleCommittedIndex = "committed-index"
	// StreamBundleCommittedIndexVersion is the bundle "v" value of a
	// committed-index bundle.
	StreamBundleCommittedIndexVersion = 2

	defaultMaxCommittedIndexTail = 4096
)

// IndexedLog names the log a committed index covers: the scope and log
// prefix that every stream reference (lr) on that log shares.
type IndexedLog struct {
	Scope     string
	LogPrefix string
}

// IndexKey is the mapping function of the committed index. It returns the
// canonical key an entry is indexed under, or ok=false when the entry maps to
// no key.
//
// An entry maps to key exactly when all of these hold:
//   - the raw-scan candidate selection ScanSource uses would select the entry
//     for the domain key: the entry is a canonical JSON object whose "fqdn"
//     equals key under Unicode case folding. For a lower-case ASCII key, such
//     as any normalized FQDN, that is the same as key being the fqdn with
//     every rune replaced by the lower-case ASCII member of its case-folding
//     orbit; an fqdn with a rune that has no ASCII member maps to no key;
//   - the entry's "lr" parses as a stream reference on log (same scope and
//     log prefix), and the entry meets the stream-reference rules a Client
//     reading that stream applies (method, log_origin, stream_id and lr);
//   - key is a valid tlog-vindex canonical key.
//
// Every entry a Client for a stream on log would accept for a normalized FQDN
// therefore maps to that FQDN; entries that map to a key but that a Client
// skips, such as malformed lifecycle events, are still indexed, because the
// Client, not the indexer, classifies them. Index state entries, and anything
// else that is not a canonical JSON object, map to no key. The only error is
// a JSON nesting-limit failure, which the raw scanner also treats as fatal.
func IndexKey(entry []byte, log IndexedLog) (key string, ok bool, err error) {
	fqdn, ok, err := candidateFQDNValue(entry)
	if err != nil || !ok {
		return "", false, err
	}
	key, ok = foldToASCIIKey(fqdn)
	if !ok || tlogindex.ValidKey(key) != nil {
		return "", false, nil
	}
	// candidateFQDNValue succeeded, so the payload decodes; read its lr.
	payload, err := payloadObjectFromEntry(entry)
	if err != nil {
		return "", false, nil
	}
	lr, _ := payload["lr"].(string)
	ref, err := ParseReference(lr)
	if err != nil || ref.Scope != log.Scope || ref.LogPrefix != log.LogPrefix {
		return "", false, nil
	}
	if err := validateEntryMetadataFor(ref, entry); err != nil {
		if errors.Is(err, jsonutil.ErrNestingLimit) {
			return "", false, err
		}
		return "", false, nil
	}
	return key, true, nil
}

// foldToASCIIKey maps each rune of s to the lower-case ASCII rune in its
// simple case-folding orbit, so that for any lower-case ASCII d,
// strings.EqualFold(s, d) holds exactly when the result equals d.
func foldToASCIIKey(s string) (string, bool) {
	out := make([]byte, 0, len(s))
	for _, r := range s {
		ascii := rune(-1)
		for f := r; ; {
			if f < unicode.MaxASCII+1 {
				ascii = f
				break
			}
			if f = unicode.SimpleFold(f); f == r {
				break
			}
		}
		if ascii < 0 {
			return "", false
		}
		if 'A' <= ascii && ascii <= 'Z' {
			ascii += 'a' - 'A'
		}
		out = append(out, byte(ascii))
	}
	return string(out), true
}

// IndexMapFunc returns IndexKey bound to log, for use with
// tlogindex.NewReplayer by an indexer or auditor.
func IndexMapFunc(log IndexedLog) tlogindex.MapFunc {
	return func(entry []byte) (string, bool, error) { return IndexKey(entry, log) }
}

// ReplayIndex recomputes the committed index over entries, which must be the
// log's entries [0, len(entries)), and returns the MPT root a state entry with
// input-size len(entries) must commit.
func ReplayIndex(entries [][]byte, log IndexedLog) (tlogindex.Hash, error) {
	return tlogindex.Replay(entries, IndexMapFunc(log))
}

// AuditIndexState checks a committed state entry against the log. entries
// must be the log's entries from index 0 through at least state.InputSize,
// authenticated by the caller (for example with ScanSource.FetchEntriesThrough).
// It fails if the log's RFC 6962 root at InputSize is not state.InputRoot or
// if replaying [0, InputSize) through IndexKey does not give state.MPTRoot. A
// failure on authenticated entries is permanent public evidence that the
// indexer committed a wrong root.
func AuditIndexState(entries [][]byte, state tlogindex.StateEntry, log IndexedLog) error {
	if uint64(len(entries)) < state.InputSize {
		return fmt.Errorf("dnsid: index audit needs %d entries, have %d", state.InputSize, len(entries))
	}
	prefix := entries[:state.InputSize]
	if !bytes.Equal(merkleRoot(prefix), state.InputRoot[:]) {
		return fmt.Errorf("dnsid: index state input-root does not match the log at size %d", state.InputSize)
	}
	root, err := ReplayIndex(prefix, log)
	if err != nil {
		return err
	}
	if root != state.MPTRoot {
		return fmt.Errorf("dnsid: index state mpt-root does not match the replayed index at size %d", state.InputSize)
	}
	return nil
}

// CommittedIndexTrust opts a verifier in to version 2 committed-index stream
// bundles. VerifyStreamBundle accepts them only when StreamBundleTrust
// carries a non-nil CommittedIndexTrust.
type CommittedIndexTrust struct {
	// Fetcher reads the log's own entry bundles and hash tiles for the tail
	// scan of [input-size, checkpoint size). It is required.
	Fetcher BoundedResourceFetcher
	// MaxTailEntries bounds the tail scan. Zero uses 4096.
	MaxTailEntries uint64
	// MaxEntryBundleBytes bounds one entry bundle read. Zero uses the
	// scanner's fixed maximum.
	MaxEntryBundleBytes int64
}

// peekCommittedIndexBundle reports whether data decodes to a JSON object
// whose "v" is the committed-index bundle version.
func peekCommittedIndexBundle(data []byte) bool {
	object, err := decodeJSONObject(data)
	if err != nil {
		return false
	}
	version, err := bundleUint(object, "v")
	return err == nil && version == StreamBundleCommittedIndexVersion
}

// verifyCommittedIndexBundle verifies a version 2 bundle. In order, it checks:
//  1. the checkpoint and its witnesses, as version 1 does;
//  2. the inclusion of the index state entry at index_state.index;
//  3. that the state's input-size is at most that index;
//  4. the MPT proof for the bundle's fqdn against the state's mpt-root, an
//     inclusion proof of the value log over the events' indices when there
//     are events, otherwise a non-inclusion proof;
//  5. that every event index is below input-size (the value log root itself
//     is checked by step 4);
//  6. that every event has an inclusion proof under the same checkpoint and
//     maps to the bundle's fqdn under IndexKey;
//  7. a tail scan of [input-size, checkpoint size) through the log's entry
//     bundles and hash tiles, authenticated against the checkpoint, adding
//     every entry that maps to the fqdn.
//
// The combined entries are then replayed through full Client verification
// exactly as version 1 replays its events, and the bundle's state summary
// must match. There is no bundle signature to check.
func verifyCommittedIndexBundle(ctx context.Context, data []byte, trust StreamBundleTrust, maxBytes int) (*VerifiedStreamBundle, error) {
	if trust.CommittedIndex == nil || trust.CommittedIndex.Fetcher == nil {
		return nil, fmt.Errorf("dnsid: c2sp committed-index bundle requires a log fetcher for the tail scan")
	}
	object, err := decodeJSONObject(data)
	if err != nil {
		return nil, fmt.Errorf("dnsid: parsing c2sp stream bundle: %w", err)
	}
	if err := requireExactFields(object, "checkpoint", "complete_through_size", "completeness_mode", "events", "expires", "fqdn", "index_proof", "index_state", "lr", "policy_hash", "state", "type", "v"); err != nil {
		return nil, err
	}
	canonical, err := canonicalJSON(object)
	if err != nil || !bytes.Equal(canonical, data) {
		return nil, fmt.Errorf("dnsid: c2sp stream bundle is not canonical JCS")
	}
	version, err := bundleUint(object, "v")
	if err != nil || version != StreamBundleCommittedIndexVersion {
		return nil, fmt.Errorf("dnsid: unsupported c2sp stream bundle version")
	}
	typeName, err := bundleString(object, "type")
	if err != nil || typeName != StreamBundleType {
		return nil, fmt.Errorf("dnsid: unsupported c2sp stream bundle type")
	}
	mode, err := bundleString(object, "completeness_mode")
	if err != nil || mode != StreamBundleCommittedIndex {
		return nil, fmt.Errorf("dnsid: unsupported c2sp stream bundle completeness mode")
	}
	fqdn, err := bundleString(object, "fqdn")
	if err != nil {
		return nil, err
	}
	// The index is keyed by the normalized FQDN, so only that form can be proven.
	if normalized, err := dnsid.NormalizeFQDN(fqdn); err != nil || normalized != fqdn || tlogindex.ValidKey(fqdn) != nil {
		return nil, fmt.Errorf("dnsid: c2sp committed-index bundle fqdn must be a normalized FQDN")
	}
	referenceText, err := bundleString(object, "lr")
	if err != nil {
		return nil, err
	}
	reference, err := ParseReference(referenceText)
	if err != nil {
		return nil, err
	}
	indexedLog := IndexedLog{Scope: reference.Scope, LogPrefix: reference.LogPrefix}

	now := time.Now()
	if trust.Now != nil {
		now = trust.Now()
	}
	expiresUnix, err := bundleUint(object, "expires")
	if err != nil {
		return nil, err
	}
	expires := time.Unix(int64(expiresUnix), 0).UTC()
	if !expires.After(now) {
		return nil, fmt.Errorf("dnsid: c2sp stream bundle expired")
	}
	if trust.MaxBundleLifetime <= 0 {
		return nil, fmt.Errorf("dnsid: c2sp stream bundle maximum lifetime is required")
	}
	policyHashText, err := bundleString(object, "policy_hash")
	if err != nil {
		return nil, err
	}
	policyHash, err := decodeBundleBase64("policy_hash", policyHashText, tlogindex.HashSize, tlogindex.HashSize)
	if err != nil {
		return nil, err
	}
	policy, err := bundlePolicy(trust, policyHash)
	if err != nil {
		return nil, err
	}
	checkpointText, err := bundleString(object, "checkpoint")
	if err != nil {
		return nil, err
	}
	checkpoint, err := decodeBundleBase64("checkpoint", checkpointText, 1, maxBytes)
	if err != nil {
		return nil, err
	}
	completeThrough, err := bundleUint(object, "complete_through_size")
	if err != nil {
		return nil, err
	}
	maxTreeSize := trust.MaxTreeSize
	if maxTreeSize == 0 {
		maxTreeSize = defaultScanMaxTreeSize
	}
	if completeThrough > maxTreeSize {
		return nil, fmt.Errorf("dnsid: c2sp stream bundle checkpoint exceeds configured tree-size maximum")
	}

	// 1. Checkpoint and witnesses.
	checkpointProof, err := policy.verifyCheckpoint(reference, checkpoint)
	if err != nil {
		return nil, err
	}
	treeSize := checkpointProof.Checkpoint.Size
	if completeThrough != treeSize {
		return nil, fmt.Errorf("dnsid: c2sp stream bundle complete_through_size does not match checkpoint")
	}

	// 2. State entry inclusion.
	stateObject, err := bundleObject(object, "index_state")
	if err != nil {
		return nil, err
	}
	if err := requireExactFields(stateObject, "entry", "index", "proof"); err != nil {
		return nil, err
	}
	stateEntry, err := parseBundleEntry(stateObject, "index_state", checkpoint)
	if err != nil {
		return nil, err
	}
	// The proof is bound to the bundle checkpoint and to index_state.index
	// by construction in parseBundleEntry.
	if _, err := policy.VerifyProof(reference, stateEntry.Entry, stateEntry.Proof); err != nil {
		return nil, fmt.Errorf("dnsid: c2sp committed-index state entry inclusion: %w", err)
	}
	state, err := tlogindex.ParseStateEntry(stateEntry.Entry)
	if err != nil {
		return nil, fmt.Errorf("dnsid: c2sp committed-index state entry: %w", err)
	}

	// 3. The state may only cover entries before itself.
	inputSize := state.InputSize
	if inputSize > stateEntry.Index {
		return nil, fmt.Errorf("dnsid: c2sp committed-index input-size %d exceeds state entry index %d", inputSize, stateEntry.Index)
	}

	// 4 and 5. MPT proof, value log root and index bounds.
	entries, err := parseBundleEntries(object["events"], checkpoint, trust.MaxEvents)
	if err != nil {
		return nil, err
	}
	proofText, err := bundleString(object, "index_proof")
	if err != nil {
		return nil, err
	}
	indexProof, err := decodeBundleBase64("index_proof", proofText, 0, maxBytes)
	if err != nil {
		return nil, err
	}
	if len(entries) == 0 {
		if err := tlogindex.VerifyNonInclusion(state.MPTRoot, fqdn, indexProof); err != nil {
			return nil, fmt.Errorf("dnsid: c2sp committed-index non-inclusion proof: %w", err)
		}
	} else {
		indices := make([]uint64, len(entries))
		for i, entry := range entries {
			indices[i] = entry.Index
		}
		valueRoot, err := tlogindex.ValueRoot(indices)
		if err != nil {
			return nil, err
		}
		if err := tlogindex.VerifyInclusion(state.MPTRoot, fqdn, valueRoot, indexProof); err != nil {
			return nil, fmt.Errorf("dnsid: c2sp committed-index inclusion proof: %w", err)
		}
		if last := indices[len(indices)-1]; last >= inputSize {
			return nil, fmt.Errorf("dnsid: c2sp committed-index event %d is not below input-size %d", last, inputSize)
		}
	}

	// 6. The indexed events are exactly the proven entries at those indices.
	for _, entry := range entries {
		if _, err := policy.VerifyProof(reference, entry.Entry, entry.Proof); err != nil {
			return nil, dnsid.NewVerificationError(dnsid.VerificationCodeInvalidEvidence, false, "dnsid: invalid c2sp committed-index event inclusion", err)
		}
		key, ok, err := IndexKey(entry.Entry, indexedLog)
		if err != nil || !ok || key != fqdn {
			return nil, fmt.Errorf("dnsid: c2sp committed-index entry %d does not map to the bundle fqdn", entry.Index)
		}
	}

	// 7. Tail scan.
	tail, err := scanCommittedIndexTail(ctx, *trust.CommittedIndex, reference, checkpoint, checkpointProof, inputSize, fqdn)
	if err != nil {
		return nil, err
	}
	entries = append(entries, tail...)
	sort.Slice(entries, func(i, j int) bool { return entries[i].Index < entries[j].Index })
	if len(entries) == 0 {
		return nil, fmt.Errorf("dnsid: c2sp stream bundle requires events")
	}
	maxEvents := trust.MaxEvents
	if maxEvents == 0 {
		maxEvents = defaultMaxStreamBundleEvents
	}
	if len(entries) > maxEvents {
		return nil, fmt.Errorf("dnsid: c2sp stream bundle event count exceeds limit")
	}

	source := &StreamBundleSource{reference: reference, domain: fqdn, entries: entries, globalCandidates: true}
	client, err := newBundleReplayClient(referenceText, source, policy, trust)
	if err != nil {
		return nil, err
	}
	events, err := client.RebuildHistory(ctx, fqdn)
	if err != nil {
		return nil, err
	}
	if expires.After(checkpointProof.CheckpointFreshnessTime.Add(trust.MaxBundleLifetime)) {
		return nil, fmt.Errorf("dnsid: c2sp stream bundle lifetime exceeds checkpoint-relative policy")
	}
	source.checkpoint = append([]byte(nil), checkpoint...)
	source.completeThrough = completeThrough
	source.completenessMode = mode
	source.checkpointFreshness = checkpointProof.CheckpointFreshnessTime
	snapshot, err := dnsidlog.NewDomainLog(fqdn, events).SnapshotAt(now)
	if err != nil {
		return nil, err
	}
	if err := verifyBundleState(object["state"], snapshot, events); err != nil {
		return nil, err
	}
	if err := finishBundleVerification(ctx, client, trust, checkpointProof, expires); err != nil {
		return nil, err
	}
	source.expires, source.now = expires, trust.Now
	return &VerifiedStreamBundle{
		Reference:           reference,
		FQDN:                fqdn,
		Events:              events,
		Snapshot:            snapshot,
		LoggedState:         snapshot.HistoricalState.String(),
		Expires:             expires,
		CompleteThroughSize: completeThrough,
		CompletenessMode:    mode,
		Source:              source,
	}, nil
}

// scanCommittedIndexTail authenticates the log's entries [from, checkpoint
// size) against the checkpoint root through its hash tiles and returns, with
// inclusion proofs, every entry that maps to fqdn.
func scanCommittedIndexTail(ctx context.Context, trust CommittedIndexTrust, reference Reference, checkpoint []byte, verified *VerifiedProof, from uint64, fqdn string) (result []ProvenEntry, err error) {
	ctx, cancel := dnsid.VerificationContext(ctx)
	defer cancel()
	defer func() {
		var classified *dnsid.VerificationError
		if err != nil && !errors.As(err, &classified) {
			err = dnsid.NewVerificationError(dnsid.VerificationCodeInvalidEvidence, false, "dnsid: invalid c2sp committed-index tail scan", err)
		}
	}()
	treeSize := verified.Checkpoint.Size
	if from >= treeSize {
		return nil, nil
	}
	maxTail := trust.MaxTailEntries
	if maxTail == 0 {
		maxTail = defaultMaxCommittedIndexTail
	}
	if treeSize-from > maxTail {
		return nil, fmt.Errorf("dnsid: c2sp committed-index tail of %d entries exceeds limit %d", treeSize-from, maxTail)
	}
	maxBundleBytes := trust.MaxEntryBundleBytes
	if maxBundleBytes == 0 {
		maxBundleBytes = defaultScanMaxBundleBytes
	}
	if maxBundleBytes < 1 || maxBundleBytes > defaultScanMaxBundleBytes {
		return nil, fmt.Errorf("dnsid: c2sp committed-index entry bundle byte limit must be in 1..%d", defaultScanMaxBundleBytes)
	}
	tree := tlog.Tree{N: int64(treeSize)}
	copy(tree.Hash[:], verified.Checkpoint.Hash)
	tiles := &checkpointTiles{fetcher: trust.Fetcher, ref: reference, size: treeSize, tiles: make(map[hashTileKey][]tlog.Hash)}
	hashes := tlog.TileHashReader(tree, &tileHashSource{ctx: ctx, tiles: tiles})
	log := IndexedLog{Scope: reference.Scope, LogPrefix: reference.LogPrefix}
	for bundle := from / entriesPerC2spBundle; bundle*entriesPerC2spBundle < treeSize; bundle++ {
		decoded, err := fetchEntryBundle(ctx, trust.Fetcher, reference.LogPrefix, bundle, treeSize, maxBundleBytes)
		if err != nil {
			return nil, err
		}
		first := max(from, bundle*entriesPerC2spBundle)
		last := bundle*entriesPerC2spBundle + uint64(len(decoded))
		indexes := make([]int64, 0, last-first)
		for index := first; index < last; index++ {
			indexes = append(indexes, tlog.StoredHashIndex(0, int64(index)))
		}
		leaves, err := hashes.ReadHashes(indexes)
		if err != nil {
			return nil, err
		}
		for i, index := 0, first; index < last; i, index = i+1, index+1 {
			entry := decoded[index-bundle*entriesPerC2spBundle]
			if tlog.RecordHash(entry) != leaves[i] {
				return nil, fmt.Errorf("dnsid: c2sp-tlog entry %d does not match its authenticated leaf hash", index)
			}
			key, ok, err := IndexKey(entry, log)
			if err != nil {
				return nil, err
			}
			if !ok || key != fqdn {
				continue
			}
			recordProof, err := tlog.ProveRecord(tree.N, int64(index), hashes)
			if err != nil {
				return nil, err
			}
			proofHashes := make([][tlog.HashSize]byte, len(recordProof))
			for j, hash := range recordProof {
				proofHashes[j] = [tlog.HashSize]byte(hash)
			}
			rawProof := formatproof.TLogProof{Index: index, Hashes: proofHashes, Checkpoint: checkpoint}.Marshal()
			result = append(result, ProvenEntry{Index: index, Entry: append([]byte(nil), entry...), Proof: rawProof})
		}
	}
	return result, nil
}

// tileHashSource adapts the C2SP hash-tile fetcher to tlog.TileReader. The
// returned TileHashReader authenticates every tile it reads against the tree.
type tileHashSource struct {
	ctx   context.Context
	tiles *checkpointTiles
}

func (*tileHashSource) Height() int { return 8 }

func (s *tileHashSource) ReadTiles(tiles []tlog.Tile) ([][]byte, error) {
	data := make([][]byte, len(tiles))
	for i, tile := range tiles {
		if tile.H != 8 || tile.L < 0 || tile.N < 0 {
			return nil, fmt.Errorf("dnsid: unexpected c2sp-tlog tile request %v", tile)
		}
		hashes, err := s.tiles.fetch(s.ctx, hashTileKey{level: uint(tile.L), index: uint64(tile.N)})
		if err != nil {
			return nil, err
		}
		if len(hashes) != tile.W {
			return nil, fmt.Errorf("dnsid: c2sp-tlog tile %d/%d width %d, want %d", tile.L, tile.N, len(hashes), tile.W)
		}
		buf := make([]byte, 0, tile.W*tlog.HashSize)
		for _, hash := range hashes {
			buf = append(buf, hash[:]...)
		}
		data[i] = buf
	}
	return data, nil
}

func (*tileHashSource) SaveTiles([]tlog.Tile, [][]byte) {}
