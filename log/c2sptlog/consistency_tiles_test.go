package c2sptlog

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	dnsid "github.com/dnsid-ai/dnsid-go"
	"github.com/transparency-dev/merkle/proof"
	"github.com/transparency-dev/merkle/rfc6962"
	"golang.org/x/mod/sumdb/note"
	"golang.org/x/mod/sumdb/tlog"
)

// tileLog is an in-memory C2SP hash-tile server for a log of raw entries.
type tileLog struct {
	stored []tlog.Hash
	size   int64
}

func newTileLog(t *testing.T, entries [][]byte) *tileLog {
	t.Helper()
	l := &tileLog{}
	for i, entry := range entries {
		hashes, err := tlog.StoredHashes(int64(i), entry, l)
		if err != nil {
			t.Fatal(err)
		}
		l.stored = append(l.stored, hashes...)
	}
	l.size = int64(len(entries))
	return l
}

func syntheticEntries(n int) [][]byte {
	entries := make([][]byte, n)
	for i := range entries {
		entries[i] = []byte("entry-" + strconv.Itoa(i))
	}
	return entries
}

func (l *tileLog) ReadHashes(indexes []int64) ([]tlog.Hash, error) {
	out := make([]tlog.Hash, len(indexes))
	for i, index := range indexes {
		if index >= int64(len(l.stored)) {
			return nil, fmt.Errorf("hash index %d not stored", index)
		}
		out[i] = l.stored[index]
	}
	return out, nil
}

func (l *tileLog) root(t *testing.T, n int64) []byte {
	t.Helper()
	hash, err := tlog.TreeHash(n, l)
	if err != nil {
		t.Fatal(err)
	}
	return hash[:]
}

// resources serves every hash tile a log of size n publishes, in C2SP paths
// relative to the log prefix.
func (l *tileLog) resources(t *testing.T, n int64) map[string][]byte {
	t.Helper()
	resources := make(map[string][]byte)
	for _, tile := range tlog.NewTiles(c2spTileHeight, 0, n) {
		data, err := tlog.ReadTileData(tile, l)
		if err != nil {
			t.Fatal(err)
		}
		path := "/tile/" + strconv.Itoa(tile.L) + "/" + tileNumber(uint64(tile.N))
		if tile.W < 1<<c2spTileHeight {
			path += ".p/" + strconv.Itoa(tile.W)
		}
		resources[path] = data
	}
	return resources
}

const tileTestPrefix = "https://log.example/log"

type countingTileFetcher struct {
	mu        sync.Mutex
	resources map[string][]byte
	requests  []string
	// missingStatus is the HTTP status for a missing object; zero means 404.
	missingStatus int
}

func (f *countingTileFetcher) FetchBounded(_ context.Context, rawURL string, maximum int64) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.requests = append(f.requests, rawURL)
	data, ok := f.resources[strings.TrimPrefix(rawURL, tileTestPrefix)]
	if !ok {
		status := f.missingStatus
		if status == 0 {
			status = http.StatusNotFound
		}
		return nil, &ResourceFetchError{Kind: ResourceFetchHTTPStatus, URL: rawURL, HTTPStatus: status}
	}
	if int64(len(data)) > maximum {
		return nil, &ResourceFetchError{Kind: ResourceFetchResponseLimit, URL: rawURL, MaximumBytes: maximum}
	}
	return append([]byte(nil), data...), nil
}

func (*countingTileFetcher) SecurityGuarantees() ResourceFetchGuarantees {
	return ResourceFetchGuarantees{}
}

func tileTestSource(t *testing.T, fetcher BoundedResourceFetcher) (*ScanSource, Reference) {
	t.Helper()
	policy, _ := scanFixture(t, [][]byte{[]byte("x")})
	source, err := NewScanSource(policy, ScanSourceConfig{ResourceFetcher: fetcher})
	if err != nil {
		t.Fatal(err)
	}
	reference, err := ParseReference("c2sp-tlog:testnet:" + tileTestPrefix + "#identity-01")
	if err != nil {
		t.Fatal(err)
	}
	return source, reference
}

func tileCheckpoint(size int64, root []byte) TrustedC2spCheckpoint {
	return TrustedC2spCheckpoint{Origin: "log.example/log", TreeSize: uint64(size), RootHash: root, WitnessTime: time.Unix(1, 0)}
}

func TestScanSourceProvesConsistencyFromHashTilesWithoutEntryBundles(t *testing.T) {
	// Three tile levels: 256^2 < 70000 entries.
	const size = 70_000
	log := newTileLog(t, syntheticEntries(size))
	for _, old := range []int64{1, 2, 255, 256, 257, 65_535, 65_536, 69_999} {
		for _, next := range []int64{old + 1, size} {
			if next > size || next <= old {
				continue
			}
			t.Run(fmt.Sprintf("%d-%d", old, next), func(t *testing.T) {
				fetcher := &countingTileFetcher{resources: log.resources(t, next)}
				source, reference := tileTestSource(t, fetcher)
				hashes, err := source.proveCheckpointConsistency(context.Background(), reference, tileCheckpoint(old, log.root(t, old)), tileCheckpoint(next, log.root(t, next)))
				if err != nil {
					t.Fatalf("proveCheckpointConsistency: %v", err)
				}
				if err := proof.VerifyConsistency(rfc6962.DefaultHasher, uint64(old), uint64(next), hashes, log.root(t, old), log.root(t, next)); err != nil {
					t.Fatalf("VerifyConsistency: %v", err)
				}
				// O(log N): a bounded handful of hash tiles, never entry bundles.
				if len(fetcher.requests) > 12 {
					t.Fatalf("fetched %d tiles, want <= 12: %v", len(fetcher.requests), fetcher.requests)
				}
				for _, request := range fetcher.requests {
					if strings.Contains(request, "/tile/entries/") {
						t.Fatalf("consistency proof fetched entry bundle %s", request)
					}
				}
			})
		}
	}
}

func TestScanSourceConsistencyReadsCurrentTileWhenPartialIsGone(t *testing.T) {
	log := newTileLog(t, syntheticEntries(1024))
	const old, next = 100, 600
	// The log has grown and deleted its partial tiles for size 600
	// (0/002.p/88 and 1/000.p/2): at 700 they are wider partials, at 1024
	// level zero is full and level one is 1/000.p/4. Object stores without
	// list permission answer 403 for the deleted partial, so cover both.
	for _, missingStatus := range []int{http.StatusNotFound, http.StatusForbidden} {
		for _, current := range []int64{700, 1024} {
			t.Run(fmt.Sprintf("%d-%d", missingStatus, current), func(t *testing.T) {
				resources := log.resources(t, current)
				resources["/checkpoint"] = []byte("log.example/log\n" + strconv.FormatInt(current, 10) + "\nAAAA\n")
				source, reference := tileTestSource(t, &countingTileFetcher{resources: resources, missingStatus: missingStatus})
				hashes, err := source.proveCheckpointConsistency(context.Background(), reference, tileCheckpoint(old, log.root(t, old)), tileCheckpoint(next, log.root(t, next)))
				if err != nil {
					t.Fatalf("proveCheckpointConsistency: %v", err)
				}
				if err := proof.VerifyConsistency(rfc6962.DefaultHasher, old, next, hashes, log.root(t, old), log.root(t, next)); err != nil {
					t.Fatalf("VerifyConsistency: %v", err)
				}
			})
		}
	}
}

func TestScanSourceConsistencyRejectsCurrentLogNarrowerThanCandidate(t *testing.T) {
	log := newTileLog(t, syntheticEntries(600))
	resources := log.resources(t, 500)
	resources["/checkpoint"] = []byte("log.example/log\n500\nAAAA\n")
	source, reference := tileTestSource(t, &countingTileFetcher{resources: resources})
	_, err := source.proveCheckpointConsistency(context.Background(), reference, tileCheckpoint(100, log.root(t, 100)), tileCheckpoint(600, log.root(t, 600)))
	if err == nil || !strings.Contains(err.Error(), "missing from current log") {
		t.Fatalf("error = %v, want missing tile", err)
	}
	checkpointCode(t, err, dnsid.VerificationCodeInvalidEvidence, true)
}

func TestScanSourceConsistencyRejectsTilesThatDoNotMatchCandidateRoot(t *testing.T) {
	log := newTileLog(t, syntheticEntries(600))
	resources := log.resources(t, 600)
	resources["/tile/0/001"][5] ^= 0xff
	source, reference := tileTestSource(t, &countingTileFetcher{resources: resources})
	_, err := source.proveCheckpointConsistency(context.Background(), reference, tileCheckpoint(300, log.root(t, 300)), tileCheckpoint(600, log.root(t, 600)))
	if !errors.Is(err, errHashTilesInconsistent) {
		t.Fatalf("error = %v, want hash tiles inconsistent", err)
	}
	checkpointCode(t, err, dnsid.VerificationCodeInvalidEvidence, false)
}

func TestScanSourceConsistencyPreservesFetchFailures(t *testing.T) {
	log := newTileLog(t, syntheticEntries(600))
	resources := log.resources(t, 600)
	delete(resources, "/tile/0/001")
	source, reference := tileTestSource(t, &countingTileFetcher{resources: resources})
	_, err := source.proveCheckpointConsistency(context.Background(), reference, tileCheckpoint(300, log.root(t, 300)), tileCheckpoint(600, log.root(t, 600)))
	var fetchErr *ResourceFetchError
	if !errors.As(err, &fetchErr) || fetchErr.HTTPStatus != http.StatusNotFound || errors.Is(err, errHashTilesInconsistent) {
		t.Fatalf("error = %v, want preserved 404 fetch failure", err)
	}
}

func TestScanSourceConsistencyRejectsCandidateAboveTreeLimit(t *testing.T) {
	source, reference := tileTestSource(t, &countingTileFetcher{})
	source.maxTreeSize = 10
	_, err := source.proveCheckpointConsistency(context.Background(), reference, tileCheckpoint(1, make([]byte, 32)), tileCheckpoint(11, make([]byte, 32)))
	checkpointCode(t, err, dnsid.VerificationCodeInvalidEvidence, false)
}

// The bundle path advances the trusted checkpoint from hash tiles alone, in
// both prefer-bundle and require-bundle mode, rejects a contradicting trusted
// root, and never falls back to a raw scan when the hash-tile proof fails.
func TestFetchedStreamBundleSourceAdvancesCheckpointWithHashTiles(t *testing.T) {
	vector := loadStreamBundleVector(t)
	verifier, err := note.NewVerifier(vector.Trust.BundleVerifierKey)
	if err != nil {
		t.Fatal(err)
	}
	trust := StreamBundleTrust{
		PolicyDocument:    []byte(vector.Policy),
		BundleVerifier:    verifier,
		Now:               func() time.Time { return time.Unix(vector.Trust.Now, 0).UTC() },
		MaxBundleLifetime: time.Duration(vector.Trust.MaxBundleLifetime) * time.Millisecond,
		MaxCheckpointAge:  time.Duration(vector.Trust.CheckpointFreshness) * time.Millisecond,
	}
	bundle, err := VerifyStreamBundle(context.Background(), []byte(vector.Bundle), trust)
	if err != nil {
		t.Fatal(err)
	}
	policy, err := ParsePolicy([]byte(vector.Policy))
	if err != nil {
		t.Fatal(err)
	}
	policy.Now = trust.Now
	policy.MaxCheckpointAge = trust.MaxCheckpointAge
	origin, err := bundle.Reference.Origin()
	if err != nil {
		t.Fatal(err)
	}
	raw := make([][]byte, len(bundle.Source.entries))
	for i, entry := range bundle.Source.entries {
		raw[i] = entry.Entry
	}
	if len(raw) < 2 {
		t.Fatalf("fixture has %d entries, need a growing tree", len(raw))
	}
	log := newTileLog(t, raw)

	type advanceCase struct {
		name          string
		requireBundle bool
		oldSize       uint64
		oldRoot       []byte
		tilesDown     bool
		wantCode      dnsid.VerificationCode
		wantTransient bool
		wantAdvanced  bool
	}
	var cases []advanceCase
	for _, requireBundle := range []bool{false, true} {
		mode := "prefer"
		if requireBundle {
			mode = "require"
		}
		cases = append(cases,
			advanceCase{name: mode + "/consistent", requireBundle: requireBundle, oldSize: 1, oldRoot: log.root(t, 1), wantAdvanced: true},
			advanceCase{name: mode + "/contradicting trusted root", requireBundle: requireBundle, oldSize: 1, oldRoot: make([]byte, 32), wantCode: dnsid.VerificationCodeLogInconsistent},
			advanceCase{name: mode + "/empty trusted tree with non-empty root", requireBundle: requireBundle, oldSize: 0, oldRoot: make([]byte, 32), wantCode: dnsid.VerificationCodeLogInconsistent},
			advanceCase{name: mode + "/hash tiles unavailable", requireBundle: requireBundle, oldSize: 1, oldRoot: log.root(t, 1), tilesDown: true, wantCode: dnsid.VerificationCodeLogError, wantTransient: true},
		)
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			store := NewMemoryTrustedC2spCheckpointStore()
			old := TrustedC2spCheckpoint{Origin: origin, TreeSize: test.oldSize, RootHash: test.oldRoot, WitnessTime: time.Unix(1, 0)}
			if swapped, err := store.CompareAndSwap(origin, nil, old); err != nil || !swapped {
				t.Fatalf("seed checkpoint = %v, %v", swapped, err)
			}
			tiles := log.resources(t, int64(len(raw)))
			var mu sync.Mutex
			var requests []string
			fetcher := &testBoundedFetcher{fetch: func(_ context.Context, rawURL string, _ int64) ([]byte, error) {
				mu.Lock()
				requests = append(requests, rawURL)
				mu.Unlock()
				if strings.Contains(rawURL, "/streams/") {
					return []byte(vector.Bundle), nil
				}
				if test.tilesDown && strings.Contains(rawURL, "/tile/") {
					return nil, &ResourceFetchError{Kind: ResourceFetchHTTPStatus, URL: rawURL, HTTPStatus: http.StatusServiceUnavailable, TransientFailure: true}
				}
				if data, ok := tiles[strings.TrimPrefix(rawURL, bundle.Reference.LogPrefix)]; ok {
					return append([]byte(nil), data...), nil
				}
				return nil, &ResourceFetchError{Kind: ResourceFetchHTTPStatus, URL: rawURL, HTTPStatus: http.StatusNotFound}
			}}
			scanner, err := NewScanSource(policy, ScanSourceConfig{ResourceFetcher: fetcher})
			if err != nil {
				t.Fatal(err)
			}
			source := &fetchedStreamBundleSource{fetcher: fetcher, fallback: scanner, trust: trust, requireBundle: test.requireBundle}
			client, err := New(bundle.Reference.String(), WithSource(source), WithPolicy(policy), WithTrustedCheckpointStore(store))
			if err != nil {
				t.Fatal(err)
			}
			_, err = client.RebuildHistory(context.Background(), bundle.FQDN)
			if test.wantAdvanced {
				if err != nil {
					t.Fatalf("RebuildHistory: %v", err)
				}
			} else {
				checkpointCode(t, err, test.wantCode, test.wantTransient)
			}
			trusted, err := store.Load(origin)
			if err != nil {
				t.Fatal(err)
			}
			wantSize := test.oldSize
			if test.wantAdvanced {
				wantSize = uint64(len(raw))
			}
			if trusted.TreeSize != wantSize {
				t.Fatalf("trusted size = %d, want %d", trusted.TreeSize, wantSize)
			}
			for _, request := range requests {
				if strings.Contains(request, "/tile/entries/") || strings.HasSuffix(request, "/checkpoint") {
					t.Fatalf("advance used raw scan request %s", request)
				}
			}
		})
	}
}
