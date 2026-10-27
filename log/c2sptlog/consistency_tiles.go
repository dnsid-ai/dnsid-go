package c2sptlog

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"sync"

	dnsid "github.com/dnsid-ai/dnsid-go"
	"golang.org/x/mod/sumdb/tlog"
)

// c2spTileHeight is the fixed C2SP tlog-tiles hash tile height.
const c2spTileHeight = 8

// authenticatedConsistencySource proves that a trusted checkpoint is a prefix
// of a signed candidate checkpoint. Implementations authenticate every hash
// they read against the candidate root before building the proof, so a proof
// that then fails against the trusted root is evidence of inconsistency rather
// than of corrupt transport.
type authenticatedConsistencySource interface {
	proveCheckpointConsistency(ctx context.Context, reference Reference, old, next TrustedC2spCheckpoint) ([][]byte, error)
}

var _ authenticatedConsistencySource = (*ScanSource)(nil)

// errHashTilesInconsistent reports hash tiles that do not hash to the signed
// candidate root. It says nothing about the trusted checkpoint.
var errHashTilesInconsistent = errors.New("dnsid: c2sp-tlog hash tiles do not match candidate checkpoint")

// proveCheckpointConsistency builds an RFC 6962 consistency proof from the
// log's hash tiles. It reads O(log N) tiles, most of them full immutable tiles,
// instead of every entry bundle. Every tile is authenticated against
// next.RootHash, which the caller has already verified from a signed checkpoint.
func (s *ScanSource) proveCheckpointConsistency(ctx context.Context, reference Reference, old, next TrustedC2spCheckpoint) (hashes [][]byte, err error) {
	ctx, cancel := dnsid.VerificationContext(ctx)
	defer cancel()
	if s == nil || s.fetcher == nil {
		return nil, fmt.Errorf("dnsid: c2sp-tlog scan source is required")
	}
	if err := reference.Validate(); err != nil {
		return nil, err
	}
	if next.TreeSize > s.maxTreeSize {
		return nil, dnsid.NewVerificationError(dnsid.VerificationCodeInvalidEvidence, false, "dnsid: c2sp-tlog candidate checkpoint exceeds configured tree size", fmt.Errorf("tree size %d exceeds configured maximum %d", next.TreeSize, s.maxTreeSize))
	}
	if old.TreeSize >= next.TreeSize || next.TreeSize > uint64(1)<<62 || len(next.RootHash) != tlog.HashSize {
		return nil, dnsid.NewArgumentError("dnsid: c2sp-tlog consistency proof requires a larger candidate tree with a SHA-256 root", nil)
	}
	if old.TreeSize == 0 {
		return [][]byte{}, nil
	}
	var root tlog.Hash
	copy(root[:], next.RootHash)
	reader := &c2spTileReader{ctx: ctx, source: s, prefix: reference.LogPrefix}
	proof, err := tlog.ProveTree(int64(next.TreeSize), int64(old.TreeSize), tlog.TileHashReader(tlog.Tree{N: int64(next.TreeSize), Hash: root}, reader))
	if err != nil {
		if fetchErr := reader.err(); fetchErr != nil {
			return nil, fetchErr
		}
		return nil, dnsid.NewVerificationError(dnsid.VerificationCodeInvalidEvidence, false, errHashTilesInconsistent.Error(), errors.Join(errHashTilesInconsistent, err))
	}
	hashes = make([][]byte, len(proof))
	for i := range proof {
		hashes[i] = append([]byte(nil), proof[i][:]...)
	}
	return hashes, nil
}

// c2spTileReader adapts the C2SP tile layout, which omits the tile height from
// paths, to tlog.TileReader. Tile data is untrusted until TileHashReader
// authenticates it against the candidate tree root.
type c2spTileReader struct {
	ctx    context.Context
	source *ScanSource
	prefix string

	mu          sync.Mutex
	fetchErr    error
	currentSize uint64
}

func (r *c2spTileReader) Height() int { return c2spTileHeight }

func (r *c2spTileReader) ReadTiles(tiles []tlog.Tile) ([][]byte, error) {
	data := make([][]byte, len(tiles))
	errs := make([]error, len(tiles))
	var wg sync.WaitGroup
	for i, tile := range tiles {
		wg.Add(1)
		go func() {
			defer wg.Done()
			data[i], errs[i] = r.readTile(tile)
		}()
	}
	wg.Wait()
	for _, err := range errs {
		if err != nil {
			r.mu.Lock()
			if r.fetchErr == nil {
				r.fetchErr = err
			}
			r.mu.Unlock()
			return nil, err
		}
	}
	return data, nil
}

// SaveTiles is a no-op: callers cache tiles through their resource fetcher.
func (*c2spTileReader) SaveTiles([]tlog.Tile, [][]byte) {}

func (r *c2spTileReader) err() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.fetchErr
}

func (r *c2spTileReader) readTile(tile tlog.Tile) ([]byte, error) {
	if tile.H != c2spTileHeight || tile.L < 0 || tile.N < 0 || tile.W < 1 || tile.W > 1<<c2spTileHeight {
		return nil, fmt.Errorf("dnsid: unsupported c2sp-tlog hash tile %+v", tile)
	}
	full := r.prefix + "/tile/" + strconv.Itoa(tile.L) + "/" + tileNumber(uint64(tile.N))
	want := tile.W * tlog.HashSize
	if tile.W == 1<<c2spTileHeight {
		return r.fetchExact(full, want)
	}
	data, err := r.fetchExact(full+".p/"+strconv.Itoa(tile.W), want)
	var fetchErr *ResourceFetchError
	if err == nil || !errors.As(err, &fetchErr) || fetchErr.Kind != ResourceFetchHTTPStatus || fetchErr.HTTPStatus != http.StatusNotFound {
		return data, err
	}
	// C2SP tlog-tiles lets logs delete a partial tile once the log grows past
	// it. Any wider version of the same tile starts with the same hashes, so
	// read the tile at the log's current width and keep the prefix.
	current, err := r.currentWidth(tile)
	if err != nil {
		return nil, err
	}
	if current < tile.W {
		// A stale cached checkpoint can cause this, so allow a retry.
		return nil, dnsid.NewVerificationError(dnsid.VerificationCodeInvalidEvidence, true, "dnsid: c2sp-tlog hash tile missing from current log", fmt.Errorf("tile %d/%d has width %d in the current log, want at least %d", tile.L, tile.N, current, tile.W))
	}
	path := full
	if current < 1<<c2spTileHeight {
		path += ".p/" + strconv.Itoa(current)
	}
	data, err = r.fetchExact(path, current*tlog.HashSize)
	if err != nil {
		return nil, err
	}
	return data[:want], nil
}

// currentWidth reads the log's current checkpoint size once, as an untrusted
// hint for which tile width exists. Hashes read at that width are still
// authenticated against the candidate root.
func (r *c2spTileReader) currentWidth(tile tlog.Tile) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.currentSize == 0 {
		checkpoint, err := r.source.fetch(r.ctx, r.prefix+"/checkpoint", r.source.maxCheckpointBytes)
		if err != nil {
			return 0, err
		}
		lines := strings.SplitN(string(checkpoint), "\n", 3)
		size, err := strconv.ParseUint(strings.TrimSpace(firstOr(lines, 1)), 10, 63)
		if len(lines) < 3 || err != nil || size == 0 {
			return 0, dnsid.NewVerificationError(dnsid.VerificationCodeInvalidEvidence, false, "dnsid: invalid c2sp-tlog checkpoint size", err)
		}
		r.currentSize = size
	}
	available := r.currentSize >> (uint(tile.L) * c2spTileHeight)
	start := uint64(tile.N) << c2spTileHeight
	if available <= start {
		return 0, nil
	}
	return int(min(available-start, 1<<c2spTileHeight)), nil
}

func firstOr(values []string, index int) string {
	if index < len(values) {
		return values[index]
	}
	return ""
}

func (r *c2spTileReader) fetchExact(rawURL string, want int) ([]byte, error) {
	data, err := r.source.fetch(r.ctx, rawURL, int64(want))
	if err != nil {
		return nil, err
	}
	if len(data) != want {
		return nil, dnsid.NewVerificationError(dnsid.VerificationCodeInvalidEvidence, false, "dnsid: invalid c2sp-tlog hash tile", fmt.Errorf("hash tile length %d, want %d", len(data), want))
	}
	return data, nil
}
