package c2sptlog

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http"
	"strconv"

	dnsid "github.com/dnsid-ai/dnsid-go"
	"golang.org/x/mod/sumdb/tlog"
)

// A scan is retained only for the verification invocation that obtained it.
type scanEvidenceKey struct{}
type scanEvidence struct{ scan *completeScan }

func withScanEvidence(ctx context.Context) context.Context {
	if _, ok := ctx.Value(scanEvidenceKey{}).(*scanEvidence); ok {
		return ctx
	}
	return context.WithValue(ctx, scanEvidenceKey{}, &scanEvidence{})
}

// Internal capability: custom readers without it retain the legacy exception.
type checkpointTileSource interface {
	verifyTileConsistency(context.Context, Reference, TrustedC2spCheckpoint, TrustedC2spCheckpoint) error
}

type hashTileKey struct {
	level uint
	index uint64
}

type checkpointTiles struct {
	source *ScanSource
	ref    Reference
	size   uint64
	tiles  map[hashTileKey][]tlog.Hash
}

func invalidHashTile(message string, cause error) error {
	return dnsid.NewVerificationError(dnsid.VerificationCodeInvalidEvidence, false, "dnsid: c2sp-tlog "+message, cause)
}

func (s *ScanSource) verifyTileConsistency(ctx context.Context, ref Reference, old, next TrustedC2spCheckpoint) error {
	if next.TreeSize > s.maxTreeSize {
		return invalidHashTile("checkpoint exceeds configured tree-size maximum", nil)
	}
	tiles := checkpointTiles{source: s, ref: ref, size: next.TreeSize, tiles: make(map[hashTileKey][]tlog.Hash)}
	root, err := tiles.root(ctx, next.TreeSize)
	if err != nil {
		return err
	}
	if !bytes.Equal(root[:], next.RootHash) {
		return invalidHashTile("hash tiles do not match candidate checkpoint root", nil)
	}
	prefix, err := tiles.root(ctx, old.TreeSize)
	if err != nil {
		return err
	}
	// Full tiles not on the candidate's right edge must authenticate through
	// their own entries, never through a parent-provided subtree shortcut.
	for key := range tiles.tiles {
		if err := tiles.authenticate(ctx, key); err != nil {
			return err
		}
	}
	if !bytes.Equal(prefix[:], old.RootHash) {
		return checkpointAdvanceError(CheckpointAdvanceConsistencyFailed, old, next, fmt.Errorf("authenticated hash tiles contradict trusted prefix root"))
	}
	return nil
}

func (t *checkpointTiles) fetch(ctx context.Context, key hashTileKey) ([]tlog.Hash, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if hashes, ok := t.tiles[key]; ok {
		return hashes, nil
	}
	available := t.size >> (8 * key.level)
	width := min(uint64(256), available-key.index*256)
	path := t.ref.LogPrefix + "/tile/" + strconv.FormatUint(uint64(key.level), 10) + "/" + tileNumber(key.index)
	requested := path
	if width < 256 {
		requested += ".p/" + strconv.FormatUint(width, 10)
	}
	data, err := t.fetchExact(ctx, requested, width)
	var fetchErr *ResourceFetchError
	if width < 256 && errors.As(err, &fetchErr) && fetchErr.Kind == ResourceFetchHTTPStatus && fetchErr.HTTPStatus == http.StatusNotFound {
		data, err = t.fetchExact(ctx, path, 256)
		if err == nil {
			data = data[:width*tlog.HashSize]
		}
	}
	if err != nil {
		return nil, err
	}
	hashes := make([]tlog.Hash, width)
	for i := range hashes {
		copy(hashes[i][:], data[i*tlog.HashSize:(i+1)*tlog.HashSize])
	}
	t.tiles[key] = hashes
	return hashes, nil
}

func (t *checkpointTiles) fetchExact(ctx context.Context, path string, width uint64) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	data, err := fetchBounded(t.source.fetcher, ctx, path, int64(width)*tlog.HashSize)
	var fetchErr *ResourceFetchError
	if errors.As(err, &fetchErr) && fetchErr.Kind == ResourceFetchResponseLimit {
		return nil, invalidHashTile("hash tile exceeds requested width", err)
	}
	if err != nil {
		return nil, logVerificationError(err, true)
	}
	if len(data) != int(width)*tlog.HashSize {
		return nil, invalidHashTile("hash tile has incorrect length", nil)
	}
	return data, nil
}

// Each base-256 digit selects a prefix in one tile. Smaller subtrees fold
// from right to left, just as in the RFC 6962 root of an uneven tree.
func (t *checkpointTiles) root(ctx context.Context, size uint64) (tlog.Hash, error) {
	var root tlog.Hash
	haveRoot := false
	for level := uint(0); size > 0; level++ {
		width := size % 256
		if width != 0 {
			hashes, err := t.fetch(ctx, hashTileKey{level, size / 256})
			if err != nil {
				return root, err
			}
			// The smaller lower-level remainder is the rightmost subtree.
			nodes := append([]tlog.Hash(nil), hashes[:width]...)
			if haveRoot {
				nodes = append(nodes, root)
			}
			root = hashTileRoot(nodes)
			haveRoot = true
		}
		size /= 256
	}
	return root, nil
}

func hashTileRoot(hashes []tlog.Hash) tlog.Hash {
	if len(hashes) == 1 {
		return hashes[0]
	}
	split := 1
	for split*2 < len(hashes) {
		split *= 2
	}
	return tlog.NodeHash(hashTileRoot(hashes[:split]), hashTileRoot(hashes[split:]))
}

func (t *checkpointTiles) authenticate(ctx context.Context, key hashTileKey) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	available := t.size >> (8 * key.level)
	if available%256 != 0 && key.index == available/256 {
		return nil
	} // Candidate right edge.
	hashes, err := t.fetch(ctx, key)
	if err != nil {
		return err
	}
	parentKey := hashTileKey{key.level + 1, key.index / 256}
	parent, err := t.fetch(ctx, parentKey)
	if err != nil {
		return err
	}
	if hashTileRoot(hashes) != parent[key.index%256] {
		return invalidHashTile("hash tile fails candidate authentication", nil)
	}
	return t.authenticate(ctx, parentKey)
}

func (s *fetchedStreamBundleSource) verifyTileConsistency(ctx context.Context, ref Reference, old, next TrustedC2spCheckpoint) error {
	if source, ok := s.fallback.(C2spConsistencyProofSource); ok {
		return verifyExplicitConsistency(ctx, source, ref, old, next)
	}
	if source, ok := s.fallback.(checkpointTileSource); ok {
		return source.verifyTileConsistency(ctx, ref, old, next)
	}
	if !s.requireBundle {
		if source, ok := s.fallback.(C2spFullLogSource); ok {
			return verifyScanConsistency(ctx, source, ref, old, next)
		}
	}
	return checkpointAdvanceError(CheckpointAdvanceConsistencyUnavailable, old, next, ErrConsistencyUnavailable)
}
