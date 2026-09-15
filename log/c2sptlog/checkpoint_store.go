package c2sptlog

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"sync"
	"time"

	"github.com/transparency-dev/merkle/proof"
	"github.com/transparency-dev/merkle/rfc6962"
	"golang.org/x/mod/sumdb/tlog"
)

// CheckpointAdvanceErrorKind describes an observed continuity failure, not its cause.
type CheckpointAdvanceErrorKind string

const (
	// CheckpointAdvanceRollback indicates a smaller candidate tree.
	CheckpointAdvanceRollback CheckpointAdvanceErrorKind = "rollback"
	// CheckpointAdvanceRootConflict indicates different roots at equal sizes.
	CheckpointAdvanceRootConflict CheckpointAdvanceErrorKind = "root_conflict"
	// CheckpointAdvanceConsistencyFailed indicates invalid supplied proof or scan evidence.
	CheckpointAdvanceConsistencyFailed CheckpointAdvanceErrorKind = "consistency_failed"
	// CheckpointAdvanceConsistencyUnavailable indicates no supported consistency source.
	CheckpointAdvanceConsistencyUnavailable CheckpointAdvanceErrorKind = "consistency_unavailable"
)

// CheckpointAdvanceError rejects a candidate without replacing trusted state.
// Root hashes are copied from the checkpoints. Fetch and storage errors retain
// their original types instead of being classified as inconsistent evidence.
type CheckpointAdvanceError struct {
	Kind        CheckpointAdvanceErrorKind
	Origin      string
	OldTreeSize uint64
	NewTreeSize uint64
	OldRootHash []byte
	NewRootHash []byte
	// SplitView means an observed equal-size root conflict, not proven malice.
	// False never authorizes recovery or implies the failure is safe.
	SplitView bool
	Cause     error
}

func (e *CheckpointAdvanceError) Error() string {
	if e == nil {
		return "<nil>"
	}
	message := fmt.Sprintf("dnsid: c2sp-tlog checkpoint %s for %q from size %d to %d", e.Kind, e.Origin, e.OldTreeSize, e.NewTreeSize)
	if e.Cause != nil {
		message += ": " + e.Cause.Error()
	}
	return message
}

// Unwrap preserves the underlying evidence verification failure.
func (e *CheckpointAdvanceError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Cause
}

// Transient is false: retrying must never reset checkpoint trust.
func (e *CheckpointAdvanceError) Transient() bool { return false }

func checkpointAdvanceError(kind CheckpointAdvanceErrorKind, old, next TrustedC2spCheckpoint, cause error) error {
	return &CheckpointAdvanceError{
		Kind: kind, Origin: next.Origin,
		OldTreeSize: old.TreeSize, NewTreeSize: next.TreeSize,
		OldRootHash: append([]byte(nil), old.RootHash...),
		NewRootHash: append([]byte(nil), next.RootHash...),
		SplitView:   kind == CheckpointAdvanceRootConflict, Cause: cause,
	}
}

// TrustedC2spCheckpoint is append-only state scoped by checkpoint origin.
// A store may be seeded out of band; otherwise its first accepted checkpoint
// is trust on first use.
type TrustedC2spCheckpoint struct {
	Origin      string
	TreeSize    uint64
	RootHash    []byte
	WitnessTime time.Time
}

// TrustedC2spCheckpointStore atomically advances trusted checkpoint state.
// Administrative re-baselining must use an independently authorized, verified
// replacement and exact expected state, with verification stopped. See
// https://github.com/dnsid-ai/dnsid-go/blob/main/CHECKPOINT_RECOVERY.md.
// Verification never resets trust; custom stores may reject administrative downgrades.
type TrustedC2spCheckpointStore interface {
	// Load returns the trusted checkpoint for origin, or nil (with a nil
	// error) when none has been recorded.
	Load(origin string) (*TrustedC2spCheckpoint, error)
	// CompareAndSwap stores candidate only if the current state for origin
	// equals expected (nil expected means no state recorded). It reports
	// whether the swap happened; false with a nil error means another writer
	// advanced the state first and the caller should reload and retry.
	CompareAndSwap(origin string, expected *TrustedC2spCheckpoint, candidate TrustedC2spCheckpoint) (bool, error)
}

// C2spConsistencyProofSource supplies an RFC 6962 consistency proof between
// two checkpoint sizes. Implementations return untrusted hashes.
type C2spConsistencyProofSource interface {
	FetchConsistencyProof(ctx context.Context, reference Reference, fromSize, toSize uint64) ([][]byte, error)
}

// C2spFullLogSource supplies all raw entries in [0, treeSize). It is an
// optional fallback for proving an old prefix when no consistency-proof source
// is available. The SDK recomputes both roots; the source is not trusted.
type C2spFullLogSource interface {
	FetchEntriesThrough(ctx context.Context, reference Reference, treeSize uint64) ([][]byte, error)
}

// MemoryTrustedC2spCheckpointStore protects against rollback for the lifetime
// of this store instance. Use durable injected storage for protection across restarts.
type MemoryTrustedC2spCheckpointStore struct {
	mu          sync.Mutex
	checkpoints map[string]TrustedC2spCheckpoint
}

// NewMemoryTrustedC2spCheckpointStore returns an empty in-memory store. It is
// safe for concurrent use.
func NewMemoryTrustedC2spCheckpointStore() *MemoryTrustedC2spCheckpointStore {
	return &MemoryTrustedC2spCheckpointStore{checkpoints: make(map[string]TrustedC2spCheckpoint)}
}

// Load implements TrustedC2spCheckpointStore. It returns a copy of the stored
// checkpoint, nil when none is recorded, and an error on a nil receiver.
func (s *MemoryTrustedC2spCheckpointStore) Load(origin string) (*TrustedC2spCheckpoint, error) {
	if s == nil {
		return nil, fmt.Errorf("dnsid: nil trusted c2sp checkpoint store")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	checkpoint, ok := s.checkpoints[origin]
	if !ok {
		return nil, nil
	}
	copy := cloneTrustedCheckpoint(checkpoint)
	return &copy, nil
}

// CompareAndSwap implements TrustedC2spCheckpointStore. It returns an error
// on a nil receiver or when candidate's Origin does not match origin.
func (s *MemoryTrustedC2spCheckpointStore) CompareAndSwap(origin string, expected *TrustedC2spCheckpoint, candidate TrustedC2spCheckpoint) (bool, error) {
	if s == nil {
		return false, fmt.Errorf("dnsid: nil trusted c2sp checkpoint store")
	}
	if origin == "" || candidate.Origin != origin {
		return false, fmt.Errorf("dnsid: trusted c2sp checkpoint origin mismatch")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	current, ok := s.checkpoints[origin]
	if expected == nil {
		if ok {
			return false, nil
		}
	} else if !ok || !trustedCheckpointsEqual(current, *expected) {
		return false, nil
	}
	s.checkpoints[origin] = cloneTrustedCheckpoint(candidate)
	return true, nil
}

func (c *Client) advanceTrustedCheckpoints(ctx context.Context, checkpoints []*VerifiedProof) error {
	if c.checkpointStore == nil || len(checkpoints) == 0 {
		return nil
	}
	for _, verified := range checkpoints {
		candidate := TrustedC2spCheckpoint{
			Origin:      verified.Checkpoint.Origin,
			TreeSize:    verified.Checkpoint.Size,
			RootHash:    append([]byte(nil), verified.Checkpoint.Hash...),
			WitnessTime: verified.CheckpointWitnessTime,
		}
		if err := c.advanceTrustedCheckpoint(ctx, candidate); err != nil {
			return err
		}
	}
	return nil
}

func (c *Client) advanceTrustedCheckpoint(ctx context.Context, candidate TrustedC2spCheckpoint) error {
	for {
		trusted, err := c.checkpointStore.Load(candidate.Origin)
		if err != nil {
			return fmt.Errorf("dnsid: loading trusted c2sp checkpoint: %w", err)
		}
		if trusted != nil {
			switch {
			case candidate.TreeSize < trusted.TreeSize:
				return checkpointAdvanceError(CheckpointAdvanceRollback, *trusted, candidate, nil)
			case candidate.TreeSize == trusted.TreeSize:
				if !bytes.Equal(candidate.RootHash, trusted.RootHash) {
					return checkpointAdvanceError(CheckpointAdvanceRootConflict, *trusted, candidate, nil)
				}
				return nil
			default:
				if err := c.verifyCheckpointConsistency(ctx, *trusted, candidate); err != nil {
					return err
				}
			}
		}
		advanced, err := c.checkpointStore.CompareAndSwap(candidate.Origin, trusted, candidate)
		if err != nil {
			return fmt.Errorf("dnsid: advancing trusted c2sp checkpoint: %w", err)
		}
		if advanced {
			return nil
		}
	}
}

func (c *Client) verifyCheckpointConsistency(ctx context.Context, old, next TrustedC2spCheckpoint) error {
	if source, ok := c.source.(C2spConsistencyProofSource); ok {
		hashes, err := source.FetchConsistencyProof(ctx, c.ref, old.TreeSize, next.TreeSize)
		if err != nil {
			return fmt.Errorf("dnsid: fetching c2sp-tlog consistency proof: %w", err)
		}
		if err := proof.VerifyConsistency(rfc6962.DefaultHasher, old.TreeSize, next.TreeSize, hashes, old.RootHash, next.RootHash); err != nil {
			return checkpointAdvanceError(CheckpointAdvanceConsistencyFailed, old, next, err)
		}
		return nil
	}
	if source, ok := c.source.(C2spFullLogSource); ok {
		entries, err := source.FetchEntriesThrough(ctx, c.ref, next.TreeSize)
		if err != nil {
			return fmt.Errorf("dnsid: fetching complete c2sp-tlog scan: %w", err)
		}
		if uint64(len(entries)) != next.TreeSize {
			return checkpointAdvanceError(CheckpointAdvanceConsistencyFailed, old, next, fmt.Errorf("complete scan returned %d entries, want %d", len(entries), next.TreeSize))
		}
		oldRoot := merkleRoot(entries[:old.TreeSize])
		nextRoot := merkleRoot(entries)
		if !bytes.Equal(oldRoot, old.RootHash) || !bytes.Equal(nextRoot, next.RootHash) {
			return checkpointAdvanceError(CheckpointAdvanceConsistencyFailed, old, next, fmt.Errorf("complete scan does not match trusted checkpoints"))
		}
		return nil
	}
	return checkpointAdvanceError(CheckpointAdvanceConsistencyUnavailable, old, next, nil)
}

func merkleRoot(entries [][]byte) []byte {
	if len(entries) == 0 {
		empty := sha256.Sum256(nil)
		return empty[:]
	}
	if len(entries) == 1 {
		leaf := tlog.RecordHash(entries[0])
		return leaf[:]
	}
	split := 1
	for split<<1 < len(entries) {
		split <<= 1
	}
	left := merkleRoot(entries[:split])
	right := merkleRoot(entries[split:])
	input := make([]byte, 1, 1+len(left)+len(right))
	input[0] = 1
	input = append(input, left...)
	input = append(input, right...)
	hash := sha256.Sum256(input)
	return hash[:]
}

func cloneTrustedCheckpoint(checkpoint TrustedC2spCheckpoint) TrustedC2spCheckpoint {
	checkpoint.RootHash = append([]byte(nil), checkpoint.RootHash...)
	return checkpoint
}

func trustedCheckpointsEqual(a, b TrustedC2spCheckpoint) bool {
	return a.Origin == b.Origin && a.TreeSize == b.TreeSize && bytes.Equal(a.RootHash, b.RootHash) && a.WitnessTime.Equal(b.WitnessTime)
}
