package c2sptlog

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"math"
	"time"

	dnsid "github.com/dnsid-ai/dnsid-go"
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
	// CheckpointAdvanceConsistencyFailed indicates an invalid proof or a candidate-valid scan contradicting trusted history.
	CheckpointAdvanceConsistencyFailed CheckpointAdvanceErrorKind = "consistency_failed"
	// CheckpointAdvanceConsistencyUnavailable indicates no supported consistency source.
	CheckpointAdvanceConsistencyUnavailable CheckpointAdvanceErrorKind = "consistency_unavailable"
)

// CheckpointAdvanceError rejects a candidate without replacing trusted state.
// Root hashes are copied from the checkpoints. Fetch and storage errors retain
// their causes instead of being classified as inconsistent evidence.
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
	// advanced the state first and the verifier should reload and retry.
	// Administrative replacement instead stops on contention. Errors never
	// imply that publication was undone; reconcile state before recovery.
	CompareAndSwap(origin string, expected *TrustedC2spCheckpoint, candidate TrustedC2spCheckpoint) (bool, error)
}

// ContextTrustedC2spCheckpointStore supports cancellation during lock waits and
// staging, up to publication. Stores that wait or stage writes must implement
// this interface; legacy synchronous operations start publication when called.
// Once publication starts, errors may leave an indeterminate outcome. Callers
// must reconcile storage before recovery, never assume that an error undid a write.
type ContextTrustedC2spCheckpointStore interface {
	TrustedC2spCheckpointStore
	LoadContext(ctx context.Context, origin string) (*TrustedC2spCheckpoint, error)
	CompareAndSwapContext(ctx context.Context, origin string, expected *TrustedC2spCheckpoint, candidate TrustedC2spCheckpoint) (bool, error)
}

// C2spConsistencyProofSource supplies an RFC 6962 consistency proof between
// two checkpoint sizes. Implementations return untrusted hashes.
type C2spConsistencyProofSource interface {
	FetchConsistencyProof(ctx context.Context, reference Reference, fromSize, toSize uint64) ([][]byte, error)
}

// ErrConsistencyUnavailable identifies a source that cannot provide consistency
// evidence. It is not a retrieval failure or permission to reset trust.
var ErrConsistencyUnavailable = errors.New("dnsid: c2sp-tlog consistency evidence unavailable")

// C2spFullLogSource supplies all raw entries in [0, treeSize). It is an
// optional fallback for proving an old prefix when no consistency-proof source
// is available. The SDK recomputes both roots; the source is not trusted.
type C2spFullLogSource interface {
	FetchEntriesThrough(ctx context.Context, reference Reference, treeSize uint64) ([][]byte, error)
}

// MemoryTrustedC2spCheckpointStore protects against rollback for the lifetime
// of this store instance. Use durable injected storage for protection across restarts.
// Construct it with NewMemoryTrustedC2spCheckpointStore before use.
type MemoryTrustedC2spCheckpointStore struct {
	mu          chan struct{}
	checkpoints map[string]TrustedC2spCheckpoint
}

// NewMemoryTrustedC2spCheckpointStore returns an empty in-memory store. It is
// safe for concurrent use.
func NewMemoryTrustedC2spCheckpointStore() *MemoryTrustedC2spCheckpointStore {
	return &MemoryTrustedC2spCheckpointStore{
		mu: make(chan struct{}, 1), checkpoints: make(map[string]TrustedC2spCheckpoint),
	}
}

// Load implements TrustedC2spCheckpointStore. It returns a copy of the stored
// checkpoint, nil when none is recorded, and an error on a nil receiver.
func (s *MemoryTrustedC2spCheckpointStore) Load(origin string) (*TrustedC2spCheckpoint, error) {
	return s.LoadContext(context.Background(), origin)
}

// LoadContext is Load with a cancellable lock wait.
func (s *MemoryTrustedC2spCheckpointStore) LoadContext(ctx context.Context, origin string) (*TrustedC2spCheckpoint, error) {
	if origin == "" {
		return nil, dnsid.NewArgumentError("dnsid: checkpoint origin is required", nil)
	}
	if err := s.lock(ctx); err != nil {
		return nil, err
	}
	defer func() { <-s.mu }()
	checkpoint, ok := s.checkpoints[origin]
	if !ok {
		return nil, nil
	}
	if err := validateTrustedCheckpoint(origin, checkpoint); err != nil {
		return nil, checkpointStoreError("invalid stored c2sp checkpoint", err)
	}
	copy := cloneTrustedCheckpoint(checkpoint)
	return &copy, nil
}

func (s *MemoryTrustedC2spCheckpointStore) lock(ctx context.Context) error {
	if s == nil || s.mu == nil {
		return checkpointStoreError("uninitialized trusted c2sp checkpoint store", nil)
	}
	if ctx == nil {
		return dnsid.NewArgumentError("dnsid: checkpoint context is required", nil)
	}
	select {
	case s.mu <- struct{}{}:
		if err := ctx.Err(); err != nil {
			<-s.mu
			return err
		}
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// CompareAndSwap implements TrustedC2spCheckpointStore. It returns an error
// on invalid input. Administrative replacements require external authorization.
func (s *MemoryTrustedC2spCheckpointStore) CompareAndSwap(origin string, expected *TrustedC2spCheckpoint, candidate TrustedC2spCheckpoint) (bool, error) {
	return s.CompareAndSwapContext(context.Background(), origin, expected, candidate)
}

// CompareAndSwapContext cancels lock waits and checks cancellation immediately
// before publication. It never leaves a queued write running after return.
func (s *MemoryTrustedC2spCheckpointStore) CompareAndSwapContext(ctx context.Context, origin string, expected *TrustedC2spCheckpoint, candidate TrustedC2spCheckpoint) (bool, error) {
	if err := validateTrustedCheckpoint(origin, candidate); err != nil {
		return false, err
	}
	if expected != nil {
		if err := validateTrustedCheckpoint(origin, *expected); err != nil {
			return false, err
		}
		copy := cloneTrustedCheckpoint(*expected)
		expected = &copy
	}
	candidate = cloneTrustedCheckpoint(candidate)
	if err := s.lock(ctx); err != nil {
		return false, err
	}
	defer func() { <-s.mu }()
	current, ok := s.checkpoints[origin]
	if ok {
		if err := validateTrustedCheckpoint(origin, current); err != nil {
			return false, checkpointStoreError("invalid stored c2sp checkpoint", err)
		}
	}
	if expected == nil {
		if ok {
			return false, nil
		}
	} else if !ok || !trustedCheckpointsEqual(current, *expected) {
		return false, nil
	}
	if err := ctx.Err(); err != nil {
		return false, err
	}
	s.checkpoints[origin] = candidate
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
	if err := validateTrustedCheckpoint(candidate.Origin, candidate); err != nil {
		return dnsid.NewVerificationError(dnsid.VerificationCodeInvalidEvidence, false, "dnsid: invalid accepted c2sp checkpoint tuple", err)
	}
	candidate = cloneTrustedCheckpoint(candidate)
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		var trusted *TrustedC2spCheckpoint
		var err error
		contextStore, contextual := c.checkpointStore.(ContextTrustedC2spCheckpointStore)
		if contextual {
			trusted, err = contextStore.LoadContext(ctx, candidate.Origin)
		} else {
			trusted, err = c.checkpointStore.Load(candidate.Origin)
		}
		if err != nil {
			if ctx.Err() != nil && errors.Is(err, ctx.Err()) {
				return err
			}
			return checkpointStoreError("loading trusted c2sp checkpoint", err)
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if trusted != nil {
			if err := validateTrustedCheckpoint(candidate.Origin, *trusted); err != nil {
				return checkpointStoreError("invalid stored c2sp checkpoint", err)
			}
			copy := cloneTrustedCheckpoint(*trusted)
			trusted = &copy
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
		if err := ctx.Err(); err != nil {
			return err
		}
		var advanced bool
		if contextual {
			advanced, err = contextStore.CompareAndSwapContext(ctx, candidate.Origin, trusted, candidate)
		} else {
			advanced, err = c.checkpointStore.CompareAndSwap(candidate.Origin, trusted, candidate)
		}
		if err != nil {
			// Publication may have happened. Never retry a failed write or reset trust.
			return checkpointStoreError("advancing trusted c2sp checkpoint; reconcile stored state before recovery", err)
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
			if errors.Is(err, ErrConsistencyUnavailable) {
				return checkpointAdvanceError(CheckpointAdvanceConsistencyUnavailable, old, next, err)
			}
			return logVerificationError(fmt.Errorf("dnsid: fetching c2sp-tlog consistency proof: %w", err), true)
		}
		if err := proof.VerifyConsistency(rfc6962.DefaultHasher, old.TreeSize, next.TreeSize, hashes, old.RootHash, next.RootHash); err != nil {
			return checkpointAdvanceError(CheckpointAdvanceConsistencyFailed, old, next, err)
		}
		return nil
	}
	if source, ok := c.source.(C2spFullLogSource); ok {
		entries, err := source.FetchEntriesThrough(ctx, c.ref, next.TreeSize)
		if err != nil {
			if errors.Is(err, ErrConsistencyUnavailable) {
				return checkpointAdvanceError(CheckpointAdvanceConsistencyUnavailable, old, next, err)
			}
			return logVerificationError(fmt.Errorf("dnsid: fetching complete c2sp-tlog scan: %w", err), true)
		}
		if uint64(len(entries)) != next.TreeSize {
			return dnsid.NewVerificationError(dnsid.VerificationCodeInvalidEvidence, false, "dnsid: incomplete candidate checkpoint scan", fmt.Errorf("complete scan returned %d entries, want %d", len(entries), next.TreeSize))
		}
		if !bytes.Equal(merkleRoot(entries), next.RootHash) {
			return dnsid.NewVerificationError(dnsid.VerificationCodeInvalidEvidence, false, "dnsid: complete scan does not match candidate checkpoint root", nil)
		}
		if !bytes.Equal(merkleRoot(entries[:old.TreeSize]), old.RootHash) {
			return checkpointAdvanceError(CheckpointAdvanceConsistencyFailed, old, next, fmt.Errorf("complete scan contradicts trusted prefix root"))
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

func checkpointStoreError(message string, cause error) error {
	return dnsid.NewVerificationError(dnsid.VerificationCodeCheckpointStore, false, "dnsid: "+message, cause)
}

func validateTrustedCheckpoint(origin string, checkpoint TrustedC2spCheckpoint) error {
	if origin == "" || checkpoint.Origin != origin || checkpoint.TreeSize > math.MaxInt64 || len(checkpoint.RootHash) != sha256.Size || checkpoint.WitnessTime.IsZero() || checkpoint.WitnessTime.Year() < 1 || checkpoint.WitnessTime.Year() > 9999 {
		return dnsid.NewArgumentError("dnsid: checkpoint requires a matching nonempty origin, int64 tree size, SHA-256 root and valid witnessed time", nil)
	}
	return nil
}

func cloneTrustedCheckpoint(checkpoint TrustedC2spCheckpoint) TrustedC2spCheckpoint {
	checkpoint.RootHash = append([]byte(nil), checkpoint.RootHash...)
	return checkpoint
}

func trustedCheckpointsEqual(a, b TrustedC2spCheckpoint) bool {
	return a.Origin == b.Origin && a.TreeSize == b.TreeSize && bytes.Equal(a.RootHash, b.RootHash) && a.WitnessTime.Equal(b.WitnessTime)
}
