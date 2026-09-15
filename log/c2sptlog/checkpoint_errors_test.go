package c2sptlog

import (
	"bytes"
	"context"
	"errors"
	"testing"
)

type checkpointProofSource struct {
	basicSource
	hashes [][]byte
	err    error
}

func (s checkpointProofSource) FetchConsistencyProof(context.Context, Reference, uint64, uint64) ([][]byte, error) {
	return s.hashes, s.err
}

type checkpointScanSource struct {
	basicSource
	entries [][]byte
	err     error
}

func (s checkpointScanSource) FetchEntriesThrough(context.Context, Reference, uint64) ([][]byte, error) {
	return s.entries, s.err
}

func TestCheckpointAdvanceError_Classifications(t *testing.T) {
	entries := [][]byte{[]byte("one"), []byte("two")}
	old := TrustedC2spCheckpoint{Origin: "log", TreeSize: 1, RootHash: merkleRoot(entries[:1])}
	next := TrustedC2spCheckpoint{Origin: "log", TreeSize: 2, RootHash: merkleRoot(entries)}
	rollback := cloneTrustedCheckpoint(old)
	rollback.TreeSize = 0
	conflict := cloneTrustedCheckpoint(old)
	conflict.RootHash = bytes.Repeat([]byte{0xff}, 32)
	for _, tt := range []struct {
		name      string
		candidate TrustedC2spCheckpoint
		source    Source
		kind      CheckpointAdvanceErrorKind
		cause     bool
	}{
		{"rollback", rollback, basicSource{}, CheckpointAdvanceRollback, false},
		{"conflict", conflict, basicSource{}, CheckpointAdvanceRootConflict, false},
		{"proof", next, checkpointProofSource{}, CheckpointAdvanceConsistencyFailed, true},
		{"scan count", next, checkpointScanSource{entries: entries[:1]}, CheckpointAdvanceConsistencyFailed, true},
		{"scan root", next, checkpointScanSource{entries: [][]byte{[]byte("other"), []byte("two")}}, CheckpointAdvanceConsistencyFailed, true},
		{"missing", next, basicSource{}, CheckpointAdvanceConsistencyUnavailable, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			store := NewMemoryTrustedC2spCheckpointStore()
			if ok, err := store.CompareAndSwap(old.Origin, nil, old); err != nil || !ok {
				t.Fatal(ok, err)
			}
			client := &Client{source: tt.source, checkpointStore: store}
			candidate := cloneTrustedCheckpoint(tt.candidate)
			err := client.advanceTrustedCheckpoint(context.Background(), candidate)
			var typed *CheckpointAdvanceError
			if !errors.As(err, &typed) {
				t.Fatalf("untyped error: %v", err)
			}
			if typed.Kind != tt.kind || typed.Origin != old.Origin || typed.OldTreeSize != old.TreeSize || typed.NewTreeSize != candidate.TreeSize || !bytes.Equal(typed.OldRootHash, old.RootHash) || !bytes.Equal(typed.NewRootHash, candidate.RootHash) || typed.SplitView != (tt.kind == CheckpointAdvanceRootConflict) || typed.Transient() {
				t.Fatalf("error = %+v", typed)
			}
			if (typed.Unwrap() != nil) != tt.cause || typed.Error() == "" {
				t.Fatalf("cause = %v", typed.Unwrap())
			}
			if tt.cause && !errors.Is(err, typed.Cause) {
				t.Fatal("lost cause")
			}
			typed.OldRootHash[0] ^= 0xff
			typed.NewRootHash[0] ^= 0xff
			if !bytes.Equal(candidate.RootHash, tt.candidate.RootHash) {
				t.Fatal("error aliases candidate")
			}
			got, err := store.Load(old.Origin)
			if err != nil || !trustedCheckpointsEqual(*got, old) {
				t.Fatalf("trust changed: %v, %v", got, err)
			}
		})
	}
}

type failingCheckpointStore struct {
	TrustedC2spCheckpointStore
	loadErr, casErr error
}

func (s failingCheckpointStore) Load(origin string) (*TrustedC2spCheckpoint, error) {
	if s.loadErr != nil {
		return nil, s.loadErr
	}
	return s.TrustedC2spCheckpointStore.Load(origin)
}
func (s failingCheckpointStore) CompareAndSwap(origin string, expected *TrustedC2spCheckpoint, next TrustedC2spCheckpoint) (bool, error) {
	if s.casErr != nil {
		return false, s.casErr
	}
	return s.TrustedC2spCheckpointStore.CompareAndSwap(origin, expected, next)
}

func TestCheckpointAdvanceError_PreservesFetchAndStorageCauses(t *testing.T) {
	entries := [][]byte{[]byte("one"), []byte("two")}
	old := TrustedC2spCheckpoint{Origin: "log", TreeSize: 1, RootHash: merkleRoot(entries[:1])}
	next := TrustedC2spCheckpoint{Origin: "log", TreeSize: 2, RootHash: merkleRoot(entries)}
	cause := errors.New("storage unavailable")
	for _, mode := range []string{"proof fetch", "scan fetch", "load", "cas"} {
		t.Run(mode, func(t *testing.T) {
			store := NewMemoryTrustedC2spCheckpointStore()
			if ok, err := store.CompareAndSwap(old.Origin, nil, old); err != nil || !ok {
				t.Fatal(ok, err)
			}
			client := &Client{source: checkpointScanSource{entries: entries}, checkpointStore: store}
			want := context.Canceled
			switch mode {
			case "proof fetch":
				client.source = checkpointProofSource{err: want}
			case "scan fetch":
				client.source = checkpointScanSource{err: want}
			case "load":
				want = cause
				client.checkpointStore = failingCheckpointStore{TrustedC2spCheckpointStore: store, loadErr: cause}
			case "cas":
				want = cause
				client.checkpointStore = failingCheckpointStore{TrustedC2spCheckpointStore: store, casErr: cause}
			}
			err := client.advanceTrustedCheckpoint(context.Background(), next)
			var typed *CheckpointAdvanceError
			if !errors.Is(err, want) || errors.As(err, &typed) {
				t.Fatalf("incorrect classification: %v", err)
			}
			got, err := store.Load(old.Origin)
			if err != nil || !trustedCheckpointsEqual(*got, old) {
				t.Fatal("trust changed")
			}
		})
	}
}

type racingCheckpointStore struct {
	TrustedC2spCheckpointStore
	winner TrustedC2spCheckpoint
}

func (s racingCheckpointStore) CompareAndSwap(origin string, expected *TrustedC2spCheckpoint, _ TrustedC2spCheckpoint) (bool, error) {
	// Another verifier wins the race after Load and before this CAS.
	_, err := s.TrustedC2spCheckpointStore.CompareAndSwap(origin, expected, s.winner)
	return false, err
}

func TestCheckpointAdvanceError_ReloadsAfterCASRace(t *testing.T) {
	entries := [][]byte{[]byte("one"), []byte("two"), []byte("three")}
	old := TrustedC2spCheckpoint{Origin: "log", TreeSize: 1, RootHash: merkleRoot(entries[:1])}
	next := TrustedC2spCheckpoint{Origin: "log", TreeSize: 2, RootHash: merkleRoot(entries[:2])}
	winner := TrustedC2spCheckpoint{Origin: "log", TreeSize: 3, RootHash: merkleRoot(entries)}
	store := NewMemoryTrustedC2spCheckpointStore()
	if ok, err := store.CompareAndSwap("log", nil, old); err != nil || !ok {
		t.Fatal(ok, err)
	}
	client := &Client{source: checkpointScanSource{entries: entries[:2]}, checkpointStore: racingCheckpointStore{store, winner}}
	var typed *CheckpointAdvanceError
	if err := client.advanceTrustedCheckpoint(context.Background(), next); !errors.As(err, &typed) || typed.Kind != CheckpointAdvanceRollback || typed.OldTreeSize != 3 {
		t.Fatalf("did not classify against concurrent winner: %v", err)
	}
	got, err := store.Load("log")
	if err != nil || !trustedCheckpointsEqual(*got, winner) {
		t.Fatal("concurrent winner overwritten")
	}
}

func TestMemoryCheckpointStore_AuthorizedReplacement(t *testing.T) {
	store := NewMemoryTrustedC2spCheckpointStore()
	old := TrustedC2spCheckpoint{Origin: "log", TreeSize: 10, RootHash: bytes.Repeat([]byte{1}, 32)}
	replacement := TrustedC2spCheckpoint{Origin: "log", TreeSize: 5, RootHash: bytes.Repeat([]byte{2}, 32)}
	if ok, err := store.CompareAndSwap("log", nil, old); err != nil || !ok {
		t.Fatal(ok, err)
	}
	// Authorization, evidence verification and writer fencing are administrative
	// preconditions, not provided by CAS. Two stale administrative writers cannot
	// both replace the exact same expected state.
	results := make(chan bool, 2)
	for range 2 {
		go func() {
			ok, err := store.CompareAndSwap("log", &old, replacement)
			if err != nil {
				t.Error(err)
			}
			results <- ok
		}()
	}
	first, second := <-results, <-results
	if first == second {
		t.Fatal("expected exactly one successful replacement")
	}
	got, err := store.Load("log")
	if err != nil || !trustedCheckpointsEqual(*got, replacement) {
		t.Fatal("replacement not stored")
	}
	replacement.RootHash[0] ^= 0xff
	got.RootHash[0] ^= 0xff
	stored, err := store.Load("log")
	if err != nil || stored.RootHash[0] != 2 {
		t.Fatal("store aliases caller memory")
	}
	// The normal verifier still rejects rollback after administrative replacement.
	client := &Client{checkpointStore: store}
	lower := cloneTrustedCheckpoint(*stored)
	lower.TreeSize--
	var typed *CheckpointAdvanceError
	if err := client.advanceTrustedCheckpoint(context.Background(), lower); !errors.As(err, &typed) || typed.Kind != CheckpointAdvanceRollback {
		t.Fatalf("rollback accepted: %v", err)
	}
}
