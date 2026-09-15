package c2sptlog

import (
	"bytes"
	"context"
	"testing"
)

type fullLogTestSource struct {
	basicSource
	entries [][]byte
}

func (s fullLogTestSource) FetchEntriesThrough(_ context.Context, _ Reference, treeSize uint64) ([][]byte, error) {
	return s.entries[:treeSize], nil
}

func TestTrustedCheckpointStoreRejectsRollbackAndConflict(t *testing.T) {
	ref, err := ParseReference("c2sp-tlog:public:https://log.example/test#stream")
	if err != nil {
		t.Fatal(err)
	}
	origin, err := ref.Origin()
	if err != nil {
		t.Fatal(err)
	}
	entries := [][]byte{[]byte("one"), []byte("two"), []byte("three")}
	store := NewMemoryTrustedC2spCheckpointStore()
	client := &Client{ref: ref, source: fullLogTestSource{entries: entries}, checkpointStore: store}

	first := TrustedC2spCheckpoint{Origin: origin, TreeSize: 1, RootHash: merkleRoot(entries[:1])}
	if err := client.advanceTrustedCheckpoint(context.Background(), first); err != nil {
		t.Fatalf("first checkpoint: %v", err)
	}
	third := TrustedC2spCheckpoint{Origin: origin, TreeSize: 3, RootHash: merkleRoot(entries)}
	if err := client.advanceTrustedCheckpoint(context.Background(), third); err != nil {
		t.Fatalf("consistent checkpoint: %v", err)
	}
	got, err := store.Load(origin)
	if err != nil {
		t.Fatal(err)
	}
	if got.TreeSize != 3 || !bytes.Equal(got.RootHash, third.RootHash) {
		t.Fatalf("stored checkpoint = %+v, want size 3", got)
	}

	if err := client.advanceTrustedCheckpoint(context.Background(), first); err == nil {
		t.Fatal("rollback checkpoint accepted")
	}
	conflict := third
	conflict.RootHash = bytes.Repeat([]byte{0xff}, len(third.RootHash))
	if err := client.advanceTrustedCheckpoint(context.Background(), conflict); err == nil {
		t.Fatal("equal-size conflicting checkpoint accepted")
	}
}

func TestTrustedCheckpointAdvanceRequiresConsistencyEvidence(t *testing.T) {
	ref, err := ParseReference("c2sp-tlog:public:https://log.example/test#stream")
	if err != nil {
		t.Fatal(err)
	}
	origin, err := ref.Origin()
	if err != nil {
		t.Fatal(err)
	}
	store := NewMemoryTrustedC2spCheckpointStore()
	client := &Client{ref: ref, source: basicSource{}, checkpointStore: store}
	first := TrustedC2spCheckpoint{Origin: origin, TreeSize: 1, RootHash: merkleRoot([][]byte{[]byte("one")})}
	if err := client.advanceTrustedCheckpoint(context.Background(), first); err != nil {
		t.Fatal(err)
	}
	next := TrustedC2spCheckpoint{Origin: origin, TreeSize: 2, RootHash: merkleRoot([][]byte{[]byte("one"), []byte("two")})}
	if err := client.advanceTrustedCheckpoint(context.Background(), next); err == nil {
		t.Fatal("checkpoint advanced without consistency evidence")
	}
}

func TestMemoryCheckpointStoreCompareAndSwapUsesExactExpectedState(t *testing.T) {
	store := NewMemoryTrustedC2spCheckpointStore()
	first := TrustedC2spCheckpoint{Origin: "log", TreeSize: 1, RootHash: []byte("one")}
	if swapped, err := store.CompareAndSwap("log", nil, first); err != nil || !swapped {
		t.Fatalf("initial CompareAndSwap = %v, %v", swapped, err)
	}
	stale := first
	stale.RootHash = []byte("stale")
	second := TrustedC2spCheckpoint{Origin: "log", TreeSize: 2, RootHash: []byte("two")}
	if swapped, err := store.CompareAndSwap("log", &stale, second); err != nil || swapped {
		t.Fatalf("stale CompareAndSwap = %v, %v", swapped, err)
	}
}
