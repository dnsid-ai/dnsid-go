package tlogindex

import (
	"fmt"
	"slices"
)

// MapFunc is a deterministic mapping function from one raw log entry to the
// canonical key it is indexed under. ok is false when the entry maps to no
// key. A non-nil error aborts indexing: the index cannot be computed past an
// entry the mapping function cannot classify.
type MapFunc func(entry []byte) (key string, ok bool, err error)

// Replayer recomputes an index by consuming log entries in order from index
// 0. Auditors use it to recompute the MPT root a state entry commits to;
// indexers use it to build the trie and proofs they serve.
type Replayer struct {
	mapFn   MapFunc
	next    uint64
	entries map[string][]uint64
}

// NewReplayer returns a Replayer that maps entries with mapFn.
func NewReplayer(mapFn MapFunc) *Replayer {
	return &Replayer{mapFn: mapFn, entries: make(map[string][]uint64)}
}

// Size returns the number of entries consumed so far, the index of the next
// entry Append expects.
func (r *Replayer) Size() uint64 { return r.next }

// Append consumes the entry at index Size().
func (r *Replayer) Append(entry []byte) error {
	key, ok, err := r.mapFn(entry)
	if err != nil {
		return fmt.Errorf("tlogindex: mapping entry %d: %w", r.next, err)
	}
	if ok {
		if err := ValidKey(key); err != nil {
			return fmt.Errorf("tlogindex: entry %d mapped to an invalid key: %w", r.next, err)
		}
		r.entries[key] = append(r.entries[key], r.next)
	}
	r.next++
	return nil
}

// Entries returns the sorted entry indices recorded for key, or nil.
func (r *Replayer) Entries(key string) []uint64 {
	return slices.Clone(r.entries[key])
}

// Trie builds the MPT over every key's value log root as of Size().
func (r *Replayer) Trie() (*Trie, error) {
	values := make(map[string]Hash, len(r.entries))
	for key, indices := range r.entries {
		root, err := ValueRoot(indices)
		if err != nil {
			return nil, err
		}
		values[key] = root
	}
	return NewTrie(values)
}

// Replay consumes entries as the log entries [0, len(entries)) and returns the
// resulting MPT root. A caller holding a state entry compares the result
// with its MPTRoot after checking that len(entries) equals its InputSize.
func Replay(entries [][]byte, mapFn MapFunc) (Hash, error) {
	r := NewReplayer(mapFn)
	for _, entry := range entries {
		if err := r.Append(entry); err != nil {
			return Hash{}, err
		}
	}
	trie, err := r.Trie()
	if err != nil {
		return Hash{}, err
	}
	return trie.Root(), nil
}
