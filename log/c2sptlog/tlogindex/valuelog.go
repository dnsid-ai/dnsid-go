package tlogindex

import (
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/transparency-dev/merkle/compact"
	"github.com/transparency-dev/merkle/rfc6962"
)

var valueLogRanges = compact.RangeFactory{Hash: rfc6962.DefaultHasher.HashChildren}

// ValueLogLeafHash returns value_log_leaf_hash(idx), the RFC 6962 leaf hash
// of uint64_be(idx).
func ValueLogLeafHash(idx uint64) Hash {
	var leaf [8]byte
	binary.BigEndian.PutUint64(leaf[:], idx)
	return Hash(rfc6962.DefaultHasher.HashLeaf(leaf[:]))
}

// ValueRoot returns a key's value log root: the RFC 6962 Merkle Tree Hash
// over leaves uint64_be(idx) for each entry index in indices. indices must be
// non-empty and strictly increasing, because a key with no occurrences is
// absent from the MPT rather than mapped to an empty value log.
func ValueRoot(indices []uint64) (Hash, error) {
	if len(indices) == 0 {
		return Hash{}, errors.New("tlogindex: value log must be non-empty")
	}
	r := valueLogRanges.NewEmptyRange(0)
	for i, idx := range indices {
		if i > 0 && idx <= indices[i-1] {
			return Hash{}, fmt.Errorf("tlogindex: value log indices must be strictly increasing at position %d", i)
		}
		leaf := ValueLogLeafHash(idx)
		if err := r.Append(leaf[:], nil); err != nil {
			return Hash{}, err
		}
	}
	root, err := r.GetRootHash(nil)
	if err != nil {
		return Hash{}, err
	}
	return Hash(root), nil
}
