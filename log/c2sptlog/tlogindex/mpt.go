package tlogindex

import (
	"crypto/sha256"
	"fmt"
	"slices"
)

// LeafHash returns mpt_leaf_hash(key, value).
func LeafHash(key string, value Hash) Hash {
	buf := make([]byte, 0, 1+2+len(key)+1+HashSize)
	buf = append(buf, 0x00)
	buf = appendUvarint(buf, uint64(len(key)))
	buf = append(buf, key...)
	buf = appendUvarint(buf, HashSize)
	buf = append(buf, value[:]...)
	return sha256.Sum256(buf)
}

// InnerHash returns mpt_inner_hash(b, left, right).
func InnerHash(b uint64, left, right Hash) Hash {
	buf := make([]byte, 0, 1+maxUvarintLen+2*HashSize)
	buf = append(buf, 0x01)
	buf = appendUvarint(buf, b)
	buf = append(buf, left[:]...)
	buf = append(buf, right[:]...)
	return sha256.Sum256(buf)
}

type node struct {
	leaf        bool
	key         string
	value       Hash
	bit         uint64
	left, right *node
	hash        Hash
}

// Trie is an immutable binary Merkle Patricia Trie over canonical keys, built
// in one pass from the full key set. The zero value is not usable; build one
// with NewTrie.
type Trie struct {
	root *node
	size int
}

// NewTrie builds the MPT over values, a map from canonical key to value log
// root. It sorts the keys once and builds the trie in O(n) from the split
// bits of adjacent keys, which the spec's topology rule makes equivalent to
// inserting the keys one at a time in any order. It returns an error wrapping
// ErrInvalidKey if any key is not canonical.
func NewTrie(values map[string]Hash) (*Trie, error) {
	keys := make([]string, 0, len(values))
	for key := range values {
		if err := ValidKey(key); err != nil {
			return nil, err
		}
		keys = append(keys, key)
	}
	// Canonical keys contain no 0x00, so byte order is padded bit order.
	slices.Sort(keys)
	t := &Trie{size: len(keys)}
	if len(keys) == 0 {
		return t, nil
	}
	// The trie is the Cartesian tree of the adjacent split bits: the smallest
	// split in a key range is that range's root. stack holds the inner nodes
	// on the current right spine whose right child is still open.
	var stack []*node
	current := &node{leaf: true, key: keys[0], value: values[keys[0]]}
	for i := 1; i < len(keys); i++ {
		split := splitBit(keys[i-1], keys[i])
		for len(stack) > 0 && stack[len(stack)-1].bit > split {
			top := stack[len(stack)-1]
			stack = stack[:len(stack)-1]
			top.right = current
			current = top
		}
		stack = append(stack, &node{bit: split, left: current})
		current = &node{leaf: true, key: keys[i], value: values[keys[i]]}
	}
	for len(stack) > 0 {
		top := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		top.right = current
		current = top
	}
	t.root = current
	hashNode(t.root)
	return t, nil
}

func hashNode(n *node) Hash {
	if n.leaf {
		n.hash = LeafHash(n.key, n.value)
	} else {
		n.hash = InnerHash(n.bit, hashNode(n.left), hashNode(n.right))
	}
	return n.hash
}

// Root returns the MPT root hash: EmptyMPTRoot when the trie has no keys.
func (t *Trie) Root() Hash {
	if t == nil || t.root == nil {
		return EmptyMPTRoot
	}
	return t.root.hash
}

// Len returns the number of keys in the trie.
func (t *Trie) Len() int {
	if t == nil {
		return 0
	}
	return t.size
}

// Lookup returns the value log root stored for key and whether it is present.
func (t *Trie) Lookup(key string) (Hash, bool) {
	leaf, _ := t.walk(key)
	if leaf == nil || leaf.key != key {
		return Hash{}, false
	}
	return leaf.value, true
}

// walk follows target's bits from the root to a leaf and returns the leaf and
// the encoded path steps from that leaf up to the root.
func (t *Trie) walk(target string) (*node, []byte) {
	if t == nil || t.root == nil {
		return nil, nil
	}
	type step struct {
		bit     uint64
		sibling Hash
	}
	var path []step
	n := t.root
	for !n.leaf {
		if bit(target, n.bit) == 0 {
			path = append(path, step{n.bit, n.right.hash})
			n = n.left
		} else {
			path = append(path, step{n.bit, n.left.hash})
			n = n.right
		}
	}
	var steps []byte
	for i := len(path) - 1; i >= 0; i-- {
		steps = appendUvarint(steps, path[i].bit)
		steps = append(steps, path[i].sibling[:]...)
	}
	return n, steps
}

// ProveInclusion returns the binary MPT proof that key is present: the path
// steps from key's leaf to the root, without the key and value. A trie with
// one key has an empty inclusion proof.
func (t *Trie) ProveInclusion(key string) ([]byte, error) {
	if err := ValidKey(key); err != nil {
		return nil, err
	}
	leaf, steps := t.walk(key)
	if leaf == nil || leaf.key != key {
		return nil, fmt.Errorf("tlogindex: key %q is not in the trie", key)
	}
	return steps, nil
}

// ProveNonInclusion returns the binary MPT proof that key is absent: the
// terminal leaf reached by walking key's bits, encoded as
// uvarint(len(path_key)) || path_key || uvarint(32) || path_val, followed by
// that leaf's path steps. An empty trie has an empty proof.
func (t *Trie) ProveNonInclusion(key string) ([]byte, error) {
	if err := ValidKey(key); err != nil {
		return nil, err
	}
	leaf, steps := t.walk(key)
	if leaf == nil {
		return []byte{}, nil
	}
	if leaf.key == key {
		return nil, fmt.Errorf("tlogindex: key %q is in the trie", key)
	}
	proof := appendUvarint(nil, uint64(len(leaf.key)))
	proof = append(proof, leaf.key...)
	proof = appendUvarint(proof, HashSize)
	proof = append(proof, leaf.value[:]...)
	return append(proof, steps...), nil
}
