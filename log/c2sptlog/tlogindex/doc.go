// Package tlogindex implements the encodings of a verifiable index committed
// into a C2SP tiled transparency log: per-key value logs, the binary Merkle
// Patricia Trie (MPT) that maps each key to its value log root, binary MPT
// inclusion and non-inclusion proofs, and the index state entry that commits
// an MPT root into the indexed log itself.
//
// The value log, MPT node hashing, key padding and binary proof step
// encodings follow the "Index Structure", "Binary MPT proofs" and "Verifying
// an MPT path" sections of the C2SP tlog-vindex specification
// (https://github.com/transparency-dev/incubator/blob/main/vindex/docs/tlog-vindex.md),
// unchanged, so any tlog-vindex auditor recomputes the same roots:
//
//	value_log_leaf_hash(idx)        = SHA-256(0x00 || uint64_be(idx))
//	value_log_node_hash(l, r)       = SHA-256(0x01 || l || r)
//	mpt_leaf_hash(key, value_root)  = SHA-256(0x00 || uvarint(len(key)) || key || uvarint(32) || value_root)
//	mpt_inner_hash(b, left, right)  = SHA-256(0x01 || uvarint(b) || left || right)
//	empty_mpt_hash                  = SHA-256("")
//	proof step                      = uvarint(b) || sibling_hash
//
// The state entry is the one part that is specific to DNSid: the index is
// committed into the log it indexes rather than into a separate output log,
// so the entry carries only the indexed size, the input root at that size and
// the MPT root. Its line layout follows the tlog-vindex state entry so the two
// can converge. See [StateEntry].
//
// This package holds pure encodings and has no network or log-format
// dependencies; the DNSid mapping function and bundle verification live in
// the parent c2sptlog package.
package tlogindex
