package tlogindex

import (
	"errors"
	"fmt"
)

// ProofStep is one decoded binary MPT path step: an inner node's split bit
// and the hash of the sibling subtree at that split.
type ProofStep struct {
	Bit     uint64
	Sibling Hash
}

// ParseProofSteps decodes a sequence of path steps, uvarint(b) || sib_hash,
// ordered from the leaf up to the root. It enforces the spec's decoder
// rules: every uvarint is minimal and at most 10 bytes, every split bit is at
// most 8192, split bits strictly decrease, every sibling hash is a full 32
// bytes, and no bytes trail the last step.
func ParseProofSteps(data []byte) ([]ProofStep, error) {
	var steps []ProofStep
	for offset := 0; offset < len(data); {
		b, n, err := readUvarint(data[offset:])
		if err != nil {
			return nil, err
		}
		offset += n
		if b > MaxSplitBit {
			return nil, fmt.Errorf("tlogindex: split bit %d exceeds %d", b, MaxSplitBit)
		}
		if len(steps) > 0 && b >= steps[len(steps)-1].Bit {
			return nil, errors.New("tlogindex: split bits must strictly decrease")
		}
		if len(data)-offset < HashSize {
			return nil, errors.New("tlogindex: truncated sibling hash")
		}
		var step ProofStep
		step.Bit = b
		copy(step.Sibling[:], data[offset:offset+HashSize])
		offset += HashSize
		steps = append(steps, step)
	}
	return steps, nil
}

// ParseNonInclusionProof splits a non-empty non-inclusion proof into its
// terminal leaf (path_key, path_val) and path steps. path_key must be a
// canonical key and path_val exactly 32 bytes.
func ParseNonInclusionProof(data []byte) (pathKey string, pathVal Hash, steps []ProofStep, err error) {
	keyLen, n, err := readUvarint(data)
	if err != nil {
		return "", Hash{}, nil, err
	}
	offset := n
	if uint64(len(data)-offset) < keyLen {
		return "", Hash{}, nil, errors.New("tlogindex: truncated path key")
	}
	pathKey = string(data[offset : offset+int(keyLen)])
	offset += int(keyLen)
	if err := ValidKey(pathKey); err != nil {
		return "", Hash{}, nil, err
	}
	valLen, n, err := readUvarint(data[offset:])
	if err != nil {
		return "", Hash{}, nil, err
	}
	offset += n
	if valLen != HashSize || len(data)-offset < HashSize {
		return "", Hash{}, nil, errors.New("tlogindex: path value must be 32 bytes")
	}
	copy(pathVal[:], data[offset:offset+HashSize])
	offset += HashSize
	steps, err = ParseProofSteps(data[offset:])
	if err != nil {
		return "", Hash{}, nil, err
	}
	return pathKey, pathVal, steps, nil
}

// verifyPath recomputes the root from a starting node hash, checking that
// target and pathKey agree at every split bit.
func verifyPath(root, nodeHash Hash, target, pathKey string, steps []ProofStep) error {
	for _, step := range steps {
		targetBit := bit(target, step.Bit)
		if targetBit != bit(pathKey, step.Bit) {
			return fmt.Errorf("tlogindex: target and path key disagree at split bit %d", step.Bit)
		}
		if targetBit == 0 {
			nodeHash = InnerHash(step.Bit, nodeHash, step.Sibling)
		} else {
			nodeHash = InnerHash(step.Bit, step.Sibling, nodeHash)
		}
	}
	if nodeHash != root {
		return errors.New("tlogindex: MPT proof does not match root")
	}
	return nil
}

// VerifyInclusion verifies that root maps key to value, given the binary
// inclusion proof (path steps only).
func VerifyInclusion(root Hash, key string, value Hash, proof []byte) error {
	if err := ValidKey(key); err != nil {
		return err
	}
	steps, err := ParseProofSteps(proof)
	if err != nil {
		return err
	}
	return verifyPath(root, LeafHash(key, value), key, key, steps)
}

// VerifyNonInclusion verifies that key is absent from root. For the empty
// trie the proof must be empty. Otherwise the proof names the terminal leaf
// reached by key's bits; it is accepted only if that leaf's key differs from
// key, agrees with key at every split bit on the path, and hashes up to root.
func VerifyNonInclusion(root Hash, key string, proof []byte) error {
	if err := ValidKey(key); err != nil {
		return err
	}
	if root == EmptyMPTRoot {
		if len(proof) != 0 {
			return errors.New("tlogindex: empty MPT requires an empty proof")
		}
		return nil
	}
	pathKey, pathVal, steps, err := ParseNonInclusionProof(proof)
	if err != nil {
		return err
	}
	if pathKey == key {
		return errors.New("tlogindex: non-inclusion path key equals the target")
	}
	return verifyPath(root, LeafHash(pathKey, pathVal), key, pathKey, steps)
}
