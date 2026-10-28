package tlogindex

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
)

const (
	// HashSize is the size of every hash in the index: SHA-256.
	HashSize = sha256.Size
	// MaxKeyLen is the longest canonical key, in bytes.
	MaxKeyLen = 1024
	// MaxSplitBit is the largest split bit two distinct canonical keys can
	// have: the first bit of the 0x00 terminator after a 1024-byte key.
	MaxSplitBit = 8 * MaxKeyLen
	// maxUvarintLen is the spec's bound on any uvarint in a proof.
	maxUvarintLen = binary.MaxVarintLen64
)

// Hash is a 32-byte SHA-256 digest: a value log root, an MPT node hash or an
// RFC 6962 tree root.
type Hash [HashSize]byte

// EmptyMPTRoot is the root hash of an MPT with no keys, SHA-256 of the empty
// string.
var EmptyMPTRoot = Hash(sha256.Sum256(nil))

// ErrInvalidKey reports a key that is not a canonical key.
var ErrInvalidKey = errors.New("tlogindex: invalid canonical key")

// ValidKey reports whether key is a canonical key: 1 to 1024 bytes, each a
// printable ASCII byte in 0x21..0x7E. It returns an error wrapping
// ErrInvalidKey otherwise.
func ValidKey(key string) error {
	if len(key) < 1 || len(key) > MaxKeyLen {
		return fmt.Errorf("%w: length %d outside 1..%d", ErrInvalidKey, len(key), MaxKeyLen)
	}
	for i := 0; i < len(key); i++ {
		if key[i] < 0x21 || key[i] > 0x7e {
			return fmt.Errorf("%w: byte 0x%02x at offset %d", ErrInvalidKey, key[i], i)
		}
	}
	return nil
}

// paddedByte is byte i of key || 0x00 || 0xFF 0xFF ...
func paddedByte(key string, i uint64) byte {
	switch {
	case i < uint64(len(key)):
		return key[i]
	case i == uint64(len(key)):
		return 0x00
	default:
		return 0xff
	}
}

// bit returns bit b of the padded key, numbered from the most significant bit
// of key[0].
func bit(key string, b uint64) byte {
	return (paddedByte(key, b/8) >> (7 - b%8)) & 1
}

// splitBit returns the first bit position at which the padded forms of two
// distinct canonical keys differ.
func splitBit(x, y string) uint64 {
	limit := uint64(max(len(x), len(y))) + 1
	for i := uint64(0); i <= limit; i++ {
		a, b := paddedByte(x, i), paddedByte(y, i)
		if a != b {
			diff := a ^ b
			offset := uint64(0)
			for diff&0x80 == 0 {
				diff <<= 1
				offset++
			}
			return 8*i + offset
		}
	}
	// Unreachable for distinct keys: the terminator of the shorter key differs
	// from the longer key's next byte, which is never 0x00.
	return MaxSplitBit + 1
}

func appendUvarint(dst []byte, v uint64) []byte {
	return binary.AppendUvarint(dst, v)
}

// readUvarint decodes one minimal uvarint of at most 10 bytes.
func readUvarint(data []byte) (uint64, int, error) {
	v, n := binary.Uvarint(data)
	if n == 0 {
		return 0, 0, errors.New("tlogindex: truncated uvarint")
	}
	if n < 0 || n > maxUvarintLen {
		return 0, 0, errors.New("tlogindex: uvarint exceeds 10 bytes or overflows")
	}
	if n > 1 && data[n-1] == 0 {
		return 0, 0, errors.New("tlogindex: non-minimal uvarint")
	}
	return v, n, nil
}
