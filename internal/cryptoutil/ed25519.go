package cryptoutil

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
)

// ed25519SmallOrder holds every canonical encoding of a point of order 1, 2, 4 or 8, plus the two
// sign-bit variants of x = 0 (libsodium's list).
var ed25519SmallOrder = func() [][]byte {
	var out [][]byte
	for _, h := range []string{
		"0100000000000000000000000000000000000000000000000000000000000000",
		"0100000000000000000000000000000000000000000000000000000000000080",
		"ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
		"ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
		"0000000000000000000000000000000000000000000000000000000000000000",
		"0000000000000000000000000000000000000000000000000000000000000080",
		"26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
		"26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85",
		"c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
		"c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa",
	} {
		b, _ := hex.DecodeString(h)
		out = append(out, b)
	}
	return out
}()

// ValidEd25519PublicKey reports whether pub is a 32-byte canonical encoding (y < p) that is not a
// small-order point. A small-order key lets its holder make one signature valid for many messages.
func ValidEd25519PublicKey(pub []byte) bool {
	if len(pub) != ed25519.PublicKeySize {
		return false
	}
	// y < p = 2^255 - 19, little-endian, ignoring the sign bit.
	y := bytes.Clone(pub)
	y[31] &= 0x7f
	if y[31] == 0x7f && bytes.Equal(y[1:31], bytes.Repeat([]byte{0xff}, 30)) && y[0] >= 0xed {
		return false
	}
	for _, bad := range ed25519SmallOrder {
		if bytes.Equal(pub, bad) {
			return false
		}
	}
	return true
}

// VerifyEd25519 is RFC 8032 cofactorless verification (crypto/ed25519 rejects S >= L) that also
// rejects non-canonical and small-order public keys.
func VerifyEd25519(pub ed25519.PublicKey, payload, sig []byte) bool {
	return len(sig) == ed25519.SignatureSize && ValidEd25519PublicKey(pub) && ed25519.Verify(pub, payload, sig)
}
