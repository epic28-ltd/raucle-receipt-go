package raucle

import (
	"crypto/sha256"
	"encoding/hex"
)

// SHA256Hex returns the lowercase hex SHA-256 of data.
func SHA256Hex(data []byte) string {
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:])
}

// HashText hashes a string per Raucle spec §7: "sha256:" prefix + lowercase hex.
func HashText(s string) string {
	return "sha256:" + SHA256Hex([]byte(s))
}

// HashObj hashes an arbitrary JSON-serialisable object per Raucle spec §7.
// The object is canonicalised before hashing so map key order is irrelevant.
func HashObj(v any) (string, error) {
	b, err := Canonicalize(v)
	if err != nil {
		return "", err
	}
	return "sha256:" + SHA256Hex(b), nil
}

// MustHashObj is HashObj that panics on error — convenient when the input is
// known JSON-safe (e.g. literals in tests).
func MustHashObj(v any) string {
	h, err := HashObj(v)
	if err != nil {
		panic(err)
	}
	return h
}
