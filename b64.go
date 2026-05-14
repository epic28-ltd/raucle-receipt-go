package raucle

import "encoding/base64"

// B64URLEncode encodes data as unpadded base64url (RFC 4648 §5).
func B64URLEncode(data []byte) string {
	return base64.RawURLEncoding.EncodeToString(data)
}

// B64URLDecode decodes an unpadded base64url string.
func B64URLDecode(s string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(s)
}
