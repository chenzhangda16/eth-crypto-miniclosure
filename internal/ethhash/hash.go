package ethhash

import (
	"encoding/hex"
	"golang.org/x/crypto/sha3"
)

func Keccak256(parts ...[]byte) []byte {
	h := sha3.NewLegacyKeccak256()
	for _, p := range parts {
		_, _ = h.Write(p)
	}
	return h.Sum(nil)
}

func Keccak256Hex(parts ...[]byte) string {
	return hex.EncodeToString(Keccak256(parts...))
}
