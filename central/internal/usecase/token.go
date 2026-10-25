package usecase

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
)

// NewToken returns a random 256-bit token (hex) and the hash to store.
func NewToken() (token string, hash []byte) {
	b := make([]byte, 32)
	rand.Read(b) // never returns an error (crypto/rand docs)
	token = hex.EncodeToString(b)
	return token, HashToken(token)
}

func HashToken(token string) []byte {
	h := sha256.Sum256([]byte(token))
	return h[:]
}
