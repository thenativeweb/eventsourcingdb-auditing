package receipt

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
)

// KeyIDOf derives the ID of a key from its public key, so that the ID can not
// be given to another key by mistake.
func KeyIDOf(publicKey ed25519.PublicKey) string {
	hash := sha256.Sum256(publicKey)
	return hex.EncodeToString(hash[:16])
}
