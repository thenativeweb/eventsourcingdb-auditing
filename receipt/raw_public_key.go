package receipt

import (
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
)

// EncodeRawPublicKey encodes a public key as base64url without padding, which
// fits into a single line, e.g. for embedding it into a build.
func EncodeRawPublicKey(publicKey ed25519.PublicKey) string {
	return base64.RawURLEncoding.EncodeToString(publicKey)
}

// DecodeRawPublicKey decodes a public key from base64url without padding.
func DecodeRawPublicKey(value string) (ed25519.PublicKey, error) {
	publicKey, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil {
		return nil, fmt.Errorf("the public key is not base64url: %w", err)
	}
	if len(publicKey) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("the public key must have %d bytes, got %d", ed25519.PublicKeySize, len(publicKey))
	}

	return publicKey, nil
}
