package receipt

import (
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"time"
)

// keyCertificateType is the JWS type of a key certificate.
const keyCertificateType = "io.thenativeweb.custody.key-certificate"

// KeyCertificate states that the root key of the native web vouches for a
// signing key within a period.
type KeyCertificate struct {
	KeyID      string
	PublicKey  ed25519.PublicKey
	ValidFrom  time.Time
	ValidUntil time.Time
}

type keyCertificateClaims struct {
	KeyID      string    `json:"keyId"`
	PublicKey  string    `json:"publicKey"`
	ValidFrom  time.Time `json:"validFrom"`
	ValidUntil time.Time `json:"validUntil"`
}

// IsValidAt reports whether the key may sign at the given time.
func (c KeyCertificate) IsValidAt(at time.Time) bool {
	return !at.Before(c.ValidFrom) && at.Before(c.ValidUntil)
}

// Certify signs a key certificate with the root key.
func Certify(certificate KeyCertificate, rootPrivateKey ed25519.PrivateKey) (string, error) {
	if len(certificate.PublicKey) != ed25519.PublicKeySize {
		return "", fmt.Errorf("the public key must have %d bytes, got %d", ed25519.PublicKeySize, len(certificate.PublicKey))
	}
	if certificate.KeyID != KeyIDOf(certificate.PublicKey) {
		return "", fmt.Errorf("the key id %q does not belong to the public key", certificate.KeyID)
	}
	if !certificate.ValidFrom.Before(certificate.ValidUntil) {
		return "", fmt.Errorf("the certificate must begin before it ends")
	}

	claims := keyCertificateClaims{
		KeyID:      certificate.KeyID,
		PublicKey:  base64.RawURLEncoding.EncodeToString(certificate.PublicKey),
		ValidFrom:  certificate.ValidFrom.UTC(),
		ValidUntil: certificate.ValidUntil.UTC(),
	}

	rootPublicKey := rootPrivateKey.Public().(ed25519.PublicKey)

	return sign(claims, keyCertificateType, KeyIDOf(rootPublicKey), rootPrivateKey)
}

// VerifyKeyCertificate checks that the root key has signed a key certificate,
// and returns what it states.
func VerifyKeyCertificate(jws string, rootPublicKey ed25519.PublicKey) (KeyCertificate, error) {
	jwsHeader, err := readHeader(jws, keyCertificateType)
	if err != nil {
		return KeyCertificate{}, err
	}
	if jwsHeader.KeyID != KeyIDOf(rootPublicKey) {
		return KeyCertificate{}, fmt.Errorf("%w: the key certificate was not signed by the root key", ErrInvalid)
	}

	payload, err := verifyCompact(jws, rootPublicKey)
	if err != nil {
		return KeyCertificate{}, err
	}

	var claims keyCertificateClaims
	err = strictUnmarshal(payload, &claims)
	if err != nil {
		return KeyCertificate{}, fmt.Errorf("%w: the key certificate is malformed: %v", ErrInvalid, err)
	}

	publicKey, err := base64.RawURLEncoding.DecodeString(claims.PublicKey)
	if err != nil || len(publicKey) != ed25519.PublicKeySize {
		return KeyCertificate{}, fmt.Errorf("%w: the key certificate holds no valid public key", ErrInvalid)
	}
	if claims.KeyID != KeyIDOf(publicKey) {
		return KeyCertificate{}, fmt.Errorf("%w: the key id does not belong to the public key", ErrInvalid)
	}

	return KeyCertificate{
		KeyID:      claims.KeyID,
		PublicKey:  publicKey,
		ValidFrom:  claims.ValidFrom,
		ValidUntil: claims.ValidUntil,
	}, nil
}
