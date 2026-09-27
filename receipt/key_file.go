package receipt

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
)

// EncodePrivateKey encodes a private key as PEM (PKCS #8), the format most
// tools read.
func EncodePrivateKey(privateKey ed25519.PrivateKey) ([]byte, error) {
	der, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return nil, err
	}

	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
}

// DecodePrivateKey decodes a private key from PEM (PKCS #8).
func DecodePrivateKey(data []byte) (ed25519.PrivateKey, error) {
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "PRIVATE KEY" {
		return nil, errors.New("expected a PEM block of type PRIVATE KEY")
	}

	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	privateKey, ok := key.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("expected an Ed25519 key, got %T", key)
	}

	return privateKey, nil
}

// EncodePublicKey encodes a public key as PEM (PKIX).
func EncodePublicKey(publicKey ed25519.PublicKey) ([]byte, error) {
	der, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return nil, err
	}

	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), nil
}

// DecodePublicKey decodes a public key from PEM (PKIX).
func DecodePublicKey(data []byte) (ed25519.PublicKey, error) {
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "PUBLIC KEY" {
		return nil, errors.New("expected a PEM block of type PUBLIC KEY")
	}

	key, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	publicKey, ok := key.(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("expected an Ed25519 key, got %T", key)
	}

	return publicKey, nil
}
