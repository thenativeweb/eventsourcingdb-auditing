package receipttest

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"

	"github.com/thenativeweb/eventsourcingdb-auditing/receipt"
)

// ValidFrom and ValidUntil span the period of the signing keys created here.
// It covers the time the tests run at.
var (
	ValidFrom  = time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
	ValidUntil = time.Date(2100, 1, 1, 0, 0, 0, 0, time.UTC)
)

// NewSigningKey creates a root key and a signing key that the root key has
// certified, and returns the public root key together with the signing key.
func NewSigningKey(t testing.TB) (ed25519.PublicKey, receipt.SigningKey) {
	t.Helper()

	rootPublicKey, rootPrivateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	return rootPublicKey, NewSigningKeyFor(t, rootPublicKey, rootPrivateKey)
}

// NewSigningKeyFor creates a signing key that the given root key has
// certified, e.g. to replace a signing key with a new one.
func NewSigningKeyFor(t testing.TB, rootPublicKey ed25519.PublicKey, rootPrivateKey ed25519.PrivateKey) receipt.SigningKey {
	t.Helper()

	signingPublicKey, signingPrivateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	certificateJWS, err := receipt.Certify(receipt.KeyCertificate{
		KeyID:      receipt.KeyIDOf(signingPublicKey),
		PublicKey:  signingPublicKey,
		ValidFrom:  ValidFrom,
		ValidUntil: ValidUntil,
	}, rootPrivateKey)
	if err != nil {
		t.Fatal(err)
	}

	signingKey, err := receipt.NewSigningKey(signingPrivateKey, certificateJWS, rootPublicKey)
	if err != nil {
		t.Fatal(err)
	}

	return signingKey
}
