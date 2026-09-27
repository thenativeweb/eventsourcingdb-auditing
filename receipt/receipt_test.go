package receipt_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/thenativeweb/eventsourcingdb-auditing/receipt"
)

var (
	validFrom  = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	validUntil = time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC)
	receivedAt = time.Date(2026, 9, 26, 12, 0, 0, 0, time.UTC)
)

func newKey(t *testing.T) ed25519.PrivateKey {
	t.Helper()

	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	return privateKey
}

// newSigningKey returns a root key and a signing key certified by it.
func newSigningKey(t *testing.T) (ed25519.PrivateKey, receipt.SigningKey) {
	t.Helper()

	rootKey := newKey(t)
	signingPrivateKey := newKey(t)
	signingPublicKey := signingPrivateKey.Public().(ed25519.PublicKey)

	certificateJWS, err := receipt.Certify(receipt.KeyCertificate{
		KeyID:      receipt.KeyIDOf(signingPublicKey),
		PublicKey:  signingPublicKey,
		ValidFrom:  validFrom,
		ValidUntil: validUntil,
	}, rootKey)
	require.NoError(t, err)

	signingKey, err := receipt.NewSigningKey(signingPrivateKey, certificateJWS, rootKey.Public().(ed25519.PublicKey))
	require.NoError(t, err)

	return rootKey, signingKey
}

func newReceipt() receipt.Receipt {
	return receipt.Receipt{
		InstanceID: "instance-1",
		EventID:    "5",
		EventHash:  "hash-5",
		ReceivedAt: receivedAt,
		Sequence:   1,
	}
}

// replacePart replaces one part of a JWS in compact form, to forge one.
func replacePart(jws string, index int, value string) string {
	parts := strings.Split(jws, ".")
	parts[index] = base64.RawURLEncoding.EncodeToString([]byte(value))

	return strings.Join(parts, ".")
}

func TestReceipt(t *testing.T) {
	t.Run("signs a receipt that verifies with the certificate of its key", func(t *testing.T) {
		_, signingKey := newSigningKey(t)

		jws, err := signingKey.Sign(newReceipt())
		require.NoError(t, err)

		verified, err := receipt.Verify(jws, signingKey.Certificate)
		require.NoError(t, err)
		assert.Equal(t, newReceipt(), verified)

		keyID, err := receipt.KeyIDOfReceipt(jws)
		require.NoError(t, err)
		assert.Equal(t, signingKey.Certificate.KeyID, keyID)
	})

	t.Run("rejects a receipt whose payload has been changed", func(t *testing.T) {
		_, signingKey := newSigningKey(t)
		jws, err := signingKey.Sign(newReceipt())
		require.NoError(t, err)

		forged := replacePart(jws, 1, `{"instanceId":"instance-1","eventId":"5","eventHash":"another-hash","receivedAt":"2026-09-26T12:00:00Z","sequence":1,"previousReceiptHash":""}`)

		_, err = receipt.Verify(forged, signingKey.Certificate)
		assert.ErrorIs(t, err, receipt.ErrInvalid)
	})

	t.Run("rejects a receipt signed by another key", func(t *testing.T) {
		_, signingKey := newSigningKey(t)
		_, anotherSigningKey := newSigningKey(t)

		jws, err := anotherSigningKey.Sign(newReceipt())
		require.NoError(t, err)

		_, err = receipt.Verify(jws, signingKey.Certificate)
		assert.ErrorIs(t, err, receipt.ErrInvalid)
	})

	t.Run("rejects any algorithm other than EdDSA", func(t *testing.T) {
		_, signingKey := newSigningKey(t)
		jws, err := signingKey.Sign(newReceipt())
		require.NoError(t, err)

		for _, forgedHeader := range []string{
			`{"alg":"none","typ":"io.thenativeweb.custody.receipt","kid":"` + signingKey.Certificate.KeyID + `"}`,
			`{"alg":"HS256","typ":"io.thenativeweb.custody.receipt","kid":"` + signingKey.Certificate.KeyID + `"}`,
		} {
			_, err := receipt.Verify(replacePart(jws, 0, forgedHeader), signingKey.Certificate)
			assert.ErrorIs(t, err, receipt.ErrInvalid, forgedHeader)
		}
	})

	t.Run("rejects a header with fields it does not know", func(t *testing.T) {
		_, signingKey := newSigningKey(t)
		jws, err := signingKey.Sign(newReceipt())
		require.NoError(t, err)

		forged := replacePart(jws, 0, `{"alg":"EdDSA","typ":"io.thenativeweb.custody.receipt","kid":"`+signingKey.Certificate.KeyID+`","crit":["exp"]}`)

		_, err = receipt.Verify(forged, signingKey.Certificate)
		assert.ErrorIs(t, err, receipt.ErrInvalid)
	})

	t.Run("rejects a key certificate passed off as a receipt", func(t *testing.T) {
		_, signingKey := newSigningKey(t)

		_, err := receipt.Verify(signingKey.CertificateJWS, signingKey.Certificate)
		assert.ErrorIs(t, err, receipt.ErrInvalid)
	})

	t.Run("rejects something that is not a JWS", func(t *testing.T) {
		_, signingKey := newSigningKey(t)

		for _, notAJWS := range []string{"", "a.b", "a.b.c.d", "!!!.???.***"} {
			_, err := receipt.Verify(notAJWS, signingKey.Certificate)
			assert.ErrorIs(t, err, receipt.ErrInvalid, notAJWS)
		}
	})

	t.Run("parses a receipt without checking its signature", func(t *testing.T) {
		_, signingKey := newSigningKey(t)
		jws, err := signingKey.Sign(newReceipt())
		require.NoError(t, err)

		parsed, err := receipt.ParseUnverified(jws)
		require.NoError(t, err)
		assert.Equal(t, newReceipt(), parsed)

		_, err = receipt.ParseUnverified(signingKey.CertificateJWS)
		assert.ErrorIs(t, err, receipt.ErrInvalid, "a key certificate is no receipt")
	})

	t.Run("refuses to sign outside the period of the certificate", func(t *testing.T) {
		_, signingKey := newSigningKey(t)

		lateReceipt := newReceipt()
		lateReceipt.ReceivedAt = validUntil

		_, err := signingKey.Sign(lateReceipt)
		assert.Error(t, err)
	})

	t.Run("tells whether a receipt follows another one", func(t *testing.T) {
		_, signingKey := newSigningKey(t)

		first := newReceipt()
		firstJWS, err := signingKey.Sign(first)
		require.NoError(t, err)

		second := newReceipt()
		second.Sequence = 2
		second.PreviousReceiptHash = receipt.Hash(firstJWS)

		assert.True(t, first.IsFirst())
		assert.False(t, second.IsFirst())
		assert.True(t, second.Follows(firstJWS, first))

		skipping := second
		skipping.Sequence = 3
		assert.False(t, skipping.Follows(firstJWS, first), "a receipt must not skip a number")

		pointingElsewhere := second
		pointingElsewhere.PreviousReceiptHash = receipt.Hash("another receipt")
		assert.False(t, pointingElsewhere.Follows(firstJWS, first), "a receipt must point to the one before it")

		ofAnotherInstance := second
		ofAnotherInstance.InstanceID = "instance-2"
		assert.False(t, ofAnotherInstance.Follows(firstJWS, first))
	})
}

func TestKeyCertificate(t *testing.T) {
	t.Run("verifies a certificate signed by the root key", func(t *testing.T) {
		rootKey, signingKey := newSigningKey(t)

		certificate, err := receipt.VerifyKeyCertificate(signingKey.CertificateJWS, rootKey.Public().(ed25519.PublicKey))
		require.NoError(t, err)

		assert.Equal(t, signingKey.Certificate, certificate)
		assert.True(t, certificate.IsValidAt(receivedAt))
		assert.False(t, certificate.IsValidAt(validUntil))
		assert.False(t, certificate.IsValidAt(validFrom.Add(-time.Second)))
	})

	t.Run("rejects a certificate signed by another root key", func(t *testing.T) {
		_, signingKey := newSigningKey(t)
		anotherRootKey := newKey(t)

		_, err := receipt.VerifyKeyCertificate(signingKey.CertificateJWS, anotherRootKey.Public().(ed25519.PublicKey))
		assert.ErrorIs(t, err, receipt.ErrInvalid)
	})

	t.Run("refuses to certify a key under an id that is not its own", func(t *testing.T) {
		rootKey := newKey(t)
		signingPublicKey := newKey(t).Public().(ed25519.PublicKey)

		_, err := receipt.Certify(receipt.KeyCertificate{
			KeyID:      "another-key-id",
			PublicKey:  signingPublicKey,
			ValidFrom:  validFrom,
			ValidUntil: validUntil,
		}, rootKey)
		assert.Error(t, err)
	})

	t.Run("refuses a signing key whose certificate belongs to another key", func(t *testing.T) {
		rootKey, signingKey := newSigningKey(t)

		_, err := receipt.NewSigningKey(newKey(t), signingKey.CertificateJWS, rootKey.Public().(ed25519.PublicKey))
		assert.ErrorIs(t, err, receipt.ErrInvalid)
	})
}

func TestKeyFiles(t *testing.T) {
	t.Run("encodes and decodes a private key", func(t *testing.T) {
		privateKey := newKey(t)

		encoded, err := receipt.EncodePrivateKey(privateKey)
		require.NoError(t, err)
		assert.Contains(t, string(encoded), "BEGIN PRIVATE KEY")

		decoded, err := receipt.DecodePrivateKey(encoded)
		require.NoError(t, err)
		assert.Equal(t, privateKey, decoded)
	})

	t.Run("encodes and decodes a public key", func(t *testing.T) {
		publicKey := newKey(t).Public().(ed25519.PublicKey)

		encoded, err := receipt.EncodePublicKey(publicKey)
		require.NoError(t, err)

		decoded, err := receipt.DecodePublicKey(encoded)
		require.NoError(t, err)
		assert.Equal(t, publicKey, decoded)
	})

	t.Run("rejects a public key where a private key is expected, and the other way round", func(t *testing.T) {
		privateKey := newKey(t)

		encodedPrivateKey, err := receipt.EncodePrivateKey(privateKey)
		require.NoError(t, err)
		encodedPublicKey, err := receipt.EncodePublicKey(privateKey.Public().(ed25519.PublicKey))
		require.NoError(t, err)

		_, err = receipt.DecodePrivateKey(encodedPublicKey)
		assert.Error(t, err)
		_, err = receipt.DecodePublicKey(encodedPrivateKey)
		assert.Error(t, err)
		_, err = receipt.DecodePrivateKey([]byte("not pem"))
		assert.Error(t, err)
	})
}
