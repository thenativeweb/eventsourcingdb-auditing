package timestamping

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"os"
	"testing"
	"time"

	"github.com/digitorus/timestamp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/thenativeweb/eventsourcingdb-auditing/trustedlists"
	"github.com/thenativeweb/eventsourcingdb-auditing/trustedlists/trustedliststest"
)

// readDGNRecording returns the request TestInterop has sent to DGN, the time
// stamping authority of the custodian, and the answer DGN has given, so that
// every run checks what a real authority sends, without credentials and
// without using up time stamps.
func readDGNRecording(t *testing.T) (*timestamp.Request, []byte) {
	t.Helper()

	rawRequest, err := os.ReadFile("testdata/dgn.tsq")
	require.NoError(t, err)
	request, err := timestamp.ParseRequest(rawRequest)
	require.NoError(t, err)

	answer, err := os.ReadFile("testdata/dgn.tsr")
	require.NoError(t, err)

	return request, answer
}

// newRSAAuthority answers a request for a digest the way an authority with
// an RSA key does, which signs with PKCS #1 v1.5, and whose certificate is
// valid in the given period.
func newRSAAuthority(t *testing.T, notBefore, notAfter, at time.Time, digest [sha256.Size]byte) []byte {
	t.Helper()

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "Test Time Stamping Authority"},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageTimeStamping},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	require.NoError(t, err)
	certificate, err := x509.ParseCertificate(der)
	require.NoError(t, err)

	answer, err := (&timestamp.Timestamp{
		HashAlgorithm:     crypto.SHA256,
		HashedMessage:     digest[:],
		Time:              at,
		Nonce:             big.NewInt(42),
		Policy:            asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 99999, 1},
		AddTSACertificate: true,
	}).CreateResponseWithOpts(certificate, privateKey, crypto.SHA256)
	require.NoError(t, err)

	return answer
}

func TestVerify(t *testing.T) {
	t.Run("checks the answer of DGN, which is signed with RSA-PSS", func(t *testing.T) {
		request, answer := readDGNRecording(t)

		rawToken, err := tokenOf(answer)
		require.NoError(t, err)

		token, info, err := verify(rawToken, [sha256.Size]byte(request.HashedMessage))
		require.NoError(t, err)

		assert.Zero(t, request.Nonce.Cmp(info.Nonce), "the answer carries the nonce of the request")
		assert.Equal(t, time.Date(2026, 9, 28, 16, 12, 46, 0, time.UTC), token.Time)
		assert.Equal(t, "dgnservice TSS25", token.Certificate.Subject.CommonName)

		// DGN does not put the qualified statement into its time stamps,
		// so only the EU trusted lists tell that they are qualified.
		assert.False(t, token.IsQualified)
	})

	t.Run("confirms the time stamp of DGN as qualified with the EU trusted lists", func(t *testing.T) {
		request, answer := readDGNRecording(t)

		rawToken, err := tokenOf(answer)
		require.NoError(t, err)
		token, _, err := verify(rawToken, [sha256.Size]byte(request.HashedMessage))
		require.NoError(t, err)

		checker, err := trustedlists.NewChecker(t.Context(), trustedliststest.Source{})
		require.NoError(t, err)

		qualification, err := checker.Qualification(t.Context(), token.Certificate, token.Time)
		require.NoError(t, err)
		assert.True(t, qualification.IsQualified, qualification.Reason)
		assert.Equal(t, "DE", qualification.Country)
		assert.Equal(t, "DGN Zeitstempelservice", qualification.Service)
	})

	t.Run("rejects the time stamp of DGN if its signature has been changed", func(t *testing.T) {
		request, answer := readDGNRecording(t)

		rawToken, err := tokenOf(answer)
		require.NoError(t, err)

		// The signature is at the end of the token.
		changed := append([]byte{}, rawToken...)
		changed[len(changed)-10] ^= 0xff

		_, _, err = verify(changed, [sha256.Size]byte(request.HashedMessage))
		assert.ErrorIs(t, err, ErrInvalid)
		assert.ErrorContains(t, err, "does not match its certificate")
	})

	t.Run("rejects the time stamp of DGN for another digest", func(t *testing.T) {
		_, answer := readDGNRecording(t)

		rawToken, err := tokenOf(answer)
		require.NoError(t, err)

		_, _, err = verify(rawToken, sha256.Sum256([]byte("another anchor")))
		assert.ErrorIs(t, err, ErrInvalid)
		assert.ErrorContains(t, err, "covers another digest")
	})

	t.Run("checks a time stamp signed with RSA and PKCS #1 v1.5", func(t *testing.T) {
		digest := sha256.Sum256([]byte("an anchor"))
		now := time.Now().UTC()
		answer := newRSAAuthority(t, now.Add(-time.Hour), now.Add(time.Hour), now, digest)

		rawToken, err := tokenOf(answer)
		require.NoError(t, err)

		token, _, err := verify(rawToken, digest)
		require.NoError(t, err)
		assert.Equal(t, "Test Time Stamping Authority", token.Certificate.Subject.CommonName)
	})

	t.Run("rejects a time stamp issued outside the validity of its certificate", func(t *testing.T) {
		digest := sha256.Sum256([]byte("an anchor"))
		now := time.Now().UTC()
		answer := newRSAAuthority(t, now.Add(-time.Hour), now.Add(time.Hour), now.Add(2*time.Hour), digest)

		rawToken, err := tokenOf(answer)
		require.NoError(t, err)

		_, _, err = verify(rawToken, digest)
		assert.ErrorIs(t, err, ErrInvalid)
		assert.ErrorContains(t, err, "outside the validity of its certificate")
	})
}

func TestTokenOf(t *testing.T) {
	t.Run("fails if the authority has rejected the request", func(t *testing.T) {
		answer, err := asn1.Marshal(timeStampResponse{Status: pkiStatusInfo{Status: 2}})
		require.NoError(t, err)

		_, err = tokenOf(answer)
		assert.ErrorContains(t, err, "rejected the request with status 2")
	})

	t.Run("fails if the answer carries no time stamp", func(t *testing.T) {
		answer, err := asn1.Marshal(timeStampResponse{Status: pkiStatusInfo{Status: statusGranted}})
		require.NoError(t, err)

		_, err = tokenOf(answer)
		assert.ErrorContains(t, err, "carries no time stamp")
	})
}
