package timestampingtest

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/digitorus/timestamp"
	"github.com/thenativeweb/eventsourcingdb-auditing/timestamping"
)

// Authority is a time stamping authority for tests.
type Authority struct {
	timestamping.Authority

	// Available lets a test make the authority answer with 503 for a while.
	Available atomic.Bool

	// Requests counts the time stamps the authority has been asked for.
	Requests atomic.Int64
}

// NewAuthority starts a time stamping authority that answers RFC 3161 requests
// until the test ends.
func NewAuthority(t testing.TB) *Authority {
	t.Helper()

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test Time Stamping Authority"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageTimeStamping},
		BasicConstraintsValid: true,
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		t.Fatal(err)
	}

	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}

	authority := &Authority{}
	authority.Available.Store(true)

	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		authority.Requests.Add(1)

		if !authority.Available.Load() {
			writer.WriteHeader(http.StatusServiceUnavailable)
			return
		}

		body, err := io.ReadAll(request.Body)
		if err != nil {
			writer.WriteHeader(http.StatusBadRequest)
			return
		}

		timestampRequest, err := timestamp.ParseRequest(body)
		if err != nil {
			writer.WriteHeader(http.StatusBadRequest)
			return
		}

		response, err := (&timestamp.Timestamp{
			HashAlgorithm:     timestampRequest.HashAlgorithm,
			HashedMessage:     timestampRequest.HashedMessage,
			Time:              time.Now().UTC(),
			Nonce:             timestampRequest.Nonce,
			Policy:            asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 99999, 1},
			AddTSACertificate: timestampRequest.Certificates,
		}).CreateResponseWithOpts(certificate, privateKey, crypto.SHA256)
		if err != nil {
			writer.WriteHeader(http.StatusInternalServerError)
			return
		}

		writer.Header().Set("Content-Type", "application/timestamp-reply")
		_, _ = writer.Write(response)
	}))
	t.Cleanup(server.Close)

	authority.URL = server.URL

	return authority
}
