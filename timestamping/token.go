package timestamping

import (
	"bytes"
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"fmt"
	"time"

	"github.com/digitorus/pkcs7"
	"github.com/digitorus/timestamp"
)

// Token is a time stamp, as the time stamping authority has signed it.
type Token struct {
	// Raw is the time stamp token in DER form, which is what an auditor
	// checks.
	Raw []byte

	// Time is the time the authority has put into the time stamp.
	Time time.Time

	// IsQualified reports whether the time stamp claims to be qualified.
	// Only the certificate of the authority can confirm that.
	IsQualified bool

	// Certificate is the certificate the time stamp was signed with, that
	// is, the one of the time stamping unit of the authority. Whether it
	// belongs to a qualified trust service is up to the EU trusted lists.
	Certificate *x509.Certificate
}

// ErrInvalid means that a time stamp does not cover the expected digest, or
// that its signature does not match. Check for it with errors.Is.
var ErrInvalid = errors.New("invalid time stamp")

// Verify checks that a time stamp token covers the given digest, and that its
// signature matches the certificate it carries.
func Verify(raw []byte, digest [sha256.Size]byte) (Token, error) {
	parsed, err := timestamp.Parse(raw)
	if err != nil {
		return Token{}, fmt.Errorf("%w: %v", ErrInvalid, err)
	}

	return check(parsed, digest)
}

func check(parsed *timestamp.Timestamp, digest [sha256.Size]byte) (Token, error) {
	// Without the certificate of the authority, the library does not check
	// the signature at all, so such a time stamp proves nothing here.
	if len(parsed.Certificates) == 0 {
		return Token{}, fmt.Errorf("%w: the time stamp carries no certificate to check its signature with", ErrInvalid)
	}
	if parsed.HashAlgorithm != crypto.SHA256 {
		return Token{}, fmt.Errorf("%w: expected SHA-256, got %v", ErrInvalid, parsed.HashAlgorithm)
	}
	if !bytes.Equal(parsed.HashedMessage, digest[:]) {
		return Token{}, fmt.Errorf("%w: the time stamp covers another digest", ErrInvalid)
	}

	signed, err := pkcs7.Parse(parsed.RawToken)
	if err != nil {
		return Token{}, fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	certificate := signed.GetOnlySigner()
	if certificate == nil {
		return Token{}, fmt.Errorf("%w: the time stamp does not carry the certificate it was signed with", ErrInvalid)
	}

	return Token{
		Raw:         parsed.RawToken,
		Time:        parsed.Time,
		IsQualified: parsed.Qualified,
		Certificate: certificate,
	}, nil
}
