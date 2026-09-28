package timestamping

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"math/big"
	"time"
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

var (
	oidQCStatements          = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 3}
	oidQualifiedTimeStamping = asn1.ObjectIdentifier{0, 4, 0, 19422, 1, 1}
)

type tstInfo struct {
	Version        int
	Policy         asn1.ObjectIdentifier
	MessageImprint messageImprint
	SerialNumber   *big.Int
	Time           time.Time        `asn1:"generalized"`
	Accuracy       accuracy         `asn1:"optional"`
	Ordering       bool             `asn1:"optional,default:false"`
	Nonce          *big.Int         `asn1:"optional"`
	TSA            asn1.RawValue    `asn1:"optional,tag:0"`
	Extensions     []pkix.Extension `asn1:"optional,tag:1"`
}

type messageImprint struct {
	HashAlgorithm pkix.AlgorithmIdentifier
	HashedMessage []byte
}

type accuracy struct {
	Seconds      int `asn1:"optional"`
	Milliseconds int `asn1:"optional,tag:0"`
	Microseconds int `asn1:"optional,tag:1"`
}

type qcStatement struct {
	StatementID   asn1.ObjectIdentifier
	StatementInfo asn1.RawValue `asn1:"optional"`
}

// Verify checks that a time stamp token covers the given digest, and that its
// signature matches the certificate it carries.
func Verify(raw []byte, digest [sha256.Size]byte) (Token, error) {
	token, _, err := verify(raw, digest)

	return token, err
}

// verify is Verify, but also returns the TSTInfo, whose nonce Stamp checks.
func verify(raw []byte, digest [sha256.Size]byte) (Token, tstInfo, error) {
	content, certificate, err := verifySignedData(raw)
	if err != nil {
		return Token{}, tstInfo{}, fmt.Errorf("%w: %v", ErrInvalid, err)
	}

	var info tstInfo
	rest, err := asn1.Unmarshal(content, &info)
	if err != nil {
		return Token{}, tstInfo{}, fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	if len(rest) > 0 {
		return Token{}, tstInfo{}, fmt.Errorf("%w: the TSTInfo is followed by other data", ErrInvalid)
	}

	if !info.MessageImprint.HashAlgorithm.Algorithm.Equal(oidSHA256) {
		return Token{}, tstInfo{}, fmt.Errorf("%w: expected SHA-256, got %v", ErrInvalid, info.MessageImprint.HashAlgorithm.Algorithm)
	}
	if !bytes.Equal(info.MessageImprint.HashedMessage, digest[:]) {
		return Token{}, tstInfo{}, fmt.Errorf("%w: the time stamp covers another digest", ErrInvalid)
	}
	if info.Time.Before(certificate.NotBefore) || info.Time.After(certificate.NotAfter) {
		return Token{}, tstInfo{}, fmt.Errorf("%w: the time stamp was issued at %s, outside the validity of its certificate", ErrInvalid, info.Time.Format(time.RFC3339))
	}

	return Token{
		Raw:         raw,
		Time:        info.Time,
		IsQualified: claimsQualified(info.Extensions),
		Certificate: certificate,
	}, info, nil
}

// claimsQualified reports whether a time stamp carries the statement of ETSI
// EN 319 422 that it is a qualified electronic time stamp.
func claimsQualified(extensions []pkix.Extension) bool {
	for _, extension := range extensions {
		if !extension.Id.Equal(oidQCStatements) {
			continue
		}

		var statements []qcStatement
		_, err := asn1.Unmarshal(extension.Value, &statements)
		if err != nil {
			return false
		}

		for _, statement := range statements {
			if statement.StatementID.Equal(oidQualifiedTimeStamping) {
				return true
			}
		}
	}

	return false
}
