package receipt

import (
	"crypto/sha256"
	"fmt"
	"time"
)

// anchorType is the JWS type of an anchor.
const anchorType = "io.thenativeweb.custody.anchor"

// Anchor is the hourly statement of the custodian: the root of the Merkle tree
// over the latest receipt of every instance in that hour. The anchors form a
// chain, since each one carries the hash of the one before, so that no anchor
// can be replaced or left out without being noticed.
type Anchor struct {
	Hour               time.Time `json:"hour"`
	Root               string    `json:"root"`
	LeafCount          int       `json:"leafCount"`
	PreviousAnchorHash string    `json:"previousAnchorHash"`
}

// Follows reports whether the anchor comes right after the given one. The
// first anchor follows none.
func (a Anchor) Follows(previousJWS string, previous Anchor) bool {
	return a.PreviousAnchorHash == Hash(previousJWS) && a.Hour.After(previous.Hour)
}

// IsFirst reports whether the anchor is the first one of the custodian.
func (a Anchor) IsFirst() bool {
	return a.PreviousAnchorHash == ""
}

// SignAnchor signs an anchor.
func (k SigningKey) SignAnchor(anchor Anchor, at time.Time) (string, error) {
	if !k.Certificate.IsValidAt(at) {
		return "", fmt.Errorf("the signing key is not valid at %s", at.Format(time.RFC3339))
	}

	anchor.Hour = anchor.Hour.UTC()

	return sign(anchor, anchorType, k.Certificate.KeyID, k.PrivateKey)
}

// KeyIDOfAnchor returns the ID of the key an anchor claims to be signed with.
// It does not check the signature.
func KeyIDOfAnchor(jws string) (string, error) {
	jwsHeader, err := readHeader(jws, anchorType)
	if err != nil {
		return "", err
	}

	return jwsHeader.KeyID, nil
}

// VerifyAnchor checks that the key of the certificate has signed an anchor, and
// returns the anchor. The certificate must have been verified against the root
// key before.
func VerifyAnchor(jws string, certificate KeyCertificate) (Anchor, error) {
	jwsHeader, err := readHeader(jws, anchorType)
	if err != nil {
		return Anchor{}, err
	}
	if jwsHeader.KeyID != certificate.KeyID {
		return Anchor{}, fmt.Errorf("%w: the anchor was signed with key %q, not with key %q", ErrInvalid, jwsHeader.KeyID, certificate.KeyID)
	}

	payload, err := verifyCompact(jws, certificate.PublicKey)
	if err != nil {
		return Anchor{}, err
	}

	var anchor Anchor
	err = strictUnmarshal(payload, &anchor)
	if err != nil {
		return Anchor{}, fmt.Errorf("%w: the anchor is malformed: %v", ErrInvalid, err)
	}

	return anchor, nil
}

// Digest returns the SHA-256 digest of a JWS, which is what a time stamping
// authority stamps for an anchor.
func Digest(jws string) [sha256.Size]byte {
	return sha256.Sum256([]byte(jws))
}
