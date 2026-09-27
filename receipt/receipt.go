package receipt

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"
)

// receiptType is the JWS type of a receipt.
const receiptType = "io.thenativeweb.custody.receipt"

// Receipt confirms that the custodian has received the fingerprint of an
// instance at a time. The receipts of an instance form a chain: each one
// carries its number and the hash of the one before, so that a missing, an
// inserted, or a changed receipt is noticed.
type Receipt struct {
	InstanceID          string    `json:"instanceId"`
	EventID             string    `json:"eventId"`
	EventHash           string    `json:"eventHash"`
	ReceivedAt          time.Time `json:"receivedAt"`
	Sequence            uint64    `json:"sequence"`
	PreviousReceiptHash string    `json:"previousReceiptHash"`
}

// Follows reports whether the receipt comes right after the given one in the
// chain of its instance. The first receipt of an instance follows none.
func (r Receipt) Follows(previousJWS string, previous Receipt) bool {
	return r.InstanceID == previous.InstanceID &&
		r.Sequence == previous.Sequence+1 &&
		r.PreviousReceiptHash == Hash(previousJWS)
}

// IsFirst reports whether the receipt is the first one of its instance.
func (r Receipt) IsFirst() bool {
	return r.Sequence == 1 && r.PreviousReceiptHash == ""
}

// SigningKey is the key the custodian signs receipts with, together with the
// certificate the root key has issued for it.
type SigningKey struct {
	PrivateKey     ed25519.PrivateKey
	Certificate    KeyCertificate
	CertificateJWS string
}

// NewSigningKey checks that the certificate belongs to the private key and has
// been signed by the root key.
func NewSigningKey(privateKey ed25519.PrivateKey, certificateJWS string, rootPublicKey ed25519.PublicKey) (SigningKey, error) {
	certificate, err := VerifyKeyCertificate(certificateJWS, rootPublicKey)
	if err != nil {
		return SigningKey{}, err
	}

	publicKey := privateKey.Public().(ed25519.PublicKey)
	if !publicKey.Equal(certificate.PublicKey) {
		return SigningKey{}, fmt.Errorf("%w: the key certificate belongs to another key", ErrInvalid)
	}

	return SigningKey{
		PrivateKey:     privateKey,
		Certificate:    certificate,
		CertificateJWS: certificateJWS,
	}, nil
}

// Sign signs a receipt. It refuses to sign outside the period of the
// certificate, since no client would accept such a receipt.
func (k SigningKey) Sign(receipt Receipt) (string, error) {
	if !k.Certificate.IsValidAt(receipt.ReceivedAt) {
		return "", fmt.Errorf("the signing key is not valid at %s", receipt.ReceivedAt.Format(time.RFC3339))
	}

	receipt.ReceivedAt = receipt.ReceivedAt.UTC()

	return sign(receipt, receiptType, k.Certificate.KeyID, k.PrivateKey)
}

// KeyIDOfReceipt returns the ID of the key a receipt claims to be signed with,
// so that the matching certificate can be looked up. It does not check the
// signature.
func KeyIDOfReceipt(jws string) (string, error) {
	jwsHeader, err := readHeader(jws, receiptType)
	if err != nil {
		return "", err
	}

	return jwsHeader.KeyID, nil
}

// Verify checks that the key of the certificate has signed a receipt within
// the period of the certificate, and returns the receipt. The certificate must
// have been verified against the root key before.
func Verify(jws string, certificate KeyCertificate) (Receipt, error) {
	jwsHeader, err := readHeader(jws, receiptType)
	if err != nil {
		return Receipt{}, err
	}
	if jwsHeader.KeyID != certificate.KeyID {
		return Receipt{}, fmt.Errorf("%w: the receipt was signed with key %q, not with key %q", ErrInvalid, jwsHeader.KeyID, certificate.KeyID)
	}

	payload, err := verifyCompact(jws, certificate.PublicKey)
	if err != nil {
		return Receipt{}, err
	}

	var receipt Receipt
	err = strictUnmarshal(payload, &receipt)
	if err != nil {
		return Receipt{}, fmt.Errorf("%w: the receipt is malformed: %v", ErrInvalid, err)
	}

	if !certificate.IsValidAt(receipt.ReceivedAt) {
		return Receipt{}, fmt.Errorf("%w: the receipt was signed outside the period of its key", ErrInvalid)
	}

	return receipt, nil
}

// ParseUnverified returns what a receipt states, without checking its
// signature. It is meant for the custodian, which reads the receipts it has
// issued itself, possibly with a key it no longer holds, and for a verification
// tool, which reports a receipt that does not verify, and then still checks
// the ones after it. Anyone else must use Verify.
func ParseUnverified(jws string) (Receipt, error) {
	_, err := readHeader(jws, receiptType)
	if err != nil {
		return Receipt{}, err
	}

	_, payload, _, err := splitCompact(jws)
	if err != nil {
		return Receipt{}, err
	}

	var parsed Receipt
	err = strictUnmarshal(payload, &parsed)
	if err != nil {
		return Receipt{}, fmt.Errorf("%w: the receipt is malformed: %v", ErrInvalid, err)
	}

	return parsed, nil
}

// Hash returns the hash by which the next receipt refers to this one. It is
// taken over the JWS as it is, so that it covers the signature as well.
func Hash(jws string) string {
	hash := sha256.Sum256([]byte(jws))
	return hex.EncodeToString(hash[:])
}
