package receipt

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
)

// algorithm is the only algorithm this package signs with and accepts.
const algorithm = "EdDSA"

// header is the protected header of a JWS.
type header struct {
	Algorithm string `json:"alg"`
	Type      string `json:"typ"`
	KeyID     string `json:"kid"`
}

// signCompact signs a payload and returns the JWS in compact form. The header
// is given as bytes, because the signature covers exactly these bytes.
func signCompact(protectedHeader, payload []byte, privateKey ed25519.PrivateKey) string {
	signingInput := base64.RawURLEncoding.EncodeToString(protectedHeader) + "." + base64.RawURLEncoding.EncodeToString(payload)
	signature := ed25519.Sign(privateKey, []byte(signingInput))

	return signingInput + "." + base64.RawURLEncoding.EncodeToString(signature)
}

// splitCompact takes a JWS in compact form apart, without checking its
// signature.
func splitCompact(jws string) ([]byte, []byte, []byte, error) {
	parts := strings.Split(jws, ".")
	if len(parts) != 3 {
		return nil, nil, nil, fmt.Errorf("%w: a JWS in compact form has three parts, got %d", ErrInvalid, len(parts))
	}

	decoded := make([][]byte, 3)
	for i, part := range parts {
		value, err := base64.RawURLEncoding.DecodeString(part)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("%w: part %d is not base64url: %v", ErrInvalid, i+1, err)
		}
		decoded[i] = value
	}

	return decoded[0], decoded[1], decoded[2], nil
}

// verifyCompact checks the signature of a JWS in compact form, and returns
// its payload.
func verifyCompact(jws string, publicKey ed25519.PublicKey) ([]byte, error) {
	_, payload, signature, err := splitCompact(jws)
	if err != nil {
		return nil, err
	}

	signingInput := jws[:strings.LastIndex(jws, ".")]
	if !ed25519.Verify(publicKey, []byte(signingInput), signature) {
		return nil, fmt.Errorf("%w: the signature does not match", ErrInvalid)
	}

	return payload, nil
}

// sign signs claims as a JWS of the given type, with the given key.
func sign(claims any, jwsType, keyID string, privateKey ed25519.PrivateKey) (string, error) {
	protectedHeader, err := json.Marshal(header{
		Algorithm: algorithm,
		Type:      jwsType,
		KeyID:     keyID,
	})
	if err != nil {
		return "", err
	}

	payload, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}

	return signCompact(protectedHeader, payload, privateKey), nil
}

// readHeader returns the protected header of a JWS, and checks that it uses
// the only algorithm this package accepts, and the expected type. It does not
// check the signature, which needs the key that the header names.
func readHeader(jws, jwsType string) (header, error) {
	protectedHeader, _, _, err := splitCompact(jws)
	if err != nil {
		return header{}, err
	}

	var jwsHeader header
	err = strictUnmarshal(protectedHeader, &jwsHeader)
	if err != nil {
		return header{}, fmt.Errorf("%w: the header is malformed: %v", ErrInvalid, err)
	}

	if jwsHeader.Algorithm != algorithm {
		return header{}, fmt.Errorf("%w: expected algorithm %q, got %q", ErrInvalid, algorithm, jwsHeader.Algorithm)
	}
	if jwsHeader.Type != jwsType {
		return header{}, fmt.Errorf("%w: expected type %q, got %q", ErrInvalid, jwsType, jwsHeader.Type)
	}
	if jwsHeader.KeyID == "" {
		return header{}, fmt.Errorf("%w: the header does not name a key", ErrInvalid)
	}

	return jwsHeader, nil
}

// strictUnmarshal decodes JSON and rejects unknown fields, so that a header or
// a payload can not carry anything that this package would silently ignore.
func strictUnmarshal(data []byte, value any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()

	return decoder.Decode(value)
}
