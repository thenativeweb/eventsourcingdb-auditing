package timestamping

import (
	"bytes"
	"crypto"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"math/big"
)

// The object identifiers of CMS (RFC 5652), of RFC 3161, and of the
// algorithms time stamps are signed with.
var (
	oidSignedData    = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}
	oidTSTInfo       = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 1, 4}
	oidContentType   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 3}
	oidMessageDigest = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 4}

	oidSHA256 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
	oidSHA384 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 2}
	oidSHA512 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 3}

	oidRSAEncryption   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 1}
	oidRSASSAPSS       = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 10}
	oidMGF1            = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 8}
	oidSHA256WithRSA   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 11}
	oidSHA384WithRSA   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 12}
	oidSHA512WithRSA   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 13}
	oidECDSAWithSHA256 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2}
	oidECDSAWithSHA384 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 3}
	oidECDSAWithSHA512 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 4}
)

type contentInfo struct {
	ContentType asn1.ObjectIdentifier
	Content     asn1.RawValue `asn1:"explicit,tag:0"`
}

type signedData struct {
	Version          int
	DigestAlgorithms []pkix.AlgorithmIdentifier `asn1:"set"`
	EncapContentInfo encapsulatedContentInfo
	Certificates     asn1.RawValue `asn1:"optional,tag:0"`
	CRLs             asn1.RawValue `asn1:"optional,tag:1"`
	SignerInfos      []signerInfo  `asn1:"set"`
}

type encapsulatedContentInfo struct {
	ContentType asn1.ObjectIdentifier
	Content     []byte `asn1:"explicit,optional,tag:0"`
}

type signerInfo struct {
	Version            int
	SignerID           asn1.RawValue
	DigestAlgorithm    pkix.AlgorithmIdentifier
	SignedAttributes   asn1.RawValue `asn1:"optional,tag:0"`
	SignatureAlgorithm pkix.AlgorithmIdentifier
	Signature          []byte
	UnsignedAttributes asn1.RawValue `asn1:"optional,tag:1"`
}

type issuerAndSerialNumber struct {
	Issuer       asn1.RawValue
	SerialNumber *big.Int
}

type attribute struct {
	Type   asn1.ObjectIdentifier
	Values []asn1.RawValue `asn1:"set"`
}

type pssParameters struct {
	Hash         pkix.AlgorithmIdentifier `asn1:"explicit,optional,tag:0"`
	MGF          pkix.AlgorithmIdentifier `asn1:"explicit,optional,tag:1"`
	SaltLength   int                      `asn1:"explicit,optional,tag:2,default:20"`
	TrailerField int                      `asn1:"explicit,optional,tag:3,default:1"`
}

// verifySignedData checks the signature of a time stamp token, which is CMS
// signed data with a single signer, and returns the TSTInfo it signs,
// together with the certificate of the signer.
func verifySignedData(token []byte) ([]byte, *x509.Certificate, error) {
	var info contentInfo
	rest, err := asn1.Unmarshal(token, &info)
	if err != nil {
		return nil, nil, err
	}
	if len(rest) > 0 {
		return nil, nil, errors.New("the time stamp token is followed by other data")
	}
	if !info.ContentType.Equal(oidSignedData) {
		return nil, nil, errors.New("the time stamp token is no signed data")
	}

	var signed signedData
	_, err = asn1.Unmarshal(info.Content.Bytes, &signed)
	if err != nil {
		return nil, nil, err
	}
	if !signed.EncapContentInfo.ContentType.Equal(oidTSTInfo) || len(signed.EncapContentInfo.Content) == 0 {
		return nil, nil, errors.New("the time stamp token carries no TSTInfo")
	}
	if len(signed.SignerInfos) != 1 {
		return nil, nil, fmt.Errorf("the time stamp token has %d signers instead of one", len(signed.SignerInfos))
	}
	signer := signed.SignerInfos[0]

	// Without the certificate of the authority, there is nothing to check
	// the signature with, so such a time stamp proves nothing here.
	if len(signed.Certificates.Bytes) == 0 {
		return nil, nil, errors.New("the time stamp carries no certificate to check its signature with")
	}
	certificates, err := x509.ParseCertificates(signed.Certificates.Bytes)
	if err != nil {
		return nil, nil, err
	}
	certificate, err := signer.certificateIn(certificates)
	if err != nil {
		return nil, nil, err
	}

	signedAttributes, err := signer.checkAttributes(signed.EncapContentInfo.Content)
	if err != nil {
		return nil, nil, err
	}

	err = checkSignature(certificate, signer.SignatureAlgorithm, signer.DigestAlgorithm, signedAttributes, signer.Signature)
	if err != nil {
		return nil, nil, fmt.Errorf("the signature of the time stamp does not match its certificate: %w", err)
	}

	return signed.EncapContentInfo.Content, certificate, nil
}

// certificateIn finds the certificate of the signer, either by its issuer and
// serial number, or by its subject key identifier.
func (s signerInfo) certificateIn(certificates []*x509.Certificate) (*x509.Certificate, error) {
	switch {
	case s.SignerID.Class == asn1.ClassUniversal && s.SignerID.Tag == asn1.TagSequence:
		var id issuerAndSerialNumber
		_, err := asn1.Unmarshal(s.SignerID.FullBytes, &id)
		if err != nil {
			return nil, err
		}

		for _, certificate := range certificates {
			if bytes.Equal(certificate.RawIssuer, id.Issuer.FullBytes) && certificate.SerialNumber.Cmp(id.SerialNumber) == 0 {
				return certificate, nil
			}
		}
	case s.SignerID.Class == asn1.ClassContextSpecific && s.SignerID.Tag == 0:
		for _, certificate := range certificates {
			if len(certificate.SubjectKeyId) > 0 && bytes.Equal(certificate.SubjectKeyId, s.SignerID.Bytes) {
				return certificate, nil
			}
		}
	}

	return nil, errors.New("the time stamp does not carry the certificate it was signed with")
}

// checkAttributes checks that the signed attributes name the TSTInfo as the
// content, and carry its digest, and returns them the way they are signed.
func (s signerInfo) checkAttributes(content []byte) ([]byte, error) {
	if len(s.SignedAttributes.FullBytes) == 0 {
		return nil, errors.New("the time stamp has no signed attributes")
	}

	// The attributes are signed as a SET, not with the tag they carry in
	// the signer info.
	signedAttributes := append([]byte{0x31}, s.SignedAttributes.FullBytes[1:]...)

	var attributes []attribute
	_, err := asn1.UnmarshalWithParams(signedAttributes, &attributes, "set")
	if err != nil {
		return nil, err
	}

	var contentType asn1.ObjectIdentifier
	err = unmarshalAttribute(attributes, oidContentType, &contentType)
	if err != nil {
		return nil, err
	}
	if !contentType.Equal(oidTSTInfo) {
		return nil, errors.New("the signed attributes name another content than the TSTInfo")
	}

	var messageDigest []byte
	err = unmarshalAttribute(attributes, oidMessageDigest, &messageDigest)
	if err != nil {
		return nil, err
	}

	hash, err := hashFor(s.DigestAlgorithm)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(messageDigest, digestOf(hash, content)) {
		return nil, errors.New("the signed attributes carry another digest than the one of the TSTInfo")
	}

	return signedAttributes, nil
}

// unmarshalAttribute reads the value of an attribute that must be there
// exactly once, with a single value.
func unmarshalAttribute(attributes []attribute, attributeType asn1.ObjectIdentifier, value any) error {
	var found *attribute
	for i, candidate := range attributes {
		if !candidate.Type.Equal(attributeType) {
			continue
		}
		if found != nil {
			return fmt.Errorf("the signed attributes carry %v more than once", attributeType)
		}
		found = &attributes[i]
	}
	if found == nil {
		return fmt.Errorf("the signed attributes lack %v", attributeType)
	}
	if len(found.Values) != 1 {
		return fmt.Errorf("the signed attribute %v has %d values instead of one", attributeType, len(found.Values))
	}

	rest, err := asn1.Unmarshal(found.Values[0].FullBytes, value)
	if err != nil {
		return err
	}
	if len(rest) > 0 {
		return fmt.Errorf("the signed attribute %v is followed by other data", attributeType)
	}

	return nil
}

// checkSignature checks a signature with RSA (PKCS #1 v1.5 or PSS) or with
// ECDSA, with SHA-256, SHA-384, or SHA-512.
func checkSignature(certificate *x509.Certificate, signatureAlgorithm, digestAlgorithm pkix.AlgorithmIdentifier, signed, signature []byte) error {
	algorithm := signatureAlgorithm.Algorithm

	if algorithm.Equal(oidRSASSAPSS) {
		return checkPSSSignature(certificate, signatureAlgorithm.Parameters, signed, signature)
	}

	byAlgorithm := map[string]x509.SignatureAlgorithm{
		oidSHA256WithRSA.String():   x509.SHA256WithRSA,
		oidSHA384WithRSA.String():   x509.SHA384WithRSA,
		oidSHA512WithRSA.String():   x509.SHA512WithRSA,
		oidECDSAWithSHA256.String(): x509.ECDSAWithSHA256,
		oidECDSAWithSHA384.String(): x509.ECDSAWithSHA384,
		oidECDSAWithSHA512.String(): x509.ECDSAWithSHA512,
	}
	if x509Algorithm, isKnown := byAlgorithm[algorithm.String()]; isKnown {
		return certificate.CheckSignature(x509Algorithm, signed, signature)
	}

	// With rsaEncryption, the signature uses the hash of the digest
	// algorithm.
	if algorithm.Equal(oidRSAEncryption) {
		byHash := map[crypto.Hash]x509.SignatureAlgorithm{
			crypto.SHA256: x509.SHA256WithRSA,
			crypto.SHA384: x509.SHA384WithRSA,
			crypto.SHA512: x509.SHA512WithRSA,
		}

		hash, err := hashFor(digestAlgorithm)
		if err != nil {
			return err
		}

		return certificate.CheckSignature(byHash[hash], signed, signature)
	}

	return fmt.Errorf("the signature algorithm %v is not supported", algorithm)
}

// checkPSSSignature checks an RSA signature with PSS, with the hash, the mask
// generation, and the salt length its parameters name.
func checkPSSSignature(certificate *x509.Certificate, rawParameters asn1.RawValue, signed, signature []byte) error {
	var parameters pssParameters
	_, err := asn1.Unmarshal(rawParameters.FullBytes, &parameters)
	if err != nil {
		return fmt.Errorf("the parameters of PSS are malformed: %v", err)
	}

	// Without a hash, PSS falls back to SHA-1, which is not accepted.
	hash, err := hashFor(parameters.Hash)
	if err != nil {
		return err
	}

	var mgfHash pkix.AlgorithmIdentifier
	if parameters.MGF.Algorithm.Equal(oidMGF1) {
		_, err = asn1.Unmarshal(parameters.MGF.Parameters.FullBytes, &mgfHash)
		if err != nil {
			return fmt.Errorf("the parameters of PSS are malformed: %v", err)
		}
	}
	if !mgfHash.Algorithm.Equal(parameters.Hash.Algorithm) {
		return errors.New("PSS is only supported with MGF1 over the same hash as the signature")
	}
	if parameters.TrailerField != 1 {
		return fmt.Errorf("the trailer field %d of PSS is not supported", parameters.TrailerField)
	}

	publicKey, isRSA := certificate.PublicKey.(*rsa.PublicKey)
	if !isRSA {
		return errors.New("the key of the certificate is no RSA key")
	}

	return rsa.VerifyPSS(publicKey, hash, digestOf(hash, signed), signature, &rsa.PSSOptions{SaltLength: parameters.SaltLength, Hash: hash})
}

func hashFor(algorithm pkix.AlgorithmIdentifier) (crypto.Hash, error) {
	switch {
	case algorithm.Algorithm.Equal(oidSHA256):
		return crypto.SHA256, nil
	case algorithm.Algorithm.Equal(oidSHA384):
		return crypto.SHA384, nil
	case algorithm.Algorithm.Equal(oidSHA512):
		return crypto.SHA512, nil
	default:
		return 0, fmt.Errorf("the hash algorithm %v is not supported", algorithm.Algorithm)
	}
}

func digestOf(hash crypto.Hash, data []byte) []byte {
	digest := hash.New()
	digest.Write(data)

	return digest.Sum(nil)
}
