package trustedlists

import (
	"bytes"
	"crypto"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/xml"
	"errors"
	"fmt"
	"math/big"
	"strings"

	"github.com/beevik/etree"
	dsig "github.com/russellhaering/goxmldsig"
	"github.com/russellhaering/goxmldsig/etreeutils"
)

const (
	envelopedSignatureTransform = "http://www.w3.org/2000/09/xmldsig#enveloped-signature"
	exclusiveCanonicalization   = "http://www.w3.org/2001/10/xml-exc-c14n#"
	inclusiveCanonicalization   = "http://www.w3.org/TR/2001/REC-xml-c14n-20010315"
)

// digestAlgorithms are the digests a reference may use. SHA-1 is not among
// them on purpose.
var digestAlgorithms = map[string]crypto.Hash{
	"http://www.w3.org/2001/04/xmlenc#sha256":       crypto.SHA256,
	"http://www.w3.org/2001/04/xmldsig-more#sha384": crypto.SHA384,
	"http://www.w3.org/2001/04/xmlenc#sha512":       crypto.SHA512,
}

// signatureAlgorithm is how a signature method is checked.
type signatureAlgorithm struct {
	x509  x509.SignatureAlgorithm
	ecdsa bool

	// pss is the hash of an RSA signature with PSS, which is checked
	// separately, since Go can not use a certificate whose key is marked
	// for PSS only, as the one of the German trusted list is.
	pss crypto.Hash
}

// signatureAlgorithms are the signature methods a trusted list may use. RSA
// with PSS (RFC 6931) is among them, since the German trusted list uses it.
var signatureAlgorithms = map[string]signatureAlgorithm{
	"http://www.w3.org/2001/04/xmldsig-more#rsa-sha256":      {x509: x509.SHA256WithRSA},
	"http://www.w3.org/2001/04/xmldsig-more#rsa-sha384":      {x509: x509.SHA384WithRSA},
	"http://www.w3.org/2001/04/xmldsig-more#rsa-sha512":      {x509: x509.SHA512WithRSA},
	"http://www.w3.org/2007/05/xmldsig-more#sha256-rsa-MGF1": {pss: crypto.SHA256},
	"http://www.w3.org/2007/05/xmldsig-more#sha384-rsa-MGF1": {pss: crypto.SHA384},
	"http://www.w3.org/2007/05/xmldsig-more#sha512-rsa-MGF1": {pss: crypto.SHA512},
	"http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256":    {x509: x509.ECDSAWithSHA256, ecdsa: true},
	"http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384":    {x509: x509.ECDSAWithSHA384, ecdsa: true},
	"http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha512":    {x509: x509.ECDSAWithSHA512, ecdsa: true},
}

type signedInfo struct {
	CanonicalizationMethod algorithmAttribute `xml:"CanonicalizationMethod"`
	SignatureMethod        algorithmAttribute `xml:"SignatureMethod"`
	References             []reference        `xml:"Reference"`
}

type algorithmAttribute struct {
	Algorithm string `xml:"Algorithm,attr"`
}

type reference struct {
	URI          string             `xml:"URI,attr"`
	Transforms   []transform        `xml:"Transforms>Transform"`
	DigestMethod algorithmAttribute `xml:"DigestMethod"`
	DigestValue  string             `xml:"DigestValue"`
}

type transform struct {
	Algorithm           string `xml:"Algorithm,attr"`
	InclusiveNamespaces *struct {
		PrefixList string `xml:"PrefixList,attr"`
	} `xml:"InclusiveNamespaces"`
}

// ErrInvalidSignature means that the signature of a trusted list does not
// verify.
var ErrInvalidSignature = errors.New("the signature of the trusted list does not verify")

// verifySignature checks the enveloped signature of a trusted list: that it
// covers the whole list, that every reference it signs matches, and that its
// value matches the certificate it names. It returns that certificate, which
// the caller still has to trust.
func verifySignature(data []byte) (*x509.Certificate, error) {
	document := etree.NewDocument()
	err := document.ReadFromBytes(data)
	if err != nil {
		return nil, fmt.Errorf("%w: the list is not XML: %v", ErrInvalidSignature, err)
	}
	root := document.Root()
	if root == nil {
		return nil, fmt.Errorf("%w: the list is empty", ErrInvalidSignature)
	}

	signatureElement, signatureContext, err := findSignature(root)
	if err != nil {
		return nil, err
	}

	canonicalSignedInfo, err := canonicalizeSignedInfo(signatureElement, signatureContext)
	if err != nil {
		return nil, err
	}

	var info signedInfo
	err = xml.Unmarshal(canonicalSignedInfo, &info)
	if err != nil {
		return nil, fmt.Errorf("%w: the signed info is malformed: %v", ErrInvalidSignature, err)
	}

	certificate, err := checkSignatureValue(signatureElement, info, canonicalSignedInfo)
	if err != nil {
		return nil, err
	}

	coversDocument := false
	for _, ref := range info.References {
		err := checkReference(root, signatureElement, ref)
		if err != nil {
			return nil, err
		}
		if ref.URI == "" {
			coversDocument = true
		}
	}
	if !coversDocument {
		return nil, fmt.Errorf("%w: the signature does not cover the whole list", ErrInvalidSignature)
	}

	return certificate, nil
}

// findSignature finds the one signature among the children of the root.
func findSignature(root *etree.Element) (*etree.Element, etreeutils.NSContext, error) {
	var found *etree.Element
	var foundContext etreeutils.NSContext
	count := 0

	rootContext, err := etreeutils.NSBuildParentContext(root)
	if err != nil {
		return nil, foundContext, fmt.Errorf("%w: %v", ErrInvalidSignature, err)
	}

	err = etreeutils.NSFindChildrenIterateCtx(rootContext, root, dsig.Namespace, dsig.SignatureTag, func(ctx etreeutils.NSContext, element *etree.Element) error {
		count++
		found, foundContext = element, ctx
		return nil
	})
	if err != nil {
		return nil, foundContext, fmt.Errorf("%w: %v", ErrInvalidSignature, err)
	}

	switch count {
	case 0:
		return nil, foundContext, fmt.Errorf("%w: the list is not signed", ErrInvalidSignature)
	case 1:
		return found, foundContext, nil
	default:
		return nil, foundContext, fmt.Errorf("%w: the list has %d signatures", ErrInvalidSignature, count)
	}
}

// canonicalizeSignedInfo detaches the signed info from the document together
// with the namespaces it uses, and canonicalizes it the way it names.
func canonicalizeSignedInfo(signatureElement *etree.Element, signatureContext etreeutils.NSContext) ([]byte, error) {
	var canonical []byte

	err := etreeutils.NSFindChildrenIterateCtx(signatureContext, signatureElement, dsig.Namespace, dsig.SignedInfoTag, func(ctx etreeutils.NSContext, element *etree.Element) error {
		detached, err := etreeutils.NSDetatch(ctx, element)
		if err != nil {
			return err
		}

		method, err := etreeutils.NSFindOneChildCtx(ctx, detached, dsig.Namespace, dsig.CanonicalizationMethodTag)
		if err != nil {
			return err
		}
		if method == nil {
			return errors.New("the signed info names no canonicalization")
		}

		canonicalizer, err := canonicalizerFor(method.SelectAttrValue(dsig.AlgorithmAttr, ""), "")
		if err != nil {
			return err
		}

		canonical, err = canonicalizer.Canonicalize(detached)
		if err != nil {
			return err
		}

		return etreeutils.ErrTraversalHalted
	})
	if err != nil && !errors.Is(err, etreeutils.ErrTraversalHalted) {
		return nil, fmt.Errorf("%w: %v", ErrInvalidSignature, err)
	}
	if canonical == nil {
		return nil, fmt.Errorf("%w: the signature has no signed info", ErrInvalidSignature)
	}

	return canonical, nil
}

func canonicalizerFor(algorithm, prefixList string) (dsig.Canonicalizer, error) {
	switch algorithm {
	case exclusiveCanonicalization:
		return dsig.MakeC14N10ExclusiveCanonicalizerWithPrefixList(prefixList), nil
	case inclusiveCanonicalization:
		return dsig.MakeC14N10RecCanonicalizer(), nil
	default:
		return nil, fmt.Errorf("the canonicalization %q is not supported", algorithm)
	}
}

// checkSignatureValue checks the value of the signature over the canonical
// signed info with the certificate the signature names.
func checkSignatureValue(signatureElement *etree.Element, info signedInfo, canonicalSignedInfo []byte) (*x509.Certificate, error) {
	algorithm, isSupported := signatureAlgorithms[info.SignatureMethod.Algorithm]
	if !isSupported {
		return nil, fmt.Errorf("%w: the signature method %q is not supported", ErrInvalidSignature, info.SignatureMethod.Algorithm)
	}

	valueElement := childElement(signatureElement, "SignatureValue")
	if valueElement == nil {
		return nil, fmt.Errorf("%w: the signature has no value", ErrInvalidSignature)
	}
	value, err := base64.StdEncoding.DecodeString(stripWhitespace(valueElement.Text()))
	if err != nil {
		return nil, fmt.Errorf("%w: the value of the signature is not base64", ErrInvalidSignature)
	}

	certificateElement := signatureElement.FindElement("./KeyInfo/X509Data/X509Certificate")
	if certificateElement == nil {
		return nil, fmt.Errorf("%w: the signature names no certificate", ErrInvalidSignature)
	}
	certificateDER, err := base64.StdEncoding.DecodeString(stripWhitespace(certificateElement.Text()))
	if err != nil {
		return nil, fmt.Errorf("%w: the certificate of the signature is not base64", ErrInvalidSignature)
	}
	certificate, err := x509.ParseCertificate(certificateDER)
	if err != nil {
		return nil, fmt.Errorf("%w: the certificate of the signature is malformed: %v", ErrInvalidSignature, err)
	}

	if algorithm.pss != 0 {
		err = checkPSSSignature(certificate, algorithm.pss, canonicalSignedInfo, value)
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrInvalidSignature, err)
		}

		return certificate, nil
	}

	if algorithm.ecdsa {
		value, err = ecdsaSignatureToASN1(value)
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrInvalidSignature, err)
		}
	}

	err = certificate.CheckSignature(algorithm.x509, canonicalSignedInfo, value)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidSignature, err)
	}

	return certificate, nil
}

// checkPSSSignature checks an RSA signature with PSS. The key is read from
// the certificate directly, whether it is marked as an RSA key or as one for
// PSS only, since both hold the same RSA public key.
func checkPSSSignature(certificate *x509.Certificate, hash crypto.Hash, signed, value []byte) error {
	publicKey, isRSA := certificate.PublicKey.(*rsa.PublicKey)
	if !isRSA {
		var info struct {
			Algorithm pkix.AlgorithmIdentifier
			PublicKey asn1.BitString
		}
		_, err := asn1.Unmarshal(certificate.RawSubjectPublicKeyInfo, &info)
		if err != nil {
			return fmt.Errorf("the key of the certificate is malformed: %v", err)
		}
		if !info.Algorithm.Algorithm.Equal(oidRSAEncryption) && !info.Algorithm.Algorithm.Equal(oidRSASSAPSS) {
			return fmt.Errorf("the key of the certificate is no RSA key")
		}

		publicKey, err = x509.ParsePKCS1PublicKey(info.PublicKey.Bytes)
		if err != nil {
			return fmt.Errorf("the key of the certificate is malformed: %v", err)
		}
	}

	digest := hash.New()
	digest.Write(signed)

	return rsa.VerifyPSS(publicKey, hash, digest.Sum(nil), value, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthAuto, Hash: hash})
}

var (
	oidRSAEncryption = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 1}
	oidRSASSAPSS     = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 10}
)

// ecdsaSignatureToASN1 turns an ECDSA signature the way XML signatures write
// it, r and s of equal length one after the other, into the ASN.1 form Go
// checks.
func ecdsaSignatureToASN1(value []byte) ([]byte, error) {
	if len(value) == 0 || len(value)%2 != 0 {
		return nil, errors.New("the ECDSA signature has an odd length")
	}

	half := len(value) / 2

	return asn1.Marshal(struct{ R, S *big.Int }{
		R: new(big.Int).SetBytes(value[:half]),
		S: new(big.Int).SetBytes(value[half:]),
	})
}

// checkReference checks that the digest of a reference matches what it
// references.
func checkReference(root, signatureElement *etree.Element, ref reference) error {
	hash, isSupported := digestAlgorithms[ref.DigestMethod.Algorithm]
	if !isSupported {
		return fmt.Errorf("%w: the digest method %q is not supported", ErrInvalidSignature, ref.DigestMethod.Algorithm)
	}

	expected, err := base64.StdEncoding.DecodeString(stripWhitespace(ref.DigestValue))
	if err != nil {
		return fmt.Errorf("%w: a digest is not base64", ErrInvalidSignature)
	}

	target, err := referencedElement(root, signatureElement, ref)
	if err != nil {
		return err
	}

	canonicalizer := dsig.Canonicalizer(dsig.MakeC14N10RecCanonicalizer())
	for _, step := range ref.Transforms {
		if step.Algorithm == envelopedSignatureTransform {
			continue
		}

		prefixList := ""
		if step.InclusiveNamespaces != nil {
			prefixList = step.InclusiveNamespaces.PrefixList
		}
		canonicalizer, err = canonicalizerFor(step.Algorithm, prefixList)
		if err != nil {
			return fmt.Errorf("%w: %v", ErrInvalidSignature, err)
		}
	}

	canonical, err := canonicalizer.Canonicalize(target)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidSignature, err)
	}

	digest := hash.New()
	digest.Write(canonical)
	if !bytes.Equal(digest.Sum(nil), expected) {
		return fmt.Errorf("%w: the digest of reference %q does not match, so the list has been changed", ErrInvalidSignature, ref.URI)
	}

	return nil
}

// referencedElement returns a copy of what a reference points to: the whole
// list without its signature for an empty URI, or the element with the given
// ID, together with the namespaces it uses.
func referencedElement(root, signatureElement *etree.Element, ref reference) (*etree.Element, error) {
	if ref.URI == "" {
		isEnveloped := false
		for _, step := range ref.Transforms {
			isEnveloped = isEnveloped || step.Algorithm == envelopedSignatureTransform
		}
		if !isEnveloped {
			return nil, fmt.Errorf("%w: the reference to the whole list does not leave out the signature", ErrInvalidSignature)
		}

		copied := root.Copy()
		copied.RemoveChildAt(signatureElement.Index())

		return copied, nil
	}

	id, isLocal := strings.CutPrefix(ref.URI, "#")
	if !isLocal || id == "" {
		return nil, fmt.Errorf("%w: the reference %q does not point into the list", ErrInvalidSignature, ref.URI)
	}

	var found []*etree.Element
	for _, element := range root.FindElements("//*") {
		if element.SelectAttrValue("Id", "") == id {
			found = append(found, element)
		}
	}
	if len(found) != 1 {
		return nil, fmt.Errorf("%w: the reference %q points to %d elements", ErrInvalidSignature, ref.URI, len(found))
	}

	context, err := etreeutils.NSBuildParentContext(found[0])
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidSignature, err)
	}

	detached, err := etreeutils.NSDetatch(context, found[0])
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidSignature, err)
	}

	return detached, nil
}

func childElement(parent *etree.Element, tag string) *etree.Element {
	for _, child := range parent.ChildElements() {
		if child.Tag == tag {
			return child
		}
	}

	return nil
}

func stripWhitespace(value string) string {
	return strings.Join(strings.Fields(value), "")
}
