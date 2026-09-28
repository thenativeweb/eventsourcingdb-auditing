package trustedlists

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"fmt"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/beevik/etree"
	dsig "github.com/russellhaering/goxmldsig"
	"github.com/stretchr/testify/require"
)

// The trusted lists in testdata are real ones: the list of the lists of
// 2026-09-24, and the lists of Germany (RSA with PSS), Hungary (ECDSA with
// SHA-256), Slovenia (ECDSA with SHA-512), and Iceland (RSA with SHA-256).
var testdataByURL = map[string]string{
	ListOfTheListsURL: "eu-lotl.xml.gz",
	"https://tl.bundesnetzagentur.de/TL-DE.xml":                "de.xml.gz",
	"https://www.nmhh.hu/tl/pub/HU_TL.xml":                     "hu.xml.gz",
	"https://www.tl.gov.si/SI_TL.xml":                          "si.xml.gz",
	"https://tsl.fjarskiptastofa.is/library/skrar/tsl/tsl.xml": "is.xml.gz",
}

func readTestdata(t testing.TB, name string) []byte {
	t.Helper()

	file, err := os.Open(filepath.Join("testdata", name))
	require.NoError(t, err)
	defer file.Close()

	reader, err := gzip.NewReader(file)
	require.NoError(t, err)

	data, err := io.ReadAll(reader)
	require.NoError(t, err)

	return data
}

// testdataSource provides the trusted lists in testdata by their URLs, and
// any other list from the given map.
type testdataSource struct {
	t     testing.TB
	extra map[string][]byte
}

func (s testdataSource) Fetch(ctx context.Context, url string) ([]byte, error) {
	if data, isKnown := s.extra[url]; isKnown {
		return data, nil
	}
	if name, isKnown := testdataByURL[url]; isKnown {
		return readTestdata(s.t, name), nil
	}

	return nil, fmt.Errorf("%s is not in testdata", url)
}

// testKey is a key with a self-signed certificate, for signing test lists.
type testKey struct {
	key         *rsa.PrivateKey
	certificate *x509.Certificate
}

func newTestKey(t testing.TB, name string) testKey {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: name, Country: []string{"EU"}},
		NotBefore:    time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:     time.Date(2100, 1, 1, 0, 0, 0, 0, time.UTC),
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)

	certificate, err := x509.ParseCertificate(der)
	require.NoError(t, err)

	return testKey{key: key, certificate: certificate}
}

func (k testKey) base64() string {
	return base64.StdEncoding.EncodeToString(k.certificate.Raw)
}

// sign signs a list with an enveloped signature that covers the whole list,
// the way trusted lists are signed.
func (k testKey) sign(t testing.TB, list string) []byte {
	t.Helper()

	document := etree.NewDocument()
	require.NoError(t, document.ReadFromString(list))

	context := dsig.NewDefaultSigningContext(dsig.TLSCertKeyStore(tls.Certificate{
		Certificate: [][]byte{k.certificate.Raw},
		PrivateKey:  k.key,
	}))
	context.Canonicalizer = dsig.MakeC14N10ExclusiveCanonicalizerWithPrefixList("")

	// Without an ID, the signature references the whole list.
	context.IdAttribute = "NoID"

	signed, err := context.SignEnveloped(document.Root())
	require.NoError(t, err)
	document.SetRoot(signed)

	data, err := document.WriteToBytes()
	require.NoError(t, err)

	return data
}

// listOfTheLists writes a list of the lists that names the given pivots, and
// announces the given certificates for itself.
func listOfTheLists(pivots []string, announced ...testKey) string {
	var uris bytes.Buffer
	for _, pivot := range pivots {
		fmt.Fprintf(&uris, `<URI xml:lang="en">%s</URI>`, pivot)
	}

	var identities bytes.Buffer
	for _, key := range announced {
		fmt.Fprintf(&identities, `<ServiceDigitalIdentity><DigitalId><X509Certificate>%s</X509Certificate></DigitalId></ServiceDigitalIdentity>`, key.base64())
	}

	return fmt.Sprintf(`<TrustServiceStatusList xmlns="http://uri.etsi.org/02231/v2#"><SchemeInformation><TSLType>%s</TSLType><ListIssueDateTime>2026-09-01T00:00:00Z</ListIssueDateTime><SchemeInformationURI>%s</SchemeInformationURI><PointersToOtherTSL><OtherTSLPointer><ServiceDigitalIdentities>%s</ServiceDigitalIdentities><TSLLocation>https://example.com/lotl.xml</TSLLocation><AdditionalInformation><OtherInformation><TSLType>%s</TSLType></OtherInformation></AdditionalInformation></OtherTSLPointer></PointersToOtherTSL></SchemeInformation></TrustServiceStatusList>`,
		listTypeListOfTheLists, uris.String(), identities.String(), listTypeListOfTheLists)
}
