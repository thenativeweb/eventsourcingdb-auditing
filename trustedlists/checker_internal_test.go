package trustedlists

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/thenativeweb/eventsourcingdb-auditing/trustedlists/trustedliststest"
)

// dgnCertificate returns the certificate of a time stamping unit of DGN, as the
// German trusted list names it.
func dgnCertificate(t *testing.T) *x509.Certificate {
	t.Helper()

	list, err := parseList(readTestdata(t, "de.xml.gz"))
	require.NoError(t, err)

	for _, provider := range list.Providers {
		if !strings.Contains(firstName(provider.Names), "DGN") {
			continue
		}
		for _, listed := range provider.Services {
			if listed.Information.TypeIdentifier != serviceTypeQTST {
				continue
			}
			certificates := listed.Information.Identity.certificates()
			if len(certificates) > 0 {
				return certificates[0]
			}
		}
	}

	require.FailNow(t, "the German trusted list names no time stamping service of DGN")
	return nil
}

// newCertificate returns a certificate for the given subject, issued by the
// given certificate, or self-signed without one.
func newCertificate(t *testing.T, subject pkix.Name, issuer *x509.Certificate, issuerKey *rsa.PrivateKey) (*x509.Certificate, *rsa.PrivateKey) {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               subject,
		NotBefore:             time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:              time.Date(2100, 1, 1, 0, 0, 0, 0, time.UTC),
		IsCA:                  issuer == nil,
		BasicConstraintsValid: true,
	}
	if issuer == nil {
		issuer, issuerKey = template, key
	}

	der, err := x509.CreateCertificate(rand.Reader, template, issuer, &key.PublicKey, issuerKey)
	require.NoError(t, err)

	certificate, err := x509.ParseCertificate(der)
	require.NoError(t, err)

	return certificate, key
}

func newTestdataChecker(t *testing.T) *Checker {
	t.Helper()

	checker, err := NewChecker(t.Context(), trustedliststest.Source{})
	require.NoError(t, err)

	return checker
}

func TestNewChecker(t *testing.T) {
	t.Run("trusts the list of the lists signed with a certificate announced in the Official Journal", func(t *testing.T) {
		checker := newTestdataChecker(t)

		assert.Equal(t, time.Date(2026, 9, 24, 12, 4, 6, 0, time.UTC), checker.ListOfTheListsIssuedAt())
	})

	t.Run("follows the pivots to a certificate that is announced later", func(t *testing.T) {
		oldKey, newKey := newTestKey(t, "Old LOTL Signer"), newTestKey(t, "New LOTL Signer")
		source := trustedliststest.Source{Extra: map[string][]byte{
			"https://example.com/lotl.xml":    newKey.sign(t, listOfTheLists([]string{"https://example.com/pivot-2.xml", "https://example.com/pivot-1.xml"}, newKey)),
			"https://example.com/pivot-2.xml": newKey.sign(t, listOfTheLists(nil, newKey)),
			"https://example.com/pivot-1.xml": oldKey.sign(t, listOfTheLists(nil, newKey)),
		}}

		_, err := NewChecker(t.Context(), source, WithListOfTheLists("https://example.com/lotl.xml", fingerprint(oldKey.certificate)))

		assert.NoError(t, err)
	})

	t.Run("does not trust a certificate announced by a pivot it does not trust", func(t *testing.T) {
		oldKey, newKey, strangerKey := newTestKey(t, "Old LOTL Signer"), newTestKey(t, "New LOTL Signer"), newTestKey(t, "Stranger")
		source := trustedliststest.Source{Extra: map[string][]byte{
			"https://example.com/lotl.xml":    newKey.sign(t, listOfTheLists([]string{"https://example.com/pivot-1.xml"}, newKey)),
			"https://example.com/pivot-1.xml": strangerKey.sign(t, listOfTheLists(nil, newKey)),
		}}

		_, err := NewChecker(t.Context(), source, WithListOfTheLists("https://example.com/lotl.xml", fingerprint(oldKey.certificate)))

		assert.ErrorIs(t, err, ErrUntrustedList)
	})

	t.Run("does not trust a list of another type", func(t *testing.T) {
		key := newTestKey(t, "LOTL Signer")
		list := strings.Replace(listOfTheLists(nil), "<TSLType>"+listTypeListOfTheLists, "<TSLType>"+listTypeGeneric, 1)
		source := trustedliststest.Source{Extra: map[string][]byte{"https://example.com/lotl.xml": key.sign(t, list)}}

		_, err := NewChecker(t.Context(), source, WithListOfTheLists("https://example.com/lotl.xml", fingerprint(key.certificate)))

		assert.ErrorContains(t, err, "has the type")
	})

	t.Run("fails if the list of the lists can not be fetched", func(t *testing.T) {
		_, err := NewChecker(t.Context(), trustedliststest.Source{}, WithListOfTheLists("https://example.com/missing.xml"))

		assert.ErrorContains(t, err, "is not among the lists of trustedliststest")
	})
}

func TestQualification(t *testing.T) {
	checker := newTestdataChecker(t)
	dgn := dgnCertificate(t)

	t.Run("confirms a time stamping service of DGN as qualified", func(t *testing.T) {
		qualification, err := checker.Qualification(t.Context(), dgn, time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC))

		require.NoError(t, err)
		assert.True(t, qualification.IsQualified)
		assert.Equal(t, "DE", qualification.Country)
		assert.Contains(t, qualification.Provider, "DGN")
		assert.Equal(t, "DGN Zeitstempelservice", qualification.Service)
		assert.False(t, qualification.ListIssuedAt.IsZero())
	})

	t.Run("does not confirm a service before it was listed", func(t *testing.T) {
		qualification, err := checker.Qualification(t.Context(), dgn, time.Date(2010, 1, 1, 0, 0, 0, 0, time.UTC))

		require.NoError(t, err)
		assert.False(t, qualification.IsQualified)
		assert.Contains(t, qualification.Reason, "names no qualified time stamping service")
	})

	t.Run("does not confirm a certificate the trusted list does not name", func(t *testing.T) {
		stranger, _ := newCertificate(t, pkix.Name{CommonName: "Stranger", Country: []string{"DE"}}, nil, nil)

		qualification, err := checker.Qualification(t.Context(), stranger, time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC))

		require.NoError(t, err)
		assert.False(t, qualification.IsQualified)
		assert.Contains(t, qualification.Reason, "the trusted list of DE names no qualified time stamping service")
	})

	t.Run("does not confirm a certificate of a country without a trusted list", func(t *testing.T) {
		stranger, _ := newCertificate(t, pkix.Name{CommonName: "Stranger", Country: []string{"ZZ"}}, nil, nil)

		qualification, err := checker.Qualification(t.Context(), stranger, time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC))

		require.NoError(t, err)
		assert.False(t, qualification.IsQualified)
		assert.Contains(t, qualification.Reason, "there is no trusted list for ZZ")
	})

	t.Run("does not confirm a certificate without a country", func(t *testing.T) {
		stranger, _ := newCertificate(t, pkix.Name{CommonName: "Stranger"}, nil, nil)

		qualification, err := checker.Qualification(t.Context(), stranger, time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC))

		require.NoError(t, err)
		assert.Contains(t, qualification.Reason, "names no country")
	})

	t.Run("fails if the trusted list of the country can not be fetched", func(t *testing.T) {
		french, _ := newCertificate(t, pkix.Name{CommonName: "Horodatage", Country: []string{"FR"}}, nil, nil)

		_, err := checker.Qualification(t.Context(), french, time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC))

		assert.ErrorContains(t, err, "is not among the lists of trustedliststest")
	})
}

func TestQualificationIn(t *testing.T) {
	authority, authorityKey := newCertificate(t, pkix.Name{CommonName: "Time Stamping CA", Country: []string{"DE"}}, nil, nil)
	unit, _ := newCertificate(t, pkix.Name{CommonName: "Time Stamping Unit", Country: []string{"DE"}}, authority, authorityKey)

	withdrawnAt := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	list := trustedList{Providers: []provider{{
		Names: []string{"Example Trust"},
		Services: []service{{
			Information: serviceInformation{
				TypeIdentifier:     serviceTypeQTST,
				Names:              []string{"Example Time Stamps"},
				Identity:           digitalIdentity{IDs: []digitalID{{X509Certificate: base64Of(authority)}}},
				Status:             "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/withdrawn",
				StatusStartingTime: withdrawnAt,
			},
			History: []serviceInformation{{
				TypeIdentifier:     serviceTypeQTST,
				Names:              []string{"Example Time Stamps"},
				Identity:           digitalIdentity{IDs: []digitalID{{X509Certificate: base64Of(authority)}}},
				Status:             serviceStatusGranted,
				StatusStartingTime: time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC),
			}},
		}},
	}}}

	t.Run("confirms a certificate issued by the listed one while the service was granted", func(t *testing.T) {
		qualification, isListed := qualificationIn(list, unit, withdrawnAt.Add(-time.Hour))

		assert.True(t, isListed)
		assert.True(t, qualification.IsQualified)
		assert.Equal(t, "Example Trust", qualification.Provider)
	})

	t.Run("does not confirm it after the service was withdrawn", func(t *testing.T) {
		qualification, isListed := qualificationIn(list, unit, withdrawnAt.Add(time.Hour))

		assert.True(t, isListed)
		assert.False(t, qualification.IsQualified)
		assert.Contains(t, qualification.Reason, "withdrawn")
	})
}

func base64Of(certificate *x509.Certificate) string {
	return testKey{certificate: certificate}.base64()
}

func TestDownload(t *testing.T) {
	t.Run("writes the lists into a directory, from which they are checked without network", func(t *testing.T) {
		directory := t.TempDir()

		countries, err := Download(t.Context(), trustedliststest.Source{}, directory)

		assert.ElementsMatch(t, []string{"DE", "HU", "SI", "IS"}, countries)
		assert.ErrorContains(t, err, "FR: ", "the lists that are not in trustedliststest fail, without stopping the others")

		checker, err := NewChecker(t.Context(), DirectorySource{Path: directory})
		require.NoError(t, err)

		qualification, err := checker.Qualification(t.Context(), dgnCertificate(t), time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC))
		require.NoError(t, err)
		assert.True(t, qualification.IsQualified)
	})

	t.Run("fails from a directory without the list", func(t *testing.T) {
		_, err := NewChecker(t.Context(), DirectorySource{Path: t.TempDir()})

		assert.ErrorContains(t, err, "is not in")
	})
}
