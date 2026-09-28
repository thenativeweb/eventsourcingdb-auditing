package trustedlists

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestVerifySignature(t *testing.T) {
	for _, test := range []struct {
		name   string
		file   string
		signer string
	}{
		{"the list of the lists, with RSA and SHA-512", "eu-lotl.xml.gz", "EUROPEAN COMMISSION"},
		{"the list of Germany, with RSA and PSS", "de.xml.gz", "German Trusted List Signer 14"},
		{"the list of Hungary, with ECDSA and SHA-256", "hu.xml.gz", "Hungarian Trusted List Scheme Operator"},
		{"the list of Slovenia, with ECDSA and SHA-512", "si.xml.gz", "Marija Sever"},
		{"the list of Iceland, with RSA and SHA-256", "is.xml.gz", "Bjarni Hallgrímur Bjarnason"},
	} {
		t.Run("verifies "+test.name, func(t *testing.T) {
			signer, err := verifySignature(readTestdata(t, test.file))

			require.NoError(t, err)
			assert.Equal(t, test.signer, signer.Subject.CommonName)
		})
	}

	iceland := string(readTestdata(t, "is.xml.gz"))

	t.Run("finds a list whose content has been changed", func(t *testing.T) {
		changed := strings.Replace(iceland, "<TSLSequenceNumber>", "<TSLSequenceNumber>9", 1)
		require.NotEqual(t, iceland, changed)

		_, err := verifySignature([]byte(changed))

		assert.ErrorIs(t, err, ErrInvalidSignature)
		assert.ErrorContains(t, err, "digest")
	})

	t.Run("finds a signature whose value has been changed", func(t *testing.T) {
		start := strings.Index(iceland, "SignatureValue")
		start = strings.Index(iceland[start:], ">") + start + 1
		changed := iceland[:start] + "AAAA" + iceland[start+4:]

		_, err := verifySignature([]byte(changed))

		assert.ErrorIs(t, err, ErrInvalidSignature)
	})

	t.Run("finds a signature method that is not supported", func(t *testing.T) {
		changed := strings.Replace(iceland, "xmldsig-more#rsa-sha256", "xmldsig#rsa-sha1", 1)

		_, err := verifySignature([]byte(changed))

		assert.ErrorContains(t, err, "not supported")
	})

	t.Run("rejects a list that is not signed", func(t *testing.T) {
		unsigned := `<TrustServiceStatusList xmlns="http://uri.etsi.org/02231/v2#"/>`

		_, err := verifySignature([]byte(unsigned))

		assert.ErrorContains(t, err, "not signed")
	})

	t.Run("rejects a list with two signatures", func(t *testing.T) {
		key := newTestKey(t, "Test Signer")
		signed := string(key.sign(t, listOfTheLists(nil)))
		start := strings.Index(signed, "<ds:Signature")
		end := strings.Index(signed, "</ds:Signature>") + len("</ds:Signature>")
		doubled := signed[:end] + signed[start:end] + signed[end:]

		_, err := verifySignature([]byte(doubled))

		assert.ErrorContains(t, err, "2 signatures")
	})

	t.Run("rejects what is not XML", func(t *testing.T) {
		_, err := verifySignature([]byte("not xml"))

		assert.ErrorIs(t, err, ErrInvalidSignature)
	})

	t.Run("verifies a list signed the way this package expects it", func(t *testing.T) {
		key := newTestKey(t, "Test Signer")

		signer, err := verifySignature(key.sign(t, listOfTheLists(nil)))

		require.NoError(t, err)
		assert.True(t, signer.Equal(key.certificate))
	})
}
