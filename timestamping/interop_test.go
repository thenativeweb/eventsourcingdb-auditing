package timestamping_test

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"io"
	"net/http"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/thenativeweb/eventsourcingdb-auditing/timestamping"
	"github.com/thenativeweb/eventsourcingdb-auditing/trustedlists"
)

// recordingTransport keeps the request to an authority and its answer, before
// the client looks at the answer, so that an answer the client can not handle
// is not lost along with the time stamp it has used up.
type recordingTransport struct {
	t    *testing.T
	path string
}

func (r recordingTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	body, err := io.ReadAll(request.Body)
	if err != nil {
		return nil, err
	}
	require.NoError(r.t, os.WriteFile(r.path+".tsq", body, 0o644))
	request.Body = io.NopCloser(bytes.NewReader(body))

	response, err := http.DefaultTransport.RoundTrip(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()

	answer, err := io.ReadAll(response.Body)
	if err != nil {
		return nil, err
	}
	r.t.Logf("the authority answered with HTTP status code %d and %d bytes of %s", response.StatusCode, len(answer), response.Header.Get("Content-Type"))
	require.NoError(r.t, os.WriteFile(r.path+".tsr", answer, 0o644))
	response.Body = io.NopCloser(bytes.NewReader(answer))

	return response, nil
}

// TestInterop asks a real time stamping authority for a time stamp, to check
// that the client gets along with it. It only runs if TIMESTAMP_AUTHORITY_URL
// is set, and takes the credentials from TIMESTAMP_AUTHORITY_USERNAME and
// TIMESTAMP_AUTHORITY_PASSWORD, so that no credentials end up in the
// repository:
//
//	TIMESTAMP_AUTHORITY_URL=... TIMESTAMP_AUTHORITY_USERNAME=... TIMESTAMP_AUTHORITY_PASSWORD=... \
//	  go test -run TestInterop -v ./timestamping/
//
// Every run uses up one time stamp of the account. With EU_TRUSTED_LISTS=1,
// it also checks the same time stamp against the published EU trusted lists.
// With TIMESTAMP_RECORDING=testdata/dgn, it keeps the request in
// testdata/dgn.tsq and the answer in testdata/dgn.tsr, before anything is
// checked, which is how testdata/dgn.tsq and testdata/dgn.tsr came about.
func TestInterop(t *testing.T) {
	url := os.Getenv("TIMESTAMP_AUTHORITY_URL")
	if url == "" {
		t.Skip("set TIMESTAMP_AUTHORITY_URL to test against a real time stamping authority")
	}

	authority := timestamping.Authority{
		URL:      url,
		Username: os.Getenv("TIMESTAMP_AUTHORITY_USERNAME"),
		Password: os.Getenv("TIMESTAMP_AUTHORITY_PASSWORD"),
	}
	if recording := os.Getenv("TIMESTAMP_RECORDING"); recording != "" {
		authority.HTTPClient = &http.Client{Transport: recordingTransport{t: t, path: recording}}
	}

	var random [32]byte
	_, err := rand.Read(random[:])
	require.NoError(t, err)
	digest := sha256.Sum256(random[:])

	token, err := authority.Stamp(t.Context(), digest)
	require.NoError(t, err)

	verified, err := timestamping.Verify(token.Raw, digest)
	require.NoError(t, err)
	assert.Equal(t, token.Time, verified.Time)

	require.NotNil(t, token.Certificate)
	t.Logf("time stamp at %s, claims to be qualified: %t, token size: %d bytes, signed by %s", token.Time, token.IsQualified, len(token.Raw), token.Certificate.Subject)

	if os.Getenv("EU_TRUSTED_LISTS") != "1" {
		return
	}

	checker, err := trustedlists.NewChecker(t.Context(), trustedlists.NewHTTPSource())
	require.NoError(t, err)

	qualification, err := checker.Qualification(t.Context(), token.Certificate, token.Time)
	require.NoError(t, err)
	t.Logf("according to the EU trusted lists of %s: %+v", checker.ListOfTheListsIssuedAt(), qualification)
	assert.True(t, qualification.IsQualified, qualification.Reason)
}
