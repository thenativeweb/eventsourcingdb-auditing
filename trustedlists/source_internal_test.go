package trustedlists

import (
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHTTPSource(t *testing.T) {
	t.Run("fetches a list", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
			_, _ = writer.Write([]byte("<list/>"))
		}))
		t.Cleanup(server.Close)

		data, err := NewHTTPSource().Fetch(t.Context(), server.URL)

		require.NoError(t, err)
		assert.Equal(t, "<list/>", string(data))
	})

	t.Run("fails on another status code than 200", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
			writer.WriteHeader(http.StatusNotFound)
		}))
		t.Cleanup(server.Close)

		_, err := NewHTTPSource().Fetch(t.Context(), server.URL)

		assert.ErrorContains(t, err, "404")
	})

	t.Run("fails if the list can not be reached", func(t *testing.T) {
		_, err := NewHTTPSource().Fetch(t.Context(), "http://127.0.0.1:1/list.xml")

		assert.Error(t, err)
	})
}

// TestLiveLists checks the published EU trusted lists, including whether the
// certificates announced in the Official Journal still sign the list of the
// lists. It needs the network, so it only runs with EU_TRUSTED_LISTS=1.
func TestLiveLists(t *testing.T) {
	if os.Getenv("EU_TRUSTED_LISTS") != "1" {
		t.Skip("set EU_TRUSTED_LISTS=1 to check the published EU trusted lists")
	}

	checker, err := NewChecker(t.Context(), NewHTTPSource())
	require.NoError(t, err)
	t.Logf("the list of the lists was issued at %s", checker.ListOfTheListsIssuedAt())

	qualification, err := checker.Qualification(t.Context(), dgnCertificate(t), time.Now())
	require.NoError(t, err)
	t.Logf("DGN: qualified %t, %+v", qualification.IsQualified, qualification)
}
