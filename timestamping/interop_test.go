package timestamping_test

import (
	"crypto/rand"
	"crypto/sha256"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/thenativeweb/eventsourcingdb-auditing/timestamping"
)

// TestInterop asks a real time stamping authority for a time stamp over a
// random digest, to check that the client gets along with it. It only runs if
// TIMESTAMP_AUTHORITY_URL is set, and takes the credentials from
// TIMESTAMP_AUTHORITY_USERNAME and TIMESTAMP_AUTHORITY_PASSWORD, so that no
// credentials end up in the repository:
//
//	TIMESTAMP_AUTHORITY_URL=... TIMESTAMP_AUTHORITY_USERNAME=... TIMESTAMP_AUTHORITY_PASSWORD=... \
//	  go test -run TestInterop -v ./timestamping/
//
// Every run uses up one time stamp of the account.
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

	var random [32]byte
	_, err := rand.Read(random[:])
	require.NoError(t, err)
	digest := sha256.Sum256(random[:])

	token, err := authority.Stamp(t.Context(), digest)
	require.NoError(t, err)

	verified, err := timestamping.Verify(token.Raw, digest)
	require.NoError(t, err)
	assert.Equal(t, token.Time, verified.Time)

	t.Logf("time stamp at %s, qualified: %t, token size: %d bytes", token.Time, token.IsQualified, len(token.Raw))
}
