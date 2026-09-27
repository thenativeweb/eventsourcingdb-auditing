package timestamping_test

import (
	"crypto/sha256"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/thenativeweb/eventsourcingdb-auditing/timestamping"
	"github.com/thenativeweb/eventsourcingdb-auditing/timestamping/timestampingtest"
)

func TestAuthority(t *testing.T) {
	digest := sha256.Sum256([]byte("an anchor"))

	t.Run("obtains a time stamp that covers the digest", func(t *testing.T) {
		authority := timestampingtest.NewAuthority(t)

		token, err := authority.Stamp(t.Context(), digest)
		require.NoError(t, err)

		assert.NotEmpty(t, token.Raw)
		assert.WithinDuration(t, time.Now(), token.Time, time.Minute)

		verified, err := timestamping.Verify(token.Raw, digest)
		require.NoError(t, err)
		assert.Equal(t, token.Time, verified.Time)
	})

	t.Run("rejects a time stamp for another digest", func(t *testing.T) {
		authority := timestampingtest.NewAuthority(t)

		token, err := authority.Stamp(t.Context(), digest)
		require.NoError(t, err)

		_, err = timestamping.Verify(token.Raw, sha256.Sum256([]byte("another anchor")))
		assert.ErrorIs(t, err, timestamping.ErrInvalid)
	})

	t.Run("rejects a token that has been changed", func(t *testing.T) {
		authority := timestampingtest.NewAuthority(t)

		token, err := authority.Stamp(t.Context(), digest)
		require.NoError(t, err)

		changed := append([]byte{}, token.Raw...)
		changed[len(changed)-10] ^= 0xff

		_, err = timestamping.Verify(changed, digest)
		assert.ErrorIs(t, err, timestamping.ErrInvalid)
	})

	t.Run("returns a transient error while the authority is unavailable", func(t *testing.T) {
		authority := timestampingtest.NewAuthority(t)
		authority.Available.Store(false)

		_, err := authority.Stamp(t.Context(), digest)
		assert.ErrorIs(t, err, timestamping.ErrTransient)
	})

	t.Run("returns a transient error if the authority can not be reached", func(t *testing.T) {
		authority := timestamping.Authority{URL: "http://127.0.0.1:1"}

		_, err := authority.Stamp(t.Context(), digest)
		assert.ErrorIs(t, err, timestamping.ErrTransient)
	})
}
