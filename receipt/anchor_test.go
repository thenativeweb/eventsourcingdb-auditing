package receipt_test

import (
	"encoding/hex"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/thenativeweb/eventsourcingdb-auditing/receipt"
)

func TestAnchor(t *testing.T) {
	hour := time.Date(2026, 9, 26, 15, 0, 0, 0, time.UTC)

	t.Run("signs an anchor that verifies with the certificate of its key", func(t *testing.T) {
		_, signingKey := newSigningKey(t)
		anchor := receipt.Anchor{Hour: hour, Root: "root", LeafCount: 3}

		jws, err := signingKey.SignAnchor(anchor, receivedAt)
		require.NoError(t, err)

		verified, err := receipt.VerifyAnchor(jws, signingKey.Certificate)
		require.NoError(t, err)
		assert.Equal(t, anchor, verified)
		assert.True(t, verified.IsFirst())

		keyID, err := receipt.KeyIDOfAnchor(jws)
		require.NoError(t, err)
		assert.Equal(t, signingKey.Certificate.KeyID, keyID)
	})

	t.Run("tells whether an anchor follows another one", func(t *testing.T) {
		_, signingKey := newSigningKey(t)

		first := receipt.Anchor{Hour: hour, Root: "root-1"}
		firstJWS, err := signingKey.SignAnchor(first, receivedAt)
		require.NoError(t, err)

		second := receipt.Anchor{Hour: hour.Add(time.Hour), Root: "root-2", PreviousAnchorHash: receipt.Hash(firstJWS)}
		assert.True(t, second.Follows(firstJWS, first))

		sameHour := second
		sameHour.Hour = hour
		assert.False(t, sameHour.Follows(firstJWS, first), "an anchor must be for a later hour")

		pointingElsewhere := second
		pointingElsewhere.PreviousAnchorHash = receipt.Hash("another anchor")
		assert.False(t, pointingElsewhere.Follows(firstJWS, first))
	})

	t.Run("does not accept a receipt as an anchor, or an anchor as a receipt", func(t *testing.T) {
		_, signingKey := newSigningKey(t)

		anchorJWS, err := signingKey.SignAnchor(receipt.Anchor{Hour: hour, Root: "root"}, receivedAt)
		require.NoError(t, err)
		receiptJWS, err := signingKey.Sign(newReceipt())
		require.NoError(t, err)

		_, err = receipt.VerifyAnchor(receiptJWS, signingKey.Certificate)
		assert.ErrorIs(t, err, receipt.ErrInvalid)
		_, err = receipt.Verify(anchorJWS, signingKey.Certificate)
		assert.ErrorIs(t, err, receipt.ErrInvalid)
	})

	t.Run("parses an anchor without checking its signature", func(t *testing.T) {
		_, signingKey := newSigningKey(t)
		anchor := receipt.Anchor{Hour: hour, Root: "root", LeafCount: 3}

		jws, err := signingKey.SignAnchor(anchor, receivedAt)
		require.NoError(t, err)

		parsed, err := receipt.ParseAnchorUnverified(jws)
		require.NoError(t, err)
		assert.Equal(t, anchor, parsed)

		receiptJWS, err := signingKey.Sign(newReceipt())
		require.NoError(t, err)
		_, err = receipt.ParseAnchorUnverified(receiptJWS)
		assert.ErrorIs(t, err, receipt.ErrInvalid, "a receipt is no anchor")
	})

	t.Run("digests a JWS the same way it hashes it", func(t *testing.T) {
		digest := receipt.Digest("a jws")

		assert.Equal(t, receipt.Hash("a jws"), hex.EncodeToString(digest[:]))
	})
}
