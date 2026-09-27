package receipt

import (
	"crypto/ed25519"
	"encoding/base64"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The test vector of RFC 8037, appendix A.1 and A.4.
const (
	rfc8037PrivateKey = "nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A"
	rfc8037PublicKey  = "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"
	rfc8037JWS        = "eyJhbGciOiJFZERTQSJ9.RXhhbXBsZSBvZiBFZDI1NTE5IHNpZ25pbmc.hgyY0il_MGCjP0JzlnLWG1PPOt7-09PGcvMg3AIbQR6dWbhijcNR4ki4iylGjg5BhVsPt9g7sVvpAr_MuM0KAg"
)

func TestCompactJWS(t *testing.T) {
	seed, err := base64.RawURLEncoding.DecodeString(rfc8037PrivateKey)
	require.NoError(t, err)
	publicKey, err := base64.RawURLEncoding.DecodeString(rfc8037PublicKey)
	require.NoError(t, err)

	privateKey := ed25519.NewKeyFromSeed(seed)

	t.Run("derives the public key of the test vector", func(t *testing.T) {
		assert.Equal(t, ed25519.PublicKey(publicKey), privateKey.Public())
	})

	t.Run("signs exactly like the test vector of RFC 8037", func(t *testing.T) {
		jws := signCompact([]byte(`{"alg":"EdDSA"}`), []byte("Example of Ed25519 signing"), privateKey)

		assert.Equal(t, rfc8037JWS, jws)
	})

	t.Run("verifies the test vector of RFC 8037", func(t *testing.T) {
		payload, err := verifyCompact(rfc8037JWS, publicKey)
		require.NoError(t, err)

		assert.Equal(t, "Example of Ed25519 signing", string(payload))
	})
}
