// Package testvectors holds test vectors for the specification, in
// testvectors.json, and checks that the code produces exactly them, and that
// they verify, so that the specification and the code can not drift apart.
package testvectors

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/thenativeweb/eventsourcingdb-auditing/database"
	"github.com/thenativeweb/eventsourcingdb-auditing/merkle"
	"github.com/thenativeweb/eventsourcingdb-auditing/receipt"
	"github.com/thenativeweb/eventsourcingdb-auditing/verify/verifytest"
)

const vectorsFile = "testvectors.json"

// Vectors are the test vectors of the specification.
type Vectors struct {
	RootKey     Key             `json:"rootKey"`
	SigningKey  SigningKey      `json:"signingKey"`
	Receipts    []SignedReceipt `json:"receipts"`
	MerkleTree  MerkleTree      `json:"merkleTree"`
	Anchors     []SignedAnchor  `json:"anchors"`
	EventHashes []EventHash     `json:"eventHashes"`
}

type Key struct {
	// Seed is the Ed25519 seed, from which the private key follows.
	Seed      string `json:"seed"`
	PublicKey string `json:"publicKey"`
	KeyID     string `json:"keyId"`
}

type SigningKey struct {
	Key
	ValidFrom   time.Time `json:"validFrom"`
	ValidUntil  time.Time `json:"validUntil"`
	Certificate string    `json:"certificate"`
}

type SignedReceipt struct {
	Claims receipt.Receipt `json:"claims"`
	JWS    string          `json:"jws"`
	Hash   string          `json:"hash"`
}

type MerkleTree struct {
	Leaves []Leaf           `json:"leaves"`
	Root   string           `json:"root"`
	Proofs map[string]Proof `json:"proofs"`
}

type Leaf struct {
	Salt        string `json:"salt"`
	ReceiptHash string `json:"receiptHash"`
	LeafHash    string `json:"leafHash"`
}

type Proof struct {
	Leaf     int       `json:"leaf"`
	Siblings []Sibling `json:"siblings"`
}

type Sibling struct {
	Hash     string `json:"hash"`
	Position string `json:"position"`
}

type SignedAnchor struct {
	Claims receipt.Anchor `json:"claims"`
	JWS    string         `json:"jws"`
	Hash   string         `json:"hash"`
	Digest string         `json:"digest"`
}

type EventHash struct {
	BackupLine string `json:"backupLine"`
	Hash       string `json:"hash"`
}

func seed(value byte) []byte {
	return bytes.Repeat([]byte{value}, ed25519.SeedSize)
}

func key(value byte) (ed25519.PrivateKey, Key) {
	privateKey := ed25519.NewKeyFromSeed(seed(value))
	publicKey := privateKey.Public().(ed25519.PublicKey)

	return privateKey, Key{
		Seed:      hex.EncodeToString(seed(value)),
		PublicKey: receipt.EncodeRawPublicKey(publicKey),
		KeyID:     receipt.KeyIDOf(publicKey),
	}
}

func hexOf(hash merkle.Hash) string {
	return hex.EncodeToString(hash[:])
}

// generate builds the test vectors from fixed seeds. Ed25519 signatures are
// deterministic, so the same code always produces the same vectors.
func generate(t *testing.T) Vectors {
	t.Helper()

	var vectors Vectors

	rootPrivateKey, rootKey := key(0x01)
	vectors.RootKey = rootKey

	signingPrivateKey, signingKey := key(0x02)
	validFrom := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	validUntil := time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC)
	certificate := receipt.KeyCertificate{
		KeyID:      signingKey.KeyID,
		PublicKey:  signingPrivateKey.Public().(ed25519.PublicKey),
		ValidFrom:  validFrom,
		ValidUntil: validUntil,
	}
	certificateJWS, err := receipt.Certify(certificate, rootPrivateKey)
	require.NoError(t, err)
	vectors.SigningKey = SigningKey{Key: signingKey, ValidFrom: validFrom, ValidUntil: validUntil, Certificate: certificateJWS}

	rootPublicKey := rootPrivateKey.Public().(ed25519.PublicKey)
	signer, err := receipt.NewSigningKey(signingPrivateKey, certificateJWS, rootPublicKey)
	require.NoError(t, err)

	// The receipts confirm events of the backup with five events.
	previous := ""
	for i, confirmed := range []struct {
		eventID, eventHash string
		minute             int
	}{
		{"0", "b6ae7a219468eeb110cf20151d9a8dc091ed40390a1411e36c183bf6a804900f", 5},
		{"2", "64d040f3bcf26b3a17f3172ddf56443cffa7f10fcd407eada39f2484bba36dea", 20},
		{"4", "084d451c2a2606c85577a5aec38d28837d3db41f590106c85426b535bb03a705", 40},
	} {
		previousReceiptHash := ""
		if previous != "" {
			previousReceiptHash = receipt.Hash(previous)
		}

		claims := receipt.Receipt{
			InstanceID:          "instance-1",
			EventID:             confirmed.eventID,
			EventHash:           confirmed.eventHash,
			ReceivedAt:          time.Date(2026, 9, 1, 10, confirmed.minute, 0, 0, time.UTC),
			Sequence:            uint64(i + 1),
			PreviousReceiptHash: previousReceiptHash,
		}
		signed, err := signer.Sign(claims)
		require.NoError(t, err)

		vectors.Receipts = append(vectors.Receipts, SignedReceipt{Claims: claims, JWS: signed, Hash: receipt.Hash(signed)})
		previous = signed
	}

	// The tree has five leaves, so that it is split at the largest power of
	// two below its size, rather than duplicating a node. The first leaf is
	// the latest receipt of the instance, and the others stand for other
	// instances.
	latestReceiptHash, err := hex.DecodeString(vectors.Receipts[len(vectors.Receipts)-1].Hash)
	require.NoError(t, err)

	var leafHashes []merkle.Hash
	for i := range 5 {
		salt := bytes.Repeat([]byte{byte(0x10 + i)}, 32)
		receiptHash := latestReceiptHash
		if i > 0 {
			receiptHash = bytes.Repeat([]byte{byte(0x20 + i)}, 32)
		}

		leafHash := merkle.SaltedLeafHash(salt, receiptHash)
		leafHashes = append(leafHashes, leafHash)
		vectors.MerkleTree.Leaves = append(vectors.MerkleTree.Leaves, Leaf{
			Salt:        hex.EncodeToString(salt),
			ReceiptHash: hex.EncodeToString(receiptHash),
			LeafHash:    hexOf(leafHash),
		})
	}

	root := merkle.Root(leafHashes)
	vectors.MerkleTree.Root = hexOf(root)
	vectors.MerkleTree.Proofs = map[string]Proof{}
	for _, leaf := range []int{0, 4} {
		siblings, err := merkle.Proof(leafHashes, leaf)
		require.NoError(t, err)

		proof := Proof{Leaf: leaf}
		for _, sibling := range siblings {
			proof.Siblings = append(proof.Siblings, Sibling{Hash: hexOf(sibling.Hash), Position: string(sibling.Position)})
		}
		vectors.MerkleTree.Proofs[strconv.Itoa(leaf)] = proof
	}

	// Two anchors: the first one over the tree above, and the one of the next
	// hour, without receipts, over the empty tree.
	previousAnchor := ""
	for i, anchorRoot := range []string{hexOf(root), hexOf(merkle.Root(nil))} {
		hour := time.Date(2026, 9, 1, 10+i, 0, 0, 0, time.UTC)
		claims := receipt.Anchor{Hour: hour, Root: anchorRoot, LeafCount: []int{5, 0}[i]}
		if previousAnchor != "" {
			claims.PreviousAnchorHash = receipt.Hash(previousAnchor)
		}

		signed, err := signer.SignAnchor(claims, hour.Add(time.Hour))
		require.NoError(t, err)

		digest := receipt.Digest(signed)
		vectors.Anchors = append(vectors.Anchors, SignedAnchor{Claims: claims, JWS: signed, Hash: receipt.Hash(signed), Digest: hex.EncodeToString(digest[:])})
		previousAnchor = signed
	}

	// The hashes of events, as EventSourcingDB computes them.
	lines := strings.Split(strings.TrimSpace(verifytest.BackupWithFiveEvents), "\n")
	for _, line := range lines {
		var parsed struct {
			Payload struct {
				Hash string `json:"hash"`
			} `json:"payload"`
		}
		require.NoError(t, json.Unmarshal([]byte(line), &parsed))
		vectors.EventHashes = append(vectors.EventHashes, EventHash{BackupLine: line, Hash: parsed.Payload.Hash})
	}

	return vectors
}

func TestVectors(t *testing.T) {
	generated := generate(t)

	encoded, err := json.MarshalIndent(generated, "", "  ")
	require.NoError(t, err)
	encoded = append(encoded, '\n')

	if os.Getenv("UPDATE_TEST_VECTORS") == "1" {
		require.NoError(t, os.WriteFile(vectorsFile, encoded, 0o644))
	}

	t.Run("match what the code produces", func(t *testing.T) {
		committed, err := os.ReadFile(vectorsFile)
		require.NoError(t, err)

		assert.Equal(t, string(committed), string(encoded), "run with UPDATE_TEST_VECTORS=1 after changing a format on purpose")
	})

	var vectors Vectors
	committed, err := os.ReadFile(vectorsFile)
	require.NoError(t, err)
	require.NoError(t, json.Unmarshal(committed, &vectors))

	rootPublicKey, err := receipt.DecodeRawPublicKey(vectors.RootKey.PublicKey)
	require.NoError(t, err)

	t.Run("have a key certificate that verifies against the root key", func(t *testing.T) {
		certificate, err := receipt.VerifyKeyCertificate(vectors.SigningKey.Certificate, rootPublicKey)

		require.NoError(t, err)
		assert.Equal(t, vectors.SigningKey.KeyID, certificate.KeyID)
		assert.Equal(t, vectors.RootKey.KeyID, receipt.KeyIDOf(rootPublicKey))
	})

	t.Run("have receipts that verify and form a chain", func(t *testing.T) {
		certificate, err := receipt.VerifyKeyCertificate(vectors.SigningKey.Certificate, rootPublicKey)
		require.NoError(t, err)

		for i, signed := range vectors.Receipts {
			verified, err := receipt.Verify(signed.JWS, certificate)
			require.NoError(t, err)
			assert.Equal(t, signed.Hash, receipt.Hash(signed.JWS))

			if i == 0 {
				assert.True(t, verified.IsFirst())
			} else {
				previous, err := receipt.Verify(vectors.Receipts[i-1].JWS, certificate)
				require.NoError(t, err)
				assert.True(t, verified.Follows(vectors.Receipts[i-1].JWS, previous))
			}
		}
	})

	t.Run("have proofs that lead from their leaves to the root", func(t *testing.T) {
		root, err := hex.DecodeString(vectors.MerkleTree.Root)
		require.NoError(t, err)

		for _, proof := range vectors.MerkleTree.Proofs {
			leaf := vectors.MerkleTree.Leaves[proof.Leaf]
			salt, err := hex.DecodeString(leaf.Salt)
			require.NoError(t, err)
			receiptHash, err := hex.DecodeString(leaf.ReceiptHash)
			require.NoError(t, err)

			var siblings []merkle.Sibling
			for _, sibling := range proof.Siblings {
				hash, err := hex.DecodeString(sibling.Hash)
				require.NoError(t, err)
				siblings = append(siblings, merkle.Sibling{Hash: merkle.Hash(hash), Position: merkle.Position(sibling.Position)})
			}

			assert.True(t, merkle.VerifyProof(merkle.SaltedLeafHash(salt, receiptHash), siblings, merkle.Hash(root)), "leaf %d", proof.Leaf)
		}
	})

	t.Run("have anchors that verify and form a chain", func(t *testing.T) {
		certificate, err := receipt.VerifyKeyCertificate(vectors.SigningKey.Certificate, rootPublicKey)
		require.NoError(t, err)

		for i, signed := range vectors.Anchors {
			verified, err := receipt.VerifyAnchor(signed.JWS, certificate)
			require.NoError(t, err)

			digest := receipt.Digest(signed.JWS)
			assert.Equal(t, signed.Digest, hex.EncodeToString(digest[:]))

			if i == 0 {
				assert.True(t, verified.IsFirst())
				assert.Equal(t, vectors.MerkleTree.Root, verified.Root)
			} else {
				previous, err := receipt.VerifyAnchor(vectors.Anchors[i-1].JWS, certificate)
				require.NoError(t, err)
				assert.True(t, verified.Follows(vectors.Anchors[i-1].JWS, previous))
			}
		}
	})

	t.Run("have events that hash to their hashes", func(t *testing.T) {
		var backup strings.Builder
		for _, event := range vectors.EventHashes {
			backup.WriteString(event.BackupLine + "\n")
		}

		i := 0
		for event, err := range database.ReadBackup(strings.NewReader(backup.String())) {
			require.NoError(t, err)
			assert.True(t, event.HashMatches, "event %s", event.ID)
			assert.Equal(t, vectors.EventHashes[i].Hash, event.Hash)
			i++
		}
		assert.Equal(t, len(vectors.EventHashes), i)
	})
}
