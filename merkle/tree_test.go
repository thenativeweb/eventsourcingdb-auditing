package merkle_test

import (
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/thenativeweb/eventsourcingdb-auditing/merkle"
)

// The leaves and roots of the reference test vectors of Certificate
// Transparency (RFC 6962).
var referenceLeaves = []string{
	"",
	"00",
	"10",
	"2021",
	"3031",
	"40414243",
	"5051525354555657",
	"606162636465666768696a6b6c6d6e6f",
}

var referenceRoots = []string{
	"6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d",
	"fac54203e7cc696cf0dfcb42c92a1d9dbaf70ad9e621f4bd8d98662f00e3c125",
	"aeb6bcfe274b70a14fb067a5e5578264db0fa9b51af5e0ba159158f329e06e77",
	"d37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7",
	"4e3bbb1f7b478dcfe71fb631631519a3bca12c9aefca1612bfce4c13a86264d4",
	"76e67dadbcdf1e10e1b74ddc608abd2f98dfb16fbce75277b5232a127f2087ef",
	"ddb89be403809e325750d3d263cd78929c2942b7942a34b77e122c9594a74c8c",
	"5dc9da79a70659a9ad559cb701ded9a2ab9d823aad2f4960cfe370eff4604328",
}

func leafHashes(t *testing.T, count int) []merkle.Hash {
	t.Helper()

	leaves := make([]merkle.Hash, 0, count)
	for _, leaf := range referenceLeaves[:count] {
		data, err := hex.DecodeString(leaf)
		require.NoError(t, err)

		leaves = append(leaves, merkle.LeafHash(data))
	}

	return leaves
}

func TestRoot(t *testing.T) {
	t.Run("matches the reference roots of RFC 6962 for every size up to eight", func(t *testing.T) {
		for size := 1; size <= len(referenceLeaves); size++ {
			root := merkle.Root(leafHashes(t, size))

			assert.Equal(t, referenceRoots[size-1], hex.EncodeToString(root[:]), "size %d", size)
		}
	})

	t.Run("returns the hash of nothing for an empty tree", func(t *testing.T) {
		root := merkle.Root(nil)

		assert.Equal(t, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", hex.EncodeToString(root[:]))
	})

	t.Run("does not let a duplicated last leaf yield the same root", func(t *testing.T) {
		leaves := leafHashes(t, 3)
		withDuplicate := append(leafHashes(t, 3), leaves[2])

		assert.NotEqual(t, merkle.Root(leaves), merkle.Root(withDuplicate))
	})
}

func TestProof(t *testing.T) {
	t.Run("proves every leaf of every tree up to eight leaves", func(t *testing.T) {
		for size := 1; size <= len(referenceLeaves); size++ {
			leaves := leafHashes(t, size)
			root := merkle.Root(leaves)

			for index := range leaves {
				siblings, err := merkle.Proof(leaves, index)
				require.NoError(t, err)

				assert.True(t, merkle.VerifyProof(leaves[index], siblings, root), "size %d, index %d", size, index)
			}
		}
	})

	t.Run("rejects a proof for another leaf", func(t *testing.T) {
		leaves := leafHashes(t, 5)
		root := merkle.Root(leaves)

		siblings, err := merkle.Proof(leaves, 1)
		require.NoError(t, err)

		assert.False(t, merkle.VerifyProof(leaves[2], siblings, root))
	})

	t.Run("rejects a proof against another root", func(t *testing.T) {
		leaves := leafHashes(t, 5)

		siblings, err := merkle.Proof(leaves, 1)
		require.NoError(t, err)

		assert.False(t, merkle.VerifyProof(leaves[1], siblings, merkle.Root(leafHashes(t, 4))))
	})

	t.Run("keeps inner nodes apart from leaves", func(t *testing.T) {
		leaves := leafHashes(t, 2)

		// Without the prefixes, the data of two leaf hashes would hash to the
		// inner node above them, so an inner node could be passed off as a
		// leaf with a shorter proof.
		innerNode := merkle.Root(leaves)
		sameDataAsLeaf := merkle.LeafHash(append(leaves[0][:], leaves[1][:]...))

		assert.NotEqual(t, innerNode, sameDataAsLeaf)
	})

	t.Run("rejects an index out of range", func(t *testing.T) {
		_, err := merkle.Proof(leafHashes(t, 3), 3)
		assert.ErrorIs(t, err, merkle.ErrIndexOutOfRange)
	})

	t.Run("salts a leaf, so that the same value yields another hash with another salt", func(t *testing.T) {
		value := []byte("the hash of a receipt")

		assert.NotEqual(t, merkle.SaltedLeafHash([]byte("salt-1"), value), merkle.SaltedLeafHash([]byte("salt-2"), value))
		assert.Equal(t, merkle.LeafHash(append([]byte("salt-1"), value...)), merkle.SaltedLeafHash([]byte("salt-1"), value))
	})
}
