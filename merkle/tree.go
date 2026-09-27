package merkle

import (
	"crypto/sha256"
	"errors"
	"math/bits"
)

const (
	leafPrefix = 0x00
	nodePrefix = 0x01
)

// Hash is a SHA-256 hash.
type Hash [sha256.Size]byte

// LeafHash hashes the data of a leaf.
func LeafHash(data []byte) Hash {
	return sha256.Sum256(append([]byte{leafPrefix}, data...))
}

// SaltedLeafHash hashes a leaf that consists of a salt and a value.
func SaltedLeafHash(salt, value []byte) Hash {
	data := make([]byte, 0, len(salt)+len(value))
	data = append(data, salt...)
	data = append(data, value...)

	return LeafHash(data)
}

func nodeHash(left, right Hash) Hash {
	data := make([]byte, 0, 1+2*sha256.Size)
	data = append(data, nodePrefix)
	data = append(data, left[:]...)
	data = append(data, right[:]...)

	return sha256.Sum256(data)
}

// Root returns the root of the tree over the given leaf hashes. The root of an
// empty tree is the hash of nothing, as in RFC 6962.
func Root(leaves []Hash) Hash {
	if len(leaves) == 0 {
		return sha256.Sum256(nil)
	}
	if len(leaves) == 1 {
		return leaves[0]
	}

	split := largestPowerOfTwoBelow(len(leaves))

	return nodeHash(Root(leaves[:split]), Root(leaves[split:]))
}

// Position tells on which side of the path a sibling hash lies.
type Position string

const (
	Left  Position = "left"
	Right Position = "right"
)

// Sibling is one step of a proof: the hash next to the path, and its side.
type Sibling struct {
	Hash     Hash
	Position Position
}

// ErrIndexOutOfRange means that a proof was asked for a leaf the tree does not
// have.
var ErrIndexOutOfRange = errors.New("the leaf index is out of range")

// Proof returns the siblings on the path from the leaf at the given index to
// the root, from the bottom up.
func Proof(leaves []Hash, index int) ([]Sibling, error) {
	if index < 0 || index >= len(leaves) {
		return nil, ErrIndexOutOfRange
	}

	return proof(leaves, index), nil
}

func proof(leaves []Hash, index int) []Sibling {
	if len(leaves) <= 1 {
		return nil
	}

	split := largestPowerOfTwoBelow(len(leaves))

	if index < split {
		return append(proof(leaves[:split], index), Sibling{Hash: Root(leaves[split:]), Position: Right})
	}

	return append(proof(leaves[split:], index-split), Sibling{Hash: Root(leaves[:split]), Position: Left})
}

// VerifyProof reports whether the siblings lead from the leaf to the root.
func VerifyProof(leaf Hash, siblings []Sibling, root Hash) bool {
	current := leaf

	for _, sibling := range siblings {
		switch sibling.Position {
		case Left:
			current = nodeHash(sibling.Hash, current)
		case Right:
			current = nodeHash(current, sibling.Hash)
		default:
			return false
		}
	}

	return current == root
}

// largestPowerOfTwoBelow returns the largest power of two that is smaller than
// n, for n of at least 2.
func largestPowerOfTwoBelow(n int) int {
	return 1 << (bits.Len(uint(n-1)) - 1)
}
