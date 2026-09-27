// Package merkle builds the Merkle trees the hourly anchors of the custodian
// are made of, and creates and checks the proofs that a leaf is part of one.
//
// The tree follows RFC 6962 (Certificate Transparency): a leaf is hashed with
// the prefix 0x00 and an inner node with the prefix 0x01, so that an inner
// node can never pass for a leaf, and a tree is split at the largest power of
// two below its size, so that no node is ever duplicated. Duplicating the last
// node of an odd level, as many simpler trees do, lets different sets of
// leaves share one root.
//
// A leaf of the custodian consists of a random salt and the hash of a receipt.
// The salt is only handed to the instance the receipt belongs to, so that the
// hashes next to it in a proof reveal nothing about other instances.
package merkle
