package database

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"
)

// GenesisHash is the predecessor hash of the first event of a database.
const GenesisHash = "0000000000000000000000000000000000000000000000000000000000000000"

// Event is an event of the database of a customer, with what checking it
// needs.
type Event struct {
	ID              string
	Time            time.Time
	Hash            string
	PredecessorHash string

	// HashMatches reports whether the content of the event still hashes to
	// its hash. If it does not, the event has been changed.
	HashMatches bool
}

// eventContent is what the hash of an event is computed from.
type eventContent struct {
	SpecVersion     string
	ID              string
	PredecessorHash string
	Time            string
	Source          string
	Subject         string
	Type            string
	DataContentType string
	Data            []byte
}

// hash computes the hash of an event the way EventSourcingDB does: the SHA-256
// of the hex-encoded SHA-256 of its metadata, joined by vertical bars, and the
// hex-encoded SHA-256 of its data. The time and the data must be exactly as
// they were written, so they are taken as they are, rather than parsed and
// written again.
func hash(content eventContent) string {
	metadata := fmt.Sprintf("%s|%s|%s|%s|%s|%s|%s|%s",
		content.SpecVersion,
		content.ID,
		content.PredecessorHash,
		content.Time,
		content.Source,
		content.Subject,
		content.Type,
		content.DataContentType,
	)

	metadataHash := sha256.Sum256([]byte(metadata))
	dataHash := sha256.Sum256(content.Data)
	finalHash := sha256.Sum256([]byte(hex.EncodeToString(metadataHash[:]) + hex.EncodeToString(dataHash[:])))

	return hex.EncodeToString(finalHash[:])
}
