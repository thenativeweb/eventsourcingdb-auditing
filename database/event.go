package database

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"time"
)

// GenesisHash is the predecessor hash of the first event of a database. It
// carries no prefix, whatever the version of the hash of that event.
const GenesisHash = "0000000000000000000000000000000000000000000000000000000000000000"

// hashPrefix starts every hash that names its version. A hash without it is of
// version 1, which predates the prefix.
const hashPrefix = "esdb:hash:"

// hashVersion2Prefix starts every hash of version 2, which EventSourcingDB
// writes from version 1.3 on. Events written before keep their hash of version
// 1, so a database can hold both versions.
const hashVersion2Prefix = hashPrefix + "v2:"

// The versions of hashes this package knows, as Event.HashVersion names them.
const (
	HashVersion1 = "v1"
	HashVersion2 = "v2"
)

// missingField stands for a trace context the event does not have, in the
// input of a hash of version 2.
const missingField = "-"

// Event is an event of the database of a customer, with what checking it
// needs.
type Event struct {
	ID              string
	Time            time.Time
	Hash            string
	PredecessorHash string

	// HashVersion is the version the hash of the event names: HashVersion1
	// for a hash without a prefix, and what follows "esdb:hash:" up to the
	// next colon otherwise, such as HashVersion2.
	HashVersion string

	// HashMatches reports whether the content of the event still hashes to
	// its hash. If it does not, the event has been changed, unless the hash
	// is of a version that this package does not know.
	HashMatches bool

	// HashVersionIsUnknown reports whether the hash of the event names a
	// version that this package does not know, which only a newer
	// EventSourcingDB writes. Whether such an event has been changed can not
	// be told, so it must not be taken for one that has.
	HashVersionIsUnknown bool
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
	TraceParent     *string
	TraceState      *string
	Data            []byte
}

// hashVersionOf returns the version a hash names: HashVersion1 for a hash
// without a prefix, and what follows the prefix up to the next colon
// otherwise. It tells as well whether this package knows that version.
func hashVersionOf(hash string) (string, bool) {
	if !strings.HasPrefix(hash, hashPrefix) {
		return HashVersion1, true
	}
	if strings.HasPrefix(hash, hashVersion2Prefix) {
		return HashVersion2, true
	}

	version, _, _ := strings.Cut(strings.TrimPrefix(hash, hashPrefix), ":")

	return version, false
}

// hashMatches computes the hash of an event in the version that its hash
// names, as EventSourcingDB does, since an event keeps the version of the hash
// it was written with, and tells whether it is that hash. A hash whose prefix
// names a version that this package does not know is not computed at all, and
// does not match, which hashVersionOf tells apart from a hash that was
// changed.
func hashMatches(content eventContent, hash string) bool {
	version, isKnown := hashVersionOf(hash)
	if !isKnown {
		return false
	}

	if version == HashVersion2 {
		return hashOfVersion2(content) == hash
	}

	return hashOfVersion1(content) == hash
}

// hashOfVersion1 computes a hash of version 1, the way EventSourcingDB does:
// the SHA-256 of the hex-encoded SHA-256 of its metadata, joined by vertical
// bars, and the hex-encoded SHA-256 of its data. It covers neither the
// traceparent nor the tracestate. The time and the data must be exactly as
// they were written, so they are taken as they are, rather than parsed and
// written again.
func hashOfVersion1(content eventContent) string {
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

// hashOfVersion2 computes a hash of version 2, the way EventSourcingDB does
// from version 1.3 on: the SHA-256 of its prefix and of every field of the
// event, each on a line of its own, without a line break after the last one,
// written with the prefix. A trace context the event does not have is written
// as "-". The predecessor hash goes in as it is, with its prefix if it has
// one, and the time and the data exactly as they were written, as for a hash
// of version 1.
func hashOfVersion2(content eventContent) string {
	traceParent := missingField
	if content.TraceParent != nil {
		traceParent = *content.TraceParent
	}

	traceState := missingField
	if content.TraceState != nil {
		traceState = *content.TraceState
	}

	input := strings.Join([]string{
		hashVersion2Prefix,
		content.SpecVersion,
		content.ID,
		content.PredecessorHash,
		content.Time,
		content.Source,
		content.Subject,
		content.Type,
		content.DataContentType,
		traceParent,
		traceState,
		string(content.Data),
	}, "\n")

	finalHash := sha256.Sum256([]byte(input))

	return hashVersion2Prefix + hex.EncodeToString(finalHash[:])
}
