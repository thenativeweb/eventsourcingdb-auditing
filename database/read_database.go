package database

import (
	"context"
	"errors"
	"fmt"
	"iter"

	"github.com/thenativeweb/eventsourcingdb-client-golang/v2/eventsourcingdb"
)

// ReadDatabase reads the events of a running database, in the order they were
// written, and checks the hash of every event in the version that hash names.
//
// Note that EventSourcingDB has no API token that only reads, so whoever runs
// this holds a token that could write as well.
func ReadDatabase(ctx context.Context, client *eventsourcingdb.Client) iter.Seq2[Event, error] {
	return func(yield func(Event, error) bool) {
		options := eventsourcingdb.ReadEventsOptions{
			Recursive: true,
			Order:     eventsourcingdb.OrderChronological(),
		}

		for event, err := range client.ReadEvents(ctx, "/", options) {
			if err != nil {
				yield(Event{}, fmt.Errorf("failed to read the database: %w", err))
				return
			}

			checked, err := checkReadEvent(event)
			if err != nil {
				yield(Event{}, err)
				return
			}

			if !yield(checked, nil) {
				return
			}
		}
	}
}

// checkReadEvent checks the hash of an event that the client SDK has read, in
// the version the hash names, with the client SDK, which computes it the same
// way as ReadBackup does. Since the client SDK has parsed the time, it writes
// it again in RFC 3339, with the fractional part trimmed of trailing zeros,
// which is how EventSourcingDB writes it.
func checkReadEvent(event eventsourcingdb.Event) (Event, error) {
	hashVersion, isKnown := hashVersionOf(event.Hash)

	checked := Event{
		ID:                   event.ID,
		Time:                 event.Time,
		Hash:                 event.Hash,
		PredecessorHash:      event.PredecessorHash,
		HashVersion:          hashVersion,
		HashVersionIsUnknown: !isKnown,
	}

	err := event.VerifyHash()
	switch {
	case err == nil:
		checked.HashMatches = true
	case errors.Is(err, eventsourcingdb.ErrHashVerificationFailed):
		checked.HashMatches = false
	case errors.Is(err, eventsourcingdb.ErrUnsupportedHashVersion):
		checked.HashVersionIsUnknown = true
	default:
		return Event{}, fmt.Errorf("failed to check the hash of event %s: %w", event.ID, err)
	}

	return checked, nil
}
