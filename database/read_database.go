package database

import (
	"context"
	"fmt"
	"iter"
	"time"

	"github.com/thenativeweb/eventsourcingdb-client-golang/eventsourcingdb"
)

// ReadDatabase reads the events of a running database, in the order they were
// written.
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

			computed := hash(eventContent{
				SpecVersion:     event.SpecVersion,
				ID:              event.ID,
				PredecessorHash: event.PredecessorHash,
				Time:            event.Time.Format(time.RFC3339Nano),
				Source:          event.Source,
				Subject:         event.Subject,
				Type:            event.Type,
				DataContentType: event.DataContentType,
				Data:            event.Data,
			})

			if !yield(Event{
				ID:              event.ID,
				Time:            event.Time,
				Hash:            event.Hash,
				PredecessorHash: event.PredecessorHash,
				HashMatches:     computed == event.Hash,
			}, nil) {
				return
			}
		}
	}
}
