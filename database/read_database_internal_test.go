package database

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/thenativeweb/eventsourcingdb-auditing/database/databasetest"
	"github.com/thenativeweb/eventsourcingdb-client-golang/v2/eventsourcingdb"
)

// readEventsOf returns the events of a backup as the client SDK reads them
// from a running database, so that the hashes of events EventSourcingDB has
// really written can be checked as if they were read, including changed ones,
// which no running database hands out.
func readEventsOf(t *testing.T, backup string) []eventsourcingdb.Event {
	t.Helper()

	var events []eventsourcingdb.Event
	for line := range strings.Lines(backup) {
		var parsed struct {
			Payload struct {
				Event eventsourcingdb.Event `json:"event"`
				Hash  string                `json:"hash"`
			} `json:"payload"`
		}
		require.NoError(t, json.Unmarshal([]byte(line), &parsed))

		event := parsed.Payload.Event
		event.Hash = parsed.Payload.Hash
		events = append(events, event)
	}

	return events
}

func TestCheckReadEvent(t *testing.T) {
	t.Run("checks hashes of both versions with the client SDK", func(t *testing.T) {
		for i, event := range readEventsOf(t, databasetest.BackupWithHashesOfBothVersions) {
			checked, err := checkReadEvent(event)

			require.NoError(t, err)
			assert.True(t, checked.HashMatches, "event %d", i)
			assert.False(t, checked.HashVersionIsUnknown)
			assert.Equal(t, []string{HashVersion1, HashVersion1, HashVersion2, HashVersion2}[i], checked.HashVersion)
			assert.Equal(t, event.Hash, checked.Hash)
			assert.Equal(t, event.PredecessorHash, checked.PredecessorHash)
			assert.Equal(t, event.Time, checked.Time)
		}
	})

	t.Run("tells an event that has been changed", func(t *testing.T) {
		events := readEventsOf(t, databasetest.BackupWithHashesOfBothVersions)
		changedTraceState := "vendor=other"
		events[2].TraceState = &changedTraceState

		checked, err := checkReadEvent(events[2])

		require.NoError(t, err)
		assert.False(t, checked.HashMatches)
		assert.False(t, checked.HashVersionIsUnknown)
	})

	t.Run("tells a hash of a version it does not know, rather than taking it for a changed one", func(t *testing.T) {
		events := readEventsOf(t, databasetest.BackupWithHashesOfBothVersions)
		events[3].Hash = strings.Replace(events[3].Hash, "esdb:hash:v2:", "esdb:hash:v3:", 1)

		checked, err := checkReadEvent(events[3])

		require.NoError(t, err)
		assert.False(t, checked.HashMatches)
		assert.True(t, checked.HashVersionIsUnknown)
		assert.Equal(t, "v3", checked.HashVersion)
	})
}
