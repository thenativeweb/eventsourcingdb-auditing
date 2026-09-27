package database_test

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/thenativeweb/eventsourcingdb-auditing/database"
	"github.com/thenativeweb/eventsourcingdb-client-golang/eventsourcingdb"
)

// esdbBackup holds events with the hashes EventSourcingDB has computed for
// them, taken from the tests of EventSourcingDB itself, as lines of a backup.
const esdbBackup = `{"type":"event","payload":{"event":{"source":"tag:thenativeweb.io,2023:test","subject":"/users/anne","type":"io.thenativeweb.test.registered","traceparent":"00-00000000000000000000000000000001-0000000000000001-01","tracestate":"a=1","specversion":"1","id":"0","time":"2023-01-02T13:37:00.0001Z","datacontenttype":"application/json","predecessorhash":"0000000000000000000000000000000000000000000000000000000000000000","data":{"username":"anne"}},"hash":"b6ae7a219468eeb110cf20151d9a8dc091ed40390a1411e36c183bf6a804900f"}}
{"type":"event","payload":{"event":{"source":"tag:thenativeweb.io,2023:test","subject":"/users/anne","type":"io.thenativeweb.test.loggedIn","traceparent":"00-00000000000000000000000000000002-0000000000000002-02","tracestate":"a=2","specversion":"2","id":"1","time":"2023-01-02T13:37:00.0002Z","datacontenttype":"application/json","predecessorhash":"b6ae7a219468eeb110cf20151d9a8dc091ed40390a1411e36c183bf6a804900f","data":{"username":"anne"}},"hash":"a97f96c1a2b61ea7fa1f6249079f624a244f783357e5b0b8e27b32b363a04263"}}
{"type":"event","payload":{"event":{"source":"tag:thenativeweb.io,2023:test","subject":"/users/arno","type":"io.thenativeweb.test.registered","traceparent":"00-00000000000000000000000000000003-0000000000000003-03","tracestate":"a=3","specversion":"3","id":"2","time":"2023-01-02T13:37:01.0001Z","datacontenttype":"application/json","predecessorhash":"a97f96c1a2b61ea7fa1f6249079f624a244f783357e5b0b8e27b32b363a04263","data":{"username":"arno"}},"hash":"64d040f3bcf26b3a17f3172ddf56443cffa7f10fcd407eada39f2484bba36dea"}}
{"type":"event","payload":{"event":{"source":"tag:thenativeweb.io,2023:test","subject":"/users/arno","type":"io.thenativeweb.test.loggedIn","traceparent":"00-00000000000000000000000000000004-0000000000000004-04","tracestate":"a=4","specversion":"4","id":"3","time":"2023-01-02T13:37:01.0002Z","datacontenttype":"application/json","predecessorhash":"64d040f3bcf26b3a17f3172ddf56443cffa7f10fcd407eada39f2484bba36dea","data":{"username":"arno"}},"hash":"f8fa12a86ccc776c94ad95802ed1fc1d182a17dbeed9846381711f062a5d2a47"}}
{"type":"event","payload":{"event":{"source":"tag:thenativeweb.io,2023:test","subject":"/users","type":"io.thenativeweb.test.foo","traceparent":"00-00000000000000000000000000000005-0000000000000005-05","tracestate":"a=5","specversion":"5","id":"4","time":"2023-01-02T13:37:02.0001Z","datacontenttype":"application/json","predecessorhash":"f8fa12a86ccc776c94ad95802ed1fc1d182a17dbeed9846381711f062a5d2a47","data":{}},"hash":"084d451c2a2606c85577a5aec38d28837d3db41f590106c85426b535bb03a705"}}
`

func readAll(t *testing.T, events func(func(database.Event, error) bool)) ([]database.Event, error) {
	t.Helper()

	var read []database.Event
	for event, err := range events {
		if err != nil {
			return read, err
		}
		read = append(read, event)
	}

	return read, nil
}

func TestReadBackup(t *testing.T) {
	t.Run("computes the same hashes as EventSourcingDB", func(t *testing.T) {
		events, err := readAll(t, database.ReadBackup(strings.NewReader(esdbBackup)))

		require.NoError(t, err)
		require.Len(t, events, 5)
		for _, event := range events {
			assert.True(t, event.HashMatches, "event %s", event.ID)
		}

		assert.Equal(t, "0", events[0].ID)
		assert.Equal(t, database.GenesisHash, events[0].PredecessorHash)
		assert.Equal(t, events[0].Hash, events[1].PredecessorHash)
		assert.Equal(t, time.Date(2023, 1, 2, 13, 37, 0, 100_000, time.UTC), events[0].Time)
	})

	t.Run("tells an event whose data has been changed", func(t *testing.T) {
		changed := strings.Replace(esdbBackup, `"data":{"username":"arno"}},"hash":"64d0`, `"data":{"username":"arnold"}},"hash":"64d0`, 1)

		events, err := readAll(t, database.ReadBackup(strings.NewReader(changed)))

		require.NoError(t, err)
		assert.False(t, events[2].HashMatches)
		assert.True(t, events[3].HashMatches, "the events after it still hash to their own hashes")
	})

	t.Run("hashes the data exactly as it was written, including escapes", func(t *testing.T) {
		escaped := strings.Replace(esdbBackup, `"data":{"username":"anne"}},"hash":"b6ae`, `"data":{"username":"\u0061nne"}},"hash":"b6ae`, 1)

		events, err := readAll(t, database.ReadBackup(strings.NewReader(escaped)))

		require.NoError(t, err)
		assert.False(t, events[0].HashMatches, "an escape changes the bytes, so the hash must change as well")
	})

	t.Run("skips empty lines and the schemas of event types", func(t *testing.T) {
		backup := "\n" + `{"type":"schema","payload":{"eventType":"io.thenativeweb.test.registered","schema":{}}}` + "\n" + esdbBackup

		events, err := readAll(t, database.ReadBackup(strings.NewReader(backup)))

		require.NoError(t, err)
		assert.Len(t, events, 5)
	})

	t.Run("fails on an error the database wrote into the backup", func(t *testing.T) {
		backup := esdbBackup + `{"type":"error","payload":"disk full"}` + "\n"

		events, err := readAll(t, database.ReadBackup(strings.NewReader(backup)))

		assert.ErrorContains(t, err, "disk full")
		assert.Len(t, events, 5)
	})

	t.Run("fails on lines it does not understand", func(t *testing.T) {
		for _, line := range []string{
			`not json`,
			`{"type":"something-else","payload":{}}`,
			`{"type":"event","payload":{"event":{"id":"0"}}}`,
			`{"type":"event","payload":{"event":{"id":"0","time":"yesterday"},"hash":"abc"}}`,
		} {
			_, err := readAll(t, database.ReadBackup(strings.NewReader(line)))

			assert.ErrorContains(t, err, "line 1 of the backup", line)
		}
	})
}

// newDatabase starts a real EventSourcingDB for a single test, and writes
// events into it whose data needs escaping in JSON.
func newDatabase(t *testing.T) (*eventsourcingdb.Container, *eventsourcingdb.Client) {
	t.Helper()

	container := eventsourcingdb.NewContainer()
	require.NoError(t, container.Start(t.Context()))
	t.Cleanup(func() {
		_ = container.Stop(context.Background())
	})

	client, err := container.GetClient(t.Context())
	require.NoError(t, err)

	candidates := []eventsourcingdb.EventCandidate{
		{Source: "https://example.com", Subject: "/books/42", Type: "io.example.book-acquired", Data: map[string]any{"title": "<Ümlauts & Émojis 🎉>"}},
		{Source: "https://example.com", Subject: "/books/42", Type: "io.example.book-borrowed", Data: map[string]any{"reader": "Jürgen \"J\" O'Neil"}},
		{Source: "https://example.com", Subject: "/readers/23", Type: "io.example.reader-registered", Data: map[string]any{"name": "阿部"}},
	}
	_, err = client.WriteEvents(candidates, nil)
	require.NoError(t, err)

	return container, client
}

func TestReadDatabase(t *testing.T) {
	t.Run("reads all events, and computes the hashes EventSourcingDB has written", func(t *testing.T) {
		_, client := newDatabase(t)

		events, err := readAll(t, database.ReadDatabase(t.Context(), client))

		require.NoError(t, err)
		require.Len(t, events, 3)
		for _, event := range events {
			assert.True(t, event.HashMatches, "event %s", event.ID)
		}
		assert.Equal(t, database.GenesisHash, events[0].PredecessorHash)
	})

	t.Run("reads the same events from a backup of the database", func(t *testing.T) {
		container, client := newDatabase(t)

		live, err := readAll(t, database.ReadDatabase(t.Context(), client))
		require.NoError(t, err)

		baseURL, err := container.GetBaseURL(t.Context())
		require.NoError(t, err)

		request, err := http.NewRequestWithContext(t.Context(), http.MethodPost, baseURL.JoinPath("/api/v1/backup").String(), nil)
		require.NoError(t, err)
		request.Header.Set("Authorization", "Bearer "+container.GetAPIToken())

		response, err := http.DefaultClient.Do(request)
		require.NoError(t, err)
		defer response.Body.Close()
		require.Equal(t, http.StatusOK, response.StatusCode)

		backup, err := io.ReadAll(response.Body)
		require.NoError(t, err)

		backedUp, err := readAll(t, database.ReadBackup(bytes.NewReader(backup)))
		require.NoError(t, err)

		require.Len(t, backedUp, len(live))
		for i := range live {
			assert.True(t, backedUp[i].HashMatches, "event %s", backedUp[i].ID)
			assert.Equal(t, live[i].ID, backedUp[i].ID)
			assert.Equal(t, live[i].Hash, backedUp[i].Hash)
			assert.True(t, live[i].Time.Equal(backedUp[i].Time))
		}
	})
}
