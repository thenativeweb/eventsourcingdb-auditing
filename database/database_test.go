package database_test

import (
	"bytes"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/thenativeweb/eventsourcingdb-auditing/database"
	"github.com/thenativeweb/eventsourcingdb-auditing/database/databasetest"
	"github.com/thenativeweb/eventsourcingdb-client-golang/v2/eventsourcingdb"
	"github.com/thenativeweb/eventsourcingdb-client-golang/v2/eventsourcingdbtest"
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

// changeEvent changes the line of a backup that holds the event with the
// given index, replacing the first occurrence of old in it with new.
func changeEvent(t *testing.T, backup string, index int, old, new string) string {
	t.Helper()

	lines := strings.SplitAfter(backup, "\n")
	require.Contains(t, lines[index], old)
	lines[index] = strings.Replace(lines[index], old, new, 1)

	return strings.Join(lines, "")
}

func TestReadBackup(t *testing.T) {
	t.Run("computes the same hashes as EventSourcingDB", func(t *testing.T) {
		events, err := readAll(t, database.ReadBackup(strings.NewReader(esdbBackup)))

		require.NoError(t, err)
		require.Len(t, events, 5)
		for _, event := range events {
			assert.True(t, event.HashMatches, "event %s", event.ID)
			assert.Equal(t, database.HashVersion1, event.HashVersion)
			assert.False(t, event.HashVersionIsUnknown)
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

	t.Run("computes the same hashes of version 2 as EventSourcingDB 1.3", func(t *testing.T) {
		events, err := readAll(t, database.ReadBackup(strings.NewReader(databasetest.BackupWithHashesOfVersion2)))

		require.NoError(t, err)
		require.Len(t, events, 4)
		for _, event := range events {
			assert.True(t, event.HashMatches, "event %s", event.ID)
			assert.Equal(t, database.HashVersion2, event.HashVersion)
			assert.True(t, strings.HasPrefix(event.Hash, "esdb:hash:v2:"))
		}

		assert.Equal(t, database.GenesisHash, events[0].PredecessorHash, "the genesis value has no prefix in version 2 either")
		assert.Equal(t, events[0].Hash, events[1].PredecessorHash)
	})

	t.Run("computes every event in the version its own hash names, in a backup with both versions", func(t *testing.T) {
		events, err := readAll(t, database.ReadBackup(strings.NewReader(databasetest.BackupWithHashesOfBothVersions)))

		require.NoError(t, err)
		require.Len(t, events, 4)
		for i, version := range []string{database.HashVersion1, database.HashVersion1, database.HashVersion2, database.HashVersion2} {
			assert.True(t, events[i].HashMatches, "event %s", events[i].ID)
			assert.Equal(t, version, events[i].HashVersion, "event %s", events[i].ID)
		}

		assert.Equal(t, events[1].Hash, events[2].PredecessorHash, "the first event of version 2 names the hash of version 1 before it")
		assert.Equal(t, events[2].Hash, events[3].PredecessorHash)
	})

	t.Run("tells an event of version 2 that has been changed in any field its hash covers", func(t *testing.T) {
		for _, change := range []struct {
			name     string
			index    int
			old, new string
		}{
			{"spec version", 3, `"specversion":"1.0"`, `"specversion":"1.1"`},
			{"ID", 3, `"id":"3"`, `"id":"4"`},
			{"predecessor hash", 3, `"predecessorhash":"esdb:hash:v2:0457`, `"predecessorhash":"esdb:hash:v2:1457`},
			{"time", 3, `"time":"2026-10-24T09:11:14.238369299Z"`, `"time":"2026-10-24T09:11:14.2383693Z"`},
			{"source", 3, `"source":"https://library.eventsourcingdb.io"`, `"source":"https://library.eventsourcingdb.com"`},
			{"subject", 3, `"subject":"/books/42"`, `"subject":"/books/23"`},
			{"type", 3, `"type":"io.eventsourcingdb.library.book-returned"`, `"type":"io.eventsourcingdb.library.book-lost"`},
			{"data content type", 3, `"datacontenttype":"application/json"`, `"datacontenttype":"application/cloudevents+json"`},
			{"data", 1, `"name":"阿部 🎉"`, `"name":"阿部 🎊"`},
			{"number in the data", 2, `"copies":9007199254740993`, `"copies":9007199254740992`},
			{"traceparent", 0, `"traceparent":"00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01"`, `"traceparent":"00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203332-01"`},
			{"tracestate", 0, `"tracestate":"rojo=00f067aa0ba902b7,congo=t61rcWkgMzE"`, `"tracestate":"rojo=00f067aa0ba902b7"`},
			{"removed trace context", 0, `"traceparent":"00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01","tracestate":"rojo=00f067aa0ba902b7,congo=t61rcWkgMzE",`, ``},
			{"added tracestate", 2, `"traceparent":"00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",`, `"traceparent":"00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01","tracestate":"vendor=value",`},
			{"added traceparent", 3, `"type":"io.eventsourcingdb.library.book-returned",`, `"type":"io.eventsourcingdb.library.book-returned","traceparent":"00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",`},
		} {
			t.Run(change.name, func(t *testing.T) {
				changed := changeEvent(t, databasetest.BackupWithHashesOfVersion2, change.index, change.old, change.new)

				events, err := readAll(t, database.ReadBackup(strings.NewReader(changed)))

				require.NoError(t, err)
				require.Len(t, events, 4)
				for i, event := range events {
					assert.False(t, event.HashVersionIsUnknown)
					assert.Equal(t, i != change.index, event.HashMatches, "event %d", i)
				}
			})
		}
	})

	t.Run("covers the trace context with a hash of version 2, but not with one of version 1", func(t *testing.T) {
		const traceParent, otherTraceParent = `"traceparent":"00-0af7651916cd43dd8448eb211c80319c-`, `"traceparent":"00-1af7651916cd43dd8448eb211c80319c-`
		changed := changeEvent(t, databasetest.BackupWithHashesOfBothVersions, 0, traceParent, otherTraceParent)
		changed = changeEvent(t, changed, 2, `"tracestate":"vendor=value"`, `"tracestate":"vendor=other"`)

		events, err := readAll(t, database.ReadBackup(strings.NewReader(changed)))

		require.NoError(t, err)
		assert.True(t, events[0].HashMatches, "a hash of version 1 does not cover the traceparent")
		assert.False(t, events[2].HashMatches, "a hash of version 2 covers the tracestate")
	})

	t.Run("takes a hash of version 2 without its prefix for one of version 1, which does not match", func(t *testing.T) {
		changed := changeEvent(t, databasetest.BackupWithHashesOfVersion2, 3, `"hash":"esdb:hash:v2:`, `"hash":"`)

		events, err := readAll(t, database.ReadBackup(strings.NewReader(changed)))

		require.NoError(t, err)
		assert.Equal(t, database.HashVersion1, events[3].HashVersion)
		assert.False(t, events[3].HashMatches)
		assert.False(t, events[3].HashVersionIsUnknown)
	})

	t.Run("tells a hash of a version it does not know, rather than taking it for a changed one", func(t *testing.T) {
		for _, test := range []struct {
			prefix, version string
		}{
			{"esdb:hash:v3:", "v3"},
			{"esdb:hash:v10:", "v10"},
			{"esdb:hash:V2:", "V2"},
		} {
			t.Run(test.prefix, func(t *testing.T) {
				changed := changeEvent(t, databasetest.BackupWithHashesOfVersion2, 3, `"hash":"esdb:hash:v2:`, `"hash":"`+test.prefix)

				events, err := readAll(t, database.ReadBackup(strings.NewReader(changed)))

				require.NoError(t, err)
				assert.True(t, events[3].HashVersionIsUnknown)
				assert.Equal(t, test.version, events[3].HashVersion)
				assert.False(t, events[3].HashMatches)
				assert.True(t, events[2].HashMatches)
			})
		}
	})

	t.Run("refuses a backup in the format of the v2 API, which it does not read", func(t *testing.T) {
		backup := `{"type":"backup","data":{"formatVersion":2,"lastBackedUpEvent":null}}` + "\n"

		_, err := readAll(t, database.ReadBackup(strings.NewReader(backup)))

		assert.ErrorContains(t, err, "line 1 of the backup: the backup is in the format of /api/v2/management/create-backup")
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

// newDatabase starts a real EventSourcingDB for a single test, from the image
// the environment names, and writes events into it whose data needs escaping
// in JSON, with nested objects and numbers, and with and without a trace
// context. It returns the events as the database wrote them.
func newDatabase(t *testing.T) (*eventsourcingdbtest.Container, *eventsourcingdb.Client, []eventsourcingdb.Event) {
	t.Helper()

	container, client := databasetest.Start(t)

	traceParent, traceState := "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01", "vendor=value"
	candidates := []eventsourcingdb.EventCandidate{
		{Source: "https://example.com", Subject: "/books/42", Type: "io.example.book-acquired", Data: map[string]any{"title": "<Ümlauts & Émojis 🎉>", "author": map[string]any{"name": "阿部", "born": 1917}}, TraceParent: &traceParent, TraceState: &traceState},
		{Source: "https://example.com", Subject: "/books/42", Type: "io.example.book-borrowed", Data: map[string]any{"reader": "Jürgen \"J\" O'Neil", "copies": 3, "ratio": 0.1, "whole": 1.0}, TraceParent: &traceParent},
		{Source: "https://example.com", Subject: "/readers/23", Type: "io.example.reader-registered", Data: map[string]any{"name": "阿部", "tags": []any{"a", map[string]any{"b": nil}}}},
	}
	written, err := client.WriteEvents(t.Context(), candidates, nil)
	require.NoError(t, err)

	return container, client, written
}

func TestReadDatabase(t *testing.T) {
	t.Run("reads all events, and computes the hashes EventSourcingDB has written", func(t *testing.T) {
		_, client, written := newDatabase(t)

		events, err := readAll(t, database.ReadDatabase(t.Context(), client))

		require.NoError(t, err)
		require.Len(t, events, len(written))
		for i, event := range events {
			assert.True(t, event.HashMatches, "event %s", event.ID)
			assert.False(t, event.HashVersionIsUnknown)
			assert.Equal(t, written[i].Hash, event.Hash)
		}
		assert.Equal(t, database.GenesisHash, events[0].PredecessorHash)
		t.Logf("EventSourcingDB %s wrote hashes of version %s", databasetest.ImageTag(), events[0].HashVersion)
	})

	t.Run("reads the same events from a backup of the database", func(t *testing.T) {
		container, client, _ := newDatabase(t)

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
			assert.Equal(t, live[i].HashVersion, backedUp[i].HashVersion)
			assert.True(t, live[i].Time.Equal(backedUp[i].Time))
		}
	})
}
