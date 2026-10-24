package database_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"slices"
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

	t.Run("computes the same hashes as EventSourcingDB 1.3 for a backup in the format of create-backup", func(t *testing.T) {
		events, err := readAll(t, database.ReadBackup(strings.NewReader(databasetest.LaterFullBackup)))

		require.NoError(t, err)
		require.Len(t, events, 10)
		for i, event := range events {
			assert.Equal(t, fmt.Sprint(i), event.ID)
			assert.True(t, event.HashMatches, "event %s", event.ID)
			assert.Equal(t, database.HashVersion2, event.HashVersion)
		}

		assert.Equal(t, database.GenesisHash, events[0].PredecessorHash)
		assert.Equal(t, events[3].Hash, events[4].PredecessorHash)
	})

	t.Run("reads the same events from both formats", func(t *testing.T) {
		ofVersion1, err := readAll(t, database.ReadBackup(strings.NewReader(databasetest.FullBackupOfAPIVersion1)))
		require.NoError(t, err)
		ofVersion2, err := readAll(t, database.ReadBackup(strings.NewReader(databasetest.FullBackup)))
		require.NoError(t, err)

		assert.Equal(t, ofVersion1, ofVersion2)
	})

	t.Run("fails at the end of a backup in the format of create-backup that is incomplete", func(t *testing.T) {
		withoutEnd := strings.TrimSuffix(databasetest.FullBackup, `{"type":"end","data":{}}`+"\n")

		events, err := readAll(t, database.ReadBackup(strings.NewReader(withoutEnd)))

		assert.ErrorContains(t, err, "the backup is incomplete, since it lacks its end item")
		assert.Len(t, events, 4)
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

// backedUpEventsOf reads the events of a file that holds a single backup with
// a BackupReader, and returns them together with what the backup tells about
// itself.
func backedUpEventsOf(t *testing.T, backup string) ([]database.BackedUpEvent, database.Backup, error) {
	t.Helper()

	events, backups, err := backedUpEventsOfFile(t, backup)
	if len(backups) == 0 {
		return events, database.Backup{}, err
	}
	if err == nil {
		require.Len(t, backups, 1)
	}

	return events, backups[len(backups)-1], err
}

// backedUpEventsOfFile reads the events of a file with a BackupReader, and
// returns them together with what every backup of the file tells about
// itself.
func backedUpEventsOfFile(t *testing.T, backup string) ([]database.BackedUpEvent, []database.Backup, error) {
	t.Helper()

	reader := database.NewBackupReader(strings.NewReader(backup))
	var events []database.BackedUpEvent
	for event, err := range reader.Events() {
		if err != nil {
			return events, reader.Backups(), err
		}
		events = append(events, event)
	}

	return events, reader.Backups(), nil
}

// onlyBackupOf returns what the single backup a reader has read tells about
// itself.
func onlyBackupOf(t *testing.T, reader *database.BackupReader) database.Backup {
	t.Helper()

	require.Len(t, reader.Backups(), 1)

	return reader.Backups()[0]
}

// withoutLines removes the lines of a backup from the given index on, up to
// the given one, excluding it, or to the end for -1.
func withoutLines(backup string, from, to int) string {
	lines := strings.SplitAfter(backup, "\n")
	if to < 0 {
		to = len(lines)
	}

	return strings.Join(slices.Delete(lines, from, to), "")
}

func TestBackupReader(t *testing.T) {
	t.Run("tells the format of a backup, the event it follows on, and the event it ended at", func(t *testing.T) {
		reference := func(id, hash string) *database.EventReference {
			return &database.EventReference{ID: id, Hash: hash}
		}
		event3 := reference("3", "esdb:hash:v2:da0353d7b49d540e4da98000a726116923477ceaf3cb72628fde8c4ea829c9d0")
		event6 := reference("6", "esdb:hash:v2:137a892772cf40aecc449a57dc8eb830d4d8191dd124f830805c05d1ff9aac19")
		event9 := reference("9", "esdb:hash:v2:bf4523f9089a79334d2d48d62a60e68aa56888c93307d74ac7cb8eb52ac16575")

		for _, test := range []struct {
			name                           string
			backup                         string
			formatVersion                  int
			events                         int
			followsOn, lastEvent, namedEnd *database.EventReference
			endedAt                        *database.EventReference
		}{
			{"a full backup", databasetest.FullBackup, database.BackupFormatVersion2, 4, nil, event3, event3, event3},
			{"a backup of /api/v1/backup", databasetest.FullBackupOfAPIVersion1, database.BackupFormatVersion1, 4, nil, event3, nil, event3},
			{"an incremental backup", databasetest.FirstIncrementalBackup, database.BackupFormatVersion2, 3, event3, event6, event6, event6},
			{"another incremental backup", databasetest.SecondIncrementalBackup, database.BackupFormatVersion2, 3, event6, event9, event9, event9},
			{"an incremental backup without events", databasetest.IncrementalBackupWithoutEvents, database.BackupFormatVersion2, 0, event9, nil, event9, event9},
		} {
			t.Run(test.name, func(t *testing.T) {
				events, backup, err := backedUpEventsOf(t, test.backup)

				require.NoError(t, err)
				require.Len(t, events, test.events)
				for _, event := range events {
					assert.True(t, event.HashMatches, "event %s", event.ID)
				}
				assert.Equal(t, test.formatVersion, backup.FormatVersion)
				assert.Equal(t, test.followsOn, backup.FollowsOn)
				assert.Equal(t, test.lastEvent, backup.LastEvent)
				assert.Equal(t, test.namedEnd, backup.NamedEnd)
				assert.Equal(t, test.endedAt, backup.EndedAt())
				assert.True(t, backup.IsComplete)
				assert.Empty(t, backup.Failure)
			})
		}
	})

	t.Run("takes a backup in the format of create-backup that lacks its end item for incomplete, and still reads its events", func(t *testing.T) {
		for _, test := range []struct {
			name   string
			backup string
			events int
		}{
			{"without its end item", withoutLines(databasetest.SecondIncrementalBackup, 7, -1), 3},
			{"cut short after its first event", withoutLines(databasetest.SecondIncrementalBackup, 4, -1), 1},
			{"cut short before its first event", withoutLines(databasetest.SecondIncrementalBackup, 3, -1), 0},
			{"cut short in the middle of a line", databasetest.SecondIncrementalBackup[:strings.Index(databasetest.SecondIncrementalBackup, `"id":"8"`)], 1},
			{"cut short in the middle of its end item", strings.TrimSuffix(databasetest.SecondIncrementalBackup, `":{}}`+"\n"), 3},
		} {
			t.Run(test.name, func(t *testing.T) {
				events, backup, err := backedUpEventsOf(t, test.backup)

				require.NoError(t, err)
				assert.Len(t, events, test.events)
				assert.False(t, backup.IsComplete)
				assert.Empty(t, backup.Failure)
				assert.Equal(t, "6", backup.FollowsOn.ID)
			})
		}
	})

	t.Run("takes a backup in the format of create-backup with an error for incomplete, even with its end item, and tells the error", func(t *testing.T) {
		errorLine := strings.SplitAfter(databasetest.RefusedBackup, "\n")[0]
		lines := strings.SplitAfter(databasetest.SecondIncrementalBackup, "\n")
		withError := strings.Join(slices.Concat(lines[:5], []string{errorLine, `{"type":"end","data":{}}` + "\n"}), "")

		events, backup, err := backedUpEventsOf(t, withError)

		require.NoError(t, err)
		assert.Len(t, events, 2)
		assert.False(t, backup.IsComplete)
		assert.Equal(t, "last backed up event is mismatched: the event with its ID has another hash, so the events changed since the previous backup", backup.Failure)
		assert.Nil(t, backup.NamedEnd)
	})

	t.Run("skips heartbeats and the schemas of event types", func(t *testing.T) {
		heartbeat := `{"type":"heartbeat","data":{}}` + "\n"
		lines := strings.SplitAfter(databasetest.FirstIncrementalBackup, "\n")
		withHeartbeats := heartbeat + strings.Join(slices.Concat(lines[:4], []string{heartbeat}, lines[4:6], []string{heartbeat, heartbeat}, lines[6:]), "")

		events, backup, err := backedUpEventsOf(t, withHeartbeats)

		require.NoError(t, err)
		assert.Len(t, events, 3)
		assert.Equal(t, database.BackupFormatVersion2, backup.FormatVersion)
		assert.True(t, backup.IsComplete)
	})

	t.Run("tells an event in the format of create-backup that has been changed in any field its hash covers", func(t *testing.T) {
		for _, change := range []struct {
			name     string
			index    int
			old, new string
		}{
			{"time", 3, `"time":"2026-10-24T10:47:29.`, `"time":"2026-10-24T10:47:30.`},
			{"data", 4, `"title":"Ubik"`, `"title":"Valis"`},
			{"traceparent", 3, `"traceparent":"00-11111111111111111111111111111111-`, `"traceparent":"00-11111111111111111111111111111112-`},
			{"traceparent that was null", 4, `"traceparent":null`, `"traceparent":"00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"`},
			{"tracestate", 3, `"tracestate":"vendor=value"`, `"tracestate":"vendor=other"`},
			{"removed tracestate", 3, `"tracestate":"vendor=value"`, `"tracestate":null`},
			{"predecessor hash", 5, `"predecessorhash":"esdb:hash:v2:`, `"predecessorhash":"esdb:hash:v3:`},
		} {
			t.Run(change.name, func(t *testing.T) {
				changed := changeEvent(t, databasetest.FirstIncrementalBackup, change.index, change.old, change.new)

				events, _, err := backedUpEventsOf(t, changed)

				require.NoError(t, err)
				require.Len(t, events, 3)
				for i, event := range events {
					assert.Equal(t, i+3 != change.index, event.HashMatches, "event %s", event.ID)
				}
			})
		}
	})

	t.Run("does not cover the signature with the hash", func(t *testing.T) {
		changed := changeEvent(t, databasetest.FirstIncrementalBackup, 3, `"signature":"esdb:signature:v1:`, `"signature":"esdb:signature:v1:00`)

		events, _, err := backedUpEventsOf(t, changed)

		require.NoError(t, err)
		assert.True(t, events[0].HashMatches)
	})

	t.Run("fails on a backup that names a version of its format it does not know", func(t *testing.T) {
		for _, formatVersion := range []string{`"formatVersion":3`, `"formatVersion":1`, `"formatVersion":2.0`, `"formatVersion":20`} {
			t.Run(formatVersion, func(t *testing.T) {
				changed := strings.Replace(databasetest.FirstIncrementalBackup, `"formatVersion":2`, formatVersion, 1)

				events, _, err := backedUpEventsOf(t, changed)

				require.ErrorIs(t, err, database.ErrUnknownBackupFormat)
				assert.ErrorContains(t, err, "line 1 of the backup")
				assert.Empty(t, events)
			})
		}

		for _, formatVersion := range []string{``, `"formatVersion":null,`} {
			t.Run("none, as in "+formatVersion, func(t *testing.T) {
				changed := strings.Replace(databasetest.FirstIncrementalBackup, `"formatVersion":2,`, formatVersion, 1)

				_, _, err := backedUpEventsOf(t, changed)

				require.ErrorIs(t, err, database.ErrUnknownBackupFormat)
				assert.ErrorContains(t, err, "names no version")
			})
		}
	})

	t.Run("fails on a line that is no JSON, unless it is the rest of a line that a backup in the format of create-backup ends with", func(t *testing.T) {
		cut := databasetest.SecondIncrementalBackup[:strings.Index(databasetest.SecondIncrementalBackup, `"id":"8"`)]

		for _, test := range []struct {
			name, backup, message string
		}{
			{"a line in the middle", strings.Replace(databasetest.SecondIncrementalBackup, `{"type":"event","data":{"specversion":"1.0","id":"8"`, `{"type":"event","data":{"specversion":"1.0","id":"8"}`+"\n", 1), "line 5 of the backup"},
			{"a last line that ends with a line feed", cut + "\n", "line 5 of the backup"},
			{"a last line after the end item", databasetest.SecondIncrementalBackup + `{"type":"event"`, "line 9 of the backup"},
			{"a last line of a backup of /api/v1/backup", databasetest.FullBackupOfAPIVersion1[:strings.Index(databasetest.FullBackupOfAPIVersion1, `"id":"3"`)], "line 5 of the backup"},
		} {
			t.Run(test.name, func(t *testing.T) {
				_, _, err := backedUpEventsOf(t, test.backup)

				assert.ErrorContains(t, err, test.message)
			})
		}
	})

	t.Run("fails on a file that holds no backup, but the error the database answered with instead", func(t *testing.T) {
		_, _, err := backedUpEventsOf(t, databasetest.RefusedBackup)

		assert.ErrorContains(t, err, "line 1 of the backup: the file holds no backup, but the error the database answered with instead: last backed up event is mismatched")
	})

	t.Run("reads several backups one after another in one file, as EventSourcingDB restores them", func(t *testing.T) {
		heartbeat := `{"type":"heartbeat","data":{}}` + "\n"
		for _, test := range []struct {
			name, file string
		}{
			{"as cat writes them", databasetest.FullBackup + databasetest.FirstIncrementalBackup + databasetest.SecondIncrementalBackup},
			{"with heartbeats between them", databasetest.FullBackup + heartbeat + databasetest.FirstIncrementalBackup + heartbeat + heartbeat + databasetest.SecondIncrementalBackup},
		} {
			t.Run(test.name, func(t *testing.T) {
				events, backups, err := backedUpEventsOfFile(t, test.file)

				require.NoError(t, err)
				require.Len(t, events, 10)
				for i, event := range events {
					assert.Equal(t, fmt.Sprint(i), event.ID)
					assert.True(t, event.HashMatches, "event %s", event.ID)
					assert.Equal(t, []int{0, 0, 0, 0, 1, 1, 1, 2, 2, 2}[i], event.Part, "event %s", event.ID)
				}

				require.Len(t, backups, 3)
				for i, followsOn := range []string{"", "3", "6"} {
					assert.True(t, backups[i].IsComplete)
					assert.Equal(t, database.BackupFormatVersion2, backups[i].FormatVersion)
					assert.Equal(t, []string{"3", "6", "9"}[i], backups[i].EndedAt().ID)
					if followsOn == "" {
						assert.Nil(t, backups[i].FollowsOn)
					} else {
						assert.Equal(t, followsOn, backups[i].FollowsOn.ID)
					}
				}
			})
		}
	})

	t.Run("reads several backups in one file in any order, and tells which of them is incomplete", func(t *testing.T) {
		withoutEnd := strings.TrimSuffix(databasetest.FirstIncrementalBackup, `{"type":"end","data":{}}`+"\n")

		events, backups, err := backedUpEventsOfFile(t, databasetest.SecondIncrementalBackup+databasetest.FullBackup+withoutEnd)

		require.NoError(t, err)
		assert.Len(t, events, 10)
		require.Len(t, backups, 3)
		assert.Equal(t, "6", backups[0].FollowsOn.ID)
		assert.Nil(t, backups[1].FollowsOn)
		assert.Equal(t, "3", backups[2].FollowsOn.ID)
		assert.Equal(t, []bool{true, true, false}, []bool{backups[0].IsComplete, backups[1].IsComplete, backups[2].IsComplete})
	})

	t.Run("fails on several backups in one file where one begins before the one before it ended", func(t *testing.T) {
		withoutEnd := strings.TrimSuffix(databasetest.FullBackup, `{"type":"end","data":{}}`+"\n")

		_, _, err := backedUpEventsOfFile(t, withoutEnd+databasetest.FirstIncrementalBackup)

		assert.ErrorContains(t, err, "line 8 of the backup: the backup holds a second backup item before its end item")
	})

	t.Run("fails on what EventSourcingDB answered instead of a backup after a backup", func(t *testing.T) {
		_, _, err := backedUpEventsOfFile(t, databasetest.FullBackup+databasetest.RefusedBackup)

		assert.ErrorContains(t, err, `line 9 of the backup: the backup holds an item of type "error" after its end item`)
	})

	t.Run("takes a backup of /api/v1/backup with an error for incomplete, and still reads the events before the error", func(t *testing.T) {
		lines := strings.SplitAfter(databasetest.FullBackupOfAPIVersion1, "\n")
		withError := strings.Join(slices.Concat(lines[:4], []string{`{"type":"error","payload":"failed to create backup"}` + "\n"}), "")

		events, backup, err := backedUpEventsOf(t, withError)

		require.NoError(t, err)
		assert.Len(t, events, 3)
		assert.Equal(t, database.BackupFormatVersion1, backup.FormatVersion)
		assert.False(t, backup.IsComplete)
		assert.Equal(t, "failed to create backup", backup.Failure)
		assert.Equal(t, "2", backup.EndedAt().ID)
	})

	t.Run("fails on a line after the error the database wrote into a backup", func(t *testing.T) {
		v1Lines := strings.SplitAfter(databasetest.FullBackupOfAPIVersion1, "\n")
		v2Lines := strings.SplitAfter(databasetest.SecondIncrementalBackup, "\n")
		errorLine := strings.SplitAfter(databasetest.RefusedBackup, "\n")[0]

		for _, test := range []struct {
			name, backup, message string
		}{
			{"of /api/v1/backup", strings.Join(slices.Concat(v1Lines[:3], []string{`{"type":"error","payload":"failed to create backup"}` + "\n"}, v1Lines[3:]), ""), "line 5 of the backup: the backup holds a line after the error the database wrote into it"},
			{"in the format of create-backup", strings.Join(slices.Concat(v2Lines[:4], []string{errorLine}, v2Lines[4:]), ""), `line 6 of the backup: the backup holds an item of type "event" after the error the database wrote into it`},
		} {
			t.Run(test.name, func(t *testing.T) {
				_, _, err := backedUpEventsOfFile(t, test.backup)

				assert.ErrorContains(t, err, test.message)
			})
		}
	})

	t.Run("fails on items where the format of create-backup puts none", func(t *testing.T) {
		lines := strings.SplitAfter(databasetest.FirstIncrementalBackup, "\n")

		for _, test := range []struct {
			name, backup, message string
		}{
			{"an event after the end item", databasetest.FirstIncrementalBackup + lines[3], `line 9 of the backup: the backup holds an item of type "event" after its end item`},
			{"a second backup item", strings.Join(slices.Concat(lines[:4], lines[:1], lines[4:]), ""), "line 5 of the backup: the backup holds a second backup item before its end item"},
			{"an event before the backup item", strings.Join(slices.Concat(lines[3:4], lines), ""), `line 1 of the backup: expected a backup item to begin the backup, but got one of type "event"`},
			{"an item of an unknown type", strings.Join(slices.Concat(lines[:3], []string{`{"type":"something-else","data":{}}` + "\n"}, lines[3:]), ""), `line 4 of the backup: unknown type "something-else"`},
			{"an event without a hash", changeEvent(t, databasetest.FirstIncrementalBackup, 4, `"hash":"esdb:hash:v2:`, `"other":"esdb:hash:v2:`), "line 5 of the backup: the event has no ID or no hash"},
			{"an event to follow on without a hash", strings.Replace(databasetest.FirstIncrementalBackup, `"lastBackedUpEvent":{"id":"3","hash"`, `"lastBackedUpEvent":{"id":"3","other"`, 1), "line 1 of the backup: the event the backup follows on is invalid"},
		} {
			t.Run(test.name, func(t *testing.T) {
				_, _, err := backedUpEventsOf(t, test.backup)

				assert.ErrorContains(t, err, test.message)
			})
		}
	})
}

func TestBackedUpEvent(t *testing.T) {
	t.Run("finds no differences between the same events in both formats", func(t *testing.T) {
		ofVersion1, _, err := backedUpEventsOf(t, databasetest.FullBackupOfAPIVersion1)
		require.NoError(t, err)
		ofVersion2, _, err := backedUpEventsOf(t, databasetest.FullBackup)
		require.NoError(t, err)
		later, _, err := backedUpEventsOf(t, databasetest.LaterFullBackup)
		require.NoError(t, err)

		for i := range ofVersion1 {
			assert.Empty(t, ofVersion1[i].DifferencesFrom(ofVersion2[i]), "event %d", i)
			assert.Empty(t, ofVersion2[i].DifferencesFrom(ofVersion1[i]), "event %d", i)
			assert.Empty(t, ofVersion2[i].DifferencesFrom(later[i]), "event %d", i)
		}
	})

	t.Run("names the members in which the same event differs", func(t *testing.T) {
		for _, change := range []struct {
			name         string
			backup       string
			line, event  int
			old, new     string
			differences  []string
			stillMatches bool
		}{
			{"data", databasetest.FullBackup, 2, 0, `"title":"2001 – A Space Odyssey"`, `"title":"2010 – Odyssey Two"`, []string{"data"}, false},
			{"subject and type", databasetest.FullBackup, 5, 3, `"subject":"/books/42","type":"io.eventsourcingdb.library.book-returned"`, `"subject":"/books/23","type":"io.eventsourcingdb.library.book-lost"`, []string{"subject", "type"}, false},
			{"a removed trace context", databasetest.FullBackup, 2, 0, `"traceparent":"00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01","tracestate":"rojo=00f067aa0ba902b7,congo=t61rcWkgMzE"`, `"traceparent":null,"tracestate":null`, []string{"traceparent", "tracestate"}, false},
			{"a trace context that a hash of version 1 does not cover", databasetest.BackupWithHashesOfBothVersions, 0, 0, `"traceparent":"00-0af7651916cd43dd8448eb211c80319c-`, `"traceparent":"00-1af7651916cd43dd8448eb211c80319c-`, []string{"traceparent"}, true},
			{"hash", databasetest.FullBackup, 5, 3, `"hash":"esdb:hash:v2:da03`, `"hash":"esdb:hash:v2:ea03`, []string{"hash"}, false},
		} {
			t.Run(change.name, func(t *testing.T) {
				original, _, err := backedUpEventsOf(t, change.backup)
				require.NoError(t, err)
				changed, _, err := backedUpEventsOf(t, changeEvent(t, change.backup, change.line, change.old, change.new))
				require.NoError(t, err)

				event := change.event
				assert.Equal(t, change.differences, original[event].DifferencesFrom(changed[event]))
				assert.Equal(t, change.differences, changed[event].DifferencesFrom(original[event]), "whichever event the comparison starts from")
				assert.Equal(t, change.stillMatches, changed[event].HashMatches, "whether the hash still matches")
				for i := range original {
					if i != event {
						assert.Empty(t, original[i].DifferencesFrom(changed[i]), "event %d", i)
					}
				}
			})
		}
	})

	t.Run("leaves out the signature, which EventSourcingDB computes anew with the key it has whenever it hands out an event", func(t *testing.T) {
		const signature = `"signature":"esdb:signature:v1:9133f5a2ef0c7df7567d1169d298b7c9b1dec9a976d920ecd64c07b0dccb8bbfb82e2e7265b39c4ebd137f0c638bfc65b3813048800322bbae198ff3ec7a840d"`

		original, _, err := backedUpEventsOf(t, databasetest.FullBackup)
		require.NoError(t, err)
		ofVersion1, _, err := backedUpEventsOf(t, databasetest.FullBackupOfAPIVersion1)
		require.NoError(t, err)

		for _, test := range []struct {
			name, new string
		}{
			{"of another key", `"signature":"esdb:signature:v1:0133f5a2ef0c7df7567d1169d298b7c9b1dec9a976d920ecd64c07b0dccb8bbfb82e2e7265b39c4ebd137f0c638bfc65b3813048800322bbae198ff3ec7a840d"`},
			{"of a database that signs nothing", `"signature":null`},
		} {
			t.Run(test.name, func(t *testing.T) {
				changed, _, err := backedUpEventsOf(t, changeEvent(t, databasetest.FullBackup, 5, signature, test.new))
				require.NoError(t, err)

				assert.Empty(t, original[3].DifferencesFrom(changed[3]))
				assert.Empty(t, changed[3].DifferencesFrom(original[3]))
				assert.Empty(t, ofVersion1[3].DifferencesFrom(changed[3]))
				assert.True(t, changed[3].HashMatches)
			})
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

// createBackup takes a backup of the database on
// /api/v2/management/create-backup, following on the given event, or a full
// one for nil. It skips the test on an EventSourcingDB that does not write
// backups there yet, which 1.3 begins to.
func createBackup(t *testing.T, container *eventsourcingdbtest.Container, followsOn *database.EventReference) []byte {
	t.Helper()

	baseURL, err := container.GetBaseURL(t.Context())
	require.NoError(t, err)

	body, err := json.Marshal(map[string]*database.EventReference{"lastBackedUpEvent": followsOn})
	require.NoError(t, err)

	request, err := http.NewRequestWithContext(t.Context(), http.MethodPost, baseURL.JoinPath("/api/v2/management/create-backup").String(), bytes.NewReader(body))
	require.NoError(t, err)
	request.Header.Set("Authorization", "Bearer "+container.GetAPIToken())
	request.Header.Set("Content-Type", "application/json")

	response, err := http.DefaultClient.Do(request)
	require.NoError(t, err)
	defer response.Body.Close()
	if response.StatusCode == http.StatusNotFound {
		t.Skipf("EventSourcingDB %s does not write backups on /api/v2/management/create-backup, which version 1.3 introduces, so run the tests against preview", databasetest.ImageTag())
	}
	require.Equal(t, http.StatusOK, response.StatusCode)

	backup, err := io.ReadAll(response.Body)
	require.NoError(t, err)

	return backup
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

	t.Run("reads the same events from a full and an incremental backup in the format of create-backup", func(t *testing.T) {
		container, client, _ := newDatabase(t)

		full := database.NewBackupReader(bytes.NewReader(createBackup(t, container, nil)))
		fullEvents, err := readAll(t, eventsOf(full.Events()))
		require.NoError(t, err)
		require.True(t, onlyBackupOf(t, full).IsComplete)
		require.Nil(t, onlyBackupOf(t, full).FollowsOn)

		_, err = client.WriteEvents(t.Context(), []eventsourcingdb.EventCandidate{
			{Source: "https://example.com", Subject: "/books/42", Type: "io.example.book-returned", Data: map[string]any{"by": "/readers/23"}},
		}, nil)
		require.NoError(t, err)

		incremental := database.NewBackupReader(bytes.NewReader(createBackup(t, container, onlyBackupOf(t, full).EndedAt())))
		incrementalEvents, err := readAll(t, eventsOf(incremental.Events()))
		require.NoError(t, err)
		require.True(t, onlyBackupOf(t, incremental).IsComplete)
		assert.Equal(t, onlyBackupOf(t, full).EndedAt(), onlyBackupOf(t, incremental).FollowsOn)
		assert.Equal(t, onlyBackupOf(t, incremental).LastEvent, onlyBackupOf(t, incremental).NamedEnd)

		live, err := readAll(t, database.ReadDatabase(t.Context(), client))
		require.NoError(t, err)

		backedUp := append(fullEvents, incrementalEvents...)
		require.Len(t, backedUp, len(live))
		for i := range live {
			assert.True(t, backedUp[i].HashMatches, "event %s", backedUp[i].ID)
			assert.Equal(t, live[i].ID, backedUp[i].ID)
			assert.Equal(t, live[i].Hash, backedUp[i].Hash)
			assert.True(t, live[i].Time.Equal(backedUp[i].Time))
		}
	})
}

// eventsOf returns the events a backup holds, as they are checked.
func eventsOf(backedUp func(func(database.BackedUpEvent, error) bool)) func(func(database.Event, error) bool) {
	return func(yield func(database.Event, error) bool) {
		for event, err := range backedUp {
			if !yield(event.Event, err) || err != nil {
				return
			}
		}
	}
}
