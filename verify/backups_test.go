package verify_test

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/thenativeweb/eventsourcingdb-auditing/database"
	"github.com/thenativeweb/eventsourcingdb-auditing/database/databasetest"
	"github.com/thenativeweb/eventsourcingdb-auditing/verify"
)

// namedBackup is a backup of a chain, by the name the findings use for it.
type namedBackup struct {
	name, content string
}

var (
	fullBackup               = namedBackup{"full.ndjson", databasetest.FullBackup}
	fullBackupOfV1           = namedBackup{"v1.ndjson", databasetest.FullBackupOfAPIVersion1}
	firstIncrementalBackup   = namedBackup{"incremental-1.ndjson", databasetest.FirstIncrementalBackup}
	secondIncrementalBackup  = namedBackup{"incremental-2.ndjson", databasetest.SecondIncrementalBackup}
	laterFullBackup          = namedBackup{"full-later.ndjson", databasetest.LaterFullBackup}
	backupWithoutEvents      = namedBackup{"incremental-3.ndjson", databasetest.IncrementalBackupWithoutEvents}
	eventsOfLaterFullBackup  = mustReadEvents(databasetest.LaterFullBackup)
	lastEventOfTheChainAt    = eventsOfLaterFullBackup[len(eventsOfLaterFullBackup)-1].Time
	afterTheLastConfirmation = lastEventOfTheChainAt.Add(90 * time.Second)
)

func mustReadEvents(backup string) []database.Event {
	var events []database.Event
	for event, err := range database.ReadBackup(strings.NewReader(backup)) {
		if err != nil {
			panic(err)
		}
		events = append(events, event)
	}

	return events
}

// changed returns the backup with the first occurrence of old in the line
// with the given index replaced with new, under another name, if one is
// given.
func (b namedBackup) changed(t *testing.T, index int, old, new string) namedBackup {
	t.Helper()

	lines := strings.SplitAfter(b.content, "\n")
	require.Contains(t, lines[index], old)
	lines[index] = strings.Replace(lines[index], old, new, 1)

	return namedBackup{name: b.name, content: strings.Join(lines, "")}
}

// withoutLines returns the backup without its lines from the given index on,
// up to the given one, excluding it, or to the end for -1.
func (b namedBackup) withoutLines(from, to int) namedBackup {
	lines := strings.SplitAfter(b.content, "\n")
	if to < 0 {
		to = len(lines)
	}

	return namedBackup{name: b.name, content: strings.Join(slices.Delete(lines, from, to), "")}
}

func (b namedBackup) renamed(name string) namedBackup {
	return namedBackup{name: name, content: b.content}
}

func sourcesOf(backups ...namedBackup) []verify.BackupSource {
	sources := make([]verify.BackupSource, 0, len(backups))
	for _, backup := range backups {
		sources = append(sources, verify.BackupSource{
			Name: backup.name,
			Open: func() (io.ReadCloser, error) {
				return io.NopCloser(strings.NewReader(backup.content)), nil
			},
		})
	}

	return sources
}

// confirmedChain returns a custodian that has confirmed every event of the
// chain half a minute after it was written.
func confirmedChain() verify.CustodianResult {
	var fingerprints []verify.ConfirmedFingerprint
	for i, event := range eventsOfLaterFullBackup {
		fingerprints = append(fingerprints, verify.ConfirmedFingerprint{
			EventID:            event.ID,
			EventHash:          event.Hash,
			Sequence:           uint64(i + 1),
			ReceivedAt:         event.Time.Add(30 * time.Second),
			IsAfterLatestReset: true,
		})
	}

	result := custodianResult(fingerprints)
	result.Intervals[0].ValidFrom = eventsOfLaterFullBackup[0].Time.Add(-time.Hour)

	return result
}

func verifyBackups(t *testing.T, custodian verify.CustodianResult, backups ...namedBackup) verify.BackupsResult {
	t.Helper()

	result, err := verify.VerifyBackups(sourcesOf(backups...), custodian, afterTheLastConfirmation)
	require.NoError(t, err)

	return result
}

func namesOf(result verify.BackupsResult) []string {
	var names []string
	for _, backup := range result.Backups {
		names = append(names, backup.Name)
	}

	return names
}

// assertFindings asserts that the result holds exactly the findings with the
// given messages, by their severities, and checks.
func assertFindings(t *testing.T, result verify.BackupsResult, expected ...verify.Finding) {
	t.Helper()

	require.Len(t, result.Findings, len(expected), "findings: %v", result.Findings)
	for i, finding := range expected {
		assert.Equal(t, finding.Severity, result.Findings[i].Severity, "finding %d", i)
		assert.Equal(t, finding.Check, result.Findings[i].Check, "finding %d", i)
		assert.Contains(t, result.Findings[i].Message, finding.Message, "finding %d", i)
	}
}

// permutationsOf returns every order of the given backups.
func permutationsOf(backups []namedBackup) [][]namedBackup {
	if len(backups) <= 1 {
		return [][]namedBackup{slices.Clone(backups)}
	}

	var permutations [][]namedBackup
	for i := range backups {
		rest := slices.Concat(backups[:i], backups[i+1:])
		for _, permutation := range permutationsOf(rest) {
			permutations = append(permutations, append([]namedBackup{backups[i]}, permutation...))
		}
	}

	return permutations
}

func manipulation(check, message string) verify.Finding {
	return verify.Finding{Severity: verify.SeverityManipulation, Check: check, Message: message}
}

func gap(check, message string) verify.Finding {
	return verify.Finding{Severity: verify.SeverityGap, Check: check, Message: message}
}

func notice(check, message string) verify.Finding {
	return verify.Finding{Severity: verify.SeverityNotice, Check: check, Message: message}
}

// withV1Error returns the backup of /api/v1/backup with an error line in place
// of its last event, as EventSourcingDB writes it when it fails to back up
// everything.
func withV1Error() namedBackup {
	lines := strings.SplitAfter(fullBackupOfV1.content, "\n")

	return namedBackup{name: fullBackupOfV1.name, content: strings.Join(slices.Concat(lines[:4], []string{`{"type":"error","payload":"failed to create backup"}` + "\n"}), "")}
}

// concatenated returns the backups one after another in one file, as cat
// writes them.
func concatenated(name string, backups ...namedBackup) namedBackup {
	var content strings.Builder
	for _, backup := range backups {
		content.WriteString(backup.content)
	}

	return namedBackup{name: name, content: content.String()}
}

func TestVerifyBackups(t *testing.T) {
	t.Run("finds nothing in a full backup and two incremental ones that follow on it", func(t *testing.T) {
		result := verifyBackups(t, confirmedChain(), fullBackup, firstIncrementalBackup, secondIncrementalBackup)

		assertFindings(t, result)
		assert.Equal(t, 10, result.EventCount)
		assert.Equal(t, eventsOfLaterFullBackup[0].Time, result.FirstEventAt)
		assert.Equal(t, lastEventOfTheChainAt, result.LastEventAt)
	})

	t.Run("finds nothing in a backup of /api/v1/backup and incremental ones in the format of create-backup that follow on its last event", func(t *testing.T) {
		result := verifyBackups(t, confirmedChain(), fullBackupOfV1, firstIncrementalBackup, secondIncrementalBackup)

		assertFindings(t, result)
		assert.Equal(t, 10, result.EventCount)
	})

	t.Run("orders the backups by the events they follow on, whatever order they are given in", func(t *testing.T) {
		for _, order := range [][]namedBackup{
			{backupWithoutEvents, secondIncrementalBackup, firstIncrementalBackup, fullBackup},
			{secondIncrementalBackup, fullBackup, backupWithoutEvents, firstIncrementalBackup},
			{firstIncrementalBackup, backupWithoutEvents, fullBackup, secondIncrementalBackup},
		} {
			result := verifyBackups(t, confirmedChain(), order...)

			assertFindings(t, result)
			assert.Equal(t, 10, result.EventCount)
			assert.Equal(t, []string{"full.ndjson", "incremental-1.ndjson", "incremental-2.ndjson", "incremental-3.ndjson"}, namesOf(result))
		}
	})

	t.Run("names every backup with its SHA-256, in the order of the chain", func(t *testing.T) {
		result := verifyBackups(t, confirmedChain(), secondIncrementalBackup, fullBackup, firstIncrementalBackup)

		require.Len(t, result.Backups, 3)
		for i, backup := range []namedBackup{fullBackup, firstIncrementalBackup, secondIncrementalBackup} {
			digest := sha256.Sum256([]byte(backup.content))
			assert.Equal(t, verify.CheckedBackup{Name: backup.name, SHA256: hex.EncodeToString(digest[:])}, result.Backups[i])
		}
	})

	t.Run("names the events before an incremental backup that starts the chain as a gap, and checks the rest", func(t *testing.T) {
		result := verifyBackups(t, confirmedChain(), secondIncrementalBackup, firstIncrementalBackup)

		assertFindings(t, result,
			gap(verify.CheckBackups, "Events 0 to 3 are in none of the backups, so they could not be checked"),
		)
		assert.Equal(t, 6, result.EventCount)
	})

	t.Run("names the events between backups that do not meet as a gap", func(t *testing.T) {
		result := verifyBackups(t, confirmedChain(), fullBackup, secondIncrementalBackup)

		assertFindings(t, result,
			gap(verify.CheckBackups, "Events 4 to 6 are in none of the backups, so they could not be checked"),
		)
		assert.Equal(t, 7, result.EventCount)
	})

	t.Run("names a single event that none of the backups holds", func(t *testing.T) {
		// The events 6 to 9 and the item that names the event the backup
		// ended at are taken out, so it ends at event 5, and is complete.
		withoutEvent6 := laterFullBackup.withoutLines(9, 14).renamed("full-until-5.ndjson")

		result := verifyBackups(t, confirmedChain(), withoutEvent6, secondIncrementalBackup)

		assertFindings(t, result,
			gap(verify.CheckBackups, "Event 6 is in none of the backups, so it could not be checked"),
		)
	})

	t.Run("finds an incremental backup that follows on an event with another hash than the backup before it holds it with", func(t *testing.T) {
		otherHash := firstIncrementalBackup.changed(t, 0, `"hash":"esdb:hash:v2:da03`, `"hash":"esdb:hash:v2:ea03`)

		result := verifyBackups(t, confirmedChain(), fullBackup, otherHash, secondIncrementalBackup)

		assertFindings(t, result,
			manipulation(verify.CheckBackups, "Backup incremental-1.ndjson follows on event 3 with the hash esdb:hash:v2:ea0353d7b49d540e4da98000a726116923477ceaf3cb72628fde8c4ea829c9d0, but full.ndjson holds that event with the hash esdb:hash:v2:da0353d7b49d540e4da98000a726116923477ceaf3cb72628fde8c4ea829c9d0"),
		)
	})

	t.Run("finds incremental backups that follow on an event none of the backups holds with different hashes", func(t *testing.T) {
		otherHash := secondIncrementalBackup.changed(t, 0, `"hash":"esdb:hash:v2:137a`, `"hash":"esdb:hash:v2:237a`).renamed("other.ndjson")

		result := verifyBackups(t, confirmedChain(), fullBackup, secondIncrementalBackup, otherHash)

		assertFindings(t, result,
			gap(verify.CheckBackups, "Events 4 to 6 are in none of the backups"),
			manipulation(verify.CheckBackups, "Backups incremental-2.ndjson and other.ndjson follow on event 6 with different hashes, esdb:hash:v2:137a"),
		)
	})

	t.Run("finds the first event after a gap that does not follow on the event its backup follows on", func(t *testing.T) {
		otherHash := secondIncrementalBackup.changed(t, 0, `"hash":"esdb:hash:v2:137a`, `"hash":"esdb:hash:v2:237a`)

		result := verifyBackups(t, custodianResult(nil), fullBackup, otherHash)

		assertFindings(t, result,
			gap(verify.CheckBackups, "Events 4 to 6 are in none of the backups"),
			manipulation(verify.CheckEventChain, "Event 7 does not follow event 6, which its backup follows on, since it names another predecessor hash"),
		)
	})

	t.Run("compares the hash that a backup follows on with the fingerprint of the custodian, if none of the backups holds that event", func(t *testing.T) {
		custodian := confirmedChain()
		custodian.Fingerprints[6].EventHash = "esdb:hash:v2:confirmed"

		result := verifyBackups(t, custodian, fullBackup, secondIncrementalBackup)

		assertFindings(t, result,
			gap(verify.CheckBackups, "Events 4 to 6 are in none of the backups"),
			manipulation(verify.CheckFingerprints, "Event 6 has the hash esdb:hash:v2:137a892772cf40aecc449a57dc8eb830d4d8191dd124f830805c05d1ff9aac19, as the backup that follows on it names it, but the custodian confirmed the hash esdb:hash:v2:confirmed"),
		)
	})

	t.Run("accepts backups that overlap, if they hold the same events, and counts every event once", func(t *testing.T) {
		result := verifyBackups(t, confirmedChain(), laterFullBackup, secondIncrementalBackup, fullBackupOfV1, firstIncrementalBackup, fullBackup)

		assertFindings(t, result)
		assert.Equal(t, 10, result.EventCount)
		assert.Equal(t, []string{"full.ndjson", "v1.ndjson", "full-later.ndjson", "incremental-1.ndjson", "incremental-2.ndjson"}, namesOf(result))
	})

	t.Run("finds the same, whatever order backups that overlap are given in", func(t *testing.T) {
		// EventSourcingDB signs an event whenever it hands it out, with the
		// key it has then, so the same event has another signature in a
		// backup taken after the key changed.
		otherSignature := laterFullBackup.changed(t, 4, `"signature":"esdb:signature:v1:7277`, `"signature":"esdb:signature:v1:0277`)
		changedData := fullBackupOfV1.changed(t, 2, `"city":"Zürich"`, `"city":"Zurich"`)

		for _, test := range []struct {
			name     string
			backups  []namedBackup
			findings []verify.Finding
		}{
			{
				name:    "with another signature",
				backups: []namedBackup{fullBackupOfV1, fullBackup, otherSignature, secondIncrementalBackup},
			},
			{
				name:     "with changed data",
				backups:  []namedBackup{changedData, fullBackup, otherSignature, secondIncrementalBackup},
				findings: []verify.Finding{manipulation(verify.CheckBackups, "Event 1 is not the same in full.ndjson and in v1.ndjson, which differ in data")},
			},
		} {
			t.Run(test.name, func(t *testing.T) {
				var first []verify.Finding
				for i, order := range permutationsOf(test.backups) {
					result := verifyBackups(t, confirmedChain(), order...)

					assertFindings(t, result, test.findings...)
					assert.Equal(t, 10, result.EventCount)
					assert.Equal(t, []string{"full.ndjson", "v1.ndjson", "full-later.ndjson", "incremental-2.ndjson"}, namesOf(result))
					if i == 0 {
						first = result.Findings
					}
					assert.Equal(t, first, result.Findings, "order %d", i)
				}
			})
		}
	})

	t.Run("finds an event that a backup lacks, although another backup holds it", func(t *testing.T) {
		for _, test := range []struct {
			name    string
			backups []namedBackup
			message string
		}{
			{
				name:    "a full backup that lacks an event of another full backup",
				backups: []namedBackup{laterFullBackup.withoutLines(5, 6), fullBackup},
				message: "Backup full-later.ndjson lacks event 2, which lies between its start and the event it ended at, so the event has been removed from it",
			},
			{
				name:    "an incremental backup that lacks an event of a full backup",
				backups: []namedBackup{laterFullBackup, firstIncrementalBackup.withoutLines(4, 5)},
				message: "Backup incremental-1.ndjson lacks event 5, which lies between its start and the event it ended at, so the event has been removed from it",
			},
			{
				name:    "an incremental backup that lacks its first events",
				backups: []namedBackup{laterFullBackup, firstIncrementalBackup.withoutLines(3, 5)},
				message: "Backup incremental-1.ndjson lacks events 4 to 5, which lie between its start and the event it ended at, so the events have been removed from it",
			},
		} {
			t.Run(test.name, func(t *testing.T) {
				result := verifyBackups(t, confirmedChain(), test.backups...)

				assertFindings(t, result,
					manipulation(verify.CheckBackups, test.message),
				)
				assert.Equal(t, 10, result.EventCount)
			})
		}
	})

	t.Run("finds an event that a backup lacks, which no other backup holds", func(t *testing.T) {
		result := verifyBackups(t, confirmedChain(), fullBackup, firstIncrementalBackup.withoutLines(4, 5), secondIncrementalBackup)

		lacking := eventFindingsOf(result.EventsResult, verify.SeverityManipulation, verify.CheckBackups)
		require.Len(t, lacking, 1)
		assert.Contains(t, lacking[0].Message, "Backup incremental-1.ndjson lacks event 5")
		assert.NotEmpty(t, eventFindingsOf(result.EventsResult, verify.SeverityManipulation, verify.CheckEventChain))
	})

	t.Run("finds the first events that an incremental backup after a gap lacks", func(t *testing.T) {
		result := verifyBackups(t, confirmedChain(), fullBackup, secondIncrementalBackup.withoutLines(3, 4))

		assertFindings(t, result,
			gap(verify.CheckBackups, "Events 4 to 6 are in none of the backups"),
			manipulation(verify.CheckBackups, "Backup incremental-2.ndjson lacks event 7"),
			manipulation(verify.CheckEventChain, "Event 8 does not follow event 6, which its backup follows on, since it names another predecessor hash"),
			manipulation(verify.CheckFingerprints, "1 events the custodian has confirmed are missing from the database, from event 7"),
		)
	})

	t.Run("accepts an incremental backup that follows on an event within the backup before it", func(t *testing.T) {
		result := verifyBackups(t, confirmedChain(), laterFullBackup, firstIncrementalBackup)

		assertFindings(t, result)
		assert.Equal(t, 10, result.EventCount)
	})

	t.Run("finds an event that differs between backups that overlap, naming both of them", func(t *testing.T) {
		changedLater := laterFullBackup.changed(t, 4, `"city":"Zürich"`, `"city":"Zurich"`)

		result := verifyBackups(t, confirmedChain(), changedLater, fullBackup, firstIncrementalBackup)

		assertFindings(t, result,
			manipulation(verify.CheckBackups, "Event 1 is not the same in full.ndjson and in full-later.ndjson, which differ in data"),
		)
	})

	t.Run("finds an event that differs between backups that overlap, also in a member that a hash of version 1 does not cover", func(t *testing.T) {
		original := namedBackup{"both.ndjson", databasetest.BackupWithHashesOfBothVersions}
		changed := original.changed(t, 0, `"traceparent":"00-0af7651916cd43dd8448eb211c80319c-`, `"traceparent":"00-1af7651916cd43dd8448eb211c80319c-`).renamed("changed.ndjson")

		result, err := verify.VerifyBackups(sourcesOf(original, changed), custodianResult(nil), tenOClock)
		require.NoError(t, err)

		backups := eventFindingsOf(result.EventsResult, verify.SeverityManipulation, verify.CheckBackups)
		require.Len(t, backups, 1)
		assert.Contains(t, backups[0].Message, "Event 0 is not the same in both.ndjson and in changed.ndjson, which differ in traceparent")
		assert.Empty(t, eventFindingsOf(result.EventsResult, verify.SeverityManipulation, verify.CheckEventHashes))
	})

	t.Run("finds an event that differs in the first backup that holds it, which is checked", func(t *testing.T) {
		changedFull := fullBackup.changed(t, 3, `"city":"Zürich"`, `"city":"Zurich"`)

		result := verifyBackups(t, confirmedChain(), laterFullBackup, changedFull)

		assertFindings(t, result,
			manipulation(verify.CheckBackups, "Event 1 is not the same in full.ndjson and in full-later.ndjson, which differ in data"),
			manipulation(verify.CheckEventHashes, "Event 1 has been changed"),
		)
	})

	t.Run("finds an event that has been changed in one of the backups", func(t *testing.T) {
		changed := firstIncrementalBackup.changed(t, 4, `"title":"Ubik"`, `"title":"Valis"`)

		result := verifyBackups(t, confirmedChain(), fullBackup, changed, secondIncrementalBackup)

		assertFindings(t, result,
			manipulation(verify.CheckEventHashes, "Event 5 has been changed"),
		)
	})

	t.Run("names a backup without its end item as a gap, and checks its events", func(t *testing.T) {
		withoutEnd := secondIncrementalBackup.withoutLines(7, -1)

		result := verifyBackups(t, confirmedChain(), fullBackup, firstIncrementalBackup, withoutEnd)

		assertFindings(t, result,
			gap(verify.CheckBackups, "Backup incremental-2.ndjson is incomplete, since it was cut short before its end item, so events after event 9 may be missing from it"),
		)
		assert.Equal(t, 10, result.EventCount)
	})

	t.Run("names a backup that was cut short as a gap, without taking the events it lacks for missing", func(t *testing.T) {
		cutShort := secondIncrementalBackup.withoutLines(4, -1)

		result := verifyBackups(t, confirmedChain(), fullBackup, firstIncrementalBackup, cutShort)

		assertFindings(t, result,
			gap(verify.CheckBackups, "Backup incremental-2.ndjson is incomplete, since it was cut short before its end item, so events after event 7 may be missing from it"),
		)
		assert.Equal(t, 8, result.EventCount)
	})

	t.Run("names a backup that was cut short in the middle of a line as a gap", func(t *testing.T) {
		cutShort := namedBackup{
			name:    secondIncrementalBackup.name,
			content: secondIncrementalBackup.content[:strings.Index(secondIncrementalBackup.content, `"id":"8"`)],
		}

		result := verifyBackups(t, confirmedChain(), fullBackup, firstIncrementalBackup, cutShort)

		assertFindings(t, result,
			gap(verify.CheckBackups, "Backup incremental-2.ndjson is incomplete, since it was cut short before its end item, so events after event 7 may be missing from it"),
		)
		assert.Equal(t, 8, result.EventCount)
	})

	t.Run("names a backup with an error as a gap, even with its end item", func(t *testing.T) {
		errorLine := strings.SplitAfter(databasetest.RefusedBackup, "\n")[0]
		withError := namedBackup{
			name:    secondIncrementalBackup.name,
			content: strings.Join(slices.Concat(strings.SplitAfter(secondIncrementalBackup.content, "\n")[:5], []string{errorLine, `{"type":"end","data":{}}` + "\n"}), ""),
		}

		result := verifyBackups(t, confirmedChain(), fullBackup, firstIncrementalBackup, withError)

		assertFindings(t, result,
			gap(verify.CheckBackups, "Backup incremental-2.ndjson is incomplete, since the database could not back up everything (last backed up event is mismatched"),
		)
		assert.Contains(t, result.Findings[0].Message, "so events after event 8 may be missing from it")
	})

	t.Run("names an incomplete backup as a notice, if complete backups hold every event of the chain after its last one", func(t *testing.T) {
		for _, test := range []struct {
			name    string
			backups []namedBackup
			message string
		}{
			{
				name:    "an incremental backup without its end item, before a complete one that follows on it",
				backups: []namedBackup{fullBackup, firstIncrementalBackup.withoutLines(7, -1), secondIncrementalBackup},
				message: "Backup incremental-1.ndjson is incomplete, since it was cut short before its end item, but complete backups hold every event of the chain after event 6",
			},
			{
				name:    "a full backup cut short, next to a complete full one",
				backups: []namedBackup{fullBackup.withoutLines(4, -1), laterFullBackup},
				message: "Backup full.ndjson is incomplete, since it was cut short before its end item, but complete backups hold every event of the chain after event 1",
			},
			{
				name:    "an incremental backup cut short in the middle of a line, next to a complete full one",
				backups: []namedBackup{laterFullBackup, {firstIncrementalBackup.name, firstIncrementalBackup.content[:strings.Index(firstIncrementalBackup.content, `"id":"5"`)]}},
				message: "Backup incremental-1.ndjson is incomplete, since it was cut short before its end item, but complete backups hold every event of the chain after event 4",
			},
			{
				name:    "a backup of /api/v1/backup with an error, next to a complete full one",
				backups: []namedBackup{withV1Error(), laterFullBackup},
				message: "Backup v1.ndjson is incomplete, since the database could not back up everything (failed to create backup), but complete backups hold every event of the chain after event 2",
			},
			{
				name:    "a full backup without its end item, next to a complete one that ends at the same event",
				backups: []namedBackup{fullBackup.withoutLines(7, -1), fullBackupOfV1},
				message: "Backup full.ndjson is incomplete, since it was cut short before its end item, but complete backups hold every event of the chain after event 3",
			},
		} {
			t.Run(test.name, func(t *testing.T) {
				custodian := custodianResult(nil)
				custodian.Intervals = confirmedChain().Intervals

				result := verifyBackups(t, custodian, test.backups...)

				assertFindings(t, result,
					notice(verify.CheckBackups, test.message),
				)
			})
		}
	})

	t.Run("names an incomplete backup as a gap, if events after its last one are in none of the complete backups", func(t *testing.T) {
		cutShort := firstIncrementalBackup.withoutLines(4, -1)

		result := verifyBackups(t, confirmedChain(), fullBackup, cutShort, secondIncrementalBackup)

		assertFindings(t, result,
			gap(verify.CheckBackups, "Events 5 to 6 are in none of the backups, so they could not be checked"),
			gap(verify.CheckBackups, "Backup incremental-1.ndjson is incomplete, since it was cut short before its end item, so events after event 4 may be missing from it"),
		)
	})

	t.Run("names a backup of /api/v1/backup with an error as a gap, and checks the events before the error", func(t *testing.T) {
		result := verifyBackups(t, confirmedChain(), withV1Error())

		assertFindings(t, result,
			gap(verify.CheckBackups, "Backup v1.ndjson is incomplete, since the database could not back up everything (failed to create backup), so events after event 2 may be missing from it"),
		)
		assert.Equal(t, 3, result.EventCount)
	})

	t.Run("reads several backups one after another in one file, every one as a backup of its own", func(t *testing.T) {
		chain := concatenated("chain.ndjson", fullBackup, firstIncrementalBackup, secondIncrementalBackup)

		result := verifyBackups(t, confirmedChain(), chain)

		assertFindings(t, result)
		assert.Equal(t, 10, result.EventCount)
		digest := sha256.Sum256([]byte(chain.content))
		require.Len(t, result.Backups, 1)
		assert.Equal(t, "chain.ndjson", result.Backups[0].Name)
		assert.Equal(t, hex.EncodeToString(digest[:]), result.Backups[0].SHA256)
		require.Len(t, result.Backups[0].Parts, 3)
		for i, part := range result.Backups[0].Parts {
			assert.Equal(t, i+1, part.Number)
			assert.Equal(t, []string{"3", "6", "9"}[i], part.EndedAt.ID)
		}
		assert.Nil(t, result.Backups[0].Parts[0].FollowsOn)
		assert.Equal(t, "3", result.Backups[0].Parts[1].FollowsOn.ID)
	})

	t.Run("orders the backups of a file with the ones of other files, whatever order they are given in", func(t *testing.T) {
		chain := concatenated("chain.ndjson", secondIncrementalBackup, fullBackup)

		for _, order := range permutationsOf([]namedBackup{chain, firstIncrementalBackup, laterFullBackup}) {
			result := verifyBackups(t, confirmedChain(), order...)

			assertFindings(t, result)
			assert.Equal(t, 10, result.EventCount)
			assert.Equal(t, []string{"chain.ndjson", "full-later.ndjson", "incremental-1.ndjson"}, namesOf(result))
			assert.Equal(t, []int{1, 2}, []int{result.Backups[0].Parts[0].Number, result.Backups[0].Parts[1].Number})
		}
	})

	t.Run("finds manipulations in one of the backups of a file, and names it by its number", func(t *testing.T) {
		for _, test := range []struct {
			name     string
			backups  []namedBackup
			findings []verify.Finding
		}{
			{
				name:     "a changed event",
				backups:  []namedBackup{concatenated("chain.ndjson", fullBackup, firstIncrementalBackup.changed(t, 4, `"title":"Ubik"`, `"title":"Valis"`), secondIncrementalBackup)},
				findings: []verify.Finding{manipulation(verify.CheckEventHashes, "Event 5 has been changed")},
			},
			{
				name:     "another hash to follow on",
				backups:  []namedBackup{concatenated("chain.ndjson", fullBackup, firstIncrementalBackup.changed(t, 0, `"hash":"esdb:hash:v2:da03`, `"hash":"esdb:hash:v2:ea03`), secondIncrementalBackup)},
				findings: []verify.Finding{manipulation(verify.CheckBackups, "Backup chain.ndjson, part 2 follows on event 3 with the hash esdb:hash:v2:ea0353d7b49d540e4da98000a726116923477ceaf3cb72628fde8c4ea829c9d0, but chain.ndjson, part 1 holds that event with the hash esdb:hash:v2:da0353d7b49d540e4da98000a726116923477ceaf3cb72628fde8c4ea829c9d0")},
			},
			{
				name:     "an event that one of them lacks, which another file holds",
				backups:  []namedBackup{concatenated("chain.ndjson", fullBackup, firstIncrementalBackup.withoutLines(4, 5), secondIncrementalBackup), laterFullBackup},
				findings: []verify.Finding{manipulation(verify.CheckBackups, "Backup chain.ndjson, part 2 lacks event 5, which lies between its start and the event it ended at, so the event has been removed from it")},
			},
			{
				name:    "an event that differs from the one another file holds",
				backups: []namedBackup{concatenated("chain.ndjson", fullBackup, firstIncrementalBackup), laterFullBackup.changed(t, 8, `"title":"Ubik"`, `"title":"Valis"`)},
				findings: []verify.Finding{
					manipulation(verify.CheckBackups, "Event 5 is not the same in full-later.ndjson and in chain.ndjson, part 2, which differ in data"),
					manipulation(verify.CheckEventHashes, "Event 5 has been changed"),
				},
			},
			{
				name:     "the last backup of a file without its end item",
				backups:  []namedBackup{concatenated("chain.ndjson", fullBackup, firstIncrementalBackup, secondIncrementalBackup.withoutLines(7, -1))},
				findings: []verify.Finding{gap(verify.CheckBackups, "Backup chain.ndjson, part 3 is incomplete, since it was cut short before its end item, so events after event 9 may be missing from it")},
			},
		} {
			t.Run(test.name, func(t *testing.T) {
				result := verifyBackups(t, confirmedChain(), test.backups...)

				assertFindings(t, result, test.findings...)
			})
		}
	})

	t.Run("fails on several backups in one file where one begins before the one before it ended, and names the file", func(t *testing.T) {
		chain := concatenated("chain.ndjson", fullBackup.withoutLines(7, -1), firstIncrementalBackup)

		_, err := verify.VerifyBackups(sourcesOf(chain), confirmedChain(), afterTheLastConfirmation)

		assert.ErrorContains(t, err, "failed to read the backup chain.ndjson: line 8 of the backup: the backup holds a second backup item before its end item")
	})

	t.Run("finds a backup that names another event as the one it ended at than the one it ended at", func(t *testing.T) {
		withoutLastEvent := fullBackup.withoutLines(5, 6)

		result := verifyBackups(t, confirmedChain(), withoutLastEvent, firstIncrementalBackup, secondIncrementalBackup)

		assertFindings(t, result,
			manipulation(verify.CheckBackups, "Backup full.ndjson names event 3 with the hash esdb:hash:v2:da0353d7b49d540e4da98000a726116923477ceaf3cb72628fde8c4ea829c9d0 as the one it ended at, but it ended at event 2 with the hash esdb:hash:v2:41bf50082d68c6ecabc615294031fb7afa61de93168f895f1433f721db19df67"),
			gap(verify.CheckBackups, "Event 3 is in none of the backups, so it could not be checked"),
		)
	})

	t.Run("fails on a backup that names a version of its format it does not know, and names that backup", func(t *testing.T) {
		unknown := firstIncrementalBackup.changed(t, 0, `"formatVersion":2`, `"formatVersion":3`)

		_, err := verify.VerifyBackups(sourcesOf(fullBackup, unknown, secondIncrementalBackup), confirmedChain(), afterTheLastConfirmation)

		require.ErrorIs(t, err, database.ErrUnknownBackupFormat)
		assert.ErrorContains(t, err, "failed to read the backup incremental-1.ndjson: line 1 of the backup")
		assert.ErrorContains(t, err, "names version 3")
	})

	t.Run("fails on a file that holds no backup, and names it", func(t *testing.T) {
		_, err := verify.VerifyBackups(sourcesOf(fullBackup, namedBackup{"refused.ndjson", databasetest.RefusedBackup}), confirmedChain(), afterTheLastConfirmation)

		assert.ErrorContains(t, err, "failed to read the backup refused.ndjson: line 1 of the backup: the file holds no backup")
	})

	t.Run("fails on a backup that can not be opened, and names it", func(t *testing.T) {
		sources := sourcesOf(fullBackup)
		sources[0].Open = func() (io.ReadCloser, error) {
			return nil, errors.New("no such file")
		}

		_, err := verify.VerifyBackups(sources, confirmedChain(), afterTheLastConfirmation)

		assert.ErrorContains(t, err, "failed to open the backup full.ndjson: no such file")
	})

	t.Run("fails on a backup that changes between the two reads", func(t *testing.T) {
		sources := sourcesOf(fullBackup)
		reads := 0
		sources[0].Open = func() (io.ReadCloser, error) {
			reads++
			if reads == 1 {
				return io.NopCloser(strings.NewReader(fullBackup.content)), nil
			}
			return io.NopCloser(strings.NewReader(fullBackup.content + "\n")), nil
		}

		_, err := verify.VerifyBackups(sources, confirmedChain(), afterTheLastConfirmation)

		assert.ErrorContains(t, err, "the backup full.ndjson changed while it was read")
	})

	t.Run("fails without a backup", func(t *testing.T) {
		_, err := verify.VerifyBackups(nil, confirmedChain(), afterTheLastConfirmation)

		assert.Error(t, err)
	})
}
