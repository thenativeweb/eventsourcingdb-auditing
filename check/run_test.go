package check_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/thenativeweb/eventsourcingdb-auditing/audit"
	"github.com/thenativeweb/eventsourcingdb-auditing/check"
	"github.com/thenativeweb/eventsourcingdb-auditing/database"
	"github.com/thenativeweb/eventsourcingdb-auditing/database/databasetest"
	"github.com/thenativeweb/eventsourcingdb-auditing/receipt/receipttest"
	"github.com/thenativeweb/eventsourcingdb-auditing/report"
	"github.com/thenativeweb/eventsourcingdb-auditing/trustedlists"
	"github.com/thenativeweb/eventsourcingdb-auditing/verify"
	"github.com/thenativeweb/eventsourcingdb-auditing/verify/verifytest"
	"github.com/thenativeweb/eventsourcingdb-client-golang/v2/eventsourcingdb"
	"github.com/thenativeweb/eventsourcingdb-client-golang/v2/eventsourcingdbtest"
)

const testAuditorToken = "auditor-token"

// instance is an EventSourcingDB with events, from the image the environment
// names, a custodian that has confirmed every one of them half a minute after
// it was written, and a backup of it.
type instance struct {
	container  *eventsourcingdbtest.Container
	client     *eventsourcingdb.Client
	custodian  *verifytest.Custodian
	serverURL  string
	backupPath string
	now        time.Time
}

func newInstance(t *testing.T) instance {
	t.Helper()

	container, client := databasetest.Start(t)

	traceParent := "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"
	for _, title := range []string{"2001", "<Ümlauts & Émojis 🎉>", "Dune"} {
		_, err := client.WriteEvents(t.Context(), []eventsourcingdb.EventCandidate{{
			Source: "https://example.com", Subject: "/books", Type: "io.example.book-acquired", Data: map[string]any{"title": title}, TraceParent: &traceParent,
		}}, nil)
		require.NoError(t, err)
	}

	custodian := verifytest.NewCustodian(t)
	var lastReceivedAt time.Time
	for event, err := range database.ReadDatabase(t.Context(), client) {
		require.NoError(t, err)

		lastReceivedAt = event.Time.Add(30 * time.Second)
		custodian.Record(event.ID, event.Hash, lastReceivedAt)
	}

	return instance{
		container:  container,
		client:     client,
		custodian:  custodian,
		serverURL:  verifytest.NewServer(t, custodian, testAuditorToken),
		backupPath: backUp(t, container),
		now:        lastReceivedAt.Add(time.Minute),
	}
}

// backUp writes a backup of the database into a file, and returns its path.
func backUp(t *testing.T, container *eventsourcingdbtest.Container) string {
	t.Helper()

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

	path := filepath.Join(t.TempDir(), "backup.json")
	require.NoError(t, os.WriteFile(path, backup, 0o600))

	return path
}

func (i instance) options(t *testing.T) check.Options {
	t.Helper()

	return check.Options{
		ServerURL:     i.serverURL,
		AuditorToken:  testAuditorToken,
		RootPublicKey: i.custodian.RootPublicKey,
		BackupPaths:   []string{i.backupPath},
		ToolVersion:   "1.2.3",
		Now:           func() time.Time { return i.now },
	}
}

// keepReceipts writes the receipts of the custodian into a receipts
// directory, as the client does, and returns its path.
func keepReceipts(t *testing.T, custodian *verifytest.Custodian) string {
	t.Helper()

	var lines bytes.Buffer
	for _, entry := range custodian.Chain {
		if entry.FingerprintRecorded != nil {
			line, err := json.Marshal(map[string]string{"receipt": entry.FingerprintRecorded.Receipt})
			require.NoError(t, err)
			lines.Write(append(line, '\n'))
		}
	}

	directory := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(directory, "receipts-2026-09-27.jsonl"), lines.Bytes(), 0o600))

	return directory
}

func TestRun(t *testing.T) {
	t.Run("finds nothing in a backup that matches the custodian, and names what it checked", func(t *testing.T) {
		instance := newInstance(t)
		options := instance.options(t)
		options.ReceiptsDirectory = keepReceipts(t, instance.custodian)

		built, err := check.Run(t.Context(), options)

		require.NoError(t, err)
		assert.Empty(t, built.Findings)
		assert.Equal(t, report.ResultNoFindings, built.Result)
		assert.Equal(t, report.ExitCodeNoFindings, built.ExitCode())

		assert.Equal(t, "1.2.3", built.ToolVersion)
		assert.Equal(t, instance.now, built.CheckedAt)
		assert.Equal(t, instance.custodian.Instance.InstanceID, built.Instance.ID)
		assert.Equal(t, 3, built.Events.Count)
		assert.Equal(t, 3, built.Receipts)
		assert.True(t, built.ReceiptsDirectoryChecked)

		backup, err := os.ReadFile(instance.backupPath)
		require.NoError(t, err)
		digest := sha256.Sum256(backup)
		assert.Equal(t, []report.Backup{{Path: instance.backupPath, SHA256: hex.EncodeToString(digest[:])}}, built.Sources.Backups)
	})

	t.Run("finds an event that was changed in the backup", func(t *testing.T) {
		instance := newInstance(t)

		backup, err := os.ReadFile(instance.backupPath)
		require.NoError(t, err)
		changed := strings.Replace(string(backup), `"title":"Dune"`, `"title":"Dune Messiah"`, 1)
		require.NotEqual(t, string(backup), changed)
		require.NoError(t, os.WriteFile(instance.backupPath, []byte(changed), 0o600))

		built, err := check.Run(t.Context(), instance.options(t))

		require.NoError(t, err)
		assert.Equal(t, report.ResultManipulation, built.Result)
		require.NotEmpty(t, built.Findings)
		assert.Equal(t, verify.CheckEventHashes, built.Findings[0].Check)
	})

	t.Run("checks the running database as well", func(t *testing.T) {
		instance := newInstance(t)
		options := instance.options(t)
		options.BackupPaths = nil
		options.Database = instance.client
		options.DatabaseURL = "http://database.example.com"

		built, err := check.Run(t.Context(), options)

		require.NoError(t, err)
		assert.Empty(t, built.Findings)
		assert.Equal(t, "http://database.example.com", built.Sources.Database)
		assert.Empty(t, built.Sources.Backups)
	})

	t.Run("fails without exactly one source of events", func(t *testing.T) {
		instance := newInstance(t)
		options := instance.options(t)
		options.Database = instance.client

		_, err := check.Run(t.Context(), options)

		assert.ErrorContains(t, err, "either a backup or a database")
	})

	t.Run("fails with the wrong root key", func(t *testing.T) {
		instance := newInstance(t)
		options := instance.options(t)
		options.RootPublicKey, _ = receipttest.NewSigningKey(t)

		_, err := check.Run(t.Context(), options)

		assert.ErrorIs(t, err, verify.ErrNoCertifiedKey)
	})

	t.Run("fails if the custodian refuses the auditor token", func(t *testing.T) {
		instance := newInstance(t)
		options := instance.options(t)
		options.AuditorToken = "another-token"

		_, err := check.Run(t.Context(), options)

		assert.ErrorIs(t, err, audit.ErrAccessDenied)
	})

	t.Run("fails on a backup that does not exist", func(t *testing.T) {
		instance := newInstance(t)
		options := instance.options(t)
		options.BackupPaths = []string{filepath.Join(t.TempDir(), "missing.json")}

		_, err := check.Run(t.Context(), options)

		assert.ErrorContains(t, err, "failed to open the backup")
	})

	t.Run("checks the time stamps of the anchors against the trusted lists", func(t *testing.T) {
		instance := newInstance(t)
		instance.custodian.Anchor(instance.now.Truncate(time.Hour))
		instance.serverURL = verifytest.NewServer(t, instance.custodian, testAuditorToken)

		issuedAt := time.Date(2026, 9, 24, 12, 4, 6, 0, time.UTC)
		options := instance.options(t)
		options.ServerURL = instance.serverURL
		options.TrustedLists = fakeTrustedLists{issuedAt: issuedAt, reason: "the certificate names no country, so no trusted list applies to it"}

		built, err := check.Run(t.Context(), options)

		require.NoError(t, err)
		assert.True(t, built.TrustedListsChecked)
		require.NotNil(t, built.TrustedLists)
		assert.Equal(t, issuedAt, built.TrustedLists.ListOfTheListsIssuedAt)
		assert.Equal(t, 1, built.TrustedLists.StampedAnchors)
		assert.Equal(t, 0, built.TrustedLists.QualifiedAnchors)
		require.Len(t, built.Findings, 1)
		assert.Equal(t, verify.CheckQualification, built.Findings[0].Check)
		assert.Equal(t, report.ResultNoFindings, built.Result, "a time stamp that is not qualified is a notice")
	})

	t.Run("fails if the trusted lists can not be checked", func(t *testing.T) {
		instance := newInstance(t)
		instance.custodian.Anchor(instance.now.Truncate(time.Hour))
		options := instance.options(t)
		options.ServerURL = verifytest.NewServer(t, instance.custodian, testAuditorToken)
		options.TrustedLists = fakeTrustedLists{err: errors.New("the trusted list of DE is not reachable")}

		_, err := check.Run(t.Context(), options)

		assert.ErrorContains(t, err, "not reachable")
	})
}

// chainOfBackups is the custodian of the instance whose backups databasetest
// holds, which has confirmed every one of its events half a minute after it
// was written, and the time a minute after the last confirmation.
type chainOfBackups struct {
	custodian *verifytest.Custodian
	serverURL string
	now       time.Time
	directory string
}

func newChainOfBackups(t *testing.T) chainOfBackups {
	t.Helper()

	custodian := verifytest.NewCustodian(t)
	var lastReceivedAt time.Time
	for event, err := range database.ReadBackup(strings.NewReader(databasetest.LaterFullBackup)) {
		require.NoError(t, err)

		lastReceivedAt = event.Time.Add(30 * time.Second)
		custodian.Record(event.ID, event.Hash, lastReceivedAt)
	}

	return chainOfBackups{
		custodian: custodian,
		serverURL: verifytest.NewServer(t, custodian, testAuditorToken),
		now:       lastReceivedAt.Add(time.Minute),
		directory: t.TempDir(),
	}
}

// write writes a backup into a file of the given name, and returns its path.
func (c chainOfBackups) write(t *testing.T, name, backup string) string {
	t.Helper()

	path := filepath.Join(c.directory, name)
	require.NoError(t, os.WriteFile(path, []byte(backup), 0o600))

	return path
}

func (c chainOfBackups) run(t *testing.T, backupPaths ...string) (report.Report, error) {
	t.Helper()

	return check.Run(t.Context(), check.Options{
		ServerURL:     c.serverURL,
		AuditorToken:  testAuditorToken,
		RootPublicKey: c.custodian.RootPublicKey,
		BackupPaths:   backupPaths,
		ToolVersion:   "1.2.3",
		Now:           func() time.Time { return c.now },
	})
}

func TestRunWithBackups(t *testing.T) {
	t.Run("finds nothing in a full backup and two incremental ones, given in any order, and names every one with its SHA-256, in the order of the chain", func(t *testing.T) {
		chain := newChainOfBackups(t)
		full := chain.write(t, "full.ndjson", databasetest.FullBackup)
		first := chain.write(t, "incremental-1.ndjson", databasetest.FirstIncrementalBackup)
		second := chain.write(t, "incremental-2.ndjson", databasetest.SecondIncrementalBackup)

		built, err := chain.run(t, second, full, first)

		require.NoError(t, err)
		assert.Empty(t, built.Findings)
		assert.Equal(t, report.ExitCodeNoFindings, built.ExitCode())
		assert.Equal(t, 10, built.Events.Count)

		require.Len(t, built.Sources.Backups, 3)
		for i, path := range []string{full, first, second} {
			content, err := os.ReadFile(path)
			require.NoError(t, err)
			digest := sha256.Sum256(content)
			assert.Equal(t, report.Backup{Path: path, SHA256: hex.EncodeToString(digest[:])}, built.Sources.Backups[i])
		}
	})

	t.Run("finds nothing in a backup of /api/v1/backup and incremental ones in the format of create-backup that follow on it", func(t *testing.T) {
		chain := newChainOfBackups(t)

		built, err := chain.run(t,
			chain.write(t, "v1.ndjson", databasetest.FullBackupOfAPIVersion1),
			chain.write(t, "incremental-1.ndjson", databasetest.FirstIncrementalBackup),
			chain.write(t, "incremental-2.ndjson", databasetest.SecondIncrementalBackup),
		)

		require.NoError(t, err)
		assert.Empty(t, built.Findings)
		assert.Equal(t, report.ExitCodeNoFindings, built.ExitCode())
	})

	t.Run("finds nothing in backups that overlap and hold the same events", func(t *testing.T) {
		chain := newChainOfBackups(t)

		built, err := chain.run(t,
			chain.write(t, "full-later.ndjson", databasetest.LaterFullBackup),
			chain.write(t, "full.ndjson", databasetest.FullBackup),
			chain.write(t, "v1.ndjson", databasetest.FullBackupOfAPIVersion1),
			chain.write(t, "incremental-1.ndjson", databasetest.FirstIncrementalBackup),
		)

		require.NoError(t, err)
		assert.Empty(t, built.Findings)
		assert.Equal(t, 10, built.Events.Count)
	})

	for _, test := range []struct {
		name     string
		backups  map[string]string
		check    string
		message  string
		exitCode int
	}{
		{
			name:     "ends with the exit code for gaps if the chain starts with an incremental backup",
			backups:  map[string]string{"incremental-1.ndjson": databasetest.FirstIncrementalBackup, "incremental-2.ndjson": databasetest.SecondIncrementalBackup},
			check:    verify.CheckBackups,
			message:  "Events 0 to 3 are in none of the backups, so they could not be checked",
			exitCode: report.ExitCodeGaps,
		},
		{
			name:     "ends with the exit code for gaps if a backup in the middle of the chain is missing",
			backups:  map[string]string{"full.ndjson": databasetest.FullBackup, "incremental-2.ndjson": databasetest.SecondIncrementalBackup},
			check:    verify.CheckBackups,
			message:  "Events 4 to 6 are in none of the backups, so they could not be checked",
			exitCode: report.ExitCodeGaps,
		},
		{
			name:     "ends with the exit code for gaps if a backup lacks its end item",
			backups:  map[string]string{"full.ndjson": databasetest.FullBackup, "incremental-1.ndjson": strings.TrimSuffix(databasetest.FirstIncrementalBackup, `{"type":"end","data":{}}`+"\n")},
			check:    verify.CheckBackups,
			message:  "incremental-1.ndjson is incomplete, since it was cut short before its end item",
			exitCode: report.ExitCodeGaps,
		},
		{
			name:     "ends with the exit code for a manipulation if an incremental backup follows on an event with another hash",
			backups:  map[string]string{"full.ndjson": databasetest.FullBackup, "incremental-1.ndjson": strings.Replace(databasetest.FirstIncrementalBackup, `"hash":"esdb:hash:v2:da03`, `"hash":"esdb:hash:v2:ea03`, 1), "incremental-2.ndjson": databasetest.SecondIncrementalBackup},
			check:    verify.CheckBackups,
			message:  "follows on event 3 with the hash esdb:hash:v2:ea03",
			exitCode: report.ExitCodeManipulation,
		},
		{
			name:     "ends with the exit code for a manipulation if an event differs between backups that overlap",
			backups:  map[string]string{"full.ndjson": databasetest.FullBackup, "full-later.ndjson": strings.Replace(databasetest.LaterFullBackup, `"city":"Zürich"`, `"city":"Zurich"`, 1)},
			check:    verify.CheckBackups,
			message:  "Event 1 is not the same in ",
			exitCode: report.ExitCodeManipulation,
		},
		{
			name:     "ends with the exit code for a manipulation if a backup lacks an event, even though another backup holds it",
			backups:  map[string]string{"full.ndjson": databasetest.FullBackup, "full-later.ndjson": strings.Replace(databasetest.LaterFullBackup, strings.SplitAfter(databasetest.LaterFullBackup, "\n")[5], "", 1)},
			check:    verify.CheckBackups,
			message:  "full-later.ndjson lacks event 2",
			exitCode: report.ExitCodeManipulation,
		},
		{
			name:     "ends with the exit code for a manipulation if an event was changed in one of the backups",
			backups:  map[string]string{"full.ndjson": databasetest.FullBackup, "incremental-1.ndjson": strings.Replace(databasetest.FirstIncrementalBackup, `"title":"Ubik"`, `"title":"Valis"`, 1), "incremental-2.ndjson": databasetest.SecondIncrementalBackup},
			check:    verify.CheckEventHashes,
			message:  "Event 5 has been changed",
			exitCode: report.ExitCodeManipulation,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			chain := newChainOfBackups(t)
			var paths []string
			for name, backup := range test.backups {
				paths = append(paths, chain.write(t, name, backup))
			}

			built, err := chain.run(t, paths...)

			require.NoError(t, err)
			require.Len(t, built.Findings, 1, "findings: %v", built.Findings)
			assert.Equal(t, test.check, built.Findings[0].Check)
			assert.Contains(t, built.Findings[0].Message, test.message)
			assert.Equal(t, test.exitCode, built.ExitCode())
			assert.Len(t, built.Sources.Backups, len(test.backups))
		})
	}

	t.Run("ends with the exit code for gaps for a backup of /api/v1/backup with an error, but with no findings if a complete backup holds the events after it", func(t *testing.T) {
		lines := strings.SplitAfter(databasetest.FullBackupOfAPIVersion1, "\n")
		withError := strings.Join(append(lines[:4:4], `{"type":"error","payload":"failed to create backup"}`+"\n"), "")

		chain := newChainOfBackups(t)
		v1 := chain.write(t, "v1.ndjson", withError)

		alone, err := chain.run(t, v1)

		require.NoError(t, err)
		require.Len(t, alone.Findings, 1)
		assert.Equal(t, verify.SeverityGap, alone.Findings[0].Severity)
		assert.Contains(t, alone.Findings[0].Message, "v1.ndjson is incomplete, since the database could not back up everything (failed to create backup), so events after event 2 may be missing from it")
		assert.Equal(t, report.ExitCodeGaps, alone.ExitCode())

		covered, err := chain.run(t, v1, chain.write(t, "full-later.ndjson", databasetest.LaterFullBackup))

		require.NoError(t, err)
		require.Len(t, covered.Findings, 1)
		assert.Equal(t, verify.SeverityNotice, covered.Findings[0].Severity)
		assert.Contains(t, covered.Findings[0].Message, "but complete backups hold every event of the chain after event 2")
		assert.Equal(t, report.ExitCodeNoFindings, covered.ExitCode())
	})

	t.Run("reads several backups one after another in one file, as cat writes them, together with separate files in any order, and names the file once with its backups", func(t *testing.T) {
		chain := newChainOfBackups(t)
		concatenated := chain.write(t, "chain.ndjson", databasetest.FullBackup+databasetest.FirstIncrementalBackup)
		second := chain.write(t, "incremental-2.ndjson", databasetest.SecondIncrementalBackup)
		later := chain.write(t, "full-later.ndjson", databasetest.LaterFullBackup)

		content, err := os.ReadFile(concatenated)
		require.NoError(t, err)
		digest := sha256.Sum256(content)

		for _, order := range [][]string{{concatenated, second, later}, {second, later, concatenated}, {later, concatenated, second}} {
			built, err := chain.run(t, order...)

			require.NoError(t, err)
			assert.Empty(t, built.Findings)
			assert.Equal(t, report.ExitCodeNoFindings, built.ExitCode())
			assert.Equal(t, 10, built.Events.Count)
			require.Len(t, built.Sources.Backups, 3)
			assert.Equal(t, report.Backup{
				Path:   concatenated,
				SHA256: hex.EncodeToString(digest[:]),
				Parts:  []report.BackupPart{{Number: 1, EndedAt: "3"}, {Number: 2, FollowsOn: "3", EndedAt: "6"}},
			}, built.Sources.Backups[0])
			assert.Equal(t, []string{later, second}, []string{built.Sources.Backups[1].Path, built.Sources.Backups[2].Path})
		}
	})

	t.Run("ends with the exit code for a manipulation for a manipulated backup in a file with several, and names it by its number", func(t *testing.T) {
		chain := newChainOfBackups(t)
		concatenated := chain.write(t, "chain.ndjson", databasetest.FullBackup+strings.Replace(databasetest.FirstIncrementalBackup, `"hash":"esdb:hash:v2:da03`, `"hash":"esdb:hash:v2:ea03`, 1)+databasetest.SecondIncrementalBackup)

		built, err := chain.run(t, concatenated)

		require.NoError(t, err)
		require.Len(t, built.Findings, 1)
		assert.Contains(t, built.Findings[0].Message, "Backup "+concatenated+", part 2 follows on event 3 with the hash esdb:hash:v2:ea03")
		assert.Equal(t, report.ExitCodeManipulation, built.ExitCode())
	})

	t.Run("ends with the same result, whatever order backups that overlap are given in, even if the signatures of their events differ", func(t *testing.T) {
		chain := newChainOfBackups(t)
		v1 := chain.write(t, "v1.ndjson", databasetest.FullBackupOfAPIVersion1)
		full := chain.write(t, "full.ndjson", databasetest.FullBackup)
		later := chain.write(t, "full-later.ndjson", strings.Replace(databasetest.LaterFullBackup, `"signature":"esdb:signature:v1:7277`, `"signature":"esdb:signature:v1:0277`, 1))

		for _, order := range [][]string{{v1, full, later}, {later, full, v1}, {full, v1, later}, {later, v1, full}} {
			built, err := chain.run(t, order...)

			require.NoError(t, err)
			assert.Empty(t, built.Findings)
			assert.Equal(t, report.ExitCodeNoFindings, built.ExitCode())
			assert.Equal(t, []string{full, v1, later}, []string{built.Sources.Backups[0].Path, built.Sources.Backups[1].Path, built.Sources.Backups[2].Path})
		}
	})

	t.Run("reads a backup that is no regular file, such as a pipe, once, and names it as it was given", func(t *testing.T) {
		if runtime.GOOS == "windows" {
			t.Skip("pipes have no path on Windows")
		}

		temporary := t.TempDir()
		t.Setenv("TMPDIR", temporary)

		chain := newChainOfBackups(t)
		path := pipeOf(t, databasetest.FullBackup)

		built, err := chain.run(t,
			path,
			chain.write(t, "incremental-1.ndjson", databasetest.FirstIncrementalBackup),
			chain.write(t, "incremental-2.ndjson", databasetest.SecondIncrementalBackup),
		)

		require.NoError(t, err)
		assert.Empty(t, built.Findings)
		assert.Equal(t, 10, built.Events.Count)
		digest := sha256.Sum256([]byte(databasetest.FullBackup))
		assert.Equal(t, report.Backup{Path: path, SHA256: hex.EncodeToString(digest[:])}, built.Sources.Backups[0])

		copies, err := os.ReadDir(temporary)
		require.NoError(t, err)
		assert.Empty(t, copies, "the copy of the pipe is removed")
	})

	t.Run("removes the copy of a backup that is no regular file, if the verification fails", func(t *testing.T) {
		if runtime.GOOS == "windows" {
			t.Skip("pipes have no path on Windows")
		}

		temporary := t.TempDir()
		t.Setenv("TMPDIR", temporary)

		chain := newChainOfBackups(t)
		path := pipeOf(t, strings.Replace(databasetest.FullBackup, `"formatVersion":2`, `"formatVersion":3`, 1))

		_, err := chain.run(t, path)

		require.ErrorIs(t, err, database.ErrUnknownBackupFormat)
		assert.ErrorContains(t, err, path)

		copies, err := os.ReadDir(temporary)
		require.NoError(t, err)
		assert.Empty(t, copies, "the copy of the pipe is removed")
	})

	t.Run("fails on a backup that names a version of its format it does not know, and names that backup", func(t *testing.T) {
		chain := newChainOfBackups(t)
		unknown := chain.write(t, "incremental-1.ndjson", strings.Replace(databasetest.FirstIncrementalBackup, `"formatVersion":2`, `"formatVersion":3`, 1))

		_, err := chain.run(t, chain.write(t, "full.ndjson", databasetest.FullBackup), unknown)

		require.ErrorIs(t, err, database.ErrUnknownBackupFormat)
		assert.ErrorContains(t, err, unknown)
	})
}

// pipeOf returns the path of a pipe that hands out the given backup once, as
// a process substitution does, which can not be read twice.
func pipeOf(t *testing.T, backup string) string {
	t.Helper()

	reader, writer, err := os.Pipe()
	require.NoError(t, err)
	t.Cleanup(func() {
		_ = reader.Close()
	})

	go func() {
		_, _ = writer.WriteString(backup)
		_ = writer.Close()
	}()

	return fmt.Sprintf("/dev/fd/%d", reader.Fd())
}

// createBackup takes a backup of the database on
// /api/v2/management/create-backup, following on the given event, or a full
// one for nil, writes it into a file, and returns its path, and the event it
// ended at. It skips the test on an EventSourcingDB that does not write
// backups there yet, which 1.3 begins to.
func createBackup(t *testing.T, container *eventsourcingdbtest.Container, followsOn *database.EventReference) (string, *database.EventReference) {
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

	reader := database.NewBackupReader(bytes.NewReader(backup))
	for _, err := range reader.Events() {
		require.NoError(t, err)
	}
	require.Len(t, reader.Backups(), 1)
	require.True(t, reader.Backups()[0].IsComplete)

	path := filepath.Join(t.TempDir(), "backup.ndjson")
	require.NoError(t, os.WriteFile(path, backup, 0o600))

	return path, reader.Backups()[0].EndedAt()
}

func TestRunWithBackupsOfARunningDatabase(t *testing.T) {
	t.Run("finds nothing in a full backup and an incremental one in the format of create-backup, and the events of both", func(t *testing.T) {
		instance := newInstance(t)
		full, endedAt := createBackup(t, instance.container, nil)

		_, err := instance.client.WriteEvents(t.Context(), []eventsourcingdb.EventCandidate{
			{Source: "https://example.com", Subject: "/books", Type: "io.example.book-lost", Data: map[string]any{"title": "Dune", "copies": 9007199254740993}},
		}, nil)
		require.NoError(t, err)
		incremental, _ := createBackup(t, instance.container, endedAt)

		custodian := verifytest.NewCustodian(t)
		var lastReceivedAt time.Time
		for event, err := range database.ReadDatabase(t.Context(), instance.client) {
			require.NoError(t, err)

			lastReceivedAt = event.Time.Add(30 * time.Second)
			custodian.Record(event.ID, event.Hash, lastReceivedAt)
		}

		options := instance.options(t)
		options.ServerURL = verifytest.NewServer(t, custodian, testAuditorToken)
		options.RootPublicKey = custodian.RootPublicKey
		options.BackupPaths = []string{incremental, full}
		options.Now = func() time.Time { return lastReceivedAt.Add(time.Minute) }

		built, err := check.Run(t.Context(), options)

		require.NoError(t, err)
		assert.Empty(t, built.Findings)
		assert.Equal(t, 4, built.Events.Count)
		require.Len(t, built.Sources.Backups, 2)
		assert.Equal(t, full, built.Sources.Backups[0].Path)
	})
}

// fakeTrustedLists answers every question about qualification the same way.
type fakeTrustedLists struct {
	issuedAt time.Time
	reason   string
	err      error
}

func (f fakeTrustedLists) Qualification(ctx context.Context, certificate *x509.Certificate, at time.Time) (trustedlists.Qualification, error) {
	return trustedlists.Qualification{Reason: f.reason}, f.err
}

func (f fakeTrustedLists) ListOfTheListsIssuedAt() time.Time {
	return f.issuedAt
}
