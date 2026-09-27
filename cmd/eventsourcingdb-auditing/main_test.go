package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/thenativeweb/eventsourcingdb-auditing/database"
	"github.com/thenativeweb/eventsourcingdb-auditing/receipt"
	"github.com/thenativeweb/eventsourcingdb-auditing/report"
	"github.com/thenativeweb/eventsourcingdb-auditing/verify/verifytest"
)

func runWith(args ...string) (int, string, string) {
	var stdout, stderr bytes.Buffer
	exitCode := run(context.Background(), args, &stdout, &stderr)

	return exitCode, stdout.String(), stderr.String()
}

func TestRun(t *testing.T) {
	t.Setenv("SERVER_URL", "")
	t.Setenv("AUDITOR_TOKEN", "")
	t.Setenv("ROOT_PUBLIC_KEY", "")
	t.Setenv("ESDB_URL", "")
	t.Setenv("ESDB_API_TOKEN", "")

	valid := []string{"verify", "--server-url", "http://127.0.0.1:1", "--auditor-token", "token", "--root-public-key", "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo", "--backup", "backup.json"}

	t.Run("prints the version", func(t *testing.T) {
		exitCode, stdout, _ := runWith("version")

		assert.Equal(t, report.ExitCodeNoFindings, exitCode)
		assert.Equal(t, "eventsourcingdb-auditing dev\n", stdout)
	})

	for _, test := range []struct {
		name    string
		args    []string
		message string
	}{
		{"requires the URL of the custodian", []string{"verify"}, "--server-url is required"},
		{"requires the auditor token", []string{"verify", "--server-url", "http://127.0.0.1:1"}, "--auditor-token is required"},
		{"requires the root public key", valid[:5], "--root-public-key is required"},
		{"requires a backup or a database", valid[:7], "either --backup or --esdb-url is required"},
		{"rejects a backup and a database at once", append(append([]string{}, valid...), "--esdb-url", "http://127.0.0.1:1"), "either --backup or --esdb-url is required"},
		{"requires the API token of the database", append(append([]string{}, valid[:7]...), "--esdb-url", "http://127.0.0.1:1"), "--esdb-api-token is required"},
		{"rejects an unknown format", append(append([]string{}, valid...), "--output", "xml"), "--output must be text or json"},
		{"rejects a malformed root public key", append(append([]string{}, valid[:5]...), "--root-public-key", "not-a-key", "--backup", "backup.json"), "--root-public-key"},
		{"fails if the custodian can not be reached", valid, "failed to read the instance"},
	} {
		t.Run(test.name, func(t *testing.T) {
			exitCode, _, stderr := runWith(test.args...)

			assert.Equal(t, report.ExitCodeFailure, exitCode)
			assert.Contains(t, stderr, test.message)
		})
	}
}

func TestVerify(t *testing.T) {
	t.Setenv("SERVER_URL", "")
	t.Setenv("AUDITOR_TOKEN", "")
	t.Setenv("ROOT_PUBLIC_KEY", "")
	t.Setenv("ESDB_URL", "")

	// newBackup writes the backup with five events, and a custodian that has
	// confirmed every one of them half a minute after it was written.
	newBackup := func(t *testing.T, backup string) (string, *verifytest.Custodian) {
		t.Helper()

		custodian := verifytest.NewCustodian(t)
		for event, err := range database.ReadBackup(strings.NewReader(verifytest.BackupWithFiveEvents)) {
			require.NoError(t, err)
			custodian.Record(event.ID, event.Hash, event.Time.Add(30*time.Second))
		}

		path := filepath.Join(t.TempDir(), "backup.json")
		require.NoError(t, os.WriteFile(path, []byte(backup), 0o600))

		return path, custodian
	}

	verifyArgs := func(t *testing.T, custodian *verifytest.Custodian, backupPath string, extra ...string) []string {
		t.Helper()

		return append([]string{
			"verify",
			"--server-url", verifytest.NewServer(t, custodian, "auditor-token"),
			"--auditor-token", "auditor-token",
			"--root-public-key", receipt.EncodeRawPublicKey(custodian.RootPublicKey),
			"--backup", backupPath,
		}, extra...)
	}

	t.Run("writes the report as text, and ends with the exit code of its result", func(t *testing.T) {
		backupPath, custodian := newBackup(t, verifytest.BackupWithFiveEvents)

		exitCode, stdout, stderr := runWith(verifyArgs(t, custodian, backupPath)...)

		assert.Empty(t, stderr)
		assert.Contains(t, stdout, "Events              5")
		assert.Contains(t, stdout, "Gaps in protection", "the client has been silent since 2023")
		assert.Equal(t, report.ExitCodeGaps, exitCode)
	})

	t.Run("writes the report as JSON", func(t *testing.T) {
		backupPath, custodian := newBackup(t, verifytest.BackupWithFiveEvents)

		exitCode, stdout, _ := runWith(verifyArgs(t, custodian, backupPath, "--output", "json")...)

		var built report.Report
		require.NoError(t, json.Unmarshal([]byte(stdout), &built))
		assert.Equal(t, 5, built.Events.Count)
		assert.Equal(t, report.ResultGaps, built.Result)
		assert.Equal(t, report.ExitCodeGaps, exitCode)
	})

	t.Run("ends with the exit code for a manipulation if an event was changed", func(t *testing.T) {
		changed := strings.Replace(verifytest.BackupWithFiveEvents, `"data":{"username":"arno"}},"hash":"64d0`, `"data":{"username":"arnold"}},"hash":"64d0`, 1)
		backupPath, custodian := newBackup(t, changed)

		exitCode, stdout, _ := runWith(verifyArgs(t, custodian, backupPath)...)

		assert.Contains(t, stdout, "Event 2 has been changed")
		assert.Equal(t, report.ExitCodeManipulation, exitCode)
	})
}
