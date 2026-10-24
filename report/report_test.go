package report_test

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/thenativeweb/eventsourcingdb-auditing/report"
	"github.com/thenativeweb/eventsourcingdb-auditing/verify"
)

var tenOClock = time.Date(2026, 9, 1, 10, 0, 0, 0, time.UTC)

func newReport(findings ...verify.Finding) report.Report {
	lastAt := tenOClock.Add(time.Hour)

	return report.Report{
		ToolVersion: "1.2.3",
		CheckedAt:   tenOClock.Add(2 * time.Hour),
		Instance:    report.Instance{ID: "instance-1", Name: "production", RegisteredAt: tenOClock},
		Sources: report.Sources{
			Custodian: "https://custodian.example.com",
			Backups:   []report.Backup{{Path: "backup.json", SHA256: "abc"}},
		},
		Events:   report.Events{Count: 42, FirstAt: &tenOClock, LastAt: &lastAt},
		Receipts: 7,
		Anchors:  2,
		Result:   report.ResultOf(findings),
		Findings: findings,
	}
}

func TestResult(t *testing.T) {
	manipulation := verify.Finding{Severity: verify.SeverityManipulation, Check: verify.CheckEventHashes, Message: "Event 3 has been changed"}
	gap := verify.Finding{Severity: verify.SeverityGap, Check: verify.CheckSilence, Message: "No fingerprint arrived"}
	notice := verify.Finding{Severity: verify.SeverityNotice, Check: verify.CheckLocks, Message: "The baseline was reset"}

	for _, test := range []struct {
		name     string
		findings []verify.Finding
		result   report.Result
		exitCode int
	}{
		{"no findings", nil, report.ResultNoFindings, report.ExitCodeNoFindings},
		{"notices only", []verify.Finding{notice}, report.ResultNoFindings, report.ExitCodeNoFindings},
		{"gaps", []verify.Finding{notice, gap}, report.ResultGaps, report.ExitCodeGaps},
		{"a manipulation, whatever else", []verify.Finding{gap, manipulation, notice}, report.ResultManipulation, report.ExitCodeManipulation},
	} {
		t.Run(test.name, func(t *testing.T) {
			built := newReport(test.findings...)

			assert.Equal(t, test.result, built.Result)
			assert.Equal(t, test.exitCode, built.ExitCode())
		})
	}
}

func TestWriteText(t *testing.T) {
	t.Run("names what was checked, the result, and the findings by severity", func(t *testing.T) {
		from, until := tenOClock, tenOClock.Add(20*time.Minute)
		built := newReport(
			verify.Finding{Severity: verify.SeverityGap, Check: verify.CheckSilence, Message: "No fingerprint arrived for 20m0s", From: &from, Until: &until},
			verify.Finding{Severity: verify.SeverityManipulation, Check: verify.CheckEventHashes, Message: "Event 3 has been changed"},
		)

		var out bytes.Buffer
		require.NoError(t, report.WriteText(&out, built))

		text := out.String()
		assert.Contains(t, text, "eventsourcingdb-auditing 1.2.3, checked at 2026-09-01T12:00:00Z")
		assert.Contains(t, text, "production (instance-1)")
		assert.Contains(t, text, "Backup              backup.json\n                    SHA-256 abc\n")
		assert.Contains(t, text, "Events              42, written from 2026-09-01T10:00:00Z to 2026-09-01T11:00:00Z")
		assert.Contains(t, text, "Receipts directory  not given")
		assert.Contains(t, text, "Trusted lists       not checked")
		assert.Contains(t, text, "Result              MANIPULATION (1 manipulations, 1 gaps, 0 notices)")
		assert.Less(t, bytes.Index(out.Bytes(), []byte("Manipulations")), bytes.Index(out.Bytes(), []byte("Gaps in protection")))
		assert.Contains(t, text, "  - [silence] No fingerprint arrived for 20m0s (from 2026-09-01T10:00:00Z until 2026-09-01T10:20:00Z)")
		assert.NotContains(t, text, "Notices")
	})

	t.Run("names every backup of a chain, with its SHA-256", func(t *testing.T) {
		built := newReport()
		built.Sources.Backups = []report.Backup{
			{Path: "full.ndjson", SHA256: "abc"},
			{Path: "incremental-1.ndjson", SHA256: "def"},
			{Path: "incremental-2.ndjson", SHA256: "ghi"},
		}

		var out bytes.Buffer
		require.NoError(t, report.WriteText(&out, built))

		assert.Contains(t, out.String(), "Backups             full.ndjson\n"+
			"                    SHA-256 abc\n"+
			"                    incremental-1.ndjson\n"+
			"                    SHA-256 def\n"+
			"                    incremental-2.ndjson\n"+
			"                    SHA-256 ghi\n"+
			"Events              42")
	})

	t.Run("names a file that holds several backups once, with every backup it holds", func(t *testing.T) {
		built := newReport()
		built.Sources.Backups = []report.Backup{{
			Path:   "chain.ndjson",
			SHA256: "abc",
			Parts: []report.BackupPart{
				{Number: 1, EndedAt: "3"},
				{Number: 2, FollowsOn: "3", EndedAt: "6"},
				{Number: 3, FollowsOn: "6", EndedAt: "6"},
				{Number: 4},
			},
		}}

		var out bytes.Buffer
		require.NoError(t, report.WriteText(&out, built))

		assert.Contains(t, out.String(), "Backups             chain.ndjson\n"+
			"                    SHA-256 abc\n"+
			"                    part 1, full, ended at event 3\n"+
			"                    part 2, follows on event 3, ended at event 6\n"+
			"                    part 3, follows on event 6, without events\n"+
			"                    part 4, full, without events\n"+
			"Events              42")

		out.Reset()
		require.NoError(t, report.WriteJSON(&out, built))
		assert.Contains(t, out.String(), `"parts": [`)
		assert.Contains(t, out.String(), `"followsOn": "3"`)
	})

	t.Run("names a database and a receipts directory", func(t *testing.T) {
		built := newReport()
		built.Sources.Backups = nil
		built.Sources.Database = "http://localhost:3000"
		built.Sources.ReceiptsDirectory = "/receipts"
		built.ReceiptsDirectoryChecked = true
		built.TrustedListsChecked = true
		built.TrustedLists = &report.TrustedLists{ListOfTheListsIssuedAt: tenOClock, StampedAnchors: 2, QualifiedAnchors: 1}

		var out bytes.Buffer
		require.NoError(t, report.WriteText(&out, built))

		assert.Contains(t, out.String(), "Database            http://localhost:3000")
		assert.Contains(t, out.String(), "Receipts directory  /receipts")
		assert.Contains(t, out.String(), "Trusted lists       list of the lists issued at 2026-09-01T10:00:00Z, 1 of 2 stamped anchors qualified")
		assert.Contains(t, out.String(), "NO FINDINGS")
	})
}

func TestWriteJSON(t *testing.T) {
	t.Run("writes the report as JSON", func(t *testing.T) {
		built := newReport(verify.Finding{Severity: verify.SeverityGap, Check: verify.CheckSilence, Message: "No fingerprint arrived"})

		var out bytes.Buffer
		require.NoError(t, report.WriteJSON(&out, built))

		var decoded report.Report
		require.NoError(t, json.Unmarshal(out.Bytes(), &decoded))
		assert.Equal(t, report.ResultGaps, decoded.Result)
		require.Len(t, decoded.Sources.Backups, 1)
		assert.Equal(t, "abc", decoded.Sources.Backups[0].SHA256)
		assert.Len(t, decoded.Findings, 1)
	})
}
