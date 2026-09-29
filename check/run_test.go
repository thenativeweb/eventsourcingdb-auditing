package check_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/thenativeweb/eventsourcingdb-auditing/audit"
	"github.com/thenativeweb/eventsourcingdb-auditing/check"
	"github.com/thenativeweb/eventsourcingdb-auditing/database"
	"github.com/thenativeweb/eventsourcingdb-auditing/receipt/receipttest"
	"github.com/thenativeweb/eventsourcingdb-auditing/report"
	"github.com/thenativeweb/eventsourcingdb-auditing/trustedlists"
	"github.com/thenativeweb/eventsourcingdb-auditing/verify"
	"github.com/thenativeweb/eventsourcingdb-auditing/verify/verifytest"
	"github.com/thenativeweb/eventsourcingdb-client-golang/eventsourcingdb"
	"github.com/thenativeweb/eventsourcingdb-client-golang/eventsourcingdbtest"
)

const testAuditorToken = "auditor-token"

// instance is an EventSourcingDB with events, a custodian that has confirmed
// every one of them half a minute after it was written, and a backup of it.
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

	container := eventsourcingdbtest.NewContainer()
	require.NoError(t, container.Start(t.Context()))
	t.Cleanup(func() {
		_ = container.Stop(context.Background())
	})

	client, err := container.GetClient(t.Context())
	require.NoError(t, err)

	for _, title := range []string{"2001", "<Ümlauts & Émojis 🎉>", "Dune"} {
		_, err := client.WriteEvents([]eventsourcingdb.EventCandidate{{
			Source: "https://example.com", Subject: "/books", Type: "io.example.book-acquired", Data: map[string]any{"title": title},
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
		BackupPath:    i.backupPath,
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
		require.NotNil(t, built.Sources.Backup)
		assert.Equal(t, hex.EncodeToString(digest[:]), built.Sources.Backup.SHA256)
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
		options.BackupPath = ""
		options.Database = instance.client
		options.DatabaseURL = "http://database.example.com"

		built, err := check.Run(t.Context(), options)

		require.NoError(t, err)
		assert.Empty(t, built.Findings)
		assert.Equal(t, "http://database.example.com", built.Sources.Database)
		assert.Nil(t, built.Sources.Backup)
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
		options.BackupPath = filepath.Join(t.TempDir(), "missing.json")

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
