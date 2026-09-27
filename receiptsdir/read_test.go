package receiptsdir_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/thenativeweb/eventsourcingdb-auditing/audit"
	"github.com/thenativeweb/eventsourcingdb-auditing/receiptsdir"
)

func writeFile(t *testing.T, path, content string) {
	t.Helper()

	require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o700))
	require.NoError(t, os.WriteFile(path, []byte(content), 0o600))
}

func anchorLine(t *testing.T, anchor audit.AnchorWithProof) string {
	t.Helper()

	data, err := json.Marshal(anchor)
	require.NoError(t, err)

	return string(data) + "\n"
}

func TestRead(t *testing.T) {
	t.Run("reads receipts and anchors in the order of their days, and the certificates", func(t *testing.T) {
		directory := t.TempDir()
		writeFile(t, filepath.Join(directory, "receipts-2026-09-27.jsonl"), `{"receipt":"receipt-3"}`+"\n")
		writeFile(t, filepath.Join(directory, "receipts-2026-09-26.jsonl"), `{"receipt":"receipt-1"}`+"\n\n"+`{"receipt":"receipt-2"}`+"\n")
		writeFile(t, filepath.Join(directory, "anchors-2026-09-26.jsonl"), anchorLine(t, audit.AnchorWithProof{
			StampedAnchor: audit.StampedAnchor{Anchor: "anchor-1", TimestampToken: "token-1"},
			Proof:         &audit.AnchorProof{Receipt: "receipt-2", Salt: "salt", Siblings: []audit.ProofSibling{{Hash: "hash", Position: "left"}}},
		}))
		writeFile(t, filepath.Join(directory, "certificates", "key-1.jws"), "certificate-1\n")
		writeFile(t, filepath.Join(directory, "evidence", "receipt-chain-broken.json"), "{}")

		read, err := receiptsdir.Read(directory)

		require.NoError(t, err)
		assert.Equal(t, []string{"receipt-1", "receipt-2", "receipt-3"}, read.Receipts)
		require.Len(t, read.Anchors, 1)
		assert.Equal(t, "receipt-2", read.Anchors[0].Proof.Receipt)
		assert.Equal(t, []string{"certificate-1"}, read.Certificates)
	})

	t.Run("reads an empty directory", func(t *testing.T) {
		read, err := receiptsdir.Read(t.TempDir())

		require.NoError(t, err)
		assert.Empty(t, read.Receipts)
		assert.Empty(t, read.Anchors)
	})

	t.Run("fails on a directory that does not exist", func(t *testing.T) {
		_, err := receiptsdir.Read(filepath.Join(t.TempDir(), "missing"))

		assert.ErrorContains(t, err, "receipts directory")
	})

	t.Run("fails on lines it does not understand, and names them", func(t *testing.T) {
		directory := t.TempDir()
		writeFile(t, filepath.Join(directory, "receipts-2026-09-26.jsonl"), `{"receipt":"receipt-1"}`+"\n"+`not json`+"\n")

		_, err := receiptsdir.Read(directory)

		assert.ErrorContains(t, err, "line 2 of receipts-2026-09-26.jsonl")
	})

	t.Run("fails on an anchor line without an anchor", func(t *testing.T) {
		directory := t.TempDir()
		writeFile(t, filepath.Join(directory, "anchors-2026-09-26.jsonl"), `{"proof":null}`+"\n")

		_, err := receiptsdir.Read(directory)

		assert.ErrorContains(t, err, "line 1 of anchors-2026-09-26.jsonl")
	})
}
