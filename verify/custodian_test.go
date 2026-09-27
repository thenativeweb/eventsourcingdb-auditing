package verify_test

import (
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/thenativeweb/eventsourcingdb-auditing/audit"
	"github.com/thenativeweb/eventsourcingdb-auditing/receipt/receipttest"
	"github.com/thenativeweb/eventsourcingdb-auditing/verify"
	"github.com/thenativeweb/eventsourcingdb-auditing/verify/verifytest"
)

var tenOClock = verifytest.TenOClock

// verifyAt checks the data of the test custodian at the given time.
func verifyAt(t *testing.T, custodian verify.Custodian, rootPublicKey ed25519.PublicKey, now time.Time) verify.CustodianResult {
	t.Helper()

	result, err := verify.VerifyCustodian(custodian, rootPublicKey, now)
	require.NoError(t, err)

	return result
}

func findingsOf(result verify.CustodianResult, severity verify.Severity, check string) []verify.Finding {
	var matching []verify.Finding
	for _, finding := range result.Findings {
		if finding.Severity == severity && finding.Check == check {
			matching = append(matching, finding)
		}
	}

	return matching
}

// consistentHistory records a fingerprint every five minutes from ten to half
// past eleven, and anchors the hour from ten.
func consistentHistory(t *testing.T) *verifytest.Custodian {
	t.Helper()

	custodian := verifytest.NewCustodian(t)
	for minutes := 0; minutes <= 90; minutes += 5 {
		custodian.Record(fmt.Sprint(minutes), "hash-"+fmt.Sprint(minutes), tenOClock.Add(time.Duration(minutes)*time.Minute))
	}
	custodian.Anchor(tenOClock)

	return custodian
}

func TestVerifyCustodian(t *testing.T) {
	halfPastEleven := tenOClock.Add(90 * time.Minute)

	t.Run("finds nothing in a consistent history", func(t *testing.T) {
		custodian := consistentHistory(t)

		result := verifyAt(t, custodian.Data(), custodian.RootPublicKey, halfPastEleven.Add(5*time.Minute))

		assert.Empty(t, result.Findings)
		require.Len(t, result.Fingerprints, 19)
		assert.True(t, result.Fingerprints[0].IsAfterLatestReset, "without a reset, every fingerprint counts")
	})

	t.Run("marks the fingerprints an anchor covers", func(t *testing.T) {
		custodian := consistentHistory(t)

		result := verifyAt(t, custodian.Data(), custodian.RootPublicKey, halfPastEleven.Add(5*time.Minute))

		elevenOClock := tenOClock.Add(time.Hour)
		for _, fingerprint := range result.Fingerprints {
			if fingerprint.ReceivedAt.Before(elevenOClock) {
				require.NotNil(t, fingerprint.AnchoredAt, "receipt %d", fingerprint.Sequence)
				assert.Equal(t, elevenOClock, *fingerprint.AnchoredAt)
			} else {
				assert.Nil(t, fingerprint.AnchoredAt, "receipt %d", fingerprint.Sequence)
			}
		}
	})

	t.Run("fails with the wrong root key", func(t *testing.T) {
		custodian := consistentHistory(t)
		otherRootPublicKey, _ := receipttest.NewSigningKey(t)

		_, err := verify.VerifyCustodian(custodian.Data(), otherRootPublicKey, halfPastEleven)

		assert.ErrorIs(t, err, verify.ErrNoCertifiedKey)
	})

	t.Run("finds a receipt that does not verify", func(t *testing.T) {
		custodian := consistentHistory(t)
		custodian.Chain[3].FingerprintRecorded.Receipt = verifytest.Tamper(custodian.Chain[3].FingerprintRecorded.Receipt)

		result := verifyAt(t, custodian.Data(), custodian.RootPublicKey, halfPastEleven.Add(5*time.Minute))

		receipts := findingsOf(result, verify.SeverityManipulation, verify.CheckReceipts)
		require.NotEmpty(t, receipts)
		assert.Contains(t, receipts[0].Message, "Receipt 4 does not verify")
	})

	t.Run("finds a receipt that does not follow the one before", func(t *testing.T) {
		custodian := verifytest.NewCustodian(t)
		custodian.Record("1", "hash-1", tenOClock)
		custodian.Sequence++
		custodian.Record("2", "hash-2", tenOClock.Add(5*time.Minute))

		result := verifyAt(t, custodian.Data(), custodian.RootPublicKey, tenOClock.Add(10*time.Minute))

		receipts := findingsOf(result, verify.SeverityManipulation, verify.CheckReceipts)
		require.Len(t, receipts, 1)
		assert.Contains(t, receipts[0].Message, "Receipt 3 does not follow receipt 1")
	})

	t.Run("finds an entry that differs from its receipt", func(t *testing.T) {
		custodian := consistentHistory(t)
		custodian.Chain[2].FingerprintRecorded.EventHash = "changed-hash"

		result := verifyAt(t, custodian.Data(), custodian.RootPublicKey, halfPastEleven.Add(5*time.Minute))

		assert.Len(t, findingsOf(result, verify.SeverityManipulation, verify.CheckReceipts), 1)
	})

	t.Run("reports conflicts as manipulations, and resets as notices", func(t *testing.T) {
		custodian := verifytest.NewCustodian(t)
		custodian.Record("5", "hash-5", tenOClock)
		custodian.Conflict(tenOClock.Add(time.Minute))
		custodian.Reset(tenOClock.Add(2 * time.Minute))
		custodian.Record("3", "hash-3", tenOClock.Add(3*time.Minute))

		result := verifyAt(t, custodian.Data(), custodian.RootPublicKey, tenOClock.Add(5*time.Minute))

		assert.Len(t, findingsOf(result, verify.SeverityManipulation, verify.CheckLocks), 1)
		resets := findingsOf(result, verify.SeverityNotice, verify.CheckLocks)
		require.Len(t, resets, 1)
		assert.Contains(t, resets[0].Message, "database restored from a backup")

		require.Len(t, result.Fingerprints, 2)
		assert.False(t, result.Fingerprints[0].IsAfterLatestReset)
		assert.True(t, result.Fingerprints[1].IsAfterLatestReset)
	})

	t.Run("finds an anchor whose time stamp is over something else", func(t *testing.T) {
		custodian := consistentHistory(t)
		custodian.Anchors[0].TimestampToken = custodian.Stamp(custodian.Anchors[0].Anchor + "x").TimestampToken

		result := verifyAt(t, custodian.Data(), custodian.RootPublicKey, halfPastEleven.Add(5*time.Minute))

		anchors := findingsOf(result, verify.SeverityManipulation, verify.CheckAnchors)
		require.Len(t, anchors, 1)
		assert.Contains(t, anchors[0].Message, "time stamp")
	})

	t.Run("finds an anchor that does not follow the one before", func(t *testing.T) {
		custodian := consistentHistory(t)
		custodian.LatestAnchor = ""
		custodian.Anchor(tenOClock.Add(time.Hour))

		result := verifyAt(t, custodian.Data(), custodian.RootPublicKey, halfPastEleven.Add(5*time.Minute))

		anchors := findingsOf(result, verify.SeverityManipulation, verify.CheckAnchors)
		require.Len(t, anchors, 1)
		assert.Contains(t, anchors[0].Message, "does not follow")
	})

	t.Run("finds a proof that does not lead to the root", func(t *testing.T) {
		custodian := consistentHistory(t)
		custodian.Anchors[0].Proof.Salt = hex.EncodeToString(verifytest.RandomBytes(t))

		result := verifyAt(t, custodian.Data(), custodian.RootPublicKey, halfPastEleven.Add(5*time.Minute))

		proofs := findingsOf(result, verify.SeverityManipulation, verify.CheckProofs)
		require.NotEmpty(t, proofs)
		assert.Contains(t, proofs[0].Message, "does not lead to its root")
	})

	t.Run("finds a proof for a receipt that is not in the chain", func(t *testing.T) {
		custodian := consistentHistory(t)
		other := consistentHistory(t)
		custodian.Anchors[0].Proof = other.Anchors[0].Proof

		result := verifyAt(t, custodian.Data(), custodian.RootPublicKey, halfPastEleven.Add(5*time.Minute))

		proofs := findingsOf(result, verify.SeverityManipulation, verify.CheckProofs)
		require.NotEmpty(t, proofs)
		assert.Contains(t, proofs[0].Message, "not in the chain")
	})

	t.Run("finds an anchor that leaves out a receipt of its hour", func(t *testing.T) {
		custodian := consistentHistory(t)
		custodian.Anchors[0].Proof = nil

		result := verifyAt(t, custodian.Data(), custodian.RootPublicKey, halfPastEleven.Add(5*time.Minute))

		proofs := findingsOf(result, verify.SeverityManipulation, verify.CheckProofs)
		require.Len(t, proofs, 1)
		assert.Contains(t, proofs[0].Message, "leaves out receipt 12")
	})

	t.Run("accepts that a receipt from the last minute of an hour goes into the next anchor", func(t *testing.T) {
		custodian := verifytest.NewCustodian(t)
		custodian.Record("1", "hash-1", tenOClock.Add(30*time.Minute))

		// The anchor of ten is built before the receipt from its last
		// minute arrives, so it proves the receipt before.
		custodian.Anchor(tenOClock)
		custodian.Record("2", "hash-2", tenOClock.Add(time.Hour-30*time.Second))
		custodian.Record("3", "hash-3", tenOClock.Add(time.Hour+5*time.Minute))
		custodian.Anchor(tenOClock.Add(time.Hour))

		result := verifyAt(t, custodian.Data(), custodian.RootPublicKey, tenOClock.Add(time.Hour+10*time.Minute))

		assert.Empty(t, findingsOf(result, verify.SeverityManipulation, verify.CheckProofs))
		assert.Empty(t, findingsOf(result, verify.SeverityManipulation, verify.CheckReceipts))
		require.NotNil(t, result.Fingerprints[1].AnchoredAt)
		assert.Equal(t, tenOClock.Add(2*time.Hour), *result.Fingerprints[1].AnchoredAt, "the receipt from the last minute is covered by the next anchor")
	})

	t.Run("finds anchors that differ from the public chain", func(t *testing.T) {
		custodian := consistentHistory(t)
		data := custodian.Data()
		data.PublicAnchors[0] = custodian.Stamp(verifytest.Tamper(data.PublicAnchors[0].Anchor))

		result := verifyAt(t, data, custodian.RootPublicKey, halfPastEleven.Add(5*time.Minute))

		assert.Len(t, findingsOf(result, verify.SeverityManipulation, verify.CheckPublicAnchors), 1)
	})

	t.Run("finds a public chain that is shorter than the one of the auditor", func(t *testing.T) {
		custodian := consistentHistory(t)
		data := custodian.Data()
		data.PublicAnchors = nil

		result := verifyAt(t, data, custodian.RootPublicKey, halfPastEleven.Add(5*time.Minute))

		assert.Len(t, findingsOf(result, verify.SeverityManipulation, verify.CheckPublicAnchors), 1)
	})

	t.Run("finds periods in which the client was silent for longer than its heartbeat interval", func(t *testing.T) {
		custodian := verifytest.NewCustodian(t)
		custodian.Record("1", "hash-1", tenOClock)
		custodian.Record("2", "hash-2", tenOClock.Add(10*time.Minute))
		custodian.Record("3", "hash-3", tenOClock.Add(30*time.Minute))

		result := verifyAt(t, custodian.Data(), custodian.RootPublicKey, tenOClock.Add(35*time.Minute))

		silence := findingsOf(result, verify.SeverityGap, verify.CheckSilence)
		require.Len(t, silence, 1, "ten minutes and one more of tolerance are fine, twenty are not")
		assert.Equal(t, tenOClock.Add(10*time.Minute), *silence[0].From)
		assert.Equal(t, tenOClock.Add(30*time.Minute), *silence[0].Until)
	})

	t.Run("finds a client that has been silent until now", func(t *testing.T) {
		custodian := verifytest.NewCustodian(t)
		custodian.Record("1", "hash-1", tenOClock)

		result := verifyAt(t, custodian.Data(), custodian.RootPublicKey, tenOClock.Add(20*time.Minute))

		silence := findingsOf(result, verify.SeverityGap, verify.CheckSilence)
		require.Len(t, silence, 1)
		assert.Contains(t, silence[0].Message, "has arrived")
	})

	t.Run("does not count the silence while the instance is locked", func(t *testing.T) {
		custodian := verifytest.NewCustodian(t)
		custodian.Record("5", "hash-5", tenOClock)
		custodian.Conflict(tenOClock.Add(time.Minute))
		custodian.Reset(tenOClock.Add(3 * time.Hour))
		custodian.Record("3", "hash-3", tenOClock.Add(3*time.Hour+time.Minute))

		result := verifyAt(t, custodian.Data(), custodian.RootPublicKey, tenOClock.Add(3*time.Hour+5*time.Minute))

		assert.Empty(t, findingsOf(result, verify.SeverityGap, verify.CheckSilence))
	})

	t.Run("finds receipts that have stayed without an anchor for too long", func(t *testing.T) {
		custodian := consistentHistory(t)

		result := verifyAt(t, custodian.Data(), custodian.RootPublicKey, tenOClock.Add(5*time.Hour))

		anchoring := findingsOf(result, verify.SeverityGap, verify.CheckAnchoring)
		require.Len(t, anchoring, 1)
		assert.True(t, strings.HasPrefix(anchoring[0].Message, "Receipt 13 "), anchoring[0].Message)
	})

	t.Run("finds receipts and anchors signed with a key that has no certificate", func(t *testing.T) {
		custodian := consistentHistory(t)
		_, uncertifiedKey := receipttest.NewSigningKey(t)
		custodian.SigningKey = uncertifiedKey
		custodian.Record("100", "hash-100", halfPastEleven.Add(time.Minute))
		custodian.Anchor(tenOClock.Add(time.Hour))

		result := verifyAt(t, custodian.Data(), custodian.RootPublicKey, halfPastEleven.Add(5*time.Minute))

		receipts := findingsOf(result, verify.SeverityManipulation, verify.CheckReceipts)
		require.Len(t, receipts, 1)
		assert.Contains(t, receipts[0].Message, "has no certificate")

		anchors := findingsOf(result, verify.SeverityManipulation, verify.CheckAnchors)
		require.Len(t, anchors, 1)
		assert.Contains(t, anchors[0].Message, "has no certificate")
	})

	t.Run("finds a key certificate that does not verify", func(t *testing.T) {
		custodian := consistentHistory(t)
		custodian.Instance.SigningKeyCertificates = append(custodian.Instance.SigningKeyCertificates, verifytest.Tamper(custodian.SigningKey.CertificateJWS))

		result := verifyAt(t, custodian.Data(), custodian.RootPublicKey, halfPastEleven.Add(5*time.Minute))

		assert.Len(t, findingsOf(result, verify.SeverityManipulation, verify.CheckKeyCertificates), 1)
	})

	t.Run("finds entries that lack their details, or have an unknown type", func(t *testing.T) {
		custodian := verifytest.NewCustodian(t)
		custodian.Record("1", "hash-1", tenOClock)
		custodian.Chain = append(custodian.Chain,
			audit.ChainEntry{ID: "a", RecordedAt: tenOClock, Type: audit.FingerprintRecordedType},
			audit.ChainEntry{ID: "b", RecordedAt: tenOClock, Type: audit.FingerprintConflictDetectedType},
			audit.ChainEntry{ID: "c", RecordedAt: tenOClock, Type: audit.ContinuityBreakReportedType},
			audit.ChainEntry{ID: "d", RecordedAt: tenOClock, Type: "something-else"},
		)

		result := verifyAt(t, custodian.Data(), custodian.RootPublicKey, tenOClock.Add(time.Minute))

		assert.Len(t, findingsOf(result, verify.SeverityManipulation, verify.CheckReceipts), 2)
		assert.Len(t, findingsOf(result, verify.SeverityManipulation, verify.CheckLocks), 2)
	})

	t.Run("reports a continuity break as a manipulation", func(t *testing.T) {
		custodian := verifytest.NewCustodian(t)
		custodian.Record("5", "hash-5", tenOClock)
		custodian.Chain = append(custodian.Chain, audit.ChainEntry{
			ID: "break", RecordedAt: tenOClock.Add(time.Minute), Type: audit.ContinuityBreakReportedType,
			ContinuityBreakReported: &audit.ContinuityBreakReported{StoredEventID: "5", StoredEventHash: "hash-5", ObservedEventID: "6", ObservedPredecessorHash: "other-hash"},
		})

		result := verifyAt(t, custodian.Data(), custodian.RootPublicKey, tenOClock.Add(2*time.Minute))

		locks := findingsOf(result, verify.SeverityManipulation, verify.CheckLocks)
		require.Len(t, locks, 1)
		assert.Contains(t, locks[0].Message, "event 6 does not follow event 5")
	})

	t.Run("applies the heartbeat interval that was valid at the time", func(t *testing.T) {
		custodian := verifytest.NewCustodian(t)
		custodian.Instance.Intervals = append(custodian.Instance.Intervals, audit.Intervals{
			ValidFrom:                       tenOClock.Add(time.Hour),
			MinimumIntervalInMilliseconds:   60_000,
			HeartbeatIntervalInMilliseconds: 1_800_000,
		})
		custodian.Record("1", "hash-1", tenOClock)
		custodian.Record("2", "hash-2", tenOClock.Add(20*time.Minute))
		custodian.Record("3", "hash-3", tenOClock.Add(time.Hour))
		custodian.Record("4", "hash-4", tenOClock.Add(time.Hour+20*time.Minute))

		result := verifyAt(t, custodian.Data(), custodian.RootPublicKey, tenOClock.Add(time.Hour+25*time.Minute))

		silence := findingsOf(result, verify.SeverityGap, verify.CheckSilence)
		assert.Len(t, silence, 2, "twenty minutes are too long before eleven, but fine after it")
		assert.Equal(t, tenOClock, *silence[0].From)
		assert.Equal(t, tenOClock.Add(20*time.Minute), *silence[1].From)
	})
}
