package verify_test

import (
	"encoding/hex"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/thenativeweb/eventsourcingdb-auditing/audit"
	"github.com/thenativeweb/eventsourcingdb-auditing/receiptsdir"
	"github.com/thenativeweb/eventsourcingdb-auditing/verify"
	"github.com/thenativeweb/eventsourcingdb-auditing/verify/verifytest"
)

// keptBy returns what the client of a custodian has kept: every receipt and
// every anchor it got.
func keptBy(custodian *verifytest.Custodian) receiptsdir.Directory {
	var kept receiptsdir.Directory
	for _, entry := range custodian.Chain {
		if entry.FingerprintRecorded != nil {
			kept.Receipts = append(kept.Receipts, entry.FingerprintRecorded.Receipt)
		}
	}

	for _, anchor := range custodian.Anchors {
		copied := anchor
		if anchor.Proof != nil {
			proof := *anchor.Proof
			copied.Proof = &proof
		}
		kept.Anchors = append(kept.Anchors, copied)
	}

	return kept
}

func keptFindingsOf(found []verify.Finding, severity verify.Severity, check string) []verify.Finding {
	return findingsOf(verify.CustodianResult{Findings: found}, severity, check)
}

func TestVerifyKept(t *testing.T) {
	t.Run("finds nothing if the custodian still holds what the client kept", func(t *testing.T) {
		custodian := consistentHistory(t)

		found := verify.VerifyKept(keptBy(custodian), custodian.Data(), custodian.RootPublicKey)

		assert.Empty(t, found)
	})

	t.Run("finds receipts the custodian no longer holds", func(t *testing.T) {
		custodian := consistentHistory(t)
		kept := keptBy(custodian)
		custodian.Chain = custodian.Chain[:5]

		found := verify.VerifyKept(kept, custodian.Data(), custodian.RootPublicKey)

		receipts := keptFindingsOf(found, verify.SeverityManipulation, verify.CheckKeptReceipts)
		require.Len(t, receipts, 1)
		assert.Contains(t, receipts[0].Message, "14 receipts the client kept are missing from the chain of the custodian, from receipt 6 to receipt 19")
	})

	t.Run("finds receipts the custodian has replaced with other ones", func(t *testing.T) {
		custodian := consistentHistory(t)
		kept := keptBy(custodian)

		rewritten := verifytest.NewCustodian(t)
		rewritten.RootPublicKey = custodian.RootPublicKey
		rewritten.SigningKey = custodian.SigningKey
		rewritten.Instance = custodian.Instance
		for minutes := 0; minutes <= 10; minutes += 5 {
			rewritten.Record("0", "rewritten-hash", tenOClock.Add(time.Duration(minutes)*time.Minute))
		}

		found := verify.VerifyKept(kept, rewritten.Data(), custodian.RootPublicKey)

		receipts := keptFindingsOf(found, verify.SeverityManipulation, verify.CheckKeptReceipts)
		require.Len(t, receipts, 2)
		assert.Contains(t, receipts[0].Message, "16 receipts the client kept are missing")
		assert.Contains(t, receipts[1].Message, "For 3 receipts the client kept, the custodian holds other ones with the same numbers, from receipt 1 to receipt 3")
	})

	t.Run("does not hold receipts against the custodian that do not verify", func(t *testing.T) {
		custodian := consistentHistory(t)
		kept := keptBy(custodian)
		kept.Receipts = append(kept.Receipts, verifytest.Tamper(kept.Receipts[0]))

		found := verify.VerifyKept(kept, custodian.Data(), custodian.RootPublicKey)

		assert.Empty(t, keptFindingsOf(found, verify.SeverityManipulation, verify.CheckKeptReceipts))
		assert.Len(t, keptFindingsOf(found, verify.SeverityNotice, verify.CheckKeptReceipts), 1)
	})

	t.Run("finds anchors the custodian no longer hands out", func(t *testing.T) {
		custodian := consistentHistory(t)
		custodian.Anchor(tenOClock.Add(time.Hour))
		kept := keptBy(custodian)
		custodian.Anchors = custodian.Anchors[:1]

		found := verify.VerifyKept(kept, custodian.Data(), custodian.RootPublicKey)

		anchors := keptFindingsOf(found, verify.SeverityManipulation, verify.CheckKeptAnchors)
		require.Len(t, anchors, 1)
		assert.Contains(t, anchors[0].Message, "1 anchors the client kept are missing")
	})

	t.Run("finds anchors whose proof the custodian has changed", func(t *testing.T) {
		custodian := consistentHistory(t)
		kept := keptBy(custodian)
		custodian.Anchors[0].Proof.Salt = hex.EncodeToString(verifytest.RandomBytes(t))

		found := verify.VerifyKept(kept, custodian.Data(), custodian.RootPublicKey)

		anchors := keptFindingsOf(found, verify.SeverityManipulation, verify.CheckKeptAnchors)
		require.Len(t, anchors, 1)
		assert.Contains(t, anchors[0].Message, "the custodian now hands out other anchors or proofs")
	})

	t.Run("does not hold anchors against the custodian that do not verify", func(t *testing.T) {
		custodian := consistentHistory(t)
		kept := keptBy(custodian)
		kept.Anchors = append(kept.Anchors, audit.AnchorWithProof{StampedAnchor: audit.StampedAnchor{Anchor: verifytest.Tamper(kept.Anchors[0].Anchor), TimestampToken: kept.Anchors[0].TimestampToken}})

		found := verify.VerifyKept(kept, custodian.Data(), custodian.RootPublicKey)

		assert.Empty(t, keptFindingsOf(found, verify.SeverityManipulation, verify.CheckKeptAnchors))
		assert.Len(t, keptFindingsOf(found, verify.SeverityNotice, verify.CheckKeptAnchors), 1)
	})

	t.Run("checks with the certificates the client kept as well", func(t *testing.T) {
		custodian := consistentHistory(t)
		kept := keptBy(custodian)
		kept.Certificates = []string{custodian.SigningKey.CertificateJWS}
		data := custodian.Data()
		data.Instance.SigningKeyCertificates = nil
		data.Chain = data.Chain[:1]

		found := verify.VerifyKept(kept, data, custodian.RootPublicKey)

		receipts := keptFindingsOf(found, verify.SeverityManipulation, verify.CheckKeptReceipts)
		require.Len(t, receipts, 1, "a custodian that withholds its certificates must not get away with it")
	})
}
