package verifytest

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/thenativeweb/eventsourcingdb-auditing/audit"
	"github.com/thenativeweb/eventsourcingdb-auditing/merkle"
	"github.com/thenativeweb/eventsourcingdb-auditing/receipt"
	"github.com/thenativeweb/eventsourcingdb-auditing/receipt/receipttest"
	"github.com/thenativeweb/eventsourcingdb-auditing/timestamping/timestampingtest"
	"github.com/thenativeweb/eventsourcingdb-auditing/verify"
)

// TenOClock is ten o'clock on 2026-09-01, around which the histories of the
// tests happen.
var TenOClock = time.Date(2026, 9, 1, 10, 0, 0, 0, time.UTC)

// Custodian records a history the way the custodian does: receipts that form
// a chain, and anchors over the latest receipt of every hour, signed and
// stamped. Its fields are exported, so that a test can change what it has
// recorded, and see whether a check finds it.
type Custodian struct {
	t             testing.TB
	RootPublicKey ed25519.PublicKey
	SigningKey    receipt.SigningKey
	authority     *timestampingtest.Authority

	Instance audit.ReadInstanceResponseBodyPayload
	Chain    []audit.ChainEntry
	Anchors  []audit.AnchorWithProof

	LatestReceipt string
	Sequence      uint64
	LatestAnchor  string
	entryID       int
}

// NewCustodian returns a custodian for a single test, with a root key and a
// signing key of its own, and an instance registered a minute before ten
// o'clock on 2026-09-01, with a minimum interval of a minute and a heartbeat
// interval of ten minutes.
func NewCustodian(t testing.TB) *Custodian {
	t.Helper()

	rootPublicKey, signingKey := receipttest.NewSigningKey(t)

	return &Custodian{
		t:             t,
		RootPublicKey: rootPublicKey,
		SigningKey:    signingKey,
		authority:     timestampingtest.NewAuthority(t),
		Instance: audit.ReadInstanceResponseBodyPayload{
			InstanceID:   "instance-1",
			Name:         "production",
			RegisteredAt: TenOClock.Add(-time.Minute),
			Intervals: []audit.Intervals{{
				ValidFrom:                       TenOClock.Add(-time.Minute),
				MinimumIntervalInMilliseconds:   60_000,
				HeartbeatIntervalInMilliseconds: 600_000,
			}},
			SigningKeyCertificates: []string{signingKey.CertificateJWS},
		},
	}
}

func (c *Custodian) nextEntryID() string {
	c.entryID++
	return fmt.Sprint(c.entryID)
}

// Record confirms a fingerprint with the receipt that follows the latest one.
func (c *Custodian) Record(eventID, eventHash string, at time.Time) {
	c.t.Helper()

	previousReceiptHash := ""
	if c.LatestReceipt != "" {
		previousReceiptHash = receipt.Hash(c.LatestReceipt)
	}
	c.Sequence++

	signed, err := c.SigningKey.Sign(receipt.Receipt{
		InstanceID:          c.Instance.InstanceID,
		EventID:             eventID,
		EventHash:           eventHash,
		ReceivedAt:          at,
		Sequence:            c.Sequence,
		PreviousReceiptHash: previousReceiptHash,
	})
	require.NoError(c.t, err)
	c.LatestReceipt = signed

	c.Chain = append(c.Chain, audit.ChainEntry{
		ID:         c.nextEntryID(),
		RecordedAt: at,
		Type:       audit.FingerprintRecordedType,
		FingerprintRecorded: &audit.FingerprintRecorded{
			EventID: eventID, EventHash: eventHash, Sequence: c.Sequence, Receipt: signed,
		},
	})
}

// Conflict records that the client reported another hash for event 5, which
// locks the instance.
func (c *Custodian) Conflict(at time.Time) {
	c.Chain = append(c.Chain, audit.ChainEntry{
		ID: c.nextEntryID(), RecordedAt: at, Type: audit.FingerprintConflictDetectedType,
		FingerprintConflictDetected: &audit.FingerprintConflictDetected{
			StoredEventID: "5", StoredEventHash: "hash-5", ReceivedEventID: "5", ReceivedEventHash: "tampered-hash",
		},
	})
}

// Reset records a reset of the baseline.
func (c *Custodian) Reset(at time.Time) {
	c.Chain = append(c.Chain, audit.ChainEntry{
		ID: c.nextEntryID(), RecordedAt: at, Type: audit.BaselineResetType,
		BaselineReset: &audit.BaselineReset{Reason: "database restored from a backup"},
	})
}

// Anchor builds the anchor of an hour over the latest receipt received before
// its end and a leaf of another instance, with the proof of that receipt.
func (c *Custodian) Anchor(hour time.Time) {
	c.t.Helper()

	var latest string
	for _, entry := range c.Chain {
		if entry.FingerprintRecorded == nil {
			continue
		}
		issued, err := receipt.ParseUnverified(entry.FingerprintRecorded.Receipt)
		require.NoError(c.t, err)
		if issued.ReceivedAt.Before(hour.Add(time.Hour)) {
			latest = entry.FingerprintRecorded.Receipt
		}
	}

	leaves := []merkle.Hash{randomLeaf(c.t)}
	var proof *audit.AnchorProof
	if latest != "" {
		salt := RandomBytes(c.t)
		receiptHash, err := hex.DecodeString(receipt.Hash(latest))
		require.NoError(c.t, err)

		leaves = append([]merkle.Hash{merkle.SaltedLeafHash(salt, receiptHash)}, leaves...)
		siblings, err := merkle.Proof(leaves, 0)
		require.NoError(c.t, err)

		proof = &audit.AnchorProof{Receipt: latest, Salt: hex.EncodeToString(salt)}
		for _, sibling := range siblings {
			proof.Siblings = append(proof.Siblings, audit.ProofSibling{Hash: hex.EncodeToString(sibling.Hash[:]), Position: string(sibling.Position)})
		}
	}

	root := merkle.Root(leaves)
	anchor := receipt.Anchor{Hour: hour, Root: hex.EncodeToString(root[:]), LeafCount: len(leaves)}
	if c.LatestAnchor != "" {
		anchor.PreviousAnchorHash = receipt.Hash(c.LatestAnchor)
	}

	anchorJWS, err := c.SigningKey.SignAnchor(anchor, hour.Add(time.Hour))
	require.NoError(c.t, err)
	c.LatestAnchor = anchorJWS

	c.Anchors = append(c.Anchors, audit.AnchorWithProof{StampedAnchor: c.Stamp(anchorJWS), Proof: proof})
}

// Stamp has the time stamping authority of the custodian stamp an anchor.
func (c *Custodian) Stamp(anchorJWS string) audit.StampedAnchor {
	c.t.Helper()

	token, err := c.authority.Stamp(c.t.Context(), receipt.Digest(anchorJWS))
	require.NoError(c.t, err)

	return audit.StampedAnchor{Anchor: anchorJWS, TimestampToken: base64.StdEncoding.EncodeToString(token.Raw)}
}

// Data returns what an auditor reads, with a public chain of anchors that
// matches.
func (c *Custodian) Data() verify.Custodian {
	public := make([]audit.StampedAnchor, len(c.Anchors))
	for i, anchor := range c.Anchors {
		public[i] = anchor.StampedAnchor
	}

	return verify.Custodian{Instance: c.Instance, Chain: c.Chain, Anchors: c.Anchors, PublicAnchors: public}
}

// RandomBytes returns 32 random bytes, for example a salt.
func RandomBytes(t testing.TB) []byte {
	t.Helper()

	value := make([]byte, 32)
	_, err := rand.Read(value)
	require.NoError(t, err)

	return value
}

func randomLeaf(t testing.TB) merkle.Hash {
	t.Helper()

	return merkle.LeafHash(RandomBytes(t))
}

// Tamper changes a JWS in its signature, so that it no longer verifies.
func Tamper(jws string) string {
	last := jws[len(jws)-2:]
	replacement := "AA"
	if last == replacement {
		replacement = "BB"
	}

	return jws[:len(jws)-2] + replacement
}
