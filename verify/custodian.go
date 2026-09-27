package verify

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/thenativeweb/eventsourcingdb-auditing/audit"
	"github.com/thenativeweb/eventsourcingdb-auditing/merkle"
	"github.com/thenativeweb/eventsourcingdb-auditing/receipt"
	"github.com/thenativeweb/eventsourcingdb-auditing/timestamping"
)

// Custodian is what the custodian hands out about an instance, as an auditor
// reads it.
type Custodian struct {
	Instance      audit.ReadInstanceResponseBodyPayload
	Chain         []audit.ChainEntry
	Anchors       []audit.AnchorWithProof
	PublicAnchors []audit.StampedAnchor
}

// ConfirmedFingerprint is a fingerprint the custodian has confirmed with a
// receipt, which the events of the instance are compared with.
type ConfirmedFingerprint struct {
	EventID    string
	EventHash  string
	Sequence   uint64
	ReceivedAt time.Time
	Receipt    string

	// AnchoredAt is the end of the hour of the first anchor that covers the
	// receipt, or nil if no anchor covers it yet.
	AnchoredAt *time.Time

	// IsAfterLatestReset reports whether the fingerprint was recorded after
	// the latest reset of the baseline, if there is one. The events of the
	// instance only have to match those, since a reset starts the chain of
	// events over.
	IsAfterLatestReset bool
}

// CustodianResult is what checking the data of the custodian has found.
type CustodianResult struct {
	Fingerprints []ConfirmedFingerprint
	Findings     []Finding
}

// ErrNoCertifiedKey means that none of the key certificates verifies against
// the root key, which most likely means that the wrong root key was given.
var ErrNoCertifiedKey = errors.New("none of the key certificates verifies against the root key, so the root key is probably the wrong one")

// silenceTolerance is how much later than its heartbeat interval a client may
// send, since sending takes a moment, and a failed request is tried again.
const silenceTolerance = time.Minute

// anchorMargin is how long before the end of an hour a receipt must have been
// received to belong to the anchor of that hour for certain. A receipt
// received right before the end may also go into the next anchor.
const anchorMargin = time.Minute

// anchoringDelay is how long after the end of its hour a receipt may still be
// without an anchor, before that counts as a gap.
const anchoringDelay = 2 * time.Hour

// VerifyCustodian checks what the custodian has recorded about an instance:
// that its keys are certified by the root key, that its receipts form one
// chain that matches its entries, that its anchors are signed, stamped,
// chained, and prove the receipts of the instance, that they match the public
// chain of anchors, and that the client never was silent for longer than it
// may be. The time is when the audit happens.
func VerifyCustodian(custodian Custodian, rootPublicKey ed25519.PublicKey, now time.Time) (CustodianResult, error) {
	var found findings

	certificates := verifyKeyCertificates(custodian.Instance.SigningKeyCertificates, rootPublicKey, &found)
	if len(certificates) == 0 {
		return CustodianResult{}, ErrNoCertifiedKey
	}

	fingerprints := verifyChain(custodian, certificates, &found)
	verifyAnchors(custodian.Anchors, certificates, fingerprints, &found)
	verifyPublicAnchors(custodian.Anchors, custodian.PublicAnchors, &found)
	verifySilence(custodian, &found, now)
	verifyAnchoring(fingerprints, &found, now)

	return CustodianResult{Fingerprints: fingerprints, Findings: found}, nil
}

func verifyKeyCertificates(certificateJWSs []string, rootPublicKey ed25519.PublicKey, found *findings) map[string]receipt.KeyCertificate {
	certificates := map[string]receipt.KeyCertificate{}

	for _, certificateJWS := range certificateJWSs {
		certificate, err := receipt.VerifyKeyCertificate(certificateJWS, rootPublicKey)
		if err != nil {
			found.add(SeverityManipulation, CheckKeyCertificates, "A key certificate does not verify against the root key: %v", err)
			continue
		}

		certificates[certificate.KeyID] = certificate
	}

	return certificates
}

// verifyReceiptJWS checks a receipt against the certificate of its key.
func verifyReceiptJWS(receiptJWS string, certificates map[string]receipt.KeyCertificate) (receipt.Receipt, error) {
	keyID, err := receipt.KeyIDOfReceipt(receiptJWS)
	if err != nil {
		return receipt.Receipt{}, err
	}

	certificate, isKnown := certificates[keyID]
	if !isKnown {
		return receipt.Receipt{}, fmt.Errorf("it was signed with key %s, which has no certificate", keyID)
	}

	return receipt.Verify(receiptJWS, certificate)
}

// verifyChain checks the entries of the chain in the order they were
// recorded, and returns the confirmed fingerprints.
func verifyChain(custodian Custodian, certificates map[string]receipt.KeyCertificate, found *findings) []ConfirmedFingerprint {
	var fingerprints []ConfirmedFingerprint
	latestReset := -1

	var previousJWS string
	var previous receipt.Receipt
	hasPrevious := false

	for _, entry := range custodian.Chain {
		switch entry.Type {
		case audit.FingerprintRecordedType:
			recorded := entry.FingerprintRecorded
			if recorded == nil {
				found.add(SeverityManipulation, CheckReceipts, "Entry %s of the chain has no fingerprint, although it records one", entry.ID)
				continue
			}

			issued, err := verifyReceiptJWS(recorded.Receipt, certificates)
			if err != nil {
				found.add(SeverityManipulation, CheckReceipts, "Receipt %d does not verify: %v", recorded.Sequence, err)

				// Checking the receipts after it still needs its content,
				// so that one bad receipt does not spoil all the others.
				issued, err = receipt.ParseUnverified(recorded.Receipt)
				if err != nil {
					hasPrevious = false
					continue
				}
			}

			if issued.InstanceID != custodian.Instance.InstanceID {
				found.add(SeverityManipulation, CheckReceipts, "Receipt %d belongs to instance %s, not to instance %s", recorded.Sequence, issued.InstanceID, custodian.Instance.InstanceID)
			}
			if issued.EventID != recorded.EventID || issued.EventHash != recorded.EventHash || issued.Sequence != recorded.Sequence {
				found.add(SeverityManipulation, CheckReceipts, "Receipt %d confirms event %s with hash %s as number %d, but the chain records event %s with hash %s", recorded.Sequence, issued.EventID, issued.EventHash, issued.Sequence, recorded.EventID, recorded.EventHash)
			}

			switch {
			case !hasPrevious && !issued.IsFirst():
				found.add(SeverityManipulation, CheckReceipts, "Receipt %d does not follow any receipt in the chain", issued.Sequence)
			case hasPrevious && !issued.Follows(previousJWS, previous):
				found.add(SeverityManipulation, CheckReceipts, "Receipt %d does not follow receipt %d", issued.Sequence, previous.Sequence)
			}

			previousJWS, previous, hasPrevious = recorded.Receipt, issued, true

			fingerprints = append(fingerprints, ConfirmedFingerprint{
				EventID:    recorded.EventID,
				EventHash:  recorded.EventHash,
				Sequence:   issued.Sequence,
				ReceivedAt: issued.ReceivedAt,
				Receipt:    recorded.Receipt,
			})

		case audit.FingerprintConflictDetectedType:
			conflict := entry.FingerprintConflictDetected
			if conflict == nil {
				found.add(SeverityManipulation, CheckLocks, "Entry %s of the chain has no details, although it records a conflict", entry.ID)
				continue
			}

			found.add(SeverityManipulation, CheckLocks, "On %s, the client reported event %s with hash %s, although the custodian had recorded event %s with hash %s, so the instance was locked", formatTime(entry.RecordedAt), conflict.ReceivedEventID, conflict.ReceivedEventHash, conflict.StoredEventID, conflict.StoredEventHash)

		case audit.ContinuityBreakReportedType:
			reported := entry.ContinuityBreakReported
			if reported == nil {
				found.add(SeverityManipulation, CheckLocks, "Entry %s of the chain has no details, although it records a continuity break", entry.ID)
				continue
			}

			found.add(SeverityManipulation, CheckLocks, "On %s, the client found that event %s does not follow event %s with hash %s, so the instance was locked", formatTime(entry.RecordedAt), reported.ObservedEventID, reported.StoredEventID, reported.StoredEventHash)

		case audit.BaselineResetType:
			reason := ""
			if entry.BaselineReset != nil {
				reason = entry.BaselineReset.Reason
			}

			found.add(SeverityNotice, CheckLocks, "On %s, the baseline was reset, so that the chain of events started over, with the reason: %s", formatTime(entry.RecordedAt), reason)
			latestReset = len(fingerprints)

		default:
			found.add(SeverityManipulation, CheckReceipts, "Entry %s of the chain has the unknown type %q", entry.ID, entry.Type)
		}
	}

	for i := range fingerprints {
		fingerprints[i].IsAfterLatestReset = i >= latestReset
	}

	return fingerprints
}

func verifyAnchors(anchors []audit.AnchorWithProof, certificates map[string]receipt.KeyCertificate, fingerprints []ConfirmedFingerprint, found *findings) {
	var previousJWS string
	var previous receipt.Anchor
	hasPrevious := false

	for _, stamped := range anchors {
		anchor, err := verifyAnchor(stamped.StampedAnchor, certificates)
		if err != nil {
			found.add(SeverityManipulation, CheckAnchors, "An anchor does not verify: %v", err)

			anchor, err = receipt.ParseAnchorUnverified(stamped.Anchor)
			if err != nil {
				hasPrevious = false
				continue
			}
		}

		hour := formatTime(anchor.Hour)
		switch {
		case !hasPrevious && !anchor.IsFirst():
			found.add(SeverityManipulation, CheckAnchors, "The anchor of %s does not start the chain of anchors", hour)
		case hasPrevious && !anchor.Follows(previousJWS, previous):
			found.add(SeverityManipulation, CheckAnchors, "The anchor of %s does not follow the anchor of %s", hour, formatTime(previous.Hour))
		}
		previousJWS, previous, hasPrevious = stamped.Anchor, anchor, true

		verifyProof(anchor, stamped.Proof, fingerprints, found)
	}
}

// verifyAnchor checks the signature of an anchor, its time stamp, and that its
// key was valid when it was stamped.
func verifyAnchor(stamped audit.StampedAnchor, certificates map[string]receipt.KeyCertificate) (receipt.Anchor, error) {
	keyID, err := receipt.KeyIDOfAnchor(stamped.Anchor)
	if err != nil {
		return receipt.Anchor{}, err
	}

	certificate, isKnown := certificates[keyID]
	if !isKnown {
		return receipt.Anchor{}, fmt.Errorf("it was signed with key %s, which has no certificate", keyID)
	}

	anchor, err := receipt.VerifyAnchor(stamped.Anchor, certificate)
	if err != nil {
		return receipt.Anchor{}, err
	}

	token, err := base64.StdEncoding.DecodeString(stamped.TimestampToken)
	if err != nil {
		return anchor, fmt.Errorf("the time stamp of the anchor of %s is not base64: %v", formatTime(anchor.Hour), err)
	}

	stamp, err := timestamping.Verify(token, receipt.Digest(stamped.Anchor))
	if err != nil {
		return anchor, fmt.Errorf("the time stamp of the anchor of %s does not verify: %w", formatTime(anchor.Hour), err)
	}

	if !certificate.IsValidAt(stamp.Time) {
		return anchor, fmt.Errorf("the anchor of %s was stamped at %s, outside the period of its key", formatTime(anchor.Hour), formatTime(stamp.Time))
	}

	return anchor, nil
}

// verifyProof checks the proof of the instance for an anchor, marks the
// fingerprints it covers as anchored, and checks that the anchor leaves out no
// receipt of its hour.
func verifyProof(anchor receipt.Anchor, proof *audit.AnchorProof, fingerprints []ConfirmedFingerprint, found *findings) {
	hour := formatTime(anchor.Hour)
	hourEnd := anchor.Hour.Add(time.Hour)

	proven := -1
	if proof != nil {
		proven = slices.IndexFunc(fingerprints, func(fingerprint ConfirmedFingerprint) bool {
			return fingerprint.Receipt == proof.Receipt
		})

		switch {
		case proven < 0:
			found.add(SeverityManipulation, CheckProofs, "The proof for the anchor of %s is for a receipt that is not in the chain", hour)
		case !provesToRoot(proof, anchor.Root):
			found.add(SeverityManipulation, CheckProofs, "The proof for the anchor of %s does not lead to its root", hour)
			proven = -1
		}
	}

	for i := 0; i <= proven; i++ {
		if fingerprints[i].AnchoredAt == nil {
			fingerprints[i].AnchoredAt = &hourEnd
		}
	}

	// A receipt received well within the hour must be covered by its anchor,
	// either itself or through a later receipt.
	latestInHour := -1
	for i, fingerprint := range fingerprints {
		if !fingerprint.ReceivedAt.Before(anchor.Hour) && fingerprint.ReceivedAt.Before(hourEnd.Add(-anchorMargin)) {
			latestInHour = i
		}
	}
	if latestInHour > proven {
		found.add(SeverityManipulation, CheckProofs, "The anchor of %s leaves out receipt %d, which was received in its hour", hour, fingerprints[latestInHour].Sequence)
	}
}

func provesToRoot(proof *audit.AnchorProof, rootHex string) bool {
	salt, err := hex.DecodeString(proof.Salt)
	if err != nil {
		return false
	}
	receiptHash, err := hex.DecodeString(receipt.Hash(proof.Receipt))
	if err != nil {
		return false
	}
	root, err := decodeHash(rootHex)
	if err != nil {
		return false
	}

	siblings := make([]merkle.Sibling, len(proof.Siblings))
	for i, sibling := range proof.Siblings {
		hash, err := decodeHash(sibling.Hash)
		if err != nil {
			return false
		}
		siblings[i] = merkle.Sibling{Hash: hash, Position: merkle.Position(sibling.Position)}
	}

	return merkle.VerifyProof(merkle.SaltedLeafHash(salt, receiptHash), siblings, root)
}

func decodeHash(value string) (merkle.Hash, error) {
	decoded, err := hex.DecodeString(value)
	if err != nil || len(decoded) != len(merkle.Hash{}) {
		return merkle.Hash{}, fmt.Errorf("%q is no SHA-256 hash", value)
	}

	return merkle.Hash(decoded), nil
}

// verifyPublicAnchors checks that the custodian shows the auditor the same
// anchors as everyone else. The public chain may be longer, since it is read
// after the anchors of the auditor.
func verifyPublicAnchors(anchors []audit.AnchorWithProof, publicAnchors []audit.StampedAnchor, found *findings) {
	for i, stamped := range anchors {
		if i >= len(publicAnchors) {
			found.add(SeverityManipulation, CheckPublicAnchors, "The public chain of anchors ends before the chain of anchors of the auditor, after %d anchors", len(publicAnchors))
			return
		}

		if publicAnchors[i] != stamped.StampedAnchor {
			found.add(SeverityManipulation, CheckPublicAnchors, "Anchor %d of the auditor differs from anchor %d of the public chain", i+1, i+1)
		}
	}
}

// verifySilence finds the periods in which the client did not send for longer
// than its heartbeat interval allows. The time while an instance is locked
// does not count, since its client stops on purpose then.
func verifySilence(custodian Custodian, found *findings, now time.Time) {
	var last time.Time

	for _, entry := range custodian.Chain {
		switch entry.Type {
		case audit.FingerprintRecordedType:
			if entry.FingerprintRecorded == nil {
				continue
			}

			issued, err := receipt.ParseUnverified(entry.FingerprintRecorded.Receipt)
			if err != nil {
				continue
			}

			reportSilence(custodian.Instance.Intervals, last, issued.ReceivedAt, found, "No fingerprint arrived for %s, although the heartbeat interval was %s")
			last = issued.ReceivedAt

		case audit.FingerprintConflictDetectedType, audit.ContinuityBreakReportedType:
			last = time.Time{}

		case audit.BaselineResetType:
			last = entry.RecordedAt
		}
	}

	reportSilence(custodian.Instance.Intervals, last, now, found, "No fingerprint has arrived for %s, although the heartbeat interval is %s")
}

func reportSilence(intervals []audit.Intervals, from, until time.Time, found *findings, format string) {
	if from.IsZero() {
		return
	}

	heartbeat := heartbeatIntervalAt(intervals, from)
	silence := until.Sub(from)
	if silence > heartbeat+silenceTolerance {
		found.addPeriod(SeverityGap, CheckSilence, from, until, format, silence.Round(time.Second), heartbeat)
	}
}

// heartbeatIntervalAt returns the heartbeat interval that applied at a point
// in time.
func heartbeatIntervalAt(intervals []audit.Intervals, at time.Time) time.Duration {
	var heartbeat time.Duration
	for _, interval := range intervals {
		if interval.ValidFrom.After(at) {
			break
		}
		heartbeat = time.Duration(interval.HeartbeatIntervalInMilliseconds) * time.Millisecond
	}

	return heartbeat
}

// verifyAnchoring finds receipts that have stayed without an anchor for
// longer than the custodian needs to build and stamp one.
func verifyAnchoring(fingerprints []ConfirmedFingerprint, found *findings, now time.Time) {
	for _, fingerprint := range fingerprints {
		if fingerprint.AnchoredAt != nil {
			continue
		}

		hourEnd := fingerprint.ReceivedAt.Truncate(time.Hour).Add(time.Hour)
		if now.Sub(hourEnd) > anchoringDelay {
			found.addPeriod(SeverityGap, CheckAnchoring, fingerprint.ReceivedAt, now, "Receipt %d and the ones after it have no anchor, although their hour ended more than %s ago", fingerprint.Sequence, anchoringDelay)
			return
		}
	}
}
