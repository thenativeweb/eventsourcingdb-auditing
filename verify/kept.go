package verify

import (
	"crypto/ed25519"
	"reflect"
	"time"

	"github.com/thenativeweb/eventsourcingdb-auditing/audit"
	"github.com/thenativeweb/eventsourcingdb-auditing/receipt"
	"github.com/thenativeweb/eventsourcingdb-auditing/receiptsdir"
)

// VerifyKept checks the receipts and anchors the client of the customer has
// kept against what the custodian hands out now, so that a custodian that has
// changed its history is found. Only receipts and anchors that verify count,
// since only those can be held against the custodian.
func VerifyKept(kept receiptsdir.Directory, custodian Custodian, rootPublicKey ed25519.PublicKey) []Finding {
	var found findings

	certificates := map[string]receipt.KeyCertificate{}
	for _, certificateJWS := range append(append([]string{}, custodian.Instance.SigningKeyCertificates...), kept.Certificates...) {
		certificate, err := receipt.VerifyKeyCertificate(certificateJWS, rootPublicKey)
		if err == nil {
			certificates[certificate.KeyID] = certificate
		}
	}

	verifyKeptReceipts(kept.Receipts, custodian.Chain, certificates, &found)
	verifyKeptAnchors(kept.Anchors, custodian.Anchors, certificates, &found)

	return found
}

// numbers collects the numbers of receipts that share a finding.
type numbers struct {
	count           int
	lowest, highest uint64
}

func (n *numbers) add(number uint64) {
	if n.count == 0 || number < n.lowest {
		n.lowest = number
	}
	if n.count == 0 || number > n.highest {
		n.highest = number
	}
	n.count++
}

func verifyKeptReceipts(keptReceipts []string, chain []audit.ChainEntry, certificates map[string]receipt.KeyCertificate, found *findings) {
	held := map[uint64]string{}
	for _, entry := range chain {
		if entry.FingerprintRecorded != nil {
			held[entry.FingerprintRecorded.Sequence] = entry.FingerprintRecorded.Receipt
		}
	}

	var missing, differing numbers
	invalid := 0

	for _, keptReceipt := range keptReceipts {
		issued, err := verifyReceiptJWS(keptReceipt, certificates)
		if err != nil {
			invalid++
			continue
		}

		heldReceipt, isHeld := held[issued.Sequence]
		switch {
		case !isHeld:
			missing.add(issued.Sequence)
		case heldReceipt != keptReceipt:
			differing.add(issued.Sequence)
		}
	}

	if missing.count > 0 {
		found.add(SeverityManipulation, CheckKeptReceipts, "%d receipts the client kept are missing from the chain of the custodian, from receipt %d to receipt %d", missing.count, missing.lowest, missing.highest)
	}
	if differing.count > 0 {
		found.add(SeverityManipulation, CheckKeptReceipts, "For %d receipts the client kept, the custodian holds other ones with the same numbers, from receipt %d to receipt %d", differing.count, differing.lowest, differing.highest)
	}
	if invalid > 0 {
		found.add(SeverityNotice, CheckKeptReceipts, "%d receipts in the receipts directory do not verify, so they can not be held against the custodian", invalid)
	}
}

func verifyKeptAnchors(keptAnchors []audit.AnchorWithProof, heldAnchors []audit.AnchorWithProof, certificates map[string]receipt.KeyCertificate, found *findings) {
	held := map[time.Time]audit.AnchorWithProof{}
	for _, heldAnchor := range heldAnchors {
		anchor, err := receipt.ParseAnchorUnverified(heldAnchor.Anchor)
		if err == nil {
			held[anchor.Hour.UTC()] = heldAnchor
		}
	}

	var missing, differing []time.Time
	invalid := 0

	for _, keptAnchor := range keptAnchors {
		anchor, err := verifyAnchor(keptAnchor.StampedAnchor, certificates)
		if err != nil {
			invalid++
			continue
		}

		heldAnchor, isHeld := held[anchor.Hour.UTC()]
		switch {
		case !isHeld:
			missing = append(missing, anchor.Hour)
		case heldAnchor.StampedAnchor != keptAnchor.StampedAnchor || !reflect.DeepEqual(heldAnchor.Proof, keptAnchor.Proof):
			differing = append(differing, anchor.Hour)
		}
	}

	if len(missing) > 0 {
		found.addPeriod(SeverityManipulation, CheckKeptAnchors, missing[0], missing[len(missing)-1], "%d anchors the client kept are missing from the anchors of the custodian, from the anchor of %s to the anchor of %s", len(missing), formatTime(missing[0]), formatTime(missing[len(missing)-1]))
	}
	if len(differing) > 0 {
		found.addPeriod(SeverityManipulation, CheckKeptAnchors, differing[0], differing[len(differing)-1], "For %d anchors the client kept, the custodian now hands out other anchors or proofs, from the anchor of %s to the anchor of %s", len(differing), formatTime(differing[0]), formatTime(differing[len(differing)-1]))
	}
	if invalid > 0 {
		found.add(SeverityNotice, CheckKeptAnchors, "%d anchors in the receipts directory do not verify, so they can not be held against the custodian", invalid)
	}
}
