package verify

import "time"

// Severity tells how much a finding weighs.
type Severity string

const (
	// SeverityManipulation means that data has been changed, or that the
	// custodian contradicts itself, its signatures, or the public chain of
	// anchors. It also covers the tamper signals the custodian has recorded,
	// a conflict or a continuity break, since a later reset of the baseline
	// only explains them, but does not undo them.
	SeverityManipulation Severity = "manipulation"

	// SeverityGap means that events were not protected in the way the
	// intervals of the instance promise, for example because the client was
	// silent for longer than its heartbeat interval.
	SeverityGap Severity = "gap"

	// SeverityNotice is something an auditor should know, but that is
	// neither a manipulation nor a gap, for example a reset of the baseline
	// and its reason.
	SeverityNotice Severity = "notice"
)

// The checks a finding can come from.
const (
	CheckKeyCertificates = "key-certificates"
	CheckReceipts        = "receipts"
	CheckLocks           = "locks"
	CheckAnchors         = "anchors"
	CheckProofs          = "proofs"
	CheckPublicAnchors   = "public-anchors"
	CheckSilence         = "silence"
	CheckAnchoring       = "anchoring"
	CheckEventHashes     = "event-hashes"
	CheckEventChain      = "event-chain"
	CheckFingerprints    = "fingerprints"
	CheckProtection      = "protection"
	CheckKeptReceipts    = "kept-receipts"
	CheckKeptAnchors     = "kept-anchors"
)

// Finding is one problem, or one thing worth knowing, that a check has found.
type Finding struct {
	Severity Severity `json:"severity"`
	Check    string   `json:"check"`
	Message  string   `json:"message"`

	// From and Until mark the period a finding is about, if it is about one.
	From  *time.Time `json:"from,omitempty"`
	Until *time.Time `json:"until,omitempty"`
}

// findings collects findings as the checks go.
type findings []Finding

func (f *findings) add(severity Severity, check, format string, args ...any) {
	*f = append(*f, Finding{Severity: severity, Check: check, Message: sprintf(format, args...)})
}

// addPeriod adds a finding about a period.
func (f *findings) addPeriod(severity Severity, check string, from, until time.Time, format string, args ...any) {
	*f = append(*f, Finding{Severity: severity, Check: check, Message: sprintf(format, args...), From: &from, Until: &until})
}
