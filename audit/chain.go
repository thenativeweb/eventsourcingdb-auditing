package audit

import "time"

// ReadChainPath returns the chain of the audited instance, as the custodian
// has recorded it, in the order it was recorded.
const ReadChainPath = "/api/v1/audit/read-chain"

// ChainAfterParameter is the query parameter that names the ID of the entry
// after which entries are returned. Without it, the chain is returned from its
// start.
const ChainAfterParameter = "after"

// MaxChainEntriesPerResponse bounds how many entries a single response
// carries. A caller that gets that many asks again, after the last one.
const MaxChainEntriesPerResponse = 1000

const ReadChainResponseType = "io.thenativeweb.custody.chain"

type ReadChainResponseBody struct {
	Type    string                       `json:"type"`
	Payload ReadChainResponseBodyPayload `json:"payload"`
}

type ReadChainResponseBodyPayload struct {
	Entries []ChainEntry `json:"entries"`
}

// The types of the entries of a chain.
const (
	FingerprintRecordedType         = "fingerprint-recorded"
	FingerprintConflictDetectedType = "fingerprint-conflict-detected"
	ContinuityBreakReportedType     = "continuity-break-reported"
	BaselineResetType               = "baseline-reset"
)

// ChainEntry is one entry of the chain of an instance. Exactly the field that
// belongs to its type is set.
type ChainEntry struct {
	// ID identifies the entry within the custodian, and is what the next page
	// is asked for after.
	ID string `json:"id"`

	// RecordedAt is when the custodian recorded the entry.
	RecordedAt time.Time `json:"recordedAt"`

	Type string `json:"type"`

	FingerprintRecorded         *FingerprintRecorded         `json:"fingerprintRecorded,omitempty"`
	FingerprintConflictDetected *FingerprintConflictDetected `json:"fingerprintConflictDetected,omitempty"`
	ContinuityBreakReported     *ContinuityBreakReported     `json:"continuityBreakReported,omitempty"`
	BaselineReset               *BaselineReset               `json:"baselineReset,omitempty"`
}

// FingerprintRecorded is a fingerprint the custodian has accepted, together
// with the receipt it confirmed it with.
type FingerprintRecorded struct {
	EventID   string `json:"eventId"`
	EventHash string `json:"eventHash"`
	Sequence  uint64 `json:"sequence"`
	Receipt   string `json:"receipt"`
}

// FingerprintConflictDetected is a fingerprint that contradicted the chain,
// either because an event had another hash than before, or because the event
// stream went backwards. It locked the instance.
type FingerprintConflictDetected struct {
	StoredEventID     string `json:"storedEventId"`
	StoredEventHash   string `json:"storedEventHash"`
	ReceivedEventID   string `json:"receivedEventId"`
	ReceivedEventHash string `json:"receivedEventHash"`
}

// ContinuityBreakReported is a break the client found itself: an event that
// did not link to the fingerprint before it. It locked the instance.
type ContinuityBreakReported struct {
	StoredEventID           string `json:"storedEventId"`
	StoredEventHash         string `json:"storedEventHash"`
	ObservedEventID         string `json:"observedEventId"`
	ObservedPredecessorHash string `json:"observedPredecessorHash"`
}

// BaselineReset lifted a lock, so that the chain of events started over, while
// the chain of receipts continued.
type BaselineReset struct {
	Reason string `json:"reason"`
}
