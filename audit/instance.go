package audit

import "time"

// ReadInstancePath returns what the custodian knows about the audited
// instance, apart from its chain.
const ReadInstancePath = "/api/v1/audit/read-instance"

const ReadInstanceResponseType = "io.thenativeweb.custody.audited-instance"

type ReadInstanceResponseBody struct {
	Type    string                          `json:"type"`
	Payload ReadInstanceResponseBodyPayload `json:"payload"`
}

type ReadInstanceResponseBodyPayload struct {
	InstanceID   string    `json:"instanceId"`
	Name         string    `json:"name"`
	RegisteredAt time.Time `json:"registeredAt"`

	// Intervals holds every change of how often the client sends, starting
	// with the intervals the instance was registered with, so that an auditor
	// can tell whether a gap between two receipts was allowed.
	Intervals []Intervals `json:"intervals"`

	// SigningKeyCertificates certify all keys the custodian has ever signed
	// receipts and anchors with.
	SigningKeyCertificates []string `json:"signingKeyCertificates"`

	// AuditAccess describes the access the auditor reads with.
	AuditAccess AuditAccess `json:"auditAccess"`
}

// Intervals are the intervals that apply from a point in time on: a new
// fingerprint at most once per minimum interval, and the latest one again once
// per heartbeat interval if nothing changes.
type Intervals struct {
	ValidFrom                       time.Time `json:"validFrom"`
	MinimumIntervalInMilliseconds   int       `json:"minimumIntervalInMilliseconds"`
	HeartbeatIntervalInMilliseconds int       `json:"heartbeatIntervalInMilliseconds"`
}

// AuditAccess is an access the customer has granted to an auditor.
type AuditAccess struct {
	ID         string    `json:"id"`
	GrantedAt  time.Time `json:"grantedAt"`
	ValidUntil time.Time `json:"validUntil"`
}
