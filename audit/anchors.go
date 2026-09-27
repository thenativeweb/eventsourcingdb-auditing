package audit

// ListAnchorsPath is public: anyone may read the chain of anchors, which is
// what keeps the custodian from showing different anchors to different
// parties.
const ListAnchorsPath = "/api/v1/anchors"

// ReadAnchorsPath returns the anchors together with the proofs of the audited
// instance.
const ReadAnchorsPath = "/api/v1/audit/read-anchors"

// AnchorsAfterParameter is the query parameter that names the hour after which
// anchors are returned, in RFC 3339. Without it, the chain is returned from its
// start.
const AnchorsAfterParameter = "after"

// MaxAnchorsPerResponse bounds how many anchors a single response carries. A
// caller that gets that many asks again, after the last one.
const MaxAnchorsPerResponse = 100

const (
	ListAnchorsResponseType = "io.thenativeweb.custody.anchors"
	ReadAnchorsResponseType = "io.thenativeweb.custody.anchors-with-proofs"
)

// StampedAnchor is an anchor together with the time stamp of the time stamping
// authority over it. Only stamped anchors are handed out, in the order of the
// chain.
type StampedAnchor struct {
	Anchor string `json:"anchor"`

	// TimestampToken is the RFC 3161 time stamp token in DER form, encoded
	// with standard base64.
	TimestampToken string `json:"timestampToken"`
}

type ListAnchorsResponseBody struct {
	Type    string                         `json:"type"`
	Payload ListAnchorsResponseBodyPayload `json:"payload"`
}

type ListAnchorsResponseBodyPayload struct {
	Anchors                []StampedAnchor `json:"anchors"`
	SigningKeyCertificates []string        `json:"signingKeyCertificates"`
}

// AnchorProof proves that the latest receipt of an instance in an hour is part
// of the anchor of that hour. The salt is only ever handed to that instance,
// and to its auditors.
type AnchorProof struct {
	Receipt  string         `json:"receipt"`
	Salt     string         `json:"salt"`
	Siblings []ProofSibling `json:"siblings"`
}

// ProofSibling is one step on the path from a leaf to the root: the hash next
// to the path, and whether it lies to the left or to the right.
type ProofSibling struct {
	Hash     string `json:"hash"`
	Position string `json:"position"`
}

// AnchorWithProof carries the proof of an instance, or none, if the instance
// sent nothing in that hour.
type AnchorWithProof struct {
	StampedAnchor
	Proof *AnchorProof `json:"proof,omitempty"`
}

type ReadAnchorsResponseBody struct {
	Type    string                         `json:"type"`
	Payload ReadAnchorsResponseBodyPayload `json:"payload"`
}

type ReadAnchorsResponseBodyPayload struct {
	Anchors                []AnchorWithProof `json:"anchors"`
	SigningKeyCertificates []string          `json:"signingKeyCertificates"`
}
