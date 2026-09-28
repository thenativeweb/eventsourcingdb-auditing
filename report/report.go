package report

import (
	"time"

	"github.com/thenativeweb/eventsourcingdb-auditing/verify"
)

// Result sums up the findings of a verification.
type Result string

const (
	// ResultNoFindings means that neither a manipulation nor a gap was
	// found. There may be notices.
	ResultNoFindings Result = "no-findings"

	// ResultGaps means that no manipulation was found, but events were not
	// protected in the way the intervals promise.
	ResultGaps Result = "gaps"

	// ResultManipulation means that at least one manipulation was found.
	ResultManipulation Result = "manipulation"
)

// The exit codes of the verification tool.
const (
	ExitCodeNoFindings   = 0
	ExitCodeManipulation = 1
	ExitCodeGaps         = 2
	ExitCodeFailure      = 3
)

// Report is the result of a verification, together with what was checked, so
// that an auditor can document it.
type Report struct {
	ToolVersion string    `json:"toolVersion"`
	CheckedAt   time.Time `json:"checkedAt"`

	Instance Instance `json:"instance"`
	Sources  Sources  `json:"sources"`

	Events   Events `json:"events"`
	Receipts int    `json:"receipts"`
	Anchors  int    `json:"anchors"`

	// ReceiptsDirectoryChecked reports whether the custodian was checked
	// against the receipts the client kept.
	ReceiptsDirectoryChecked bool `json:"receiptsDirectoryChecked"`

	// TrustedListsChecked reports whether the time stamps were checked
	// against the EU trusted lists, and TrustedLists what that found.
	TrustedListsChecked bool          `json:"trustedListsChecked"`
	TrustedLists        *TrustedLists `json:"trustedLists,omitempty"`

	Result   Result           `json:"result"`
	Findings []verify.Finding `json:"findings"`
}

type Instance struct {
	ID           string    `json:"id"`
	Name         string    `json:"name"`
	RegisteredAt time.Time `json:"registeredAt"`
}

// Sources name where the verification read from.
type Sources struct {
	Custodian         string  `json:"custodian"`
	Backup            *Backup `json:"backup,omitempty"`
	Database          string  `json:"database,omitempty"`
	ReceiptsDirectory string  `json:"receiptsDirectory,omitempty"`
}

// Backup names a backup, and its SHA-256, so that it is clear which one was
// checked.
type Backup struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}

type Events struct {
	Count   int        `json:"count"`
	FirstAt *time.Time `json:"firstAt,omitempty"`
	LastAt  *time.Time `json:"lastAt,omitempty"`
}

// TrustedLists describes the check of the time stamps against the EU trusted
// lists.
type TrustedLists struct {
	// ListOfTheListsIssuedAt names the state of the trusted lists the check
	// relied on.
	ListOfTheListsIssuedAt time.Time `json:"listOfTheListsIssuedAt"`

	StampedAnchors   int `json:"stampedAnchors"`
	QualifiedAnchors int `json:"qualifiedAnchors"`
}

// ResultOf sums up findings.
func ResultOf(findings []verify.Finding) Result {
	result := ResultNoFindings
	for _, finding := range findings {
		switch finding.Severity {
		case verify.SeverityManipulation:
			return ResultManipulation
		case verify.SeverityGap:
			result = ResultGaps
		}
	}

	return result
}

// ExitCode returns the exit code for the result of a report.
func (r Report) ExitCode() int {
	switch r.Result {
	case ResultManipulation:
		return ExitCodeManipulation
	case ResultGaps:
		return ExitCodeGaps
	default:
		return ExitCodeNoFindings
	}
}
