package report

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/thenativeweb/eventsourcingdb-auditing/verify"
)

// WriteJSON writes a report as JSON.
func WriteJSON(out io.Writer, report Report) error {
	encoder := json.NewEncoder(out)
	encoder.SetIndent("", "  ")

	return encoder.Encode(report)
}

// WriteText writes a report as text for people, with the result first, and
// the findings grouped by severity.
func WriteText(out io.Writer, report Report) error {
	var text strings.Builder

	fmt.Fprintf(&text, "eventsourcingdb-auditing %s, checked at %s\n\n", report.ToolVersion, formatTime(report.CheckedAt))

	fmt.Fprintf(&text, "Instance            %s (%s), registered at %s\n", report.Instance.Name, report.Instance.ID, formatTime(report.Instance.RegisteredAt))
	fmt.Fprintf(&text, "Custodian           %s\n", report.Sources.Custodian)
	switch {
	case report.Sources.Backup != nil:
		fmt.Fprintf(&text, "Backup              %s\n                    SHA-256 %s\n", report.Sources.Backup.Path, report.Sources.Backup.SHA256)
	case report.Sources.Database != "":
		fmt.Fprintf(&text, "Database            %s\n", report.Sources.Database)
	}

	fmt.Fprintf(&text, "Events              %d", report.Events.Count)
	if report.Events.FirstAt != nil && report.Events.LastAt != nil {
		fmt.Fprintf(&text, ", written from %s to %s", formatTime(*report.Events.FirstAt), formatTime(*report.Events.LastAt))
	}
	fmt.Fprintf(&text, "\nReceipts            %d\nAnchors             %d\n", report.Receipts, report.Anchors)

	if report.ReceiptsDirectoryChecked {
		fmt.Fprintf(&text, "Receipts directory  %s\n", report.Sources.ReceiptsDirectory)
	} else {
		fmt.Fprintf(&text, "Receipts directory  not given, so the custodian was not checked against the receipts the client kept\n")
	}
	switch {
	case report.TrustedListsChecked && report.TrustedLists != nil:
		fmt.Fprintf(&text, "Trusted lists       list of the lists issued at %s, %d of %d stamped anchors qualified\n",
			formatTime(report.TrustedLists.ListOfTheListsIssuedAt), report.TrustedLists.QualifiedAnchors, report.TrustedLists.StampedAnchors)
	case !report.TrustedListsChecked:
		fmt.Fprintf(&text, "Trusted lists       not checked, so whether the time stamps are qualified is not known\n")
	}

	counts := map[verify.Severity]int{}
	for _, finding := range report.Findings {
		counts[finding.Severity]++
	}
	fmt.Fprintf(&text, "\nResult              %s (%d manipulations, %d gaps, %d notices)\n",
		strings.ToUpper(strings.ReplaceAll(string(report.Result), "-", " ")),
		counts[verify.SeverityManipulation], counts[verify.SeverityGap], counts[verify.SeverityNotice])

	for _, group := range []struct {
		severity verify.Severity
		title    string
	}{
		{verify.SeverityManipulation, "Manipulations"},
		{verify.SeverityGap, "Gaps in protection"},
		{verify.SeverityNotice, "Notices"},
	} {
		if counts[group.severity] == 0 {
			continue
		}

		fmt.Fprintf(&text, "\n%s\n", group.title)
		for _, finding := range report.Findings {
			if finding.Severity != group.severity {
				continue
			}

			fmt.Fprintf(&text, "  - [%s] %s", finding.Check, finding.Message)
			if finding.From != nil && finding.Until != nil {
				fmt.Fprintf(&text, " (from %s until %s)", formatTime(*finding.From), formatTime(*finding.Until))
			}
			fmt.Fprintln(&text)
		}
	}

	_, err := io.WriteString(out, text.String())

	return err
}

func formatTime(value time.Time) string {
	return value.UTC().Format(time.RFC3339)
}
