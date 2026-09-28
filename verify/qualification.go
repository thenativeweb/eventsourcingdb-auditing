package verify

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"time"

	"github.com/thenativeweb/eventsourcingdb-auditing/audit"
	"github.com/thenativeweb/eventsourcingdb-auditing/receipt"
	"github.com/thenativeweb/eventsourcingdb-auditing/timestamping"
	"github.com/thenativeweb/eventsourcingdb-auditing/trustedlists"
)

// QualificationChecker tells whether a certificate belonged to a qualified
// time stamping service at a point in time. trustedlists.Checker is one.
type QualificationChecker interface {
	Qualification(ctx context.Context, certificate *x509.Certificate, at time.Time) (trustedlists.Qualification, error)
}

// QualificationResult is what checking the time stamps of the anchors against
// the EU trusted lists has found.
type QualificationResult struct {
	// Stamped counts the anchors whose time stamp verifies, and Qualified the
	// ones among them that a qualified time stamping service issued.
	Stamped   int
	Qualified int

	Findings []Finding
}

// unqualifiedStamps collects the anchors a certificate stamped without
// counting as qualified, for the same reason, so that they end up in one
// finding.
type unqualifiedStamps struct {
	subject     string
	reason      string
	count       int
	first, last time.Time
}

// VerifyQualification checks whether the time stamps of the anchors were
// issued by a qualified time stamping service at their time. A time stamp that
// was not is a notice, since it still proves when the anchor existed, only
// without the legal weight of a qualified one. Time stamps that do not verify
// at all are left out, since VerifyCustodian reports them.
//
// It only fails if a trusted list can not be fetched or checked.
func VerifyQualification(ctx context.Context, anchors []audit.AnchorWithProof, checker QualificationChecker) (QualificationResult, error) {
	var result QualificationResult
	var groups []*unqualifiedStamps

	for _, stamped := range anchors {
		raw, err := base64.StdEncoding.DecodeString(stamped.TimestampToken)
		if err != nil {
			continue
		}
		token, err := timestamping.Verify(raw, receipt.Digest(stamped.Anchor))
		if err != nil {
			continue
		}
		anchor, err := receipt.ParseAnchorUnverified(stamped.Anchor)
		if err != nil {
			continue
		}
		result.Stamped++

		qualification, err := checker.Qualification(ctx, token.Certificate, token.Time)
		if err != nil {
			return QualificationResult{}, err
		}
		if qualification.IsQualified {
			result.Qualified++
			continue
		}

		subject := token.Certificate.Subject.String()
		var group *unqualifiedStamps
		for _, candidate := range groups {
			if candidate.subject == subject && candidate.reason == qualification.Reason {
				group = candidate
			}
		}
		if group == nil {
			group = &unqualifiedStamps{subject: subject, reason: qualification.Reason, first: anchor.Hour}
			groups = append(groups, group)
		}
		group.count++
		group.last = anchor.Hour
	}

	var found findings
	for _, group := range groups {
		found.addPeriod(SeverityNotice, CheckQualification, group.first, group.last, "%d anchors, from the anchor of %s to the anchor of %s, were stamped by %q, which does not count as a qualified time stamping service: %s", group.count, formatTime(group.first), formatTime(group.last), group.subject, group.reason)
	}
	result.Findings = found

	return result, nil
}
