package verify_test

import (
	"context"
	"crypto/x509"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/thenativeweb/eventsourcingdb-auditing/audit"
	"github.com/thenativeweb/eventsourcingdb-auditing/trustedlists"
	"github.com/thenativeweb/eventsourcingdb-auditing/verify"
)

// fakeChecker answers every question about qualification with the result of a
// function.
type fakeChecker func(certificate *x509.Certificate, at time.Time) (trustedlists.Qualification, error)

func (f fakeChecker) Qualification(ctx context.Context, certificate *x509.Certificate, at time.Time) (trustedlists.Qualification, error) {
	return f(certificate, at)
}

func TestVerifyQualification(t *testing.T) {
	// newAnchors returns the given number of anchors, one per hour from ten
	// o'clock on, stamped by the time stamping authority of the tests.
	newAnchors := func(t *testing.T, hours int) []audit.AnchorWithProof {
		t.Helper()

		custodian := consistentHistory(t)
		for hour := 1; hour < hours; hour++ {
			custodian.Anchor(tenOClock.Add(time.Duration(hour) * time.Hour))
		}

		return custodian.Anchors
	}

	t.Run("counts the anchors stamped by a qualified service, without findings", func(t *testing.T) {
		anchors := newAnchors(t, 3)
		checker := fakeChecker(func(certificate *x509.Certificate, at time.Time) (trustedlists.Qualification, error) {
			assert.Equal(t, "Test Time Stamping Authority", certificate.Subject.CommonName)
			assert.WithinDuration(t, time.Now(), at, time.Minute, "the time of the time stamp is asked for")
			return trustedlists.Qualification{IsQualified: true}, nil
		})

		result, err := verify.VerifyQualification(t.Context(), anchors, checker)

		require.NoError(t, err)
		assert.Equal(t, 3, result.Stamped)
		assert.Equal(t, 3, result.Qualified)
		assert.Empty(t, result.Findings)
	})

	t.Run("joins the anchors a service stamped without counting as qualified, by reason", func(t *testing.T) {
		anchors := newAnchors(t, 3)
		calls := 0
		checker := fakeChecker(func(certificate *x509.Certificate, at time.Time) (trustedlists.Qualification, error) {
			calls++
			if calls == 2 {
				return trustedlists.Qualification{Reason: "there is no trusted list for ZZ"}, nil
			}
			return trustedlists.Qualification{Reason: "the certificate names no country, so no trusted list applies to it"}, nil
		})

		result, err := verify.VerifyQualification(t.Context(), anchors, checker)

		require.NoError(t, err)
		assert.Equal(t, 3, result.Stamped)
		assert.Equal(t, 0, result.Qualified)
		require.Len(t, result.Findings, 2)
		assert.Equal(t, verify.SeverityNotice, result.Findings[0].Severity)
		assert.Equal(t, verify.CheckQualification, result.Findings[0].Check)
		assert.Contains(t, result.Findings[0].Message, "2 anchors, from the anchor of 2026-09-01T10:00:00Z to the anchor of 2026-09-01T12:00:00Z")
		assert.Contains(t, result.Findings[0].Message, "names no country")
		assert.Contains(t, result.Findings[1].Message, "1 anchors, from the anchor of 2026-09-01T11:00:00Z")
	})

	t.Run("leaves out time stamps that do not verify", func(t *testing.T) {
		anchors := newAnchors(t, 2)
		anchors[0].TimestampToken = "not base64"
		checker := fakeChecker(func(certificate *x509.Certificate, at time.Time) (trustedlists.Qualification, error) {
			return trustedlists.Qualification{IsQualified: true}, nil
		})

		result, err := verify.VerifyQualification(t.Context(), anchors, checker)

		require.NoError(t, err)
		assert.Equal(t, 1, result.Stamped)
	})

	t.Run("fails if a trusted list can not be checked", func(t *testing.T) {
		anchors := newAnchors(t, 1)
		checker := fakeChecker(func(certificate *x509.Certificate, at time.Time) (trustedlists.Qualification, error) {
			return trustedlists.Qualification{}, errors.New("the trusted list of DE is not reachable")
		})

		_, err := verify.VerifyQualification(t.Context(), anchors, checker)

		assert.ErrorContains(t, err, "not reachable")
	})
}
