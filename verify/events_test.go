package verify_test

import (
	"errors"
	"fmt"
	"iter"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/thenativeweb/eventsourcingdb-auditing/audit"
	"github.com/thenativeweb/eventsourcingdb-auditing/database"
	"github.com/thenativeweb/eventsourcingdb-auditing/verify"
)

// chainOfEvents returns events with the IDs 0 to count-1 that form a chain,
// written one step apart from the given time on.
func chainOfEvents(count int, from time.Time, step time.Duration) []database.Event {
	events := make([]database.Event, count)
	for i := range events {
		predecessorHash := database.GenesisHash
		if i > 0 {
			predecessorHash = events[i-1].Hash
		}

		events[i] = database.Event{
			ID:              fmt.Sprint(i),
			Time:            from.Add(time.Duration(i) * step),
			Hash:            fmt.Sprintf("hash-%d", i),
			PredecessorHash: predecessorHash,
			HashMatches:     true,
		}
	}

	return events
}

func sequenceOf(events []database.Event) iter.Seq2[database.Event, error] {
	return func(yield func(database.Event, error) bool) {
		for _, event := range events {
			if !yield(event, nil) {
				return
			}
		}
	}
}

// confirmed returns fingerprints the custodian confirmed for the given events,
// at the given times.
func confirmed(events []database.Event, confirmations map[int]time.Time) []verify.ConfirmedFingerprint {
	var fingerprints []verify.ConfirmedFingerprint
	for i := range events {
		at, isConfirmed := confirmations[i]
		if !isConfirmed {
			continue
		}

		fingerprints = append(fingerprints, verify.ConfirmedFingerprint{
			EventID:            events[i].ID,
			EventHash:          events[i].Hash,
			Sequence:           uint64(len(fingerprints) + 1),
			ReceivedAt:         at,
			IsAfterLatestReset: true,
		})
	}

	return fingerprints
}

func custodianResult(fingerprints []verify.ConfirmedFingerprint) verify.CustodianResult {
	return verify.CustodianResult{
		Fingerprints: fingerprints,
		Intervals: []audit.Intervals{{
			ValidFrom:                       tenOClock.Add(-time.Hour),
			MinimumIntervalInMilliseconds:   60_000,
			HeartbeatIntervalInMilliseconds: 600_000,
		}},
	}
}

func verifyEventsAt(t *testing.T, events []database.Event, custodian verify.CustodianResult, now time.Time) verify.EventsResult {
	t.Helper()

	result, err := verify.VerifyEvents(sequenceOf(events), custodian, now)
	require.NoError(t, err)

	return result
}

func eventFindingsOf(result verify.EventsResult, severity verify.Severity, check string) []verify.Finding {
	return findingsOf(verify.CustodianResult{Findings: result.Findings}, severity, check)
}

// wellCovered returns ten events, written every thirty seconds from ten on,
// and a fingerprint for every second one, a minute after it was written.
func wellCovered() ([]database.Event, verify.CustodianResult) {
	events := chainOfEvents(10, tenOClock, 30*time.Second)

	confirmations := map[int]time.Time{}
	for i := 1; i < len(events); i += 2 {
		confirmations[i] = events[i].Time.Add(time.Minute)
	}

	return events, custodianResult(confirmed(events, confirmations))
}

func TestVerifyEvents(t *testing.T) {
	t.Run("finds nothing in events that match the custodian and were protected in time", func(t *testing.T) {
		events, custodian := wellCovered()

		result := verifyEventsAt(t, events, custodian, tenOClock.Add(6*time.Minute))

		assert.Empty(t, result.Findings)
		assert.Equal(t, 10, result.EventCount)
		assert.Equal(t, tenOClock, result.FirstEventAt)
		assert.Equal(t, tenOClock.Add(270*time.Second), result.LastEventAt)
	})

	t.Run("finds changed events, and joins consecutive ones", func(t *testing.T) {
		events, custodian := wellCovered()
		events[3].HashMatches = false
		events[4].HashMatches = false
		events[7].HashMatches = false

		result := verifyEventsAt(t, events, custodian, tenOClock.Add(6*time.Minute))

		changed := eventFindingsOf(result, verify.SeverityManipulation, verify.CheckEventHashes)
		require.Len(t, changed, 2)
		assert.Contains(t, changed[0].Message, "Events 3 to 4 have been changed")
		assert.Contains(t, changed[1].Message, "Event 7 has been changed")
	})

	t.Run("finds missing events and events that do not follow the one before", func(t *testing.T) {
		events, custodian := wellCovered()
		events[6].PredecessorHash = "other-hash"
		withoutFour := append(append([]database.Event{}, events[:4]...), events[5:]...)

		result := verifyEventsAt(t, withoutFour, custodian, tenOClock.Add(6*time.Minute))

		chain := eventFindingsOf(result, verify.SeverityManipulation, verify.CheckEventChain)
		require.Len(t, chain, 3)
		assert.Contains(t, chain[0].Message, "Event 5 follows event 3")
		assert.Contains(t, chain[1].Message, "Event 5 does not follow event 3")
		assert.Contains(t, chain[2].Message, "Event 6 does not follow event 5")
	})

	t.Run("finds a database that does not start with the first event", func(t *testing.T) {
		events, custodian := wellCovered()

		result := verifyEventsAt(t, events[2:], custodian, tenOClock.Add(6*time.Minute))

		chain := eventFindingsOf(result, verify.SeverityManipulation, verify.CheckEventChain)
		require.Len(t, chain, 2)
		assert.Contains(t, chain[0].Message, "starts with event 2")
	})

	t.Run("finds an event with another hash than the custodian has confirmed", func(t *testing.T) {
		events, custodian := wellCovered()
		custodian.Fingerprints[1].EventHash = "confirmed-hash"

		result := verifyEventsAt(t, events, custodian, tenOClock.Add(6*time.Minute))

		fingerprints := eventFindingsOf(result, verify.SeverityManipulation, verify.CheckFingerprints)
		require.Len(t, fingerprints, 1)
		assert.Contains(t, fingerprints[0].Message, "Event 3 has the hash hash-3, but the custodian confirmed the hash confirmed-hash")
	})

	t.Run("finds events the custodian has confirmed that are missing from the database", func(t *testing.T) {
		events, custodian := wellCovered()

		result := verifyEventsAt(t, events[:6], custodian, tenOClock.Add(6*time.Minute))

		fingerprints := eventFindingsOf(result, verify.SeverityManipulation, verify.CheckFingerprints)
		require.Len(t, fingerprints, 1)
		assert.Contains(t, fingerprints[0].Message, "2 events the custodian has confirmed are missing from the database, from event 7")
	})

	t.Run("only notes differences to fingerprints from before the latest reset", func(t *testing.T) {
		events := chainOfEvents(4, tenOClock, 30*time.Second)
		resetAt := tenOClock.Add(time.Hour)
		custodian := custodianResult([]verify.ConfirmedFingerprint{
			{EventID: "1", EventHash: "hash-before-the-restore", Sequence: 1, ReceivedAt: tenOClock.Add(time.Minute)},
			{EventID: "3", EventHash: "hash-3", Sequence: 2, ReceivedAt: resetAt.Add(time.Minute), IsAfterLatestReset: true},
		})
		custodian.LatestResetAt = &resetAt

		result := verifyEventsAt(t, events, custodian, resetAt.Add(2*time.Minute))

		assert.Empty(t, eventFindingsOf(result, verify.SeverityManipulation, verify.CheckFingerprints))
		notices := eventFindingsOf(result, verify.SeverityNotice, verify.CheckFingerprints)
		require.Len(t, notices, 1)
		assert.Contains(t, notices[0].Message, "before the baseline was reset")
		assert.Empty(t, eventFindingsOf(result, verify.SeverityGap, verify.CheckProtection), "the events before the reset are covered by the chain that started over")
	})

	t.Run("finds events a fingerprint covered later than allowed, and joins the ones of the same receipt", func(t *testing.T) {
		events := chainOfEvents(4, tenOClock, 30*time.Second)
		custodian := custodianResult(confirmed(events, map[int]time.Time{
			1: events[1].Time.Add(time.Minute),
			3: events[3].Time.Add(10 * time.Minute),
		}))

		result := verifyEventsAt(t, events, custodian, events[3].Time.Add(11*time.Minute))

		protection := eventFindingsOf(result, verify.SeverityGap, verify.CheckProtection)
		require.Len(t, protection, 1)
		assert.Contains(t, protection[0].Message, "Events 2 to 3 stayed without protection for up to 10m30s, until receipt 2 covered them")
		assert.Equal(t, events[2].Time, *protection[0].From)
	})

	t.Run("finds the events from before the first fingerprint", func(t *testing.T) {
		events := chainOfEvents(5, tenOClock.Add(-time.Hour), time.Minute)
		custodian := custodianResult(confirmed(events, map[int]time.Time{4: tenOClock}))

		result := verifyEventsAt(t, events, custodian, tenOClock.Add(time.Minute))

		protection := eventFindingsOf(result, verify.SeverityGap, verify.CheckProtection)
		require.Len(t, protection, 1)
		assert.Contains(t, protection[0].Message, "Events 0 to 4 stayed without protection for up to 1h0m0s")
	})

	t.Run("finds events no fingerprint covers yet, once they are older than allowed", func(t *testing.T) {
		events, custodian := wellCovered()
		events = append(events, chainOfEvents(12, tenOClock, 30*time.Second)[10:]...)
		events[10].PredecessorHash = events[9].Hash

		recent := verifyEventsAt(t, events, custodian, events[10].Time.Add(time.Minute))
		assert.Empty(t, eventFindingsOf(recent, verify.SeverityGap, verify.CheckProtection))

		old := verifyEventsAt(t, events, custodian, events[10].Time.Add(10*time.Minute))
		protection := eventFindingsOf(old, verify.SeverityGap, verify.CheckProtection)
		require.Len(t, protection, 1)
		assert.Contains(t, protection[0].Message, "Events 10 to 11 are not protected by any fingerprint yet, the oldest of them for 10m0s")
	})

	t.Run("fails if the events can not be read", func(t *testing.T) {
		failing := func(yield func(database.Event, error) bool) {
			yield(database.Event{}, errors.New("disk full"))
		}

		_, err := verify.VerifyEvents(failing, custodianResult(nil), tenOClock)

		assert.ErrorContains(t, err, "disk full")
	})

	t.Run("fails on an event without a valid ID", func(t *testing.T) {
		events := chainOfEvents(1, tenOClock, time.Second)
		events[0].ID = "first"

		_, err := verify.VerifyEvents(sequenceOf(events), custodianResult(nil), tenOClock)

		assert.Error(t, err)
	})
}
