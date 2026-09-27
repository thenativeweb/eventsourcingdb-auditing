package verify

import (
	"fmt"
	"iter"
	"strconv"
	"time"

	"github.com/thenativeweb/eventsourcingdb-auditing/database"
)

// protectionTolerance is how much longer than the minimum interval it may take
// until a fingerprint covers an event, since sending takes a moment, a failed
// request is tried again, and the clocks of the customer and of the custodian
// differ a little.
const protectionTolerance = time.Minute

// EventsResult is what checking the events of an instance has found.
type EventsResult struct {
	EventCount   int
	FirstEventAt time.Time
	LastEventAt  time.Time
	Findings     []Finding
}

// VerifyEvents checks the events of the database of a customer, in the order
// they were written: that every event still hashes to its hash, that they form
// one chain, that they match every fingerprint the custodian has confirmed
// since the latest reset of the baseline, and how long every event stayed
// without the protection of a fingerprint. The time is when the audit happens.
//
// It only fails if the events can not be read, since then nothing can be said
// about them.
func VerifyEvents(events iter.Seq2[database.Event, error], custodian CustodianResult, now time.Time) (EventsResult, error) {
	check := newEventsCheck(custodian, now)

	for event, err := range events {
		if err != nil {
			return EventsResult{}, err
		}

		err = check.event(event)
		if err != nil {
			return EventsResult{}, err
		}
	}

	check.finish()

	return EventsResult{
		EventCount:   check.count,
		FirstEventAt: check.firstAt,
		LastEventAt:  check.lastAt,
		Findings:     check.found,
	}, nil
}

// eventsCheck holds what checking the events needs to remember from one event
// to the next.
type eventsCheck struct {
	custodian CustodianResult
	now       time.Time
	found     findings

	count   int
	firstAt time.Time
	lastAt  time.Time

	hasPrevious bool
	previousID  uint64
	previous    database.Event

	// changed collects consecutive events whose content no longer hashes to
	// their hash, so that they end up in one finding.
	changed *eventRange

	// confirmed holds the fingerprints since the latest reset that no event
	// has matched yet, and confirmedBefore the ones before it.
	confirmed       map[string]ConfirmedFingerprint
	confirmedBefore map[string]ConfirmedFingerprint

	// covering are the fingerprints since the latest reset, in the order they
	// were confirmed, and next is the first of them that may cover the next
	// event.
	covering []coveringFingerprint
	next     int

	// late collects the events a fingerprint covered later than allowed, and
	// unprotected the ones no fingerprint covers yet.
	late        *eventRange
	lateCover   *coveringFingerprint
	unprotected *eventRange
}

type coveringFingerprint struct {
	ConfirmedFingerprint
	eventID uint64
}

// eventRange is a range of consecutive events that share a finding.
type eventRange struct {
	firstID, lastID string
	firstAt, lastAt time.Time
	longest         time.Duration
	allowed         time.Duration
}

func (r *eventRange) extend(event database.Event) {
	r.lastID = event.ID
	r.lastAt = event.Time
}

func (r *eventRange) isSingle() bool {
	return r.firstID == r.lastID
}

func newEventsCheck(custodian CustodianResult, now time.Time) *eventsCheck {
	check := &eventsCheck{
		custodian:       custodian,
		now:             now,
		confirmed:       map[string]ConfirmedFingerprint{},
		confirmedBefore: map[string]ConfirmedFingerprint{},
	}

	for _, fingerprint := range custodian.Fingerprints {
		if !fingerprint.IsAfterLatestReset {
			if _, isKnown := check.confirmedBefore[fingerprint.EventID]; !isKnown {
				check.confirmedBefore[fingerprint.EventID] = fingerprint
			}
			continue
		}

		if _, isKnown := check.confirmed[fingerprint.EventID]; !isKnown {
			check.confirmed[fingerprint.EventID] = fingerprint
		}

		eventID, err := strconv.ParseUint(fingerprint.EventID, 10, 64)
		if err != nil {
			check.found.add(SeverityManipulation, CheckFingerprints, "Receipt %d confirms event %q, which is no event ID", fingerprint.Sequence, fingerprint.EventID)
			continue
		}
		check.covering = append(check.covering, coveringFingerprint{ConfirmedFingerprint: fingerprint, eventID: eventID})
	}

	return check
}

func (c *eventsCheck) event(event database.Event) error {
	eventID, err := strconv.ParseUint(event.ID, 10, 64)
	if err != nil {
		return fmt.Errorf("event %q has no valid ID", event.ID)
	}

	c.count++
	if c.count == 1 {
		c.firstAt = event.Time
	}
	c.lastAt = event.Time

	c.checkHash(event)
	c.checkChain(event, eventID)
	c.checkFingerprint(event)
	c.checkProtection(event, eventID)

	c.previous, c.previousID, c.hasPrevious = event, eventID, true

	return nil
}

func (c *eventsCheck) checkHash(event database.Event) {
	if event.HashMatches {
		c.flushChanged()
		return
	}

	if c.changed == nil {
		c.changed = &eventRange{firstID: event.ID, firstAt: event.Time}
	}
	c.changed.extend(event)
}

func (c *eventsCheck) flushChanged() {
	if c.changed == nil {
		return
	}

	if c.changed.isSingle() {
		c.found.addPeriod(SeverityManipulation, CheckEventHashes, c.changed.firstAt, c.changed.lastAt, "Event %s has been changed, since its content no longer hashes to its hash", c.changed.firstID)
	} else {
		c.found.addPeriod(SeverityManipulation, CheckEventHashes, c.changed.firstAt, c.changed.lastAt, "Events %s to %s have been changed, since their content no longer hashes to their hashes", c.changed.firstID, c.changed.lastID)
	}
	c.changed = nil
}

func (c *eventsCheck) checkChain(event database.Event, eventID uint64) {
	if !c.hasPrevious {
		if eventID != 0 {
			c.found.add(SeverityManipulation, CheckEventChain, "The database starts with event %s, so the events before it are missing", event.ID)
		}
		if event.PredecessorHash != database.GenesisHash {
			c.found.add(SeverityManipulation, CheckEventChain, "Event %s does not start the chain of events", event.ID)
		}
		return
	}

	if eventID != c.previousID+1 {
		c.found.add(SeverityManipulation, CheckEventChain, "Event %s follows event %s, so the events between them are missing", event.ID, c.previous.ID)
	}
	if event.PredecessorHash != c.previous.Hash {
		c.found.add(SeverityManipulation, CheckEventChain, "Event %s does not follow event %s, since it names another predecessor hash", event.ID, c.previous.ID)
	}
}

func (c *eventsCheck) checkFingerprint(event database.Event) {
	if confirmed, isConfirmed := c.confirmed[event.ID]; isConfirmed {
		if confirmed.EventHash != event.Hash {
			c.found.add(SeverityManipulation, CheckFingerprints, "Event %s has the hash %s, but the custodian confirmed the hash %s on %s", event.ID, event.Hash, confirmed.EventHash, formatTime(confirmed.ReceivedAt))
		}
		delete(c.confirmed, event.ID)
	}

	if confirmed, isConfirmed := c.confirmedBefore[event.ID]; isConfirmed {
		if confirmed.EventHash != event.Hash {
			resetAt := ""
			if c.custodian.LatestResetAt != nil {
				resetAt = formatTime(*c.custodian.LatestResetAt)
			}
			c.found.add(SeverityNotice, CheckFingerprints, "Event %s has the hash %s, but the custodian confirmed the hash %s on %s, before the baseline was reset on %s", event.ID, event.Hash, confirmed.EventHash, formatTime(confirmed.ReceivedAt), resetAt)
		}
		delete(c.confirmedBefore, event.ID)
	}
}

// checkProtection finds how long an event stayed without the protection of a
// fingerprint: from when it was written until the first fingerprint that
// covers it, that is, of it or of an event after it. Events written before the
// latest reset are left out, since the chain of events started over then.
func (c *eventsCheck) checkProtection(event database.Event, eventID uint64) {
	if c.custodian.LatestResetAt != nil && !event.Time.After(*c.custodian.LatestResetAt) {
		return
	}

	for c.next < len(c.covering) && c.covering[c.next].eventID < eventID {
		c.next++
	}

	allowed := minimumIntervalAt(c.custodian.Intervals, event.Time) + protectionTolerance

	if c.next == len(c.covering) {
		c.flushLate()
		if c.unprotected == nil {
			c.unprotected = &eventRange{firstID: event.ID, firstAt: event.Time, allowed: allowed}
		}
		c.unprotected.extend(event)
		return
	}

	cover := &c.covering[c.next]
	unprotectedFor := cover.ReceivedAt.Sub(event.Time)
	if unprotectedFor <= allowed {
		c.flushLate()
		return
	}

	if c.late != nil && c.lateCover.Sequence != cover.Sequence {
		c.flushLate()
	}
	if c.late == nil {
		c.late = &eventRange{firstID: event.ID, firstAt: event.Time, allowed: allowed}
		c.lateCover = cover
	}
	c.late.extend(event)
	c.late.longest = max(c.late.longest, unprotectedFor)
}

func (c *eventsCheck) flushLate() {
	if c.late == nil {
		return
	}

	longest, coveredAt := c.late.longest.Round(time.Second), formatTime(c.lateCover.ReceivedAt)
	if c.late.isSingle() {
		c.found.addPeriod(SeverityGap, CheckProtection, c.late.firstAt, c.lateCover.ReceivedAt, "Event %s stayed without protection for %s, until receipt %d covered it on %s, although at most %s were allowed", c.late.firstID, longest, c.lateCover.Sequence, coveredAt, c.late.allowed)
	} else {
		c.found.addPeriod(SeverityGap, CheckProtection, c.late.firstAt, c.lateCover.ReceivedAt, "Events %s to %s stayed without protection for up to %s, until receipt %d covered them on %s, although at most %s were allowed", c.late.firstID, c.late.lastID, longest, c.lateCover.Sequence, coveredAt, c.late.allowed)
	}
	c.late = nil
	c.lateCover = nil
}

func (c *eventsCheck) finish() {
	c.flushChanged()
	c.flushLate()

	if c.unprotected != nil {
		unprotectedFor := c.now.Sub(c.unprotected.firstAt)
		if unprotectedFor > c.unprotected.allowed {
			if c.unprotected.isSingle() {
				c.found.addPeriod(SeverityGap, CheckProtection, c.unprotected.firstAt, c.now, "Event %s is not protected by any fingerprint yet, for %s now", c.unprotected.firstID, unprotectedFor.Round(time.Second))
			} else {
				c.found.addPeriod(SeverityGap, CheckProtection, c.unprotected.firstAt, c.now, "Events %s to %s are not protected by any fingerprint yet, the oldest of them for %s now", c.unprotected.firstID, c.unprotected.lastID, unprotectedFor.Round(time.Second))
			}
		}
	}

	if len(c.confirmed) > 0 {
		var lowest, highest ConfirmedFingerprint
		var lowestID, highestID uint64
		first := true
		for _, confirmed := range c.confirmed {
			eventID, err := strconv.ParseUint(confirmed.EventID, 10, 64)
			if err != nil {
				continue
			}
			if first || eventID < lowestID {
				lowest, lowestID = confirmed, eventID
			}
			if first || eventID > highestID {
				highest, highestID = confirmed, eventID
			}
			first = false
		}

		if !first {
			c.found.add(SeverityManipulation, CheckFingerprints, "%d events the custodian has confirmed are missing from the database, from event %s, confirmed on %s, to event %s, confirmed on %s", len(c.confirmed), lowest.EventID, formatTime(lowest.ReceivedAt), highest.EventID, formatTime(highest.ReceivedAt))
		}
	}
}
