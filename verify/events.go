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
// they were written: that every event still hashes to its hash, in the version
// that hash names, that they form one chain, that they match every fingerprint
// the custodian has confirmed since the latest reset of the baseline, and how
// long every event stayed without the protection of a fingerprint. The time is
// when the audit happens.
//
// It only fails if the events can not be read, since then nothing can be said
// about them.
func VerifyEvents(events iter.Seq2[database.Event, error], custodian CustodianResult, now time.Time) (EventsResult, error) {
	return verifyEvents(events, nil, custodian, now)
}

// uncoveredSpan is a span of events, by their IDs, that none of the backups
// of a chain holds. The event after it follows on the event that ends it,
// with the hash that the backup after it names, unless the span is open, as
// after an incomplete backup that no other backup reaches beyond, where it is
// not known which events there are.
type uncoveredSpan struct {
	firstID, lastID uint64
	lastHash        string
	isOpen          bool
}

func (s uncoveredSpan) contains(eventID uint64) bool {
	return eventID >= s.firstID && (s.isOpen || eventID <= s.lastID)
}

// verifyEvents checks events as VerifyEvents does, except that the events of
// the given spans were not read, since none of the backups holds them. They
// are neither missing, nor are the fingerprints of them, since whether they
// match can not be told. Only the fingerprint of the event that ends a span is
// compared with the hash the backup after it names, and the event after a span
// has to follow on that hash. The spans must be ordered by their IDs.
func verifyEvents(events iter.Seq2[database.Event, error], spans []uncoveredSpan, custodian CustodianResult, now time.Time) (EventsResult, error) {
	check := newEventsCheck(custodian, now, spans)

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

	// spans are the spans of events that none of the backups holds, and
	// nextSpan is the first of them that no event has been read after yet.
	spans    []uncoveredSpan
	nextSpan int

	// changed collects consecutive events whose content no longer hashes to
	// their hash, so that they end up in one finding, and unknownVersion the
	// ones whose hashes are of a version that is not known, together with
	// that version.
	changed            *eventRange
	unknownVersion     *eventRange
	unknownHashVersion string

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

func newEventsCheck(custodian CustodianResult, now time.Time, spans []uncoveredSpan) *eventsCheck {
	check := &eventsCheck{
		custodian:       custodian,
		now:             now,
		spans:           spans,
		confirmed:       map[string]ConfirmedFingerprint{},
		confirmedBefore: map[string]ConfirmedFingerprint{},
	}

	spanEndsCompared := map[uint64]bool{}
	for _, fingerprint := range custodian.Fingerprints {
		eventID, err := strconv.ParseUint(fingerprint.EventID, 10, 64)
		span, isInSpan := check.spanOf(eventID)
		isInSpan = isInSpan && err == nil

		if !fingerprint.IsAfterLatestReset {
			if _, isKnown := check.confirmedBefore[fingerprint.EventID]; !isKnown && !isInSpan {
				check.confirmedBefore[fingerprint.EventID] = fingerprint
			}
			continue
		}

		// The event of a fingerprint in a span is in none of the backups,
		// so it can not be compared, except for the event that ends a span,
		// whose hash the backup after it names. A heartbeat repeats a
		// fingerprint, which is compared only once.
		if isInSpan {
			if !span.isOpen && eventID == span.lastID && !spanEndsCompared[eventID] {
				spanEndsCompared[eventID] = true
				if fingerprint.EventHash != span.lastHash {
					check.found.add(SeverityManipulation, CheckFingerprints, "Event %s has the hash %s, as the backup that follows on it names it, but the custodian confirmed the hash %s on %s", fingerprint.EventID, span.lastHash, fingerprint.EventHash, formatTime(fingerprint.ReceivedAt))
				}
			}
		} else if _, isKnown := check.confirmed[fingerprint.EventID]; !isKnown {
			check.confirmed[fingerprint.EventID] = fingerprint
		}

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

	// The events before and after a span that none of the backups holds do
	// not follow each other, so what they share ends at the span.
	span, isAfterSpan := c.spanBefore(eventID)
	if isAfterSpan {
		c.flushChanged()
		c.flushUnknownVersion()
		c.flushLate()
	}

	c.checkHash(event)
	c.checkChain(event, eventID, span, isAfterSpan)
	c.checkFingerprint(event)
	c.checkProtection(event, eventID)

	c.previous, c.previousID, c.hasPrevious = event, eventID, true

	return nil
}

func (c *eventsCheck) checkHash(event database.Event) {
	if event.HashVersionIsUnknown {
		c.flushChanged()
		if c.unknownVersion != nil && c.unknownHashVersion != event.HashVersion {
			c.flushUnknownVersion()
		}
		if c.unknownVersion == nil {
			c.unknownVersion = &eventRange{firstID: event.ID, firstAt: event.Time}
			c.unknownHashVersion = event.HashVersion
		}
		c.unknownVersion.extend(event)
		return
	}
	c.flushUnknownVersion()

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

// flushUnknownVersion reports events whose hashes are of a version that is
// not known, which only a newer EventSourcingDB writes. Whether they have been
// changed can not be told, so they are not reported as changed, which would be
// a false alarm, but not passed either: they stay without the protection of a
// hash that can be checked, until a newer version of this tool checks them.
func (c *eventsCheck) flushUnknownVersion() {
	if c.unknownVersion == nil {
		return
	}

	if c.unknownVersion.isSingle() {
		c.found.addPeriod(SeverityGap, CheckEventHashes, c.unknownVersion.firstAt, c.unknownVersion.lastAt, "Event %s has a hash of version %q, which this version of the tool does not support, so whether it has been changed can not be told", c.unknownVersion.firstID, c.unknownHashVersion)
	} else {
		c.found.addPeriod(SeverityGap, CheckEventHashes, c.unknownVersion.firstAt, c.unknownVersion.lastAt, "Events %s to %s have hashes of version %q, which this version of the tool does not support, so whether they have been changed can not be told", c.unknownVersion.firstID, c.unknownVersion.lastID, c.unknownHashVersion)
	}
	c.unknownVersion = nil
	c.unknownHashVersion = ""
}

// spanOf returns the span that holds the event with the given ID, if there is
// one.
func (c *eventsCheck) spanOf(eventID uint64) (uncoveredSpan, bool) {
	for _, span := range c.spans {
		if span.contains(eventID) {
			return span, true
		}
	}

	return uncoveredSpan{}, false
}

// spanBefore returns the span that lies between the event before the one with
// the given ID and that one, if there is one. Of several spans that lie next
// to each other, it returns the last one, which the event follows on.
func (c *eventsCheck) spanBefore(eventID uint64) (uncoveredSpan, bool) {
	var before uncoveredSpan
	isBefore := false
	for c.nextSpan < len(c.spans) && !c.spans[c.nextSpan].isOpen && c.spans[c.nextSpan].lastID < eventID {
		span := c.spans[c.nextSpan]
		c.nextSpan++
		if !c.hasPrevious || c.previousID < span.firstID {
			before, isBefore = span, true
		}
	}

	return before, isBefore
}

// checkChain checks that an event follows on the one before it. After a span
// that none of the backups holds, the event follows on the event that ends
// the span, with the hash that the backup after it names, since the events of
// the span were not read, and the link across the span is part of the gap
// that the span is. Whether the backup after the span lacks events right
// after the one it follows on, it tells itself.
func (c *eventsCheck) checkChain(event database.Event, eventID uint64, span uncoveredSpan, isAfterSpan bool) {
	if isAfterSpan {
		if event.PredecessorHash != span.lastHash {
			c.found.add(SeverityManipulation, CheckEventChain, "Event %s does not follow event %d, which its backup follows on, since it names another predecessor hash", event.ID, span.lastID)
		}
		return
	}

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
	c.flushUnknownVersion()
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
