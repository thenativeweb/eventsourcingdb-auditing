package verify

import (
	"cmp"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"iter"
	"maps"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/thenativeweb/eventsourcingdb-auditing/database"
)

// BackupSource is a backup of the database of a customer, of either format,
// as one of a chain of backups: a full backup, and incremental backups that
// follow on it, or several full ones.
type BackupSource struct {
	// Name names the backup in findings, such as its path.
	Name string

	// Open opens the backup, to read it from its start. VerifyBackups opens
	// every backup twice: once to learn where it starts and ends, and once
	// to check its events together with the ones of the other backups.
	Open func() (io.ReadCloser, error)
}

// CheckedBackup names a backup that VerifyBackups has checked, and its
// SHA-256, so that it is clear which one was checked.
type CheckedBackup struct {
	Name   string
	SHA256 string
}

// BackupsResult is what checking the events of a chain of backups has found.
type BackupsResult struct {
	EventsResult

	// Backups are the backups that were checked, in the order of the chain.
	Backups []CheckedBackup
}

// VerifyBackups checks the events of a chain of backups, as if they came from
// a single one. It orders the backups by the events they follow on, whatever
// order they are given in: full backups first, then the incremental ones.
// Every backup has to hold every event from the one after the event it
// follows on, or from the first one, up to the one it ended at, an
// incremental backup has to follow on an event that the backups before it
// hold with the same hash, and an event that several backups hold has to be
// the same in all of them, or else it is a manipulation. A span of events
// that none of the backups holds is a gap, as is a backup that is incomplete.
// Then it checks the events of all of them, each one once, as VerifyEvents
// does, except that the events none of the backups holds do not count as
// missing.
//
// It only fails if a backup can not be read, or names a version of its format
// that is not known, since then nothing reliable can be said about the chain.
func VerifyBackups(backups []BackupSource, custodian CustodianResult, now time.Time) (BackupsResult, error) {
	if len(backups) == 0 {
		return BackupsResult{}, errors.New("no backup was given")
	}

	parts := make([]*backupPart, 0, len(backups))
	for i, source := range backups {
		part, err := scanBackup(i, source)
		if err != nil {
			return BackupsResult{}, err
		}
		parts = append(parts, part)
	}

	orderParts(parts)
	plan := planChain(parts)

	merged := &merge{parts: parts, followingOn: plan.followingOn}
	eventsResult, err := verifyEvents(merged.events(), plan.spans, custodian, now)
	if err != nil {
		return BackupsResult{}, err
	}

	// The report names the SHA-256 of what was checked, so a backup must
	// not have changed between the two reads.
	result := BackupsResult{EventsResult: eventsResult}
	for _, part := range parts {
		if part.checkedSHA256 != part.sha256 {
			return BackupsResult{}, fmt.Errorf("the backup %s changed while it was read, so it was not checked", part.source.Name)
		}
		result.Backups = append(result.Backups, CheckedBackup{Name: part.source.Name, SHA256: part.sha256})
	}

	result.Findings = slices.Concat(plan.found, merged.found, eventsResult.Findings)

	return result, nil
}

// backupPart is a backup of a chain, as reading it the first time has found
// it.
type backupPart struct {
	index  int
	source BackupSource
	backup database.Backup
	sha256 string

	// checkedSHA256 is the SHA-256 of the backup as it was read the second
	// time, when its events were checked.
	checkedSHA256 string

	// followsOnID is the ID of the event an incremental backup follows on,
	// and endedAtID the one of the event the backup ended at, if it ended
	// at one.
	isIncremental bool
	followsOnID   uint64
	hasEndedAt    bool
	endedAtID     uint64

	// lacking are the spans of events, by their IDs, that the backup lacks
	// between the event it follows on, or its start, and the one it ended
	// at.
	lacking []idSpan
}

// idSpan is a span of events by their IDs, from first to last, including
// both.
type idSpan struct {
	firstID, lastID uint64
}

// openedBackup is a backup that is being read, with its SHA-256, which
// covers everything read from it.
type openedBackup struct {
	source BackupSource
	file   io.ReadCloser
	hasher hash.Hash
	reader *database.BackupReader
}

func openBackup(source BackupSource) (*openedBackup, error) {
	file, err := source.Open()
	if err != nil {
		return nil, fmt.Errorf("failed to open the backup %s: %w", source.Name, err)
	}

	hasher := sha256.New()

	return &openedBackup{
		source: source,
		file:   file,
		hasher: hasher,
		reader: database.NewBackupReader(io.TeeReader(file, hasher)),
	}, nil
}

// digest returns the SHA-256 of the backup. Reading the events stops at the
// end of the last line, so whatever follows it counts for the hash as well.
func (o *openedBackup) digest() (string, error) {
	_, err := io.Copy(o.hasher, o.file)
	if err != nil {
		return "", fmt.Errorf("failed to read the backup %s: %w", o.source.Name, err)
	}

	return hex.EncodeToString(o.hasher.Sum(nil)), nil
}

// scanBackup reads a backup for the first time, to learn where it starts and
// where it ends, and checks that the IDs of its events are numbers, since a
// backup is placed in the chain by them. It notes the events the backup lacks
// between its start and its end, which another backup that holds them does
// not make up for, since they have been removed from this one.
func scanBackup(index int, source BackupSource) (*backupPart, error) {
	opened, err := openBackup(source)
	if err != nil {
		return nil, err
	}
	defer opened.file.Close()

	part := &backupPart{index: index, source: source}

	hasStarted, nextID := false, uint64(0)
	for event, err := range opened.reader.Events() {
		if err != nil {
			return nil, fmt.Errorf("failed to read the backup %s: %w", source.Name, err)
		}

		eventID, err := strconv.ParseUint(event.ID, 10, 64)
		if err != nil {
			return nil, fmt.Errorf("failed to read the backup %s: event %q has no valid ID", source.Name, event.ID)
		}

		// The item that names the event an incremental backup follows on
		// comes before its first event.
		if !hasStarted {
			hasStarted = true
			err = part.readFollowsOn(opened.reader.Backup())
			if err != nil {
				return nil, err
			}
			if part.isIncremental {
				nextID = part.followsOnID + 1
			}
		}

		if eventID > nextID {
			part.lacking = append(part.lacking, idSpan{firstID: nextID, lastID: eventID - 1})
		}
		nextID = max(nextID, eventID+1)
	}

	digest, err := opened.digest()
	if err != nil {
		return nil, err
	}

	part.backup, part.sha256 = opened.reader.Backup(), digest
	err = part.readFollowsOn(part.backup)
	if err != nil {
		return nil, err
	}

	if endedAt := part.backup.EndedAt(); endedAt != nil {
		part.hasEndedAt = true
		part.endedAtID, _ = strconv.ParseUint(endedAt.ID, 10, 64)
	}

	return part, nil
}

// readFollowsOn takes the event that an incremental backup follows on from
// what the backup tells about itself.
func (p *backupPart) readFollowsOn(backup database.Backup) error {
	followsOn := backup.FollowsOn
	if followsOn == nil {
		return nil
	}

	followsOnID, err := strconv.ParseUint(followsOn.ID, 10, 64)
	if err != nil {
		return fmt.Errorf("failed to read the backup %s: it follows on event %q, which is no event ID", p.source.Name, followsOn.ID)
	}
	p.isIncremental, p.followsOnID = true, followsOnID

	return nil
}

// orderParts orders the backups of a chain: full backups first, then the
// incremental ones by the event they follow on, and among those that start at
// the same event, the ones that end earlier first, and else by their names
// and their contents, so that the order does not depend on the one they were
// given in.
func orderParts(parts []*backupPart) {
	slices.SortStableFunc(parts, func(left, right *backupPart) int {
		if left.isIncremental != right.isIncremental {
			if left.isIncremental {
				return 1
			}
			return -1
		}
		if order := cmp.Compare(left.followsOnID, right.followsOnID); order != 0 {
			return order
		}
		if left.hasEndedAt != right.hasEndedAt {
			if left.hasEndedAt {
				return 1
			}
			return -1
		}
		if order := cmp.Compare(left.endedAtID, right.endedAtID); order != 0 {
			return order
		}
		if order := cmp.Compare(left.source.Name, right.source.Name); order != 0 {
			return order
		}
		if order := cmp.Compare(left.sha256, right.sha256); order != 0 {
			return order
		}

		return cmp.Compare(left.index, right.index)
	})
}

// chainPlan is what the order of the backups tells about the chain, before a
// single event is checked.
type chainPlan struct {
	found findings

	// spans are the spans of events that none of the backups holds, in the
	// order of their IDs.
	spans []uncoveredSpan

	// followingOn holds the incremental backups by the ID of the event they
	// follow on.
	followingOn map[uint64][]*backupPart
}

// planChain walks along the ordered backups, and finds where the events none
// of them holds lie, and which backups are incomplete. A span of events none
// of them holds lies before an incremental backup that follows on an event
// after the last one the backups before it reach, or on any event, if they
// reach none. An incomplete backup only says that events after the last one
// it holds may be missing from it, so if no complete backup reaches as far,
// it is not known which events follow, which the open span at the end of the
// chain stands for.
func planChain(parts []*backupPart) chainPlan {
	plan := chainPlan{followingOn: map[uint64][]*backupPart{}}

	isReaching, reach := false, uint64(0)
	for _, part := range parts {
		if part.isIncremental {
			plan.followingOn[part.followsOnID] = append(plan.followingOn[part.followsOnID], part)

			if !isReaching || part.followsOnID > reach {
				firstID := uint64(0)
				if isReaching {
					firstID = reach + 1
				}
				plan.spans = append(plan.spans, uncoveredSpan{firstID: firstID, lastID: part.followsOnID, lastHash: part.backup.FollowsOn.Hash})
				plan.found.addUncovered(firstID, part.followsOnID)
			}
		}

		if part.hasEndedAt && (!isReaching || part.endedAtID > reach) {
			isReaching, reach = true, part.endedAtID
		}

		for _, lacking := range part.lacking {
			plan.found.addLacking(part, lacking)
		}
		if !part.backup.IsComplete {
			plan.found.addIncomplete(part)
		}
		plan.found.checkNamedEnd(part)
	}

	isEndKnown := false
	for _, part := range parts {
		reachesEnd := part.hasEndedAt == isReaching && part.endedAtID == reach
		if reachesEnd && part.backup.IsComplete {
			isEndKnown = true
		}
	}
	if !isEndKnown {
		firstID := uint64(0)
		if isReaching {
			firstID = reach + 1
		}
		plan.spans = append(plan.spans, uncoveredSpan{firstID: firstID, isOpen: true})
	}

	return plan
}

func (f *findings) addUncovered(firstID, lastID uint64) {
	if firstID == lastID {
		f.add(SeverityGap, CheckBackups, "Event %d is in none of the backups, so it could not be checked", firstID)
		return
	}

	f.add(SeverityGap, CheckBackups, "Events %d to %d are in none of the backups, so they could not be checked", firstID, lastID)
}

func (f *findings) addLacking(part *backupPart, lacking idSpan) {
	if lacking.firstID == lacking.lastID {
		f.add(SeverityManipulation, CheckBackups, "Backup %s lacks event %d, which lies between its start and the event it ended at, so the event has been removed from it", part.source.Name, lacking.firstID)
		return
	}

	f.add(SeverityManipulation, CheckBackups, "Backup %s lacks events %d to %d, which lie between its start and the event it ended at, so the events have been removed from it", part.source.Name, lacking.firstID, lacking.lastID)
}

func (f *findings) addIncomplete(part *backupPart) {
	reason := "it was cut short before its end item"
	if part.backup.Failure != "" {
		reason = fmt.Sprintf("the database could not back up everything (%s)", part.backup.Failure)
	}

	if endedAt := part.backup.EndedAt(); endedAt != nil {
		f.add(SeverityGap, CheckBackups, "Backup %s is incomplete, since %s, so events after event %s may be missing from it", part.source.Name, reason, endedAt.ID)
		return
	}

	f.add(SeverityGap, CheckBackups, "Backup %s is incomplete, since %s, so events may be missing from it", part.source.Name, reason)
}

// checkNamedEnd compares the event a backup names as the one it ended at with
// the one it ended at, which are the same in every backup EventSourcingDB
// writes, so a difference means that the backup has been changed.
func (f *findings) checkNamedEnd(part *backupPart) {
	named := part.backup.NamedEnd
	if named == nil {
		return
	}

	endedAt := part.backup.EndedAt()
	if endedAt == nil {
		f.add(SeverityManipulation, CheckBackups, "Backup %s names event %s with the hash %s as the one it ended at, but it holds no event, and follows on none", part.source.Name, named.ID, named.Hash)
		return
	}

	namedID, err := strconv.ParseUint(named.ID, 10, 64)
	if err != nil || !part.hasEndedAt || namedID != part.endedAtID || named.Hash != endedAt.Hash {
		f.add(SeverityManipulation, CheckBackups, "Backup %s names event %s with the hash %s as the one it ended at, but it ended at event %s with the hash %s", part.source.Name, named.ID, named.Hash, endedAt.ID, endedAt.Hash)
	}
}

// merge reads the events of every backup of a chain at once, and hands every
// event on once, in the order of their IDs, as the first backup in the order
// of the chain that holds it holds it. Before, it compares the event with the
// same event in every other backup that holds it, and with the hash that
// every backup that follows on it names.
type merge struct {
	parts       []*backupPart
	followingOn map[uint64][]*backupPart
	found       findings
}

// mergeHead is where the merge stands in a backup: at its next event, which
// is not handed on yet.
type mergeHead struct {
	part   *backupPart
	opened *openedBackup
	next   func() (database.BackedUpEvent, error, bool)
	stop   func()

	event  database.BackedUpEvent
	id     uint64
	isDone bool
}

func (h *mergeHead) advance() error {
	event, err, isRead := h.next()
	if !isRead {
		h.isDone = true
		return nil
	}
	if err != nil {
		return fmt.Errorf("failed to read the backup %s: %w", h.part.source.Name, err)
	}

	id, err := strconv.ParseUint(event.ID, 10, 64)
	if err != nil {
		return fmt.Errorf("failed to read the backup %s: event %q has no valid ID", h.part.source.Name, event.ID)
	}
	h.event, h.id = event, id

	return nil
}

func (m *merge) events() iter.Seq2[database.Event, error] {
	return func(yield func(database.Event, error) bool) {
		heads := make([]*mergeHead, 0, len(m.parts))
		defer func() {
			for _, head := range heads {
				head.stop()
				head.opened.file.Close()
			}
		}()

		for _, part := range m.parts {
			opened, err := openBackup(part.source)
			if err != nil {
				yield(database.Event{}, err)
				return
			}

			next, stop := iter.Pull2(opened.reader.Events())
			head := &mergeHead{part: part, opened: opened, next: next, stop: stop}
			heads = append(heads, head)

			err = head.advance()
			if err != nil {
				yield(database.Event{}, err)
				return
			}
		}

		for {
			var first *mergeHead
			for _, head := range heads {
				if !head.isDone && (first == nil || head.id < first.id) {
					first = head
				}
			}
			if first == nil {
				break
			}

			for _, head := range heads {
				if head == first || head.isDone || head.id != first.id {
					continue
				}

				differences := first.event.DifferencesFrom(head.event)
				if len(differences) > 0 {
					m.found.add(SeverityManipulation, CheckBackups, "Event %s is not the same in %s and in %s, which differ in %s", first.event.ID, first.part.source.Name, head.part.source.Name, strings.Join(differences, ", "))
				}
			}
			m.compareFollowingOn(first)

			if !yield(first.event.Event, nil) {
				return
			}

			id := first.id
			for _, head := range heads {
				if head.isDone || head.id != id {
					continue
				}

				err := head.advance()
				if err != nil {
					yield(database.Event{}, err)
					return
				}
			}
		}

		m.compareFollowingOnEventsHeldByNone()

		for _, head := range heads {
			digest, err := head.opened.digest()
			if err != nil {
				yield(database.Event{}, err)
				return
			}
			head.part.checkedSHA256 = digest
		}
	}
}

// compareFollowingOn compares the hash that every backup following on an
// event names with the hash that the backup that holds the event holds it
// with. EventSourcingDB only follows on an event that it still holds with that
// hash, so a backup that names another one does not follow on the backup
// before it.
func (m *merge) compareFollowingOn(held *mergeHead) {
	for _, part := range m.followingOn[held.id] {
		if part.backup.FollowsOn.Hash != held.event.Hash {
			m.found.add(SeverityManipulation, CheckBackups, "Backup %s follows on event %s with the hash %s, but %s holds that event with the hash %s", part.source.Name, held.event.ID, part.backup.FollowsOn.Hash, held.part.source.Name, held.event.Hash)
		}
	}
	delete(m.followingOn, held.id)
}

// compareFollowingOnEventsHeldByNone compares the hashes that backups name for
// an event that none of the backups holds, which they all follow on, and
// which must be the same.
func (m *merge) compareFollowingOnEventsHeldByNone() {
	for _, id := range slices.Sorted(maps.Keys(m.followingOn)) {
		following := m.followingOn[id]
		for _, part := range following[1:] {
			if part.backup.FollowsOn.Hash != following[0].backup.FollowsOn.Hash {
				m.found.add(SeverityManipulation, CheckBackups, "Backups %s and %s follow on event %d with different hashes, %s and %s", following[0].source.Name, part.source.Name, id, following[0].backup.FollowsOn.Hash, part.backup.FollowsOn.Hash)
			}
		}
	}
}
