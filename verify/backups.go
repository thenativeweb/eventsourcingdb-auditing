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

// BackupSource is a file that holds a backup of the database of a customer,
// of either format, or several backups in the format of create-backup one
// after another, as one or more of a chain of backups: a full backup, and
// incremental backups that follow on it, or several full ones.
type BackupSource struct {
	// Name names the file in findings, such as its path.
	Name string

	// Open opens the file, to read it from its start. VerifyBackups opens
	// every file at least twice: once to learn where its backups start and
	// end, and once for every backup it holds, to check its events together
	// with the ones of the other backups, for which it seeks to the bytes of
	// that backup, and reads only them.
	Open func() (io.ReadSeekCloser, error)
}

// CheckedBackup names a file that VerifyBackups has checked, and its
// SHA-256, so that it is clear which one was checked, together with the
// backups it holds, if it holds more than one.
type CheckedBackup struct {
	Name   string
	SHA256 string
	Parts  []CheckedPart
}

// CheckedPart is one of several backups that a file holds one after another,
// by its number within the file, from 1 on, with the event it follows on, or
// none for a full backup, and the event it ended at, or none for a full
// backup without events.
type CheckedPart struct {
	Number    int
	FollowsOn *database.EventReference
	EndedAt   *database.EventReference
}

// BackupsResult is what checking the events of a chain of backups has found.
type BackupsResult struct {
	EventsResult

	// Backups are the files that were checked, in the order of the chain, by
	// the first backup each of them holds.
	Backups []CheckedBackup
}

// VerifyBackups checks the events of a chain of backups, as if they came from
// a single one. Every backup of a file that holds several of them counts as
// one of its own, which findings name by the file and its number. It orders
// the backups by the events they follow on, whatever order they are given in:
// full backups first, then the incremental ones.
// Every backup has to hold every event from the one after the event it
// follows on, or from the first one, up to the one it ended at, an
// incremental backup has to follow on an event that the backups before it
// hold with the same hash, and an event that several backups hold has to be
// the same in all of them, or else it is a manipulation. A span of events
// that none of the backups holds is a gap, as is a backup that is incomplete,
// unless complete backups hold every event it may lack, which makes it a
// notice. Then it checks the events of all of them, each one once, as VerifyEvents
// does, except that the events none of the backups holds do not count as
// missing.
//
// It only fails if a backup can not be read, or names a version of its format
// that is not known, since then nothing reliable can be said about the chain.
func VerifyBackups(backups []BackupSource, custodian CustodianResult, now time.Time) (BackupsResult, error) {
	if len(backups) == 0 {
		return BackupsResult{}, errors.New("no backup was given")
	}

	var parts []*backupPart
	for i, source := range backups {
		partsOfFile, err := scanBackup(i, source)
		if err != nil {
			return BackupsResult{}, err
		}
		parts = append(parts, partsOfFile...)
	}

	orderParts(parts)
	plan := planChain(parts)

	merged := &merge{parts: parts, followingOn: plan.followingOn}
	eventsResult, err := verifyEvents(merged.events(), plan.spans, custodian, now)
	if err != nil {
		return BackupsResult{}, err
	}

	// The report names the SHA-256 of what was checked, so the bytes of a
	// backup must not have changed between the reads.
	result := BackupsResult{EventsResult: eventsResult}
	isNamed := map[int]bool{}
	for _, part := range parts {
		if part.checkedSHA256 != part.backup.SHA256 {
			return BackupsResult{}, fmt.Errorf("the backup %s changed while it was read, so it was not checked", part.source.Name)
		}
		if isNamed[part.fileIndex] {
			continue
		}
		isNamed[part.fileIndex] = true

		result.Backups = append(result.Backups, checkedBackupOf(part, parts))
	}

	result.Findings = slices.Concat(plan.found, merged.found, eventsResult.Findings)

	return result, nil
}

// checkedBackupOf names the file of a backup, together with all backups it
// holds, in the order of the file, if it holds more than one.
func checkedBackupOf(part *backupPart, parts []*backupPart) CheckedBackup {
	checked := CheckedBackup{Name: part.source.Name, SHA256: part.sha256}
	if part.partsInFile == 1 {
		return checked
	}

	for _, other := range parts {
		if other.fileIndex == part.fileIndex {
			checked.Parts = append(checked.Parts, CheckedPart{Number: other.number, FollowsOn: other.backup.FollowsOn, EndedAt: other.backup.EndedAt()})
		}
	}
	slices.SortFunc(checked.Parts, func(left, right CheckedPart) int {
		return cmp.Compare(left.Number, right.Number)
	})

	return checked
}

// backupPart is a backup of a chain, as reading its file the first time has
// found it: the number of the backup within its file, from 1 on, among the
// backups the file holds, and the SHA-256 of the whole file, while the
// backup names the bytes of the file that belong to it, and their SHA-256.
type backupPart struct {
	fileIndex   int
	source      BackupSource
	number      int
	partsInFile int
	backup      database.Backup
	sha256      string

	// checkedSHA256 is the SHA-256 of the bytes of the backup as they were
	// read again, when its events were checked.
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

// name names a backup in findings: by its file, and, if the file holds
// several backups, by its number within the file.
func (p *backupPart) name() string {
	if p.partsInFile == 1 {
		return p.source.Name
	}

	return fmt.Sprintf("%s, part %d", p.source.Name, p.number)
}

// openedBackup is a file, or the bytes of one of its backups, that is being
// read, with their SHA-256, which covers everything read from them.
type openedBackup struct {
	source BackupSource
	file   io.ReadCloser
	bytes  io.Reader
	hasher hash.Hash
	reader *database.BackupReader
}

// openBackup opens a file, to read it from its start to its end.
func openBackup(source BackupSource) (*openedBackup, error) {
	file, err := source.Open()
	if err != nil {
		return nil, fmt.Errorf("failed to open the backup %s: %w", source.Name, err)
	}

	return newOpenedBackup(source, file, file), nil
}

// openPart opens the file of a backup again, and reads only the bytes that
// belong to the backup, as the first read has found them, so that a file with
// several backups is read once for every one of them, and not to its end.
func openPart(part *backupPart) (*openedBackup, error) {
	file, err := part.source.Open()
	if err != nil {
		return nil, fmt.Errorf("failed to open the backup %s: %w", part.source.Name, err)
	}

	_, err = file.Seek(part.backup.Offset, io.SeekStart)
	if err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("failed to read the backup %s: %w", part.name(), err)
	}

	return newOpenedBackup(part.source, file, io.LimitReader(file, part.backup.Size)), nil
}

func newOpenedBackup(source BackupSource, file io.ReadCloser, bytes io.Reader) *openedBackup {
	hasher := sha256.New()

	return &openedBackup{
		source: source,
		file:   file,
		bytes:  bytes,
		hasher: hasher,
		reader: database.NewBackupReader(io.TeeReader(bytes, hasher)),
	}
}

// digest returns the SHA-256 of what is read. Reading the events stops at the
// end of the last line, so whatever follows it counts for the hash as well.
func (o *openedBackup) digest() (string, error) {
	_, err := io.Copy(o.hasher, o.bytes)
	if err != nil {
		return "", fmt.Errorf("failed to read the backup %s: %w", o.source.Name, err)
	}

	return hex.EncodeToString(o.hasher.Sum(nil)), nil
}

// scanBackup reads a file for the first time, to learn where its backups
// start and where they end, and checks that the IDs of their events are
// numbers, since a backup is placed in the chain by them. It notes the events
// a backup lacks between its start and its end, which another backup that
// holds them does not make up for, since they have been removed from this
// one.
func scanBackup(fileIndex int, source BackupSource) ([]*backupPart, error) {
	opened, err := openBackup(source)
	if err != nil {
		return nil, err
	}
	defer opened.file.Close()

	type progress struct {
		nextID  uint64
		lacking []idSpan
	}
	progressOf := map[int]*progress{}

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
		current, isKnown := progressOf[event.Part]
		if !isKnown {
			current = &progress{}
			progressOf[event.Part] = current

			followsOnID, isIncremental, err := followsOnIDOf(source, opened.reader.Backups()[event.Part])
			if err != nil {
				return nil, err
			}
			if isIncremental {
				current.nextID = followsOnID + 1
			}
		}

		if eventID > current.nextID {
			current.lacking = append(current.lacking, idSpan{firstID: current.nextID, lastID: eventID - 1})
		}
		current.nextID = max(current.nextID, eventID+1)
	}

	digest, err := opened.digest()
	if err != nil {
		return nil, err
	}

	backups := opened.reader.Backups()
	parts := make([]*backupPart, 0, len(backups))
	for i, backup := range backups {
		part := &backupPart{fileIndex: fileIndex, source: source, number: i + 1, partsInFile: len(backups), backup: backup, sha256: digest}

		part.followsOnID, part.isIncremental, err = followsOnIDOf(source, backup)
		if err != nil {
			return nil, err
		}
		if endedAt := backup.EndedAt(); endedAt != nil {
			part.hasEndedAt = true
			part.endedAtID, _ = strconv.ParseUint(endedAt.ID, 10, 64)
		}
		if current, isKnown := progressOf[i]; isKnown {
			part.lacking = current.lacking
		}

		parts = append(parts, part)
	}

	return parts, nil
}

// followsOnIDOf returns the ID of the event an incremental backup follows on,
// and whether it is an incremental one.
func followsOnIDOf(source BackupSource, backup database.Backup) (uint64, bool, error) {
	if backup.FollowsOn == nil {
		return 0, false, nil
	}

	followsOnID, err := strconv.ParseUint(backup.FollowsOn.ID, 10, 64)
	if err != nil {
		return 0, false, fmt.Errorf("failed to read the backup %s: it follows on event %q, which is no event ID", source.Name, backup.FollowsOn.ID)
	}

	return followsOnID, true, nil
}

// orderParts orders the backups of a chain: full backups first, then the
// incremental ones by the event they follow on, and among those that start at
// the same event, the ones that end earlier first, and else by the names of
// their files, their numbers within them, and their contents, so that the
// order does not depend on the one they were given in.
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
		if order := cmp.Compare(left.number, right.number); order != 0 {
			return order
		}
		if order := cmp.Compare(left.sha256, right.sha256); order != 0 {
			return order
		}

		return cmp.Compare(left.fileIndex, right.fileIndex)
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
		plan.found.checkNamedEnd(part)
	}

	isEndKnown := false
	for _, part := range parts {
		reachesEnd := part.hasEndedAt == isReaching && part.endedAtID == reach
		if reachesEnd && part.backup.IsComplete {
			isEndKnown = true
		}
	}

	for _, part := range parts {
		if part.backup.IsComplete {
			continue
		}

		isCovered := isEndKnown && (!isReaching || isHeldByCompleteBackups(parts, part, reach))
		plan.found.addIncomplete(part, isCovered)
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

// isHeldByCompleteBackups tells whether complete backups hold every event
// after the one an incomplete backup ended at, up to the furthest event any
// backup of the chain ends at, so that the events the incomplete backup may
// lack are all checked all the same. It goes by where the complete backups
// start and end, since an event a backup lacks in between is a finding of its
// own.
func isHeldByCompleteBackups(parts []*backupPart, incomplete *backupPart, reach uint64) bool {
	nextID := uint64(0)
	if incomplete.hasEndedAt {
		nextID = incomplete.endedAtID + 1
	}

	var held []idSpan
	for _, part := range parts {
		if !part.backup.IsComplete || part.backup.LastEvent == nil {
			continue
		}

		firstID := uint64(0)
		if part.isIncremental {
			firstID = part.followsOnID + 1
		}
		held = append(held, idSpan{firstID: firstID, lastID: part.endedAtID})
	}
	slices.SortFunc(held, func(left, right idSpan) int {
		return cmp.Compare(left.firstID, right.firstID)
	})

	for _, span := range held {
		if nextID > reach || span.firstID > nextID {
			break
		}
		nextID = max(nextID, span.lastID+1)
	}

	return nextID > reach
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
		f.add(SeverityManipulation, CheckBackups, "Backup %s lacks event %d, which lies between its start and the event it ended at, so the event has been removed from it", part.name(), lacking.firstID)
		return
	}

	f.add(SeverityManipulation, CheckBackups, "Backup %s lacks events %d to %d, which lie between its start and the event it ended at, so the events have been removed from it", part.name(), lacking.firstID, lacking.lastID)
}

// addIncomplete names a backup that is incomplete, as a gap, or as a notice,
// if complete backups hold every event it may lack, which leaves nothing
// unchecked.
func (f *findings) addIncomplete(part *backupPart, isCovered bool) {
	reason := "it was cut short before its end item"
	switch {
	case part.backup.Failure != "":
		reason = fmt.Sprintf("the database could not back up everything (%s)", part.backup.Failure)
	case part.backup.FormatVersion == database.BackupFormatVersion1:
		reason = "it was cut short in the middle of its last line"
	}

	endedAt := part.backup.EndedAt()
	switch {
	case isCovered && endedAt != nil:
		f.add(SeverityNotice, CheckBackups, "Backup %s is incomplete, since %s, but complete backups hold every event of the chain after event %s", part.name(), reason, endedAt.ID)
	case isCovered:
		f.add(SeverityNotice, CheckBackups, "Backup %s is incomplete, since %s, but complete backups hold every event of the chain", part.name(), reason)
	case endedAt != nil:
		f.add(SeverityGap, CheckBackups, "Backup %s is incomplete, since %s, so events after event %s may be missing from it", part.name(), reason, endedAt.ID)
	default:
		f.add(SeverityGap, CheckBackups, "Backup %s is incomplete, since %s, so events may be missing from it", part.name(), reason)
	}
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
		f.add(SeverityManipulation, CheckBackups, "Backup %s names event %s with the hash %s as the one it ended at, but it holds no event, and follows on none", part.name(), named.ID, named.Hash)
		return
	}

	namedID, err := strconv.ParseUint(named.ID, 10, 64)
	if err != nil || !part.hasEndedAt || namedID != part.endedAtID || named.Hash != endedAt.Hash {
		f.add(SeverityManipulation, CheckBackups, "Backup %s names event %s with the hash %s as the one it ended at, but it ended at event %s with the hash %s", part.name(), named.ID, named.Hash, endedAt.ID, endedAt.Hash)
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
			opened, err := openPart(part)
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
					m.found.add(SeverityManipulation, CheckBackups, "Event %s is not the same in %s and in %s, which differ in %s", first.event.ID, first.part.name(), head.part.name(), strings.Join(differences, ", "))
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
			m.found.add(SeverityManipulation, CheckBackups, "Backup %s follows on event %s with the hash %s, but %s holds that event with the hash %s", part.name(), held.event.ID, part.backup.FollowsOn.Hash, held.part.name(), held.event.Hash)
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
				m.found.add(SeverityManipulation, CheckBackups, "Backups %s and %s follow on event %d with different hashes, %s and %s", following[0].name(), part.name(), id, following[0].backup.FollowsOn.Hash, part.backup.FollowsOn.Hash)
			}
		}
	}
}
