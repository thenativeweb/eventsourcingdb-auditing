package database

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"iter"
	"strconv"
	"time"
)

// maxBackupLineSize bounds a single line of a backup, which holds one event.
const maxBackupLineSize = 64 * 1024 * 1024

// The versions of the formats of backups, as Backup.FormatVersion names them.
const (
	// BackupFormatVersion1 is the format EventSourcingDB writes on
	// /api/v1/backup, which names no version: every line has a type and a
	// payload, and the backup holds every event.
	BackupFormatVersion1 = 1

	// BackupFormatVersion2 is the format EventSourcingDB writes on
	// /api/v2/management/create-backup from version 1.3 on: every line has a
	// type and data, the first one names the version of the format and the
	// event an incremental backup follows on, and the last one ends the
	// backup.
	BackupFormatVersion2 = 2
)

// The types of the items of a backup in the format of create-backup.
const (
	itemBackup            = "backup"
	itemEventSchema       = "eventSchema"
	itemEvent             = "event"
	itemLastBackedUpEvent = "lastBackedUpEvent"
	itemHeartbeat         = "heartbeat"
	itemError             = "error"
	itemEnd               = "end"
)

// ErrUnknownBackupFormat means that a backup names a version of its format
// that this package does not know, so it can not be read reliably.
var ErrUnknownBackupFormat = errors.New("unknown version of the format of the backup")

// EventReference names an event by its ID and its hash, as a backup names the
// event it follows on, and the one it ended at.
type EventReference struct {
	ID   string `json:"id"`
	Hash string `json:"hash"`
}

// Backup is what a backup tells about itself, besides its events.
type Backup struct {
	// FormatVersion is the version of the format of the backup,
	// BackupFormatVersion1 or BackupFormatVersion2.
	FormatVersion int

	// FollowsOn is the event an incremental backup follows on, which is the
	// one a previous backup ended at, so that it holds the events after it.
	// It is nil for a full backup, which holds every event, as a backup in
	// the format of /api/v1/backup always does.
	FollowsOn *EventReference

	// LastEvent is the last event the backup holds, or nil if it holds none.
	LastEvent *EventReference

	// NamedEnd is the event the backup names as the one it ended at, in its
	// lastBackedUpEvent item, or nil if it names none. Only a complete backup
	// in the format of create-backup names one.
	NamedEnd *EventReference

	// IsComplete reports whether the database wrote no error into the
	// backup, and whether a backup in the format of create-backup ends with
	// its end item. A backup in the format of /api/v1/backup has no end item,
	// so whether it was cut short can not be told from it.
	IsComplete bool

	// Failure is what the error says that the database wrote into the
	// backup, if it wrote one, which keeps the backup from being complete.
	Failure string

	// IsCutShort reports whether the backup ends in the middle of a line,
	// as it does when it was cut short while it was transferred, which
	// keeps it from being complete as well.
	IsCutShort bool

	// Offset and Size name the bytes of its file that belong to the backup,
	// from where the one before it ends, or from the start of the file, to
	// where the next one begins, or to the end of the file, and SHA256 is
	// the SHA-256 of them, so that a backup of a file with several can be
	// read again on its own, and be told apart from one that has changed.
	Offset int64
	Size   int64
	SHA256 string
}

// EndedAt returns the event the backup ended at: its last event, or, if it
// holds none, the event it follows on, or nil for a full backup without
// events, as of an empty database.
func (b Backup) EndedAt() *EventReference {
	if b.LastEvent != nil {
		return b.LastEvent
	}

	return b.FollowsOn
}

// BackedUpEvent is an event as a backup holds it: the event, checked, and
// everything its hash covers, so that the same event in two backups can be
// compared.
type BackedUpEvent struct {
	Event

	// Part is the number of the backup that holds the event, among the
	// backups of its file, from 0 on.
	Part int

	content eventContent
}

// DifferencesFrom names the members in which an event differs from the same
// event as another backup holds it: any member that a hash of either version
// covers, and its hash. A trace context that a backup leaves out counts as
// the same as one that is null, and the data is compared byte for byte, as it
// was written. The signature that a backup in the format of create-backup
// holds is not part of the event, and is left out: EventSourcingDB does not
// store it, but signs the hash anew whenever it hands out an event, with the
// key it has then, if any, so the same event differs in its signature between
// backups taken before and after the key changed. The comparison is the same
// whichever event it starts from.
func (e BackedUpEvent) DifferencesFrom(other BackedUpEvent) []string {
	var differences []string
	compare := func(member string, isSame bool) {
		if !isSame {
			differences = append(differences, member)
		}
	}

	compare("specversion", e.content.SpecVersion == other.content.SpecVersion)
	compare("id", e.content.ID == other.content.ID)
	compare("time", e.content.Time == other.content.Time)
	compare("source", e.content.Source == other.content.Source)
	compare("subject", e.content.Subject == other.content.Subject)
	compare("type", e.content.Type == other.content.Type)
	compare("datacontenttype", e.content.DataContentType == other.content.DataContentType)
	compare("predecessorhash", e.content.PredecessorHash == other.content.PredecessorHash)
	compare("traceparent", isSameOptional(e.content.TraceParent, other.content.TraceParent))
	compare("tracestate", isSameOptional(e.content.TraceState, other.content.TraceState))
	compare("data", bytes.Equal(e.content.Data, other.content.Data))
	compare("hash", e.Hash == other.Hash)

	return differences
}

func isSameOptional(left, right *string) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}

	return *left == *right
}

// BackupReader reads a backup of either format, as EventSourcingDB writes it
// on /api/v1/backup or on /api/v2/management/create-backup, or several
// backups in the format of create-backup one after another, as EventSourcingDB
// restores them, and tells what every backup tells about itself, once their
// events have been read.
type BackupReader struct {
	backup  io.Reader
	backups []Backup

	hasStarted    bool
	formatVersion int

	// state is where the reading stands within the backups of the file.
	state readingState
}

// readingState is where the reading stands within the backups of a file.
type readingState int

const (
	// stateBeforeBackup is before the first backup of a file in the format
	// of create-backup, and after the end item of every further one.
	stateBeforeBackup readingState = iota

	// stateInBackup is within a backup, after its backup item.
	stateInBackup

	// stateAfterFailure is after the error the database wrote into a
	// backup, which only the end item of a backup in the format of
	// create-backup may follow.
	stateAfterFailure
)

// NewBackupReader returns a reader for a backup of either format.
func NewBackupReader(backup io.Reader) *BackupReader {
	return &BackupReader{backup: backup}
}

// Events reads the events of the backups of the file, in the order they were
// written, and checks the hash of every event in the version that hash names.
// Every event names the backup it belongs to. It skips the schemas of event
// types and heartbeats.
//
// It tells the formats apart as EventSourcingDB does when it restores a
// backup: one in the format of create-backup begins with a backup item, and
// one in the format of /api/v1/backup with a line that holds a payload. A
// file in the format of create-backup may hold several backups, as
// EventSourcingDB restores them: every further one begins with its backup
// item right after the end item of the one before. A file in the format of
// /api/v1/backup always holds a single one.
//
// It fails on a line it does not understand, or that stands where the format
// puts none, and on a backup that names a version of its format this package
// does not know (ErrUnknownBackupFormat). An error the database wrote into a
// backup, and a backup in the format of create-backup that ends without its
// end item, only make the backup incomplete, which Backups tells, so that the
// events it holds can still be checked. So does the rest of a line that a
// backup of either format ends with, if it was cut short while it was
// transferred.
//
// The events of a backup can be read only once.
func (r *BackupReader) Events() iter.Seq2[BackedUpEvent, error] {
	return func(yield func(BackedUpEvent, error) bool) {
		scanner := bufio.NewScanner(r.backup)
		scanner.Buffer(make([]byte, 0, 64*1024), maxBackupLineSize)

		// The line is kept as it was read, with its line feed, so that the
		// bytes of every backup of the file are known.
		var line []byte
		isLineTerminated := true
		scanner.Split(func(data []byte, atEOF bool) (int, []byte, error) {
			advance, token, err := bufio.ScanLines(data, atEOF)
			if token != nil {
				line = data[:advance]
				isLineTerminated = data[advance-1] == '\n'
			}

			return advance, token, err
		})

		bytesOfBackup := newByteRange()
		lineNumber := 0
		for scanner.Scan() {
			lineNumber++
			if len(scanner.Bytes()) == 0 {
				bytesOfBackup.add(line)
				continue
			}

			backupsBefore := len(r.backups)
			event, isEvent, err := r.readLine(scanner.Bytes())
			if err != nil {
				// EventSourcingDB ends every line with a line feed, so a
				// backup whose last line is no JSON, and ends without one,
				// was cut short in the middle of that line, which is left
				// aside, and which makes the backup incomplete. After the
				// error the database wrote into a backup of /api/v1/backup,
				// it writes nothing more, so a line after it stays one that
				// can not be read.
				var syntaxError *json.SyntaxError
				isWithinBackup := (r.formatVersion == BackupFormatVersion2 && r.state != stateBeforeBackup) ||
					(r.formatVersion == BackupFormatVersion1 && r.state == stateInBackup)
				if errors.As(err, &syntaxError) && !isLineTerminated && isWithinBackup {
					bytesOfBackup.add(line)
					r.current().IsCutShort = true
					break
				}

				yield(BackedUpEvent{}, fmt.Errorf("line %d of the backup: %w", lineNumber, err))
				return
			}

			// A backup item after the first one begins the bytes of the
			// next backup of the file.
			if backupsBefore > 0 && len(r.backups) > backupsBefore {
				bytesOfBackup.end(&r.backups[backupsBefore-1])
			}
			bytesOfBackup.add(line)

			if !isEvent {
				continue
			}

			event.Part = len(r.backups) - 1
			r.current().LastEvent = &EventReference{ID: event.ID, Hash: event.Hash}
			if !yield(event, nil) {
				return
			}
		}

		err := scanner.Err()
		if err != nil {
			yield(BackedUpEvent{}, fmt.Errorf("failed to read the backup: %w", err))
			return
		}

		// A backup without a single line is taken for an empty one in the
		// format of /api/v1/backup, as EventSourcingDB restores it. Such a
		// backup has no end item, so it is complete unless the database
		// wrote an error into it, or it was cut short in the middle of a
		// line.
		if !r.hasStarted {
			r.backups = []Backup{{FormatVersion: BackupFormatVersion1}}
			r.formatVersion = BackupFormatVersion1
		}
		if r.formatVersion == BackupFormatVersion1 {
			r.current().IsComplete = r.current().Failure == "" && !r.current().IsCutShort
		}
		bytesOfBackup.end(r.current())
	}
}

// byteRange collects the bytes of a backup of a file, as they are read, and
// computes their SHA-256.
type byteRange struct {
	offset int64
	size   int64
	hasher hash.Hash
}

func newByteRange() *byteRange {
	return &byteRange{hasher: sha256.New()}
}

func (b *byteRange) add(line []byte) {
	b.hasher.Write(line)
	b.size += int64(len(line))
}

// end names the bytes collected so far as the ones of the given backup, and
// begins collecting the ones of the next.
func (b *byteRange) end(backup *Backup) {
	backup.Offset, backup.Size, backup.SHA256 = b.offset, b.size, hex.EncodeToString(b.hasher.Sum(nil))

	b.offset += b.size
	b.size = 0
	b.hasher = sha256.New()
}

// Backups returns what every backup of the file tells about itself, in the
// order of the file. It is only known once Events has read the file to its
// end.
func (r *BackupReader) Backups() []Backup {
	return r.backups
}

func (r *BackupReader) current() *Backup {
	return &r.backups[len(r.backups)-1]
}

// ReadBackup reads the events of the backups of a file, of either format, as
// BackupReader does, and fails at the end of the file if a backup is
// incomplete, since its events may not be all of them. To check the events of
// an incomplete backup, and to learn which event an incremental backup follows
// on, use BackupReader.
func ReadBackup(backup io.Reader) iter.Seq2[Event, error] {
	return func(yield func(Event, error) bool) {
		reader := NewBackupReader(backup)
		for event, err := range reader.Events() {
			if err != nil {
				yield(Event{}, err)
				return
			}

			if !yield(event.Event, nil) {
				return
			}
		}

		for _, read := range reader.Backups() {
			switch {
			case read.IsComplete:
				continue
			case read.Failure != "":
				yield(Event{}, fmt.Errorf("the backup is incomplete, since the database could not back up everything: %s", read.Failure))
			case read.FormatVersion == BackupFormatVersion1:
				yield(Event{}, errors.New("the backup is incomplete, since it was cut short in the middle of its last line"))
			default:
				yield(Event{}, errors.New("the backup is incomplete, since it lacks its end item"))
			}
			return
		}
	}
}

// backupLine is a line of a backup, of either format: the format of
// create-backup holds data, the one of /api/v1/backup a payload.
type backupLine struct {
	Type    string          `json:"type"`
	Data    json.RawMessage `json:"data"`
	Payload json.RawMessage `json:"payload"`
}

func (r *BackupReader) readLine(data []byte) (BackedUpEvent, bool, error) {
	var line backupLine
	err := json.Unmarshal(data, &line)
	if err != nil {
		return BackedUpEvent{}, false, err
	}

	// A heartbeat only kept the connection alive while the backup was
	// written.
	if line.Type == itemHeartbeat {
		return BackedUpEvent{}, false, nil
	}

	if !r.hasStarted {
		r.hasStarted = true
		r.formatVersion = BackupFormatVersion2
		if line.Type != itemBackup && line.Payload != nil {
			r.formatVersion = BackupFormatVersion1
			r.backups = []Backup{{FormatVersion: BackupFormatVersion1}}
			r.state = stateInBackup
		}
	}

	if r.formatVersion == BackupFormatVersion1 {
		return r.readLineOfVersion1(line)
	}

	return r.readLineOfVersion2(line)
}

// backedUpEventOfVersion1 is the payload of an event in a backup in the
// format of /api/v1/backup: the event as it was written, and its hash.
type backedUpEventOfVersion1 struct {
	Event struct {
		SpecVersion     string          `json:"specversion"`
		ID              string          `json:"id"`
		Time            string          `json:"time"`
		Source          string          `json:"source"`
		Subject         string          `json:"subject"`
		Type            string          `json:"type"`
		DataContentType string          `json:"datacontenttype"`
		PredecessorHash string          `json:"predecessorhash"`
		TraceParent     *string         `json:"traceparent"`
		TraceState      *string         `json:"tracestate"`
		Data            json.RawMessage `json:"data"`
	} `json:"event"`
	Hash string `json:"hash"`
}

// readLineOfVersion1 reads a line of a backup in the format of
// /api/v1/backup: an event, the schema of an event type, or an error the
// database ran into while backing up, which makes the backup incomplete, and
// after which EventSourcingDB writes nothing more.
func (r *BackupReader) readLineOfVersion1(line backupLine) (BackedUpEvent, bool, error) {
	if r.state == stateAfterFailure {
		return BackedUpEvent{}, false, errors.New("the backup holds a line after the error the database wrote into it")
	}

	switch line.Type {
	case itemEvent:
	case "schema", "eventType":
		return BackedUpEvent{}, false, nil
	case itemError:
		var message string
		err := json.Unmarshal(line.Payload, &message)
		if err != nil || message == "" {
			message = string(line.Payload)
		}
		r.current().Failure = message
		r.state = stateAfterFailure

		return BackedUpEvent{}, false, nil
	default:
		return BackedUpEvent{}, false, fmt.Errorf("unknown type %q", line.Type)
	}

	var backedUp backedUpEventOfVersion1
	err := json.Unmarshal(line.Payload, &backedUp)
	if err != nil {
		return BackedUpEvent{}, false, err
	}

	event, err := newBackedUpEvent(eventContent{
		SpecVersion:     backedUp.Event.SpecVersion,
		ID:              backedUp.Event.ID,
		PredecessorHash: backedUp.Event.PredecessorHash,
		Time:            backedUp.Event.Time,
		Source:          backedUp.Event.Source,
		Subject:         backedUp.Event.Subject,
		Type:            backedUp.Event.Type,
		DataContentType: backedUp.Event.DataContentType,
		TraceParent:     backedUp.Event.TraceParent,
		TraceState:      backedUp.Event.TraceState,
		Data:            backedUp.Event.Data,
	}, backedUp.Hash)
	if err != nil {
		return BackedUpEvent{}, false, err
	}

	return event, true, nil
}

// eventOfVersion2 is an event as a backup in the format of create-backup
// holds it: flat, with its hash, and with null for a trace context it does
// not have. Its signature, which EventSourcingDB computes over the hash
// whenever it hands out an event, is not part of the event, and is left
// aside.
type eventOfVersion2 struct {
	SpecVersion     string          `json:"specversion"`
	ID              string          `json:"id"`
	Source          string          `json:"source"`
	Subject         string          `json:"subject"`
	Type            string          `json:"type"`
	Time            string          `json:"time"`
	PredecessorHash string          `json:"predecessorhash"`
	DataContentType string          `json:"datacontenttype"`
	Data            json.RawMessage `json:"data"`
	TraceParent     *string         `json:"traceparent"`
	TraceState      *string         `json:"tracestate"`
	Hash            string          `json:"hash"`
}

// readLineOfVersion2 reads a line of a backup in the format of create-backup,
// and checks that it stands where the format puts it, as EventSourcingDB does
// when it restores a sequence of backups: every backup begins with its backup
// item, and ends with its end item, which only the backup item of the next
// backup may follow. After an error the database wrote into a backup, it
// writes its end item only.
func (r *BackupReader) readLineOfVersion2(line backupLine) (BackedUpEvent, bool, error) {
	switch r.state {
	case stateBeforeBackup:
		if line.Type == itemBackup {
			r.backups = append(r.backups, Backup{FormatVersion: BackupFormatVersion2})
			r.state = stateInBackup

			return BackedUpEvent{}, false, r.readBackupItem(line.Data)
		}

		switch {
		case len(r.backups) > 0:
			return BackedUpEvent{}, false, fmt.Errorf("the backup holds an item of type %q after its end item", line.Type)
		case line.Type == itemError:
			return BackedUpEvent{}, false, fmt.Errorf("the file holds no backup, but the error the database answered with instead: %s", failureOf(line.Data))
		default:
			return BackedUpEvent{}, false, fmt.Errorf("expected a backup item to begin the backup, but got one of type %q", line.Type)
		}

	case stateAfterFailure:
		if line.Type != itemEnd {
			return BackedUpEvent{}, false, fmt.Errorf("the backup holds an item of type %q after the error the database wrote into it", line.Type)
		}
	}

	switch line.Type {
	case itemBackup:
		return BackedUpEvent{}, false, errors.New("the backup holds a second backup item before its end item")

	case itemEventSchema:
		return BackedUpEvent{}, false, nil

	case itemEvent:
		var backedUp eventOfVersion2
		err := json.Unmarshal(line.Data, &backedUp)
		if err != nil {
			return BackedUpEvent{}, false, err
		}

		event, err := newBackedUpEvent(eventContent{
			SpecVersion:     backedUp.SpecVersion,
			ID:              backedUp.ID,
			PredecessorHash: backedUp.PredecessorHash,
			Time:            backedUp.Time,
			Source:          backedUp.Source,
			Subject:         backedUp.Subject,
			Type:            backedUp.Type,
			DataContentType: backedUp.DataContentType,
			TraceParent:     backedUp.TraceParent,
			TraceState:      backedUp.TraceState,
			Data:            backedUp.Data,
		}, backedUp.Hash)
		if err != nil {
			return BackedUpEvent{}, false, err
		}

		return event, true, nil

	case itemLastBackedUpEvent:
		namedEnd, err := readEventReference(line.Data)
		if err != nil {
			return BackedUpEvent{}, false, fmt.Errorf("the item that names the event the backup ended at is invalid: %w", err)
		}
		r.current().NamedEnd = namedEnd

		return BackedUpEvent{}, false, nil

	case itemError:
		r.current().Failure = failureOf(line.Data)
		r.state = stateAfterFailure

		return BackedUpEvent{}, false, nil

	case itemEnd:
		r.current().IsComplete = r.current().Failure == ""
		r.state = stateBeforeBackup

		return BackedUpEvent{}, false, nil

	default:
		return BackedUpEvent{}, false, fmt.Errorf("unknown type %q", line.Type)
	}
}

// readBackupItem reads the first item of a backup in the format of
// create-backup, which names the version of its format, and the event the
// backup follows on, if it is an incremental one. Every backup of a file names
// its own version. The version is compared as
// it is written, as EventSourcingDB does, which restores no backup that names
// another version than 2, or none.
func (r *BackupReader) readBackupItem(data json.RawMessage) error {
	var item struct {
		FormatVersion     json.Number     `json:"formatVersion"`
		LastBackedUpEvent json.RawMessage `json:"lastBackedUpEvent"`
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	err := decoder.Decode(&item)
	if err != nil {
		return err
	}

	if item.FormatVersion.String() != strconv.Itoa(BackupFormatVersion2) {
		if item.FormatVersion == "" {
			return fmt.Errorf("%w: the backup names no version, so it can not be read reliably", ErrUnknownBackupFormat)
		}

		return fmt.Errorf("%w: the backup names version %s, which this version of the tool does not support, so it can not be read reliably", ErrUnknownBackupFormat, item.FormatVersion)
	}

	if len(item.LastBackedUpEvent) == 0 || bytes.Equal(bytes.TrimSpace(item.LastBackedUpEvent), []byte("null")) {
		return nil
	}

	followsOn, err := readEventReference(item.LastBackedUpEvent)
	if err != nil {
		return fmt.Errorf("the event the backup follows on is invalid: %w", err)
	}
	r.current().FollowsOn = followsOn

	return nil
}

func readEventReference(data json.RawMessage) (*EventReference, error) {
	var reference EventReference
	err := json.Unmarshal(data, &reference)
	if err != nil {
		return nil, err
	}
	if reference.ID == "" || reference.Hash == "" {
		return nil, errors.New("it has no ID or no hash")
	}

	return &reference, nil
}

// failureOf returns what an error item of a backup in the format of
// create-backup says: its description, or its code, if it has none.
func failureOf(data json.RawMessage) string {
	var failure struct {
		Code        string `json:"code"`
		Description string `json:"description"`
	}
	_ = json.Unmarshal(data, &failure)

	switch {
	case failure.Description != "":
		return failure.Description
	case failure.Code != "":
		return failure.Code
	default:
		return string(data)
	}
}

// newBackedUpEvent checks the hash of an event a backup holds, in the version
// that its hash names.
func newBackedUpEvent(content eventContent, hash string) (BackedUpEvent, error) {
	if content.ID == "" || hash == "" {
		return BackedUpEvent{}, errors.New("the event has no ID or no hash")
	}

	writtenAt, err := time.Parse(time.RFC3339Nano, content.Time)
	if err != nil {
		return BackedUpEvent{}, fmt.Errorf("event %s has an invalid time: %w", content.ID, err)
	}

	hashVersion, isKnown := hashVersionOf(hash)

	return BackedUpEvent{
		Event: Event{
			ID:                   content.ID,
			Time:                 writtenAt,
			Hash:                 hash,
			PredecessorHash:      content.PredecessorHash,
			HashVersion:          hashVersion,
			HashMatches:          hashMatches(content, hash),
			HashVersionIsUnknown: !isKnown,
		},
		content: content,
	}, nil
}
