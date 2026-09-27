package database

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"iter"
	"time"
)

// maxBackupLineSize bounds a single line of a backup, which holds one event.
const maxBackupLineSize = 64 * 1024 * 1024

// backupLine is a line of a backup: an event, the schema of an event type, or
// an error the database ran into while backing up.
type backupLine struct {
	Type    string          `json:"type"`
	Payload json.RawMessage `json:"payload"`
}

// backedUpEvent is the payload of an event in a backup: the event as it was
// written, and its hash.
type backedUpEvent struct {
	Event struct {
		SpecVersion     string          `json:"specversion"`
		ID              string          `json:"id"`
		Time            string          `json:"time"`
		Source          string          `json:"source"`
		Subject         string          `json:"subject"`
		Type            string          `json:"type"`
		DataContentType string          `json:"datacontenttype"`
		PredecessorHash string          `json:"predecessorhash"`
		Data            json.RawMessage `json:"data"`
	} `json:"event"`
	Hash string `json:"hash"`
}

// ReadBackup reads the events of a backup, which EventSourcingDB writes as
// newline-delimited JSON on /api/v1/backup, in the order they were written. It
// skips the schemas of event types, and fails on an error the database wrote
// into the backup, since the backup is incomplete then.
func ReadBackup(backup io.Reader) iter.Seq2[Event, error] {
	return func(yield func(Event, error) bool) {
		scanner := bufio.NewScanner(backup)
		scanner.Buffer(make([]byte, 0, 64*1024), maxBackupLineSize)

		lineNumber := 0
		for scanner.Scan() {
			lineNumber++
			if len(scanner.Bytes()) == 0 {
				continue
			}

			event, isEvent, err := parseBackupLine(scanner.Bytes())
			if err != nil {
				yield(Event{}, fmt.Errorf("line %d of the backup: %w", lineNumber, err))
				return
			}
			if !isEvent {
				continue
			}

			if !yield(event, nil) {
				return
			}
		}

		err := scanner.Err()
		if err != nil {
			yield(Event{}, fmt.Errorf("failed to read the backup: %w", err))
		}
	}
}

func parseBackupLine(data []byte) (Event, bool, error) {
	var line backupLine
	err := json.Unmarshal(data, &line)
	if err != nil {
		return Event{}, false, err
	}

	switch line.Type {
	case "event":
	case "schema", "eventType":
		return Event{}, false, nil
	case "error":
		var message string
		_ = json.Unmarshal(line.Payload, &message)
		return Event{}, false, fmt.Errorf("the database could not back up everything: %s", message)
	default:
		return Event{}, false, fmt.Errorf("unknown type %q", line.Type)
	}

	var backedUp backedUpEvent
	err = json.Unmarshal(line.Payload, &backedUp)
	if err != nil {
		return Event{}, false, err
	}
	if backedUp.Event.ID == "" || backedUp.Hash == "" {
		return Event{}, false, errors.New("the event has no ID or no hash")
	}

	writtenAt, err := time.Parse(time.RFC3339Nano, backedUp.Event.Time)
	if err != nil {
		return Event{}, false, fmt.Errorf("event %s has an invalid time: %w", backedUp.Event.ID, err)
	}

	computed := hash(eventContent{
		SpecVersion:     backedUp.Event.SpecVersion,
		ID:              backedUp.Event.ID,
		PredecessorHash: backedUp.Event.PredecessorHash,
		Time:            backedUp.Event.Time,
		Source:          backedUp.Event.Source,
		Subject:         backedUp.Event.Subject,
		Type:            backedUp.Event.Type,
		DataContentType: backedUp.Event.DataContentType,
		Data:            backedUp.Event.Data,
	})

	return Event{
		ID:              backedUp.Event.ID,
		Time:            writtenAt,
		Hash:            backedUp.Hash,
		PredecessorHash: backedUp.Event.PredecessorHash,
		HashMatches:     computed == backedUp.Hash,
	}, true, nil
}
