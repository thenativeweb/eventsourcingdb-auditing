package verify

import (
	"fmt"
	"time"
)

func sprintf(format string, args ...any) string {
	return fmt.Sprintf(format, args...)
}

// formatTime writes a time the same way in every message.
func formatTime(value time.Time) string {
	return value.UTC().Format(time.RFC3339)
}
