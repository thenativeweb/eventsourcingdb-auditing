package timestamping

import "errors"

// ErrTransient marks an error after which trying again may help, for example
// because the time stamping authority was unreachable or answered with a
// server error. Check for it with errors.Is.
var ErrTransient = errors.New("time stamping authority temporarily unavailable")
