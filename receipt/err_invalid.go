package receipt

import "errors"

// ErrInvalid means that a receipt or a key certificate is malformed, carries
// a signature that does not match, or does not fit the key that is supposed
// to have signed it. Check for it with errors.Is.
var ErrInvalid = errors.New("invalid receipt")
