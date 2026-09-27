// Package verify checks what the custodian has recorded about an instance,
// and, in a later step, the events of the instance against it. Every problem
// it finds becomes a Finding, so that a report can list them all, rather than
// stopping at the first one.
package verify
