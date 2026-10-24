// Package verify checks what the custodian has recorded about an instance,
// and, in a later step, the events of the instance against it, from a single
// source, or from a chain of backups, which it checks as one. Every problem
// it finds becomes a Finding, so that a report can list them all, rather than
// stopping at the first one.
package verify
