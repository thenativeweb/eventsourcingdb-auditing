// Package audit describes what the custodian hands out to auditors, and
// provides a client to read it.
//
// An auditor reads with an auditor token, which the customer grants with the
// client of an instance. The token only reads, only covers that instance, and
// expires. The custodian records every use of it, so the customer sees who has
// read what.
//
// The chain of anchors is public, and needs no token at all.
package audit
