// Package receipt contains the receipts with which the custodian confirms the
// fingerprints it has recorded, and the key certificates that tie the keys
// signing them to the root key of the native web.
//
// Receipts and key certificates are JSON Web Signatures in compact form
// (RFC 7515) with Ed25519 (RFC 8037). The package only accepts exactly that,
// and rejects any other algorithm, so that no one can slip in a signature
// that is checked in a weaker way.
package receipt
