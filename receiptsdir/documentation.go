// Package receiptsdir reads the receipts directory, in which the client of an
// instance keeps every receipt and every anchor the custodian has handed it,
// as the evidence the customer holds against the custodian.
//
// The directory holds one file of receipts per day, receipts-2026-09-26.jsonl,
// with one JSON object per line that names a receipt, {"receipt": "<jws>"}; one
// file of anchors per day, anchors-2026-09-26.jsonl, with one anchor together
// with its time stamp and the proof of the instance per line; and the
// certificates of the signing keys in certificates/, one per file.
package receiptsdir
