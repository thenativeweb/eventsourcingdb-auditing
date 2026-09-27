# eventsourcingdb-auditing

Verify that the events in an [EventSourcingDB](https://www.eventsourcingdb.io) have not been changed afterwards, using the receipts, anchors, and time stamps of an external custodian.

EventSourcingDB links every event to the one before it with a hash. That makes changes detectable, but someone with access to the database could still compute all following hashes anew. To rule that out, a client sends the fingerprint of the latest event to an external custodian, which confirms it with a signed receipt, and anchors the receipts of all instances once per hour in a Merkle tree, stamped by a time stamping authority according to RFC 3161.

This repository holds the building blocks to check all of that, and will hold a command line tool for auditors and the specification of the formats, so that anyone can build a tool of their own.

*Note that this repository is at an early stage. Its packages and formats may still change.*
