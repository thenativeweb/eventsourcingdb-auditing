# eventsourcingdb-auditing

Verify that the events in an [EventSourcingDB](https://www.eventsourcingdb.io) have not been changed afterwards, using the receipts, anchors, and time stamps of an external custodian.

EventSourcingDB links every event to the one before it with a hash. That makes changes detectable, but someone with access to the database could still compute all following hashes anew. To rule that out, a client sends the fingerprint of the latest event to an external custodian, which confirms it with a signed receipt, and anchors the receipts of all instances once per hour in a Merkle tree, stamped by a time stamping authority according to RFC 3161.

This repository holds the building blocks to check all of that, and will hold a command line tool for auditors and the specification of the formats, so that anyone can build a tool of their own.

*Note that this repository is at an early stage. Its packages and formats may still change.*

## Packages

Install the module:

```shell
go get github.com/thenativeweb/eventsourcingdb-auditing
```

It contains the following packages:

- `receipt` signs and checks receipts, anchors, and the key certificates that tie the keys signing them to a root key. All of them are JSON Web Signatures in compact form (RFC 7515) with Ed25519 (RFC 8037), and nothing else is accepted.
- `merkle` builds the Merkle trees of the anchors, and creates and checks the proofs that a leaf is part of one. The trees follow RFC 6962, and their leaves are salted, so that a proof reveals nothing about other leaves.
- `timestamping` obtains time stamps from a time stamping authority according to RFC 3161, and checks that a time stamp covers the expected digest and is signed by the authority it names.
- `audit` describes what the custodian hands out to auditors, and provides a client to read it: the audited instance with its intervals and key certificates, its chain of fingerprints, receipts, conflicts, breaks, and resets, and the anchors with its proofs. An auditor reads with an auditor token, which the customer grants, which only reads, and which expires. The chain of anchors is public.

- `verify` checks what the custodian has recorded about an instance: that its keys are certified by the root key, that its receipts form one chain that matches its entries, that its anchors are signed, stamped, chained, and prove the receipts of the instance without leaving any out, that they match the public chain of anchors, and that the client was never silent for longer than its heartbeat interval. Every problem becomes a finding, either a manipulation, a gap in protection, or a notice, so that a report can list them all.

The packages `receipt/receipttest` and `timestamping/timestampingtest` provide keys and a time stamping authority for tests.

## Running quality assurance

To run quality assurance for this module use the following command:

```shell
$ make
```

The tests use a time stamping authority of their own. To check the `timestamping` package against a real one, pass its URL, and its credentials if it requires them. Every run uses up one time stamp:

```shell
$ TIMESTAMP_AUTHORITY_URL=<rfc-3161-url> \
  TIMESTAMP_AUTHORITY_USERNAME=<username> \
  TIMESTAMP_AUTHORITY_PASSWORD=<password> \
  go test -run TestInterop -v ./timestamping/
```
