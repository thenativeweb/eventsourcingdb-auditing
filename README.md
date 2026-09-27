# eventsourcingdb-auditing

Verify that the events in an [EventSourcingDB](https://www.eventsourcingdb.io) have not been changed afterwards, using the receipts, anchors, and time stamps of an external custodian.

EventSourcingDB links every event to the one before it with a hash. That makes changes detectable, but someone with access to the database could still compute all following hashes anew. To rule that out, a client sends the fingerprint of the latest event to an external custodian, which confirms it with a signed receipt, and anchors the receipts of all instances once per hour in a Merkle tree, stamped by a time stamping authority according to RFC 3161.

This repository holds the building blocks to check all of that, and will hold a command line tool for auditors and the specification of the formats, so that anyone can build a tool of their own.

*Note that this repository is at an early stage. Its packages and formats may still change.*

## Verifying an instance

Install the verification tool:

```shell
go install github.com/thenativeweb/eventsourcingdb-auditing/cmd/eventsourcingdb-auditing@latest
```

To verify an instance, you need the auditor token the customer has granted, the root public key of the custodian, and a backup of the EventSourcingDB of the customer, which EventSourcingDB writes on `/api/v1/backup`:

```shell
$ eventsourcingdb-auditing verify \
    --server-url <custodian-url> \
    --auditor-token <auditor-token> \
    --root-public-key <root-public-key> \
    --backup backup.json \
    --receipts-directory ./receipts
```

The tool reads what the custodian has recorded about the instance, and checks:

- that the keys of the custodian are certified by the root key, that its receipts form one chain, and that its anchors are signed, stamped, chained, prove the receipts of the instance without leaving any out, and match the public chain of anchors,
- that every event of the backup still hashes to its hash, that the events form one chain, and that they match every fingerprint the custodian has confirmed since the latest reset of the baseline,
- how long every event stayed without the protection of a fingerprint, and whether the client was ever silent for longer than its heartbeat interval,
- if the receipts directory of the client is given, that the custodian still holds every receipt and every anchor the client kept.

Instead of a backup, the tool can read the running database with `--esdb-url` and `--esdb-api-token`. Note that EventSourcingDB has no API token that only reads, so whoever runs this holds a token that could write as well.

The report names what was checked, including the SHA-256 of the backup, and lists every finding, grouped into manipulations, gaps in protection, and notices. With `--output json`, it is written as JSON. The exit code is `0` if nothing was found, `1` if a manipulation was found, `2` if only gaps in protection were found, and `3` if the verification could not be run.

*Note that the tool does not check yet whether the time stamps are qualified, since that needs the EU trusted lists. The report says so.*

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

- `database` reads the events of the EventSourcingDB of a customer, either from a backup, as EventSourcingDB writes it on `/api/v1/backup`, or from the running database, and checks for every event whether its content still hashes to its hash. From a backup, the time and the data are hashed exactly as they were written, so that escapes in the data do not get lost.
- `verify` checks what the custodian has recorded about an instance: that its keys are certified by the root key, that its receipts form one chain that matches its entries, that its anchors are signed, stamped, chained, and prove the receipts of the instance without leaving any out, that they match the public chain of anchors, and that the client was never silent for longer than its heartbeat interval. It then checks the events of the instance against it: that every event still hashes to its hash, that the events form one chain, that they match every fingerprint the custodian has confirmed since the latest reset of the baseline, and how long every event stayed without the protection of a fingerprint. Every problem becomes a finding, either a manipulation, a gap in protection, or a notice, so that a report can list them all.

- `receiptsdir` reads the receipts directory of the client.
- `report` sums up the findings of a verification, and writes them as text or as JSON.
- `check` runs a whole verification, which is what the command line tool does.

The packages `receipt/receipttest`, `timestamping/timestampingtest`, and `verify/verifytest` provide keys, a time stamping authority, and a custodian for tests.

## Running quality assurance

To run quality assurance for this module use the following command. Some tests start an EventSourcingDB in Docker:

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
