# eventsourcingdb-auditing

Verify that the events in an [EventSourcingDB](https://www.eventsourcingdb.io) have not been changed afterwards, using the receipts, anchors, and time stamps of an external custodian.

EventSourcingDB links every event to the one before it with a hash. That makes changes detectable, but someone with access to the database could still compute all following hashes anew. To rule that out, a client sends the fingerprint of the latest event to an external custodian, which confirms it with a signed receipt, and anchors the receipts of all instances once per hour in a Merkle tree, stamped by a time stamping authority according to RFC 3161.

This repository holds the building blocks to check all of that, a command line tool for auditors, and the [specification](SPECIFICATION.md) of the formats and of the verification, with test vectors, so that anyone can build a tool of their own.

*Note that this repository is at an early stage. Its packages and formats may still change.*

## Verifying an instance

Install the verification tool:

```shell
go install github.com/thenativeweb/eventsourcingdb-auditing/cmd/eventsourcingdb-auditing@latest
```

To verify an instance, you need the auditor token the customer has granted, the root public key of the custodian, and one or more backups of the EventSourcingDB of the customer:

```shell
$ eventsourcingdb-auditing verify \
    --auditor-token <auditor-token> \
    --root-public-key <root-public-key> \
    --backup backup.ndjson \
    --receipts-directory ./receipts
```

The tool reads backups in both formats EventSourcingDB writes: the one of `/api/v1/backup`, and the one of `/api/v2/management/create-backup`, which EventSourcingDB writes from version 1.3 on, as a full backup or as an incremental one that follows on the event the previous backup ended at. A full backup is created with `null`, and the item of the type `lastBackedUpEvent` near the end of a complete backup names the event the next incremental backup follows on, in the shape the request takes it:

```shell
$ curl -X POST https://<esdb>/api/v2/management/create-backup \
    -H "Authorization: Bearer <api-token>" \
    -H "Content-Type: application/json" \
    -d '{"lastBackedUpEvent": null}' > full.ndjson

$ curl -X POST https://<esdb>/api/v2/management/create-backup \
    -H "Authorization: Bearer <api-token>" \
    -H "Content-Type: application/json" \
    -d '{"lastBackedUpEvent": {"id": "4711", "hash": "esdb:hash:v2:…"}}' > incremental-1.ndjson
```

To verify a chain of backups, give `--backup` once for every one of them, for example a full backup and two incremental ones, in any order, since the tool orders them by the events they follow on itself:

```shell
$ eventsourcingdb-auditing verify \
    --auditor-token <auditor-token> \
    --root-public-key <root-public-key> \
    --backup full.ndjson \
    --backup incremental-1.ndjson \
    --backup incremental-2.ndjson \
    --receipts-directory ./receipts
```

A backup of `/api/v1/backup` counts as a full backup that ends at its last event, so incremental backups may follow on it as well. The tool checks the events of all backups as one, every event once, and it checks where the backups meet:

- Events that are in none of the backups, because the chain starts with an incremental backup, or because the backups do not meet, are a gap in protection, with their exact span, for example *Events 0 to 4711 are in none of the backups, so they could not be checked*. Everything else is checked fully, including that the first event after such a span follows on the event the backup names.
- An incremental backup that follows on an event with another hash than the backup before it holds that event with is a manipulation.
- Backups may overlap, as two full backups do, but an event that several backups hold has to be the same in all of them, including its hash and its signature. If it is not, that is a manipulation, which names both backups.
- A backup in the format of create-backup that lacks its end item, or holds an error, is incomplete. Its events are checked, and the backup is named as a gap in protection.
- A backup in the format of create-backup that names a version of its format the tool does not know can not be read reliably, so the verification is not run, and the tool names the backup.

The tool reads from the custodian at `https://auditing.eventsourcingdb.io`, or from another one given with `--server-url`. It reads what the custodian has recorded about the instance, and checks:

- that the keys of the custodian are certified by the root key, that its receipts form one chain, and that its anchors are signed, stamped, chained, prove the receipts of the instance without leaving any out, and match the public chain of anchors,
- that every event of the backups still hashes to its hash, in the version of the hash it was written with, that the events form one chain, and that they match every fingerprint the custodian has confirmed since the latest reset of the baseline,
- how long every event stayed without the protection of a fingerprint, and whether the client was ever silent for longer than its heartbeat interval,
- whether the time stamps of the anchors were issued by a qualified time stamping service at their time, using the EU trusted lists,
- if the receipts directory of the client is given, that the custodian still holds every receipt and every anchor the client kept.

Instead of backups, the tool can read the running database with `--esdb-url` and `--esdb-api-token`. Note that EventSourcingDB has no API token that only reads, so whoever runs this holds a token that could write as well.

EventSourcingDB writes hashes of version 2 from version 1.3 on, which also cover the trace context of an event, and wrote hashes of version 1 before. Events keep the version they were written with, so a database may hold both, and the tool checks every event in the version its own hash names. An event whose hash is of a version the tool does not know yet is not reported as changed, but as a gap in protection, since whether it has been changed can not be told.

The report names what was checked, including every backup with its SHA-256, in the order of the chain, and lists every finding, grouped into manipulations, gaps in protection, and notices. With `--output json`, it is written as JSON. The exit code is `0` if nothing was found, `1` if a manipulation was found, `2` if only gaps in protection were found, and `3` if the verification could not be run.

The EU trusted lists are fetched from where they are published: the list of the lists from the European Commission, and the list of the country of every time stamping authority. Their signatures are checked against the certificates the Commission has announced in the Official Journal. A time stamp that was not issued by a qualified service counts as a notice, since it still proves when an anchor existed, only without the legal weight of a qualified one. The report names the state of the lists it relied on. To verify without network, download the lists first, and read them from that directory:

```shell
$ eventsourcingdb-auditing download-trusted-lists --directory ./trusted-lists
$ eventsourcingdb-auditing verify … --trusted-lists-directory ./trusted-lists
```

To leave out the check against the trusted lists, pass `--skip-trusted-lists`. The report says so then.

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

- `database` reads the events of the EventSourcingDB of a customer, either from a backup, in the format of `/api/v1/backup` or in the one of `/api/v2/management/create-backup`, full or incremental, or from the running database, and checks for every event whether its content still hashes to its hash. For a backup, it tells which event an incremental backup follows on, which one the backup ended at, and whether it is complete. It knows both versions of the hash, and computes every event in the version its own hash names: version 1, without a prefix, and version 2, which starts with `esdb:hash:v2:`, and which EventSourcingDB writes from version 1.3 on. It tells a hash of a version it does not know from one that does not match. From a backup, the time and the data are hashed exactly as they were written, so that escapes in the data do not get lost.
- `verify` checks what the custodian has recorded about an instance: that its keys are certified by the root key, that its receipts form one chain that matches its entries, that its anchors are signed, stamped, chained, and prove the receipts of the instance without leaving any out, that they match the public chain of anchors, and that the client was never silent for longer than its heartbeat interval. It then checks the events of the instance against it, from a single source, or from a chain of backups, which it orders by the events they follow on, and whose events it checks as one, after it has checked where they meet and where they overlap: that every event still hashes to its hash, that the events form one chain, that they match every fingerprint the custodian has confirmed since the latest reset of the baseline, and how long every event stayed without the protection of a fingerprint. Every problem becomes a finding, either a manipulation, a gap in protection, or a notice, so that a report can list them all.

- `trustedlists` tells whether a time stamp was issued by a qualified time stamping service, using the EU trusted lists. It checks the XAdES signature of the list of the lists against the certificates the European Commission has announced in the Official Journal (C/2026/1944), following pivot lists to later ones, and the signature of the list of every member state against the certificates the list of the lists names for it. A time stamp counts as qualified if the certificate it was signed with, or the one that issued it, is the digital identity of a QTST service that was granted at the time of the time stamp. The lists are fetched from where they are published, or read from a directory, which `trustedlists.Download` fills, for verifying without network.
- `receiptsdir` reads the receipts directory of the client.
- `report` sums up the findings of a verification, and writes them as text or as JSON.
- `check` runs a whole verification, which is what the command line tool does.

The package `testvectors` checks that the code produces exactly the test vectors of the specification, in `testvectors/testvectors.json`. After changing a format on purpose, update them with `UPDATE_TEST_VECTORS=1 go test ./testvectors/`, and the specification with them.

The packages `database/databasetest`, `receipt/receipttest`, `timestamping/timestampingtest`, `trustedlists/trustedliststest`, and `verify/verifytest` provide an EventSourcingDB in a container together with backups of a real one, among them a chain of a full backup and incremental ones in both formats, keys, a time stamping authority, real trusted lists, and a custodian for tests.

## Running quality assurance

To run quality assurance for this module use the following command. Some tests start an EventSourcingDB in Docker:

```shell
$ make
```

The tests start the image `thenativeweb/eventsourcingdb:latest`. To run them against another version, set its tag in `EVENTSOURCINGDB_IMAGE_TAG`. The pipeline runs them against `latest` and `preview`. The tests that take backups in the format of create-backup from a running database are skipped against a version before 1.3, which does not write them. The backups in that format that `database/databasetest` holds are read in every run:

```shell
$ EVENTSOURCINGDB_IMAGE_TAG=preview make
```

The tests use a time stamping authority of their own, and an answer of DGN, the qualified time stamping authority of the custodian, which `timestamping/testdata` holds together with its request. To check the `timestamping` package against a real authority, pass its URL, and its credentials if it requires them. Every run uses up one time stamp:

```shell
$ TIMESTAMP_AUTHORITY_URL=<rfc-3161-url> \
  TIMESTAMP_AUTHORITY_USERNAME=<username> \
  TIMESTAMP_AUTHORITY_PASSWORD=<password> \
  go test -run TestInterop -v ./timestamping/
```

Add `EU_TRUSTED_LISTS=1` to also check the time stamp against the EU trusted lists as they are published now, and `TIMESTAMP_RECORDING=testdata/<name>` to keep the request and the answer, before anything is checked.

The tests of `trustedlists` use real trusted lists, which `trustedlists/trustedliststest` provides: the list of the lists, and the lists of Germany, Hungary, Slovenia, and Iceland, which cover every signature method the lists use. To check against the lists as they are published now, including whether the certificates announced in the Official Journal still sign the list of the lists, run:

```shell
$ EU_TRUSTED_LISTS=1 go test -run TestLiveLists -v ./trustedlists/
```
