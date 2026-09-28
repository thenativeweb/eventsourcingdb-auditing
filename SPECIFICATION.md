# Specification

This document specifies how the events of an [EventSourcingDB](https://www.eventsourcingdb.io) are anchored with an external custodian, and how anyone can verify that they have not been changed afterwards. It describes every format and every rule a verification tool needs, so that tools other than the one in this repository can check the same things, and reach the same result.

*Version 1, draft. The formats may still change until the first stable release.*

The key words MUST, MUST NOT, SHOULD, and MAY are to be interpreted as described in [RFC 2119](https://www.rfc-editor.org/rfc/rfc2119).

## Contents

1. [Overview](#1-overview)
2. [Conventions](#2-conventions)
3. [Events and fingerprints](#3-events-and-fingerprints)
4. [Signed objects](#4-signed-objects)
5. [Merkle trees](#5-merkle-trees)
6. [Time stamps](#6-time-stamps)
7. [Recording](#7-recording)
8. [The audit API](#8-the-audit-api)
9. [The receipts directory](#9-the-receipts-directory)
10. [Verification](#10-verification)
11. [Test vectors](#11-test-vectors)

## 1. Overview

EventSourcingDB links every event to the one before it with a hash, so that changing an event breaks the chain. Someone with access to the database could still compute all following hashes anew. To rule that out, the chain is anchored outside the database:

- The **client**, which runs next to the EventSourcingDB of a customer, sends the fingerprint of the latest event, its ID and its hash, to the **custodian**.
- The custodian records the fingerprint, and confirms it with a signed **receipt**. The receipts of an instance form a chain of their own. The client keeps every receipt, as the evidence the customer holds against the custodian.
- Once an hour, the custodian builds an **anchor**: the root of a Merkle tree over the latest receipt of every instance, signed, and chained to the anchor before. A **time stamping authority** stamps every anchor according to RFC 3161, ideally a qualified one under eIDAS. The chain of anchors is public.
- An **auditor** reads the history of an instance directly from the custodian, with a token the customer has granted, and checks the events of the customer against it.

An **instance** is a single EventSourcingDB whose chain the custodian keeps. Every instance has an ID, and an API token its client uses.

What the verification proves: that every event the custodian has confirmed is still in the database with the same content, that the events form one unbroken chain, that the custodian has not changed its own history, since the receipts and anchors are signed, chained, time stamped, and public, and how long events stayed without this protection.

## 2. Conventions

- **Hashes** are SHA-256, written as 64 lowercase hexadecimal characters, unless stated otherwise.
- **base64url** means base64 with the URL-safe alphabet and without padding (RFC 4648, section 5). **base64** means the standard alphabet with padding (RFC 4648, section 4).
- **Times** are written in RFC 3339, in UTC, with a fractional part only if it is not zero, as in `2026-09-01T10:05:00Z` or `2023-01-02T13:37:00.0001Z`.
- **Event IDs** are decimal numbers written as strings, starting at `"0"`, and are compared as numbers.
- **JSON** objects that are signed MUST NOT contain members other than the ones specified. Verifiers MUST reject unknown members.

## 3. Events and fingerprints

### 3.1 The hash of an event

The hash of an event is computed from its content as EventSourcingDB does:

1. The **metadata** is the string `specversion|id|predecessorhash|time|source|subject|type|datacontenttype`, joined with vertical bars, with every field exactly as it was written.
2. The **data** is the JSON of the data of the event, byte for byte as it was written. It MUST NOT be parsed and written again, since that may change escapes, whitespace, or the order of members.
3. The hash is `SHA-256(hex(SHA-256(metadata)) || hex(SHA-256(data)))`, where `||` joins the two hexadecimal strings.

The time is part of the metadata as a string. When reading a backup, it MUST be taken as it appears there. When reading a running database through a client SDK that parses it, it is written again in RFC 3339 with the fractional part trimmed of trailing zeros, which matches what EventSourcingDB writes.

### 3.2 The chain of events

Every event carries the hash of the event before it as `predecessorhash`. The first event of a database has the ID `"0"`, and the predecessor hash of 64 zeros (`0000…0000`). Every further event has the ID of the one before plus one.

### 3.3 Backups

EventSourcingDB writes a backup on `POST /api/v1/backup` as newline-delimited JSON. Every line is an object with a `type` and a `payload`:

- `event`: the payload is `{"event": {…}, "hash": "…"}`, the event as it was written, with the members `specversion`, `id`, `time`, `source`, `subject`, `type`, `datacontenttype`, `predecessorhash`, and `data`, and optionally `traceparent` and `tracestate`, which are not part of the hash.
- `schema` (or `eventType`): the schema of an event type, which is not part of the chain.
- `error`: an error the database ran into while backing up. A backup with such a line is incomplete, and MUST NOT be verified.

### 3.4 Fingerprints

A **fingerprint** is the ID and the hash of the latest event of a database, read recursively from the subject `/`. Since every event carries the hash of the one before, the fingerprint of an event covers every event before it.

## 4. Signed objects

### 4.1 JWS profile

Key certificates, receipts, and anchors are JSON Web Signatures in compact serialization ([RFC 7515](https://www.rfc-editor.org/rfc/rfc7515)), signed with Ed25519 ([RFC 8037](https://www.rfc-editor.org/rfc/rfc8037)):

- The protected header has exactly the members `alg`, `typ`, and `kid`. `alg` MUST be `EdDSA`. `typ` names the kind of object, as given below. `kid` names the key that signed it.
- The payload is the JSON of the claims given below.
- Verifiers MUST reject any other algorithm, any other type than the expected one, a header without `kid`, and headers or payloads with members that are not specified.

The **hash of a JWS** is the SHA-256 of the JWS in compact serialization, as a string of ASCII characters, written in hexadecimal. It is what chains receipts and anchors, and what the leaves of the Merkle trees are built from.

### 4.2 Keys and key IDs

All keys are Ed25519 keys. A public key is written as its 32 bytes in base64url. The **key ID** of a public key is the first 16 bytes of the SHA-256 of its 32 bytes, in hexadecimal (32 characters).

The **root key** of the custodian certifies its signing keys. Its public key is published by the operator of the custodian, and is what a verifier trusts. A verifier MUST get it from a source it trusts, not from the custodian's API.

### 4.3 Key certificates

A key certificate states that the root key vouches for a signing key within a period.

- `typ`: `io.thenativeweb.custody.key-certificate`
- `kid`: the key ID of the root key
- Claims:

| Member | Content |
|---|---|
| `keyId` | the key ID of the signing key |
| `publicKey` | the public key of the signing key, in base64url |
| `validFrom` | the start of the period, inclusive |
| `validUntil` | the end of the period, exclusive |

A key certificate is valid if its signature verifies with the root key, and if `keyId` is the key ID of `publicKey`. The signing key may sign at a time `t` if `validFrom ≤ t < validUntil`.

### 4.4 Receipts

A receipt confirms that the custodian has received a fingerprint of an instance at a time.

- `typ`: `io.thenativeweb.custody.receipt`
- `kid`: the key ID of the signing key
- Claims:

| Member | Content |
|---|---|
| `instanceId` | the ID of the instance |
| `eventId` | the ID of the event of the fingerprint |
| `eventHash` | the hash of the event of the fingerprint |
| `receivedAt` | when the custodian received the fingerprint |
| `sequence` | the number of the receipt within its instance, starting at 1 |
| `previousReceiptHash` | the hash of the receipt before, or the empty string for the first one |

A receipt is valid if its signature verifies with a signing key that has a valid key certificate, and if that key may sign at `receivedAt`. The receipts of an instance form a chain: the first one has the `sequence` 1 and an empty `previousReceiptHash`, and every further one has the same `instanceId`, the `sequence` of the one before plus one, and the hash of the one before as `previousReceiptHash`.

### 4.5 Anchors

An anchor is the statement of the custodian for an hour.

- `typ`: `io.thenativeweb.custody.anchor`
- `kid`: the key ID of the signing key
- Claims:

| Member | Content |
|---|---|
| `hour` | the start of the hour, in UTC |
| `root` | the root of the Merkle tree of the hour, in hexadecimal |
| `leafCount` | the number of leaves of the tree |
| `previousAnchorHash` | the hash of the anchor before, or the empty string for the first one |

An anchor is valid if its signature verifies with a signing key that has a valid key certificate, and if that key may sign at the time of its time stamp (see [section 6](#6-time-stamps)). The anchors form a chain: the first one has an empty `previousAnchorHash`, and every further one has the hash of the one before as `previousAnchorHash`, and a later `hour`.

The **digest** of an anchor, which the time stamping authority stamps, is the SHA-256 of the anchor in compact serialization, as a string of ASCII characters.

## 5. Merkle trees

### 5.1 Hashes

The trees follow [RFC 6962](https://www.rfc-editor.org/rfc/rfc6962), section 2.1:

- The hash of a leaf is `SHA-256(0x00 || data)`.
- The hash of an inner node is `SHA-256(0x01 || left || right)`, with the hashes of its children as 32 bytes each.
- The root of a tree over the leaves `D[0:n]` is:
  - for `n = 0`: `SHA-256()`, the hash of nothing (`e3b0c442…b855`),
  - for `n = 1`: the hash of the only leaf,
  - for `n > 1`: the hash of the inner node over the root of `D[0:k]` and the root of `D[k:n]`, where `k` is the largest power of two smaller than `n`.

No node is ever duplicated. The prefixes keep an inner node from passing for a leaf.

### 5.2 Salted leaves

The tree of an hour has one leaf per instance that sent a fingerprint since the anchor before: its latest receipt. The data of that leaf is `salt || receiptHash`, where `salt` is 32 random bytes and `receiptHash` is the hash of the receipt as its 32 bytes. The salt is only handed to the instance the receipt belongs to, and to its auditors, so that the hashes next to a leaf in a proof reveal nothing about other instances. The custodian puts the leaves in random order.

### 5.3 Proofs

A proof that a receipt is part of the anchor of an hour consists of:

| Member | Content |
|---|---|
| `receipt` | the receipt, as a JWS |
| `salt` | the salt of its leaf, in hexadecimal |
| `siblings` | the hashes next to the path from the leaf to the root, from the bottom up |

Every sibling has a `hash`, in hexadecimal, and a `position`, `left` or `right`, which tells on which side of the path it lies. To verify a proof, start with the hash of the leaf, `SHA-256(0x00 || salt || receiptHash)`, and for every sibling in order compute the hash of the inner node, with the sibling on its side. The proof is valid if the result is the `root` of the anchor.

## 6. Time stamps

The custodian has every anchor stamped by a time stamping authority according to [RFC 3161](https://www.rfc-editor.org/rfc/rfc3161):

- The message imprint is the digest of the anchor, with SHA-256.
- The request asks for the certificate of the authority (`certReq`), and carries a nonce.
- The time stamp token is kept in DER, and handed out in base64.

A time stamp is valid if its message imprint is the digest of the anchor, with SHA-256, and if its signature verifies with the certificate it carries. The time of the time stamp is its `genTime`. In detail:

1. The token is CMS signed data ([RFC 5652](https://www.rfc-editor.org/rfc/rfc5652)) with exactly one signer, whose content is the `TSTInfo`.
2. The certificate of the signer MUST be among the certificates the token carries, found by issuer and serial number, or by subject key identifier.
3. The signed attributes MUST name `id-ct-TSTInfo` as the content type, and carry the digest of the `TSTInfo` as the message digest, with SHA-256, SHA-384, or SHA-512.
4. The signature over the signed attributes MUST verify with the key of the certificate, with RSA (PKCS #1 v1.5, or PSS with MGF1 over the same hash) or ECDSA, and SHA-256, SHA-384, or SHA-512.
5. The `genTime` MUST lie within the validity of the certificate.

### 6.1 Qualified time stamps

A time stamp is **qualified** if the time stamping service that issued it was a qualified trust service for time stamps under eIDAS at its `genTime`. This is decided with the EU trusted lists ([ETSI TS 119 612](https://www.etsi.org/deliver/etsi_ts/119600_119699/119612/)):

1. The **list of the lists** (LOTL) is published by the European Commission at `https://ec.europa.eu/tools/lotl/eu-lotl.xml`. It is an XML document with an enveloped XAdES signature. It is trusted if it is signed with one of the certificates the Commission has announced in the Official Journal of the European Union. At the time of writing, that is the announcement C/2026/1944, with the SHA-256 fingerprints of the certificates:

   ```
   c0641c4f7d56c431b1c924742db7fce9c1eef7d7fd212113a2768486b3abcdc5
   e0a620fbb6747362bb933ac44169d676a553444716cf5f31605f12a22b8396b1
   df7e29360c34b2b8d6d5f40325c1d4d12c9922cecd33b7407674a74b2b3ca1e5
   b63d416744e7098bf9ec2caa596a93bc2468e37f8284ba65ecc061711bcbaa18
   236103f03a8031ae8f47f9059bf8de38564cdbfebedde4a597d50f8980aa653b
   d2064fdd70f6982dcc516b86d9d5c56aea939417c624b2e478c0b29de54f8474
   ```

   If the LOTL is signed with another certificate, the pivot lists it names in its `SchemeInformationURI` are followed from the oldest to the newest: every pivot that is signed with a trusted certificate announces, in its pointer to the LOTL, the certificates that may sign the lists after it.
2. The **trusted list of a member state** is found through the pointer of the LOTL whose `SchemeTerritory` is that country, whose `TSLType` is `http://uri.etsi.org/TrstSvc/TrustedList/TSLType/EUgeneric`, and whose `MimeType` is `application/vnd.etsi.tsl+xml`. It is trusted if it is signed with one of the certificates that pointer names as `ServiceDigitalIdentities`.
3. The signature of a trusted list MUST cover the whole list, through a reference with an empty URI and the enveloped signature transform, and every reference MUST match. The lists use exclusive canonicalization, SHA-256 or SHA-512 for digests, and RSA (PKCS #1 v1.5 or PSS) or ECDSA for signatures. The certificate that signs a list MUST have been valid when the list was issued.
4. The **country** of a time stamp is the country of the subject of its certificate, or else of its issuer.
5. The time stamp is qualified if the trusted list of its country has a service of the type `http://uri.etsi.org/TrstSvc/Svctype/TSA/QTST`, whose digital identity, now or in its history, is the certificate of the time stamp, or the certificate that issued it, and whose status at `genTime` was `http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/granted`. The status at a time is the status of the latest `ServiceInformation` or `ServiceHistoryInstance` whose `StatusStartingTime` is not after that time.

A time stamp that is not qualified still proves when an anchor existed, only without the legal weight of a qualified one.

## 7. Recording

This section describes what the custodian records, so that a verifier can tell what to expect. The API between the client and the custodian is not part of this specification.

### 7.1 Sending

The custodian gives every instance two **intervals**: the **minimum interval**, at most once per which the client sends a new fingerprint, and the **heartbeat interval**, once per which the client sends the latest fingerprint again if nothing has changed. By default, they are 60 seconds and 10 minutes. The intervals may change over time, and the custodian keeps their history.

### 7.2 The chain of an instance

The custodian records the entries of an instance in order:

- **Fingerprint recorded**: a fingerprint that continues the chain, confirmed with a receipt. A fingerprint continues the chain if its event ID is at least the one of the latest recorded fingerprint, with the same hash if the ID is the same. Repeating the latest fingerprint, as a heartbeat, gets a receipt of its own.
- **Conflict detected**: a fingerprint that contradicts the chain, because an event now has another hash than before, or because the event stream went backwards. It gets no receipt, and locks the instance.
- **Continuity break reported**: the client found an event that does not follow the fingerprint before it. It locks the instance.
- **Baseline reset**: the operator of the custodian lifted a lock, with a reason, so that the chain of events starts over, for example after a backup of the database has been restored. The chain of receipts continues across a reset.

While an instance is locked, the custodian records no fingerprints.

Every fingerprint names the hash of the latest receipt its client has kept. The custodian only records a fingerprint that builds on its own latest receipt. Any other one is out of date, for example because it arrived late, and is neither recorded nor held against the instance.

### 7.3 Anchoring

Every hour gets an anchor, even without receipts, so that the chain of anchors has no gaps. The anchor of an hour is built 30 seconds after the hour is over. It covers the receipts recorded since the anchor before, up to the first receipt received at or after the end of the hour, with the latest of them for every instance as a leaf. So a receipt from the last moments of an hour may go into the next anchor. The custodian publishes an anchor only once it is stamped, and in the order of the chain.

## 8. The audit API

The custodian answers the auditor under the following paths. Every request except the public chain of anchors carries the auditor token as a bearer token (`Authorization: Bearer <token>`). The custodian answers with `401` for an unknown, expired, or revoked token, and with `403` for a token that may not use a path. It records every use of an auditor token before it answers, so that the customer can see who has read what.

Every answer is a JSON object with a `type` and a `payload`. The reads of the auditor use the HTTP method `QUERY`.

### 8.1 The instance

`QUERY /api/v1/audit/read-instance` answers with the type `io.thenativeweb.custody.audited-instance`, and the payload:

| Member | Content |
|---|---|
| `instanceId` | the ID of the instance |
| `name` | its name |
| `registeredAt` | when it was registered |
| `intervals` | the history of its intervals, each with `validFrom`, `minimumIntervalInMilliseconds`, and `heartbeatIntervalInMilliseconds`, from the oldest on |
| `signingKeyCertificates` | the certificates of every key the custodian has ever signed with |
| `auditAccess` | the access of the auditor, with `id`, `grantedAt`, and `validUntil` |

### 8.2 The chain

`QUERY /api/v1/audit/read-chain?after=<id>` answers with the type `io.thenativeweb.custody.chain`, and the payload `{"entries": […]}`, at most 1,000 entries in the order they were recorded, after the entry with the given ID, or from the start without it. A caller that gets 1,000 entries asks again, after the last one. Every entry has an `id`, a `recordedAt`, a `type`, and exactly one of the following members, depending on the type:

| `type` | Member | Content |
|---|---|---|
| `fingerprint-recorded` | `fingerprintRecorded` | `eventId`, `eventHash`, `sequence`, and `receipt`, the receipt as a JWS |
| `fingerprint-conflict-detected` | `fingerprintConflictDetected` | `storedEventId`, `storedEventHash`, `receivedEventId`, and `receivedEventHash` |
| `continuity-break-reported` | `continuityBreakReported` | `storedEventId`, `storedEventHash`, `observedEventId`, and `observedPredecessorHash` |
| `baseline-reset` | `baselineReset` | `reason` |

### 8.3 The anchors

`QUERY /api/v1/audit/read-anchors?after=<hour>` answers with the type `io.thenativeweb.custody.anchors-with-proofs`, and the payload `{"anchors": […], "signingKeyCertificates": […]}`: at most 100 anchors after the given hour, in RFC 3339, or from the start without it. Every anchor has the members `anchor`, the anchor as a JWS, `timestampToken`, its time stamp token in base64, and `proof`, the proof of the instance as in [section 5.3](#53-proofs), or no `proof` if the instance sent nothing in that hour.

`GET /api/v1/anchors?after=<hour>` answers the same way without a token, with the type `io.thenativeweb.custody.anchors`, and anchors without proofs. It is the public chain of anchors, which keeps the custodian from showing different anchors to different parties.

## 9. The receipts directory

The client keeps what the custodian hands it in its receipts directory:

- `receipts-YYYY-MM-DD.jsonl`: one file per day of `receivedAt`, with one line per receipt, `{"receipt": "<jws>"}`, in the order they were kept.
- `anchors-YYYY-MM-DD.jsonl`: one file per day of the hour, with one line per anchor, `{"anchor": "<jws>", "timestampToken": "<base64>", "proof": {…}}`, as in [section 8.3](#83-the-anchors).
- `certificates/<key-id>.jws`: the certificates of the signing keys.

Sorting the files by name sorts them by day.

## 10. Verification

A verification reads the history of an instance from the custodian, the events of the database of the customer, from a backup or from the running database, and optionally the receipts directory of its client. It checks everything below, and reports every problem as a **finding**, rather than stopping at the first one. Every finding has a **severity**:

- **Manipulation**: data has been changed, or the custodian contradicts itself, its signatures, or the public chain of anchors. The conflicts and continuity breaks the custodian has recorded count as manipulations as well, since a reset of the baseline only explains them.
- **Gap**: events were not protected the way the intervals promise.
- **Notice**: something the auditor should know, for example a reset of the baseline and its reason, or a time stamp that is not qualified.

### 10.1 The custodian

1. At least one key certificate MUST verify against the root key. If none does, the root key is probably the wrong one, and the verification MUST NOT go on. Every other key certificate that does not verify is a manipulation.
2. Every receipt MUST be valid, MUST belong to the instance, MUST match its entry in `eventId`, `eventHash`, and `sequence`, and the receipts MUST form one chain across all entries. Every violation is a manipulation.
3. Every conflict and continuity break is a manipulation, and every reset of the baseline a notice with its reason.
4. Every anchor MUST be valid, its time stamp MUST cover its digest, and the anchors MUST form one chain. Every violation is a manipulation.
5. Every proof MUST lead from its leaf to the root of its anchor, and its receipt MUST be in the chain of the instance. Every violation is a manipulation.
6. An anchor MUST NOT leave out a receipt: the latest receipt received in its hour, at least one minute before its end, MUST be covered by the proof of that anchor, either itself or through a later receipt. A violation is a manipulation.
7. Every anchor the auditor reads MUST appear identically, and in the same place, in the public chain of anchors. A violation is a manipulation.
8. The time between two receipts, and between the latest receipt and the time of the verification, MUST NOT exceed the heartbeat interval valid at the time plus one minute. The time while the instance is locked, from a conflict or a break to the next reset, does not count. A violation is a gap.
9. A receipt whose hour ended more than two hours before the time of the verification MUST be covered by an anchor. A violation is a gap.

### 10.2 The events

1. Every event MUST still hash to its hash ([section 3.1](#31-the-hash-of-an-event)). A violation is a manipulation.
2. The events MUST form one chain ([section 3.2](#32-the-chain-of-events)). Every missing event, and every event that names another predecessor hash, is a manipulation.
3. Every event the custodian has confirmed since the latest reset of the baseline MUST be in the database with the confirmed hash. A different hash, and a confirmed event that is missing, is a manipulation. A difference to a fingerprint from before the latest reset is a notice.
4. An event is **protected** once a receipt covers it, that is, a receipt for it or for an event after it. The time from when an event was written until the first receipt after the latest reset that covers it MUST NOT exceed the minimum interval valid at the time plus one minute. Events written before the latest reset are left out. A violation is a gap, as is an event no receipt covers yet, once it is older than allowed.

### 10.3 The receipts directory

If the receipts directory of the client is given, every receipt and every anchor in it that verifies MUST be held by the custodian identically: every receipt under its `sequence` in the chain, and every anchor, with its time stamp and its proof, under its hour. A receipt or an anchor the custodian no longer holds, or holds differently, is a manipulation. One that does not verify can not be held against the custodian, and is a notice.

### 10.4 The trusted lists

Every time stamp of an anchor that verifies SHOULD be checked against the EU trusted lists ([section 6.1](#61-qualified-time-stamps)). A time stamp that is not qualified is a notice. A verification that does not check the trusted lists MUST say so.

### 10.5 The result

The result of a verification is **manipulation** if there is at least one manipulation, **gaps** if there is at least one gap but no manipulation, and **no findings** otherwise. Notices do not change the result. The report of a verification SHOULD name what was checked: the instance, the custodian, the SHA-256 of the backup or the database, the receipts directory, and the state of the trusted lists, that is, when the list of the lists was issued.

The tool in this repository ends with the exit code `0` for no findings, `1` for a manipulation, `2` for gaps, and `3` if the verification could not be run.

## 11. Test vectors

[`testvectors/testvectors.json`](testvectors/testvectors.json) holds test vectors for this specification. The tests in [`testvectors`](testvectors) check that the code in this repository produces exactly them, and that they verify, so that the specification and the code can not drift apart. The vectors are built from fixed seeds, and Ed25519 signatures are deterministic, so they never change unless a format does.

| Member | Content |
|---|---|
| `rootKey` | the root key, from the seed `01…01`, with its public key and key ID |
| `signingKey` | the signing key, from the seed `02…02`, with its public key, key ID, period, and key certificate |
| `receipts` | three receipts of the instance `instance-1`, with their claims, JWS, and hashes, forming a chain |
| `merkleTree` | a tree over five salted leaves, the first of which is the latest receipt, with its root, and the proofs for the leaves 0 and 4 |
| `anchors` | two anchors with their claims, JWS, hashes, and digests: one over the tree above, and one over an empty tree, which follows it |
| `eventHashes` | five lines of a backup of EventSourcingDB, with the hashes EventSourcingDB has computed for their events |
