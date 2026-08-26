# 34 — Consolidated Pre-Code Security Gate

Status: **OWNER APPROVED — STAGE A ONLY (2026-08-26)**
Prepared: 2026-08-26

This document was the owner review package. The explicit decision recorded in
section 7 authorizes only the inert Stage A boundary. It does not authorize
protected endpoints, cryptographic operations, report content handling,
authentication, file handling, export, deletion, or production deployment.

Its purpose is to replace fragmented approvals with one explicit project-owner
decision and to define the narrow code boundary that may follow that decision.

## 1. Decisions already approved

The following decisions remain approved and are not reopened by this package:

- `docs/20_SUBMISSION_ACCEPTANCE_PROTOCOL.md`: submission sequencing, retry,
  reconciliation, and lost one-time credential response behavior;
- `docs/21_RECOVERY_CREDENTIAL_CONSTRUCTION.md`: Ticket ID, Recovery Secret,
  display-once behavior, and keyed verifier construction;
- `docs/22_NO_JAVASCRIPT_CHALLENGE_PROTOCOL.md`: self-hosted no-JavaScript
  challenge, atomic consumption, and anonymous global abuse controls;
- `docs/23_AUDIT_RECEIPT_AND_TRANSPARENCY_PROTOCOL.md`: event encoding, durable
  receipts, replay controls, Merkle checkpoints, witnessing, and retention;
- `docs/24_RESPONSE_NOTE_CRYPTOGRAPHIC_PROTOCOL.md`: Response Note framing,
  AEAD envelope, non-exportable Response-DEK, staging, first read, and expiry;
- the contained decision in `docs/26_REPORT_CONTENT_CRYPTOGRAPHIC_PROTOCOL.md`
  that accepted report text is strict UTF-8 normalized to NFC and LF and no raw
  pre-normalization copy is retained.

These approvals remain non-authorizing wherever independent review, selected
products, production-equivalent proof, or another named dependency is still
OPEN.

## 2. Decisions approved by the project owner

Approval of this package means approval of the exact versioned profiles and
failure behavior in the following documents, not merely their general intent.

### 2.1 MFA, step-up, and credential lifecycle — `docs/25`

- device-bound hardware WebAuthn credentials, two per person, with no weaker
  fallback;
- separate Operator and Application Administrator RP/origin/session profiles;
- 120-second non-sliding challenge and authorization lifetime;
- deterministic-CBOR HMAC-SHA-256 action/artifact binding with a separately
  held binding key;
- single-use, concurrency-safe consumption with resumable committed workflows;
- in-person, quorum-controlled enrollment, replacement, and recovery.

### 2.2 Original report cryptography — `docs/26`

- one random, non-exportable Report-DEK per report;
- RFC 5869 HKDF-SHA-256 per-object and per-purpose subkeys;
- libsodium XChaCha20-Poly1305-IETF with random nonces;
- deterministic-CBOR context, AAD, envelope, and strict version rejection;
- constant-size canonical text and attachment framing, including the exact
  interpretation of 5 MB as 5 MiB;
- provisional staging, narrow state/lease-bound decryption, and activation only
  after every required durable condition succeeds.

### 2.3 Key Service acceptance — `docs/27`

- candidate-neutral negative capability and workload-authentication matrix;
- non-exportable per-object keys and forward-only lifecycle states;
- prohibition on restorable historical per-object key material;
- production-equivalent destructive snapshot, rollback, stale-replica,
  restore, and disaster-recovery tests;
- binary acceptance with no silent weakening or product exception;
- continued product/topology rejection until the real PoC passes.

### 2.4 Emergency Export — `docs/28`

- exact immutable request binding and single-use authorization;
- closed, deterministic, uncompressed `ustar` package profile;
- RFC 8785 manifest and detached tagged COSE Sign1/Ed25519 signature;
- binary `age` v1 with exactly one native X25519 organization recipient;
- strict recipient/signing key separation and external recipient private-key
  custody;
- fenced and resumable generation with one concurrency winner;
- plaintext-only-in-memory processing and encrypted-only staging;
- one-shot, hash-bound delivery after durable audit and alert acceptance.

### 2.5 File admission, sandbox, and safe view — `docs/29`

- closed JPEG, PNG, and PDF structural acceptance profiles;
- exact decoded size, dimension, page, object, decompression, and time ceilings;
- independent parser/scanner families and fail-closed disagreement behavior;
- fresh Firecracker microVM isolation for each untrusted object;
- bounded transient plaintext with no host filesystem, swap, core, or backup
  persistence;
- metadata-free PNG rasterization as the only ordinary operator view;
- no ordinary original-attachment download capability;
- exact cleanup, crash, fuzz-corpus, and production acceptance gates.

### 2.6 Request and multipart admission — `docs/30`

- exact 21 MiB outer request ceiling and component limits;
- closed multipart grammar and cardinality;
- streaming proxy enforcement before application dispatch;
- bounded Django upload handling inside the designated sandbox boundary;
- no implicit disk spooling or weaker parser fallback;
- independent decoded-resource limits after transport acceptance;
- fixed timeout/rate behavior without reporter fingerprinting;
- failure tests covering truncation, ambiguity, smuggling, exhaustion, and
  cleanup.

### 2.7 Administrator alerts — `docs/31`

- separate self-hosted Alert Service;
- closed, metadata-only alert schema;
- durable administrator inbox plus local SMTP wake-up queue;
- idempotent durable acceptance before acknowledgement;
- Emergency Export failure before artifact work if alert acceptance is
  unavailable;
- retry/escalation/acknowledgement and 365-day alert retention, while deletion
  cleanup and key denial continue independently.

### 2.8 Retention and deletion — `docs/32`

- 90-day expiry for a never-read Response Note and a full 72-hour window when
  its first valid read occurs before that deadline;
- ordinary operator deletion only from OPEN, without a Response Note, using a
  closed reason code and encrypted protected note;
- exceptional content-blind SEALED flood deletion only through the specified
  administrator declaration, infrastructure attestation, two-operator quorum,
  30-minute/100-report cap, and newest-first order;
- durable per-report audit receipt before forward key destruction;
- authoritative key denial/destruction independent of retrying physical
  ciphertext cleanup;
- 30-day minimized terminal metadata, 365-day audit events, and 730-day
  verification evidence under their separately controlled retention authority.

### 2.9 Operational access and workstation hardening — `docs/33`

- physically separate Operator, Application Administrator, and Infrastructure /
  Key Custodian device classes, accounts, credentials, routes, and origins;
- current patched Ubuntu LTS hardened baseline with Secure Boot, passphrase
  LUKS2, no automatic TPM unlock, no swap/hibernate/core dumps, mandatory
  confinement, and drift quarantine;
- current patched Firefox ESR single-origin ephemeral kiosk with persistence,
  extension, telemetry, developer-tool, print, clipboard, capture, external
  protocol, and ordinary download controls;
- role-specific VPN/device identity, strong authentication, session ceilings,
  revocation, and single-session enforcement;
- encrypted-artifact-only Emergency Export transfer broker;
- version-2 administrator step-up bound to actor, device, session, operation,
  target, artifact, and exceptional batch parameters;
- at least three named Key Custodians, two-person ceremonies, hardware-backed
  short-lived SSH certificates, isolated bastion, and command wrappers;
- break-glass limited to isolation, revocation, and availability recovery,
  never report decryption, per-object key restore, or MFA bypass.

## 3. Cross-document effects accepted by this decision

- The 90-day never-read Response Note rule extends the approved `docs/24`
  lifecycle without changing its first-read concurrency or +72-hour rule.
- Exceptional flood deletion uses the administrator step-up version defined in
  `docs/33`; it never binds dummy report identifiers or creates a content-reading
  capability.
- `docs/31` supplies the alert acceptance and delivery semantics referenced by
  export, audit cessation, and persistent deletion-cleanup failures.
- `docs/33` supplies the physical and operational role separation assumed by
  the MFA, export, and Key Service proposals.

No unresolved contradiction has been identified among these effects. Rejecting
or changing any one of them requires re-review of every dependent decision; a
weaker interpretation must not be selected silently.

## 4. Gates that remain OPEN after owner approval

Owner approval is necessary but not sufficient for a protected implementation
or release. At minimum, the following remain blocking where applicable:

- independent cryptographic, authentication, protocol, HTTP/proxy, parser,
  sandbox, network, and operations review;
- exact dependency, tool, font, kernel, root-image, browser, and operating-system
  artifact pinning and vulnerability review;
- selection and production-equivalent destructive PoC of the Key Service;
- selection and acceptance of Audit Service, Alert Service, HSM/signers,
  PostgreSQL, proxy, KVM/Firecracker, trusted clock, service PKI, and workload
  identity implementations;
- legal approval of retention and deletion periods and exceptional flood
  procedure;
- organization recipient-key custody, hardware inventory, staffing, quorum,
  physical security, recovery ceremonies, and production acceptance tests;
- abuse/failure/concurrency tests in `docs/14_SECURITY_TEST_PLAN.md` and the
  release checklist in `docs/18_SECURITY_REVIEW_CHECKLIST.md`.

No placeholder may become an availability-oriented fallback while a required
dependency is unavailable.

## 5. Code authorization matrix after approval

### Stage A — inert implementation permitted

The first implementation stage may create only structures that cannot receive,
persist, decrypt, display, export, or destroy protected content:

- metadata-only Report lifecycle enums, schema, constraints, and migrations;
- metadata-only ReportLease and SecurityOperation fencing structures;
- pure state-transition planners and denial-by-default orchestration shells;
- typed request/receipt descriptors and strict schema validators that do not
  handle reporter-controlled content;
- unavailable adapters for every external security service;
- PostgreSQL integration-test scaffolding and concurrency tests that use only
  synthetic non-sensitive identifiers;
- inert pages and security headers with no report form or protected action.

Stage A data must exclude report text, attachment bytes, original filenames,
recovery credentials, verifier material, cryptographic keys, raw request
metadata, untrusted headers, operator protected notes, and audit/alert free
text.

### Still prohibited

Until each dependent gate is closed, Stage A does not authorize:

- a reporter form or submission POST endpoint;
- plaintext or ciphertext report/attachment persistence;
- file upload, parsing, rasterization, CDR, or sandbox execution;
- actual encryption, decryption, key creation, unwrap, expiry, or destruction;
- reporter recovery, operator login/MFA, claim, OPEN, or content display;
- Response Note staging/finalization/retrieval;
- Emergency Export, administrator alerts, or report deletion;
- production deployment or a claim that the system is ready for real reports.

## 6. First authorized implementation slice

After explicit approval, the recommended first slice is a separate Django
`report_lifecycle` app containing metadata-only Report, ReportLease, and
SecurityOperation concepts, their server-authoritative transitions, database
constraints, and abuse/concurrency tests. It must not duplicate the existing
`submission_workflow` attempt model and must not add any protected endpoint.

SQLite tests may verify pure logic and simple constraints but cannot constitute
the PostgreSQL concurrency or release proof.

## 7. Recorded project-owner decision

The project owner recorded the following decision on 2026-08-26:

> Approvo integralmente le decisioni consolidate in docs/34 e autorizzo lo
> Stage A inerte; mantengo tutti i gate esterni e di produzione indicati.

No exception was recorded. Any future change must identify the document,
subsection, and replacement decision. Implementation may proceed only within
the inert Stage A boundary in section 5.
