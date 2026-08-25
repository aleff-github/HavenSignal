# 14 — Security Test Plan

This is a minimum plan, not a complete penetration-test program.

## Reporter input / logging

Test that:

- report text never appears in logs;
- original filename never appears in logs;
- Recovery Secret never appears in logs;
- POST bodies are not logged;
- parser exceptions cannot inject user input into logs;
- newline/control characters cannot forge log entries.

## Submission sequencing

Under the approved sequence, test every failure boundary between audit acceptance, key creation, encryption, metadata/ciphertext persistence, and one-time credential delivery.

Verify:

- audit unavailability follows the approved fail-closed behavior;
- no accepted report lacks the required truthful audit evidence;
- retry after connection loss cannot silently duplicate a report;
- plaintext never reaches durable temporary/storage paths;
- the system never claims one-time credentials were delivered when the response was lost;
- orphan keys/ciphertexts/metadata are reconciled without logging reporter data.

For `20_SUBMISSION_ACCEPTANCE_PROTOCOL.md`, also verify:

- expired, unknown, consumed, and replayed attempt credentials fail closed;
- synchronized parallel POST copies create one attempt owner and at most one
  Report-DEK, metadata record, ciphertext set, and `SEALED` report;
- `SUBMISSION_ACCEPTANCE_REQUESTED` is durable before key/material creation;
- `SUBMISSION_RECEIVED` is emitted only after exact staged objects and metadata
  are durably verified;
- lost responses never cause credential re-display, replacement credentials,
  or a duplicate report for the same attempt;
- no event or state claims that the reporter received or saved credentials;
- the reconciler cannot obtain plaintext or construct credentials and can only
  finish the evidenced transition or destroy scoped staged material;
- crash injection at each approved phase reaches only an allowed state.

## Original report cryptography

Test:

- RFC 5869 HKDF-SHA-256 vectors and per-report/object/purpose subkey separation;
- pinned XChaCha20-Poly1305 vectors, random nonce uniqueness, combined-mode
  lengths, and byte-identical idempotent retries;
- deterministic-CBOR KDF/AAD/envelope encoding and rejection of every context,
  object, slot, attempt, or key-handle substitution;
- canonical UTF-8/NFC text and fixed 20,005-byte frame validation;
- OPEN and Emergency Export recover the exact same accepted canonical text
  bytes, while no raw pre-normalization representation is persisted, encrypted,
  queued, logged, audited, or backed up;
- attachment framing at 0 and 5,242,880-byte boundaries, fixed ciphertext size,
  kind binding, zero padding, and oversized rejection;
- Reporter Gateway cannot decrypt existing content, Operator Console cannot
  receive original attachment bytes, and sandbox streams cannot be redirected;
- provisional/staged/SEALED activation crashes and races never expose content or
  issue credentials before every approved condition;
- Report-DEK destruction makes every object permanently unusable across live
  replicas, rollback, snapshot, restore, and disaster recovery.

## Recovery enumeration

Test:

- random invalid Ticket ID;
- valid Ticket ID + invalid secret;
- nonexistent Ticket ID + random secret;
- answered ticket;
- unanswered ticket;
- expired response.

Non-success responses should be intentionally uniform in status/body/timing envelope where feasible.

## Session controls

Test:

- CLAIM expires after 5 minutes;
- one operator cannot claim two active reports;
- two operators cannot open the same report concurrently;
- refresh during valid lease remains same OPEN;
- idle timeout after 5 minutes;
- absolute timeout at 60 minutes even with activity;
- stale browser cannot resume after lease invalidation;
- reopening requires reason.
- stale lease generation cannot perform any sensitive action;
- a new generation fences old tabs, delayed requests, and late retries;
- server-side time, not client time, controls idle/absolute expiry;
- database constraints prevent one operator/report from acquiring conflicting active leases.

## Finalization

Test:

- finalization without step-up MFA fails;
- finalization without CAPTCHA fails;
- finalization with audit unavailable fails closed;
- failure to persist Response Note leaves report intact;
- successful finalization destroys report key;
- stale sessions cannot read report after finalization;
- double-submit cannot cause inconsistent state.
- Response Note remains externally unavailable throughout `FINALIZING` until Report-DEK destruction is confirmed and durably audited;
- step-up authorization is bound to operator, ticket, `FINALIZE_RESPONSE`, and exact Response Note digest;
- a step-up authorization cannot be replayed or used for another operation/ticket/artifact;
- crash after each critical finalization phase resumes idempotently with the outcomes defined in `03_DATA_LIFECYCLE.md`;
- export/finalization races have one fenced, deterministic winner;
- Report-DEK destruction confirmation cannot be converted back into a readable-report state.
- committed entry to `FINALIZING` always has the exact staged Response Note ciphertext available for resume;
- after entry to `FINALIZING`, operator rendering/editing, reopen, and Emergency Export fail closed;
- crash after consumed step-up/audit receipt but before committed `FINALIZING` leaves the report OPEN and requires a new authorization.

## Key destruction

Test disaster-recovery scenarios:

- restore DB snapshot after report destruction;
- restore blob snapshot after report destruction;
- restore key-service snapshot/backup if supported.
- restore/rollback each supported live-replica state, including delayed or stale replica scenarios;
- restore combinations of wrapped/encrypted per-object key records, retained infrastructure keys, DB/blob backups, and snapshots;
- repeat the restore tests for expired/destroyed Response-DEKs.

Destroyed report MUST remain undecryptable.

This test is a release gate for the key-management design.

For `32_RETENTION_AND_DELETION_PROTOCOL.md`, also verify:

- 90-day unread expiry versus first read has one server-authoritative winner,
  and a winning pre-deadline read receives exactly the existing 72-hour window;
- operator deletion is OPEN-only and binds the exact reason, protected note,
  operator/session/lease/generation/state, CAPTCHA, step-up, and audit receipt;
- committed deletion states never reopen after crash or uncertain key outcome;
- flood deletion cannot start before closed admission, capacity attestation,
  administrator declaration, two distinct Operator approvals, and audit gates;
- flood selection is SEALED-only, content-blind, newest-first, capped, and skips
  a candidate that loses the state race without substituting another;
- each report destruction has its own pre-action receipt and partial batches
  record truthful per-item outcomes;
- cleanup retry/alert and 30-day metadata expiry cannot recreate keys or shorten
  audit retention.

For each candidate Key Service, execute the complete production-equivalent
`docs/27` PoC, including:

- every caller/operation negative-capability combination;
- synchronized create/activate/use/expiry/destroy races across nodes;
- a replica isolated before destruction and rejoined afterward;
- pre-destruction Raft/product exports plus filesystem, block, VM, memory,
  HSM/KMS/seal, configuration, and combined-backup restoration;
- clock rollback, old receipt/capability replay, leader/quorum failure, upgrade,
  node replacement, seal/key rotation, and complete disaster recovery;
- a binary failure if any restored environment can decrypt one canary.

## File upload

Test:

- exact encoded-body, aggregate-file, part/header/control, timeout, idle, and
  bounded-memory limits from `docs/30` at every ingress/application boundary;
- CL/TE, duplicate/conflicting headers, HTTP/1↔HTTP/2 translation, chunked,
  compressed, nested, truncated, slow, and multipart differential corpora;
- reverse proxy, WAF/APM, Django, queue, filesystem, swap, and backup inspection
  proves no request body/file spool or capture and no automatic POST replay;

- extension spoofing;
- MIME spoofing;
- polyglots;
- oversized body;
- path traversal filename;
- Unicode filename tricks;
- invalid filename characters;
- PDF JavaScript;
- embedded files;
- launch actions;
- malformed PDF;
- decompression/resource exhaustion;
- corrupted JPEG/PNG;
- image parser bombs;
- content with mismatched signature.
- structural-profile boundary cases once the profile is approved;
- page/object/decompression/dimension/resource limits once approved;
- verify proxy, Django upload handling, workers, and temporary workspaces do not durably spool plaintext.

Unsafe/uncertain should fail closed.

## File sandbox

Test:

- no network egress;
- no access to application secrets;
- process timeout;
- memory limit;
- temporary-file cleanup;
- crash cleanup;
- sandbox escape assumptions documented.

## Audit

Test:

- application cannot update/delete audit history;
- operator cannot read audit log;
- administrator can read but not mutate history through normal interface;
- broken audit collector blocks sensitive actions;
- hash-chain/checkpoint verification detects alteration;
- notification fires on audit interruption.
- OPEN/REOPEN Key Service release fails without the required valid pre-action receipt;
- receipts cannot be replayed across operator, report, operation, state version, or lease generation;
- REQUESTED/AUTHORIZED/COMPLETED/FAILED events represent crash and failure outcomes truthfully;
- full reopening/export operator notes never enter permanent audit;
- hash-chain verification detects mutation;
- independent checkpoints detect suffix truncation, gaps, and audit cessation.
- collector-controlled 365-day expiry cannot be accelerated by application/operator roles and preserves the approved checkpoint evidence.
- RFC 8949 deterministic CBOR and closed-schema rejection use published vectors
  and reject alternate encodings, types, sizes, unknown fields, and trailing data;
- COSE Sign1/Ed25519 verification rejects altered payloads, signatures, key IDs,
  algorithms, content types, and key substitution;
- RFC 9162 roots/inclusion/consistency and RFC 9942 receipts match published
  vectors and reject malformed or context-mismatched proofs;
- no receipt bytes are released before the audit event and receipt commit is
  durably complete, including every injected crash point;
- 20–100 synchronized retries over multiple PostgreSQL connections and
  processes produce one leaf and one byte-identical receipt for the same exact
  request, while mismatched retries and reused nonces fail closed;
- mutation, middle deletion, duplicate index, suffix truncation, fork, rollback,
  checkpoint-key substitution, and cessation are detected;
- proposed maximum merge delay, heartbeats, witness liveness, and fail-closed
  issuance cutoff are tested with a controlled clock;
- signer rotations and event/proof retention preserve historical verification
  without granting early-expiry or signing authority to application roles.

SQLite, a single process, an application cache/lock, or an in-memory collector
does not satisfy audit concurrency and durability acceptance.

## Emergency export

Test:

- export requires OPEN state;
- export requires reason;
- export requires CAPTCHA;
- export requires step-up MFA;
- admin alert occurs;
- manifest hashes match exported bytes;
- manifest signature verifies;
- final artifact is encrypted to configured organization key;
- no plaintext temporary artifact persists unexpectedly;
- audit stores artifact hash but not content.
- step-up authorization cannot be reused across export/finalization or tickets;
- permanent audit contains only the reason code, not the full protected note;
- mandatory audit/notification precondition failure blocks artifact release;
- crash/timeout cleanup removes plaintext temporary package components;
- accepted residual risk is documented and not misrepresented as prevented.
- the exact deterministic-CBOR request descriptor binds note, reason, immutable
  content envelopes, operator/session/lease/state, and active recipient/signer;
- only the closed uncompressed `ustar` profile and fixed safe member order,
  paths, metadata, sizes, padding, and end marker are accepted;
- RFC 8785 manifest bytes, detached tagged COSE Sign1/Ed25519, external key
  registry, and every exact content hash verify independently;
- binary `age` v1 contains exactly one native X25519 recipient and rejects
  passphrase, plugin, SSH, hybrid, multiple-recipient, armored, and unknown
  profiles for version 1;
- export/export, export/finalization, export/deletion, stale worker, lease
  expiry, duplicate request, and delivery replay races have one fenced winner;
- no plaintext package/member or private recipient key appears in filesystem,
  swap, core, queue, log, audit, alert, trace, proxy, or backup inspection;
- the organization-side canary decrypt/signature/content ceremony succeeds,
  while the production platform demonstrably lacks the recipient private key;
- encrypted staging is never released before the durable COMPLETED receipt and
  one-shot POST delivery cannot be resumed, replayed, or served after expiry.

## Recovery and Response-DEK

Test:

- Recovery Secret is never the sole material sufficient to decrypt a restored Response Note ciphertext;
- first valid read uses server time and fixes expiry at +72 hours;
- repeated valid reads work only inside the approved 72-hour window;
- Response-DEK destruction invalidates recovery state and leaves restored ciphertext unusable;
- server-authoritative expiry denies use even while replica/key-material/ciphertext cleanup is retrying;
- old Response-DEK replicas, snapshots, rollback, or disaster recovery cannot resurrect an expired response;
- concurrent first reads establish one immutable `first_read_at`/expiry and later reads cannot extend it;
- server never emits the Recovery Secret a second time;
- verifier key/material is purpose-separated and never logged.
- XChaCha20-Poly1305 key/nonce/tag sizes, official vectors, combined-mode length,
  and pinned library behavior match the approved profile;
- deterministic-CBOR AAD/envelope bytes reject unknown/alternate schemas and
  any cross-report, response, finalization, or key-handle substitution;
- canonical NFC/LF/UTF-8 framing rejects invalid scalars, invalid lengths,
  nonzero padding, malformed UTF-8, and over-limit text;
- all allowed Response Note lengths produce one constant ciphertext length;
- the Django/application boundary never receives or persists Response-DEK
  material and exposes no general decrypt/unwrap operation;
- provisional create, PostgreSQL `FINALIZING` commit, verification, activation,
  and every injected crash point remain idempotent and reporter-invisible;
- 20–100 synchronized first-read attempts across PostgreSQL connections and
  processes establish one immutable expiry before any decrypt;
- Key Service expiry remains authoritative while database/workers/cleanup are
  unavailable, stale, delayed, or rolled back.

## Roles and capabilities

Test:

- Application Administrator cannot read reports, obtain DEKs, invoke unwrap/decrypt, or impersonate an operator through reset/recovery/session functions;
- Infrastructure / Key Custodian does not inherit operator, application-administrator, audit-reader, or report-reader privileges;
- Application Administrator authentication requires the approved strong MFA and cannot reset/enroll an operator factor under administrator control;
- Reporter Gateway cannot invoke general decrypt/unwrap for existing SEALED reports;
- Key Service authorization is rejected for the wrong role, operation, report, state, lease generation, or receipt.

## WebAuthn, step-up, and credential lifecycle

Test:

- exact RP ID/origin, challenge, ceremony type, UV/UP, signature, COSE
  algorithm, AAGUID/attestation, device-bound backup flags, credential ownership,
  and extension validation;
- challenge and StepUpAuthorization entropy, 120-second non-sliding expiry,
  single use, and absence from URLs/logs/browser persistence;
- deterministic-CBOR HMAC artifact binding rejects any byte or
  operator/session/operation/report/lease/version change;
- synchronized multi-process consumption has one database winner and resumes
  only the immutable committed workflow after crashes;
- operator/admin credential, RP, session, cookie, role, and deployment
  separation prevents administrator impersonation;
- two-key enrollment, lost-one replacement, lost-all in-person recovery,
  separate-role quorum, 24-hour delay, and unavailable-quorum denial;
- SMS, email, TOTP, recovery links/codes, password-only, remote help-desk, and
  administrator-only fallback paths do not exist.

## CAPTCHA

Test:

- all challenge resources and validation are self-hosted;
- mandatory operations fail closed when challenge generation/verification is unavailable;
- no-JavaScript challenges are single-use, expire according to the approved policy, and cannot be replayed;
- neither CAPTCHA path uses IP/device fingerprinting or third-party tracking;
- Tor Browser Safest remains usable after the no-JavaScript technology is approved.

## Alerts

Test:

- audit gaps/cessation, persistent ciphertext deletion failure, and Emergency Export trigger the approved alert path;
- alert payloads contain only allowlisted controlled metadata;
- alert transport failure follows the approved retry/fail-closed behavior without leaking sensitive data.

For `31_ADMINISTRATOR_ALERT_PROTOCOL.md`, also verify:

- the Alert Service never acknowledges before the inbox row and fixed-template
  SMTP queue item commit durably;
- identical/conflicting concurrent retries create one logical alert and cannot
  extend or rewrite its accepted time;
- Emergency Export fails before authorization consumption or artifact work when
  durable alert acceptance is unavailable;
- deletion retry, key denial/destruction, and audit fail-closed deadlines do not
  wait for alert delivery;
- SMTP/console outages, acknowledgement races, retention failure, and restarts
  preserve the exact alert state and escalation schedule;
- prohibited sentinels never reach alerts, source outboxes, SMTP, logs, metrics,
  traces, or errors.

## Browser caching

Test headers and browser behavior for:

- reporter secret display page;
- operator report page;
- Response Note retrieval.

Verify no-store behavior and absence of intentional local persistence.

## Dependency/security checks

Before release:

- dependency vulnerability scanning;
- Django deployment checks;
- static analysis;
- secret scanning;
- container/image scanning if containers used;
- manual review of security-sensitive code.
