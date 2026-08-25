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

## File upload

Test:

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

## Roles and capabilities

Test:

- Application Administrator cannot read reports, obtain DEKs, invoke unwrap/decrypt, or impersonate an operator through reset/recovery/session functions;
- Infrastructure / Key Custodian does not inherit operator, application-administrator, audit-reader, or report-reader privileges;
- Application Administrator authentication requires the approved strong MFA and cannot reset/enroll an operator factor under administrator control;
- Reporter Gateway cannot invoke general decrypt/unwrap for existing SEALED reports;
- Key Service authorization is rejected for the wrong role, operation, report, state, lease generation, or receipt.

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
