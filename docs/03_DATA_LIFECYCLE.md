# 03 — Data Lifecycle and State Machine

## Main states

### SEALED

The report exists encrypted and has not been opened for operator processing.

No operator has ordinary content access.

### CLAIMED

An operator has reserved the report and committed to processing it.

No content has yet been disclosed.

CLAIMED expires after 5 minutes if OPEN is not started.

### OPEN

The report is being processed by exactly one operator under an active server-side lease.

Timeouts:

- idle: 5 minutes;
- absolute: 60 minutes.

### INTERRUPTED

The previous OPEN session ended unexpectedly or timed out before finalization.

A future opening requires an explicit reopening reason.

### FINALIZING

The operator has requested irreversible final publication and the system is executing the idempotent, resumable multi-service finalization protocol.

The encrypted Response Note may be durably staged in this state but is not visible to the reporter.

### RESPONSE_AVAILABLE

The Report-DEK destruction has been durably confirmed and audited. Only now may the final Response Note become observable to the reporter.

### DESTROYED

Original report text/attachments are cryptographically irrecoverable and ciphertext deletion is completed or pending secure retry.

`DESTROYED` describes the original-report lifecycle. `RESPONSE_AVAILABLE` describes the separate Response Note lifecycle and may coexist with `DESTROYED` until Response-DEK expiry.

### DELETED_WITH_REASON

The operator explicitly closes a report as spam, empty, or unmanageable without a Response Note.

The content is destroyed.

Permanent audit retains only system-controlled identifiers, an allowlisted reason code, and structured outcome metadata. Any operator note follows the encrypted operational-history lifecycle and is destroyed with the ticket.

## State transitions

```text
SEALED
  |
  | CLAIM
  v
CLAIMED
  | \
  |  \ 5 min without OPEN
  |   -> SEALED
  |
  | OPEN
  v
OPEN
  | \
  |  \ timeout/crash/lease loss
  |   -> INTERRUPTED
  |
  | REOPEN requires reason
  |
  | emergency export (does not stop normal lifecycle)
  |
  | request finalization + CAPTCHA
  | action-bound step-up MFA
  | durable FINALIZATION_REQUESTED receipt
  v
FINALIZING
  |
  | persist/verify protected Response Note (not visible)
  | destroy Report-DEK and obtain durable confirmation
  | audit REPORT_KEY_DESTROYED
  v
ORIGINAL DESTROYED + RESPONSE_AVAILABLE
  |
  | delete original ciphertext or retry + alert (original remains DESTROYED)
  | first_read_at + 72h -> deny use, destroy Response-DEK, invalidate recovery state
  v
ORIGINAL DESTROYED + RESPONSE DESTROYED
```

`ANSWERED` is retained only as a historical term. It MUST NOT represent a reporter-visible state before durable Report-DEK destruction confirmation. Implementations should use `FINALIZING` and `RESPONSE_AVAILABLE` explicitly.

## Finalization protocol

Finalization is not one distributed atomic transaction. The approved order is:

1. receive the operator's finalization request and validate the current OPEN lease/state version;
2. validate CAPTCHA;
3. consume action-bound step-up authorization tied to the exact Response Note digest;
4. durably record `FINALIZATION_REQUESTED` and obtain its audit receipt;
5. construct the protected Response Note, then revalidate the OPEN lease/current state version and commit the exact staged ciphertext plus transition to `FINALIZING` together; the staged response remains non-visible;
6. verify the staged Response Note as durable;
7. request Report-DEK destruction;
8. obtain durable Key Service confirmation that destruction propagated as required;
9. durably record `REPORT_KEY_DESTROYED`;
10. make the Response Note `RESPONSE_AVAILABLE`;
11. invalidate every report lease/session capability;
12. start physical original-ciphertext deletion and retry/audit/alert failures.

Entering `FINALIZING` freezes the exact Response Note bytes and ends ordinary operator content access, editing, reopening, and Emergency Export for the report. Only the narrowly scoped finalization protocol may resume.

Every phase must be idempotent, resumable after crash, safe for retry, fenced by current state/version, and resistant to double submit and export/finalize races.

`docs/24_RESPONSE_NOTE_CRYPTOGRAPHIC_PROTOCOL.md` contains the owner-approved
exact Response Note byte profile, ciphertext envelope, non-exportable
Response-DEK operations, staging, and first-read expiry sequence. It remains
non-authorizing pending independent cryptographic/protocol review and its named
production gates.

Required crash outcomes:

- after step-up/audit receipt but before the committed staged-response/`FINALIZING` transition: the report remains OPEN, no response is visible, and a new operator authorization is required for another attempt;
- after the committed `FINALIZING` transition: the exact staged Response Note is present for safe resume and no response is visible;
- after Response Note staging but before Report-DEK destruction confirmation: the response remains invisible and finalization resumes;
- after confirmed Report-DEK destruction but before its audit completion: no report plaintext is reopened; completion resumes without attempting to recreate the key;
- after `REPORT_KEY_DESTROYED` audit but before availability: availability publication resumes idempotently;
- after availability but before blob deletion: ciphertext deletion retries without affecting Response Note availability.

## Reopening

A report may be reopened multiple times.

Each reopening is independently logged.

Reopening does not require supervisor approval in the current baseline.

There is no fixed maximum reopening count.

Every reopening reason:

- maximum 150 characters;
- must warn the operator not to include report content;
- is encrypted as operational ticket history and destroyed with the ticket;
- is not copied into permanent audit.

Permanent audit records only the allowlisted system reason code and structured outcome metadata.

A report reopened by Alice after Alice previously opened it is another opening event.

A first opening by Bob is Bob's first opening but remains a subsequent opening event for the report.

## Locking

At most one active processing lease may exist for a report.

At most one active report may exist for an operator.

State transitions MUST be concurrency-safe and transactionally guarded against:

- double claim;
- simultaneous open;
- overlapping response creation;
- double finalization;
- export/finalization races;
- reopening races.

Each OPEN period uses a persisted `ReportLease` containing the report identifier, operator identifier, random lease identifier, monotonically increasing generation/fencing token, `opened_at`, `last_activity_at`, `absolute_expires_at`, and state/version.

Only server-side time is authoritative. Every sensitive OPEN action validates the operator, lease identifier, current generation, report state, idle expiry, and absolute expiry. A new generation invalidates every stale tab, session, request, and retry from earlier generations.

## Delayed reports

A SEALED report remains until processed.

After 7 days from receipt, it should be distinguishable internally as delayed.

After 30 days, it should be distinguishable internally as urgent.

No automatic deletion occurs solely because the report is old.

`docs/32_RETENTION_AND_DELETION_PROTOCOL.md` retains this rule,
adding a 90-day maximum for only a never-read Response Note, and defining the
separate terminal-metadata cleanup lifecycle. The design is owner-approved;
legal/operational and independent review and production gates remain OPEN.

## Interrupted reports

No automatic expiration period is currently defined for INTERRUPTED.

This should be revisited during operational-policy review.

## Inert Stage A implementation evidence

The current controlled errors, closed report/lease/operation state graphs,
pure transition and lease planners, fenced operation bindings, metadata-only
models, and PostgreSQL-only persistence boundary are guarded by a non-executing
exact-AST policy. It fixes the five-minute idle rule, monotonic versions and
lease generations, UUID and current-state bindings, database constraints,
creation-only direct model behavior, PostgreSQL capability checks, and the
reviewed metadata-only preparation, rehydration, activation, and prepared-abort
executors.

The scanner never imports, executes, or echoes target source. Separate runtime
tests exercise preparation, post-reconnection rehydration, activation, and
prepared abort on PostgreSQL, including exact one-winner 20-process contention,
a mixed activation/abort race, and rollback after injected result-construction
failures. This evidence enables no protected operation, content access,
authentication, audit receipt, key operation, deletion, or production
capability.

The recovery eligibility Stage A descriptors additionally represent only the
Response Note eligibility labels and timing facts around `RESPONSE_AVAILABLE`,
the 90-day never-read deadline, the 72-hour first-read window, generic
non-success, and recovery-state invalidation requirements. They do not
implement state lookup, first-read concurrency, decryption, key destruction,
endpoint behavior, or recovery authorization.

## Flood / sealed deletion

During a major flood of submissions, deletion of still-SEALED reports may be required.

This MUST NOT be implemented as automated "spam intelligence" in the baseline.

Any deletion mechanism for SEALED content must be exceptional, attributable, audited, and designed with explicit acknowledgment that a legitimate report could be destroyed.

`docs/32_RETENTION_AND_DELETION_PROTOCOL.md` defines the exact exceptional
capacity-flood ceremony, content-blind SEALED-only selection, multi-person
authorization, per-report receipt/destruction flow, and race behavior. Its
owner approval does not authorize implementation before every legal,
independent-review, service, staffing, and production gate closes.
