# 31 — Administrator Alert Protocol

## Status

**OWNER-APPROVED DESIGN (2026-08-26) — independent security/operations review
remains required. No alert-dependent operation is authorized for production.**

This proposal selects the self-hosted alert boundary, closed payload, durable
acceptance contract, administrator inbox, local SMTP wake-up channel,
acknowledgement, retry/escalation, retention, and per-operation failure policy.
It does not approve a PostgreSQL topology, SMTP implementation, administrator
workstation/session profile, service-authentication mechanism, deployment, or
on-call staffing procedure.

## Governing requirements

- `SEC-LOG-005..012`;
- `SEC-AUTH-008..009`;
- `SEC-DEL-006`;
- `SEC-FINALIZE-005`;
- `SEC-EXPORT-002`;
- `SEC-ALERT-001..003`;
- `SEC-ROLE-001..004`.

The trust boundaries in `docs/15` and `docs/19`, audit protocol in `docs/23`,
MFA proposal in `docs/25`, and Emergency Export proposal in `docs/28` remain
authoritative. A conflict stops implementation and returns the decision to the
project owner.

## Security outcome

Version 1 provides:

1. one separately deployed, self-hosted Alert Service;
2. durable acceptance before an alert-gated operation may proceed;
3. a closed, content-free alert schema;
4. a durable administrator inbox plus a self-hosted SMTP wake-up queue;
5. idempotent retry without duplicate logical alerts;
6. visible acknowledgement without deletion or rewriting;
7. an explicit distinction between operations that fail closed and cleanup
   operations that must continue forward.

An alert is evidence that a controlled condition was accepted for delivery. It
does not prove that a human saw, understood, or acted on it. Human
acknowledgement is recorded separately and never retroactively authorizes a
protected operation.

## Boundary and negative capabilities

The Alert Service owns a dedicated PostgreSQL database, administrator inbox,
and outbound queue. It is not a Django in-process helper and does not share the
report database credential.

The service may:

- authenticate an allowlisted source service;
- accept only that source's registered alert types;
- assign alert identifiers and server timestamps;
- durably store the closed alert record and SMTP wake-up job;
- expose alerts and acknowledgement state to the Application Administrator
  Console through a separate read/ack credential.

It must not:

- read reports, attachments, Response Notes, protected operator notes, recovery
  state, ciphertext, or DEKs;
- accept arbitrary message text, subject lines, recipient addresses, template
  fragments, URLs, headers, or attachments;
- mutate audit history or authorize a report operation by itself;
- let an operator, Application Administrator, or report application backdate,
  delete, suppress, downgrade, or shorten retention of an accepted alert;
- provide a general relay or caller-selected destination.

Alert-submit, alert-read, acknowledge, template/configuration administration,
SMTP-delivery, and retention-expiry credentials are distinct. The Reporter
Gateway has no alert-read or administrator-alert capability.

## Exact closed request and accepted record

All identifiers are random/system-generated internal values. No public Ticket
ID, Recovery Secret, reporter identity, reporter network metadata, original
filename, free text, or content-derived digest is permitted.

The authenticated caller submits deterministic CBOR matching:

```text
alert-submit-request-v1 = [
  version: 1,
  alert-type: controlled-tstr,
  severity: "HIGH" / "CRITICAL",
  object-kind: controlled-tstr,
  object-id: bstr .size 16 / nil,
  operation-id: bstr .size 16,
  actor-kind: "NONE" / "OPERATOR" / "APPLICATION_ADMIN" / "SERVICE",
  actor-id: bstr .size 16 / nil,
  source-event-id: bstr .size 16 / nil,
  condition-code: controlled-tstr,
  idempotency-id: bstr .size 16
]
```

The Alert Service authenticates and supplies `source-profile` and
`source-instance-id`; the caller cannot override them. Each alert type fixes
the allowed source, severity, object/actor rules, and condition-code registry.
Unknown fields, values, encodings, combinations, or caller/type mappings are
rejected.

The durably stored record is:

```text
administrator-alert-v1 = [
  version: 1,
  alert-id: bstr .size 16,
  alert-type: controlled-tstr,
  severity: "HIGH" / "CRITICAL",
  source-profile: controlled-tstr,
  source-instance-id: bstr .size 16,
  object-kind: controlled-tstr,
  object-id: bstr .size 16 / nil,
  operation-id: bstr .size 16,
  actor-kind: controlled-tstr,
  actor-id: bstr .size 16 / nil,
  source-event-id: bstr .size 16 / nil,
  condition-code: controlled-tstr,
  accepted-at-ms: uint,
  delivery-state: "QUEUED" / "DELIVERED" / "DELIVERY_RETRY",
  acknowledged-at-ms: uint / nil,
  acknowledged-by: bstr .size 16 / nil
]
```

`alert-id` and `accepted-at-ms` are Alert-Service controlled. Delivery and
acknowledgement changes are append-only state transitions with a separate
history row; previous values are never overwritten invisibly. An
acknowledgement has no free-text field.

## Initial version-1 alert registry

| Alert type | Severity | Required trigger | Required source |
|---|---|---|---|
| `AUDIT_GAP_DETECTED` | CRITICAL | missing, duplicate, changed, or non-contiguous committed audit evidence | checkpoint signer or witness |
| `AUDIT_FORK_OR_ROLLBACK` | CRITICAL | inconsistent checkpoint, tree fork, rollback, or invalid proof | witness |
| `AUDIT_CESSATION` | CRITICAL | no valid witnessed checkpoint for more than seven minutes | witness |
| `AUDIT_INCLUSION_LATE` | CRITICAL | accepted event lacks valid inclusion after 90 seconds | witness |
| `CIPHERTEXT_DELETE_PERSISTENT_FAILURE` | HIGH | deletion remains incomplete for 15 minutes after first failed attempt | Security Workflow Coordinator |
| `EMERGENCY_EXPORT_REQUESTED` | CRITICAL | exact export request is audit-receipted and awaits operation authorization | Emergency Export Worker |
| `EXPORT_STAGING_CLEANUP_FAILURE` | CRITICAL | encrypted export staging remains after its cleanup deadline | Emergency Export Worker |
| `KEY_STATE_MISMATCH` | CRITICAL | forbidden regression, expiry extension, stale replica, or context mismatch | Key Service or coordinator |
| `WEBAUTHN_COUNTER_REGRESSION` | CRITICAL | approved nonzero authenticator counter regresses or repeats | Authentication Service |
| `SECURITY_CREDENTIAL_CHANGE` | HIGH | enrollment, factor replacement/recovery, or privileged credential state change | Authentication Service |

Adding a type, changing severity, broadening a source, or adding a field is a
reviewed protocol change. A runtime administrator cannot create a content-bearing
custom alert.

The deletion threshold does not postpone retries. The coordinator starts
retrying immediately; at 15 minutes it creates exactly one logical persistent
failure alert and continues retrying until deletion succeeds.

## Durable acceptance and idempotency

The Alert Service enforces uniqueness on:

- `(source-profile, idempotency-id)`;
- `(source-profile, operation-id, alert-type)`;
- `alert-id`.

For a first valid request, one serializable/locked transaction:

1. authenticates the caller and validates the exact closed profile;
2. reserves the idempotency and logical-alert keys;
3. assigns the alert ID and trusted server time;
4. stores the exact request digest and alert record;
5. creates the fixed-template outbound SMTP queue item for every configured
   administrator recipient group;
6. commits using approved synchronous durability;
7. returns the stored alert ID and accepted time only after commit.

There is no memory-only acknowledgement, asynchronous "accept now, persist
later" path, caller-local substitute, or success when the transaction outcome
is unknown. An identical retry returns the original record without changing
time or generating another logical alert. Reuse with different bytes or a
second idempotency ID for the same operation/type is rejected and itself
creates controlled security evidence when the service is able to do so.

The source authenticates the Alert Service over the approved mutually
authenticated service channel and validates the returned alert ID against the
same operation. This response is an operational durable-acceptance
confirmation, not a transferable bearer capability and not a replacement for
the signed Audit Service receipt.

## Self-hosted delivery

The primary delivery surface is the durable alert inbox in the separately
authenticated Application Administrator Console. The console reads from the
Alert Service; it does not copy alert rows into the report database. Critical
unacknowledged alerts are always pinned above configuration and ordinary audit
views.

The secondary wake-up channel is an organization-operated SMTP relay and
organization-controlled mailbox group. The Alert Service owns the durable
outbound queue. No cloud email API, public push service, external webhook,
analytics service, or third-party incident platform is part of the supported
profile.

SMTP content is generated from one fixed template:

```text
Subject: [AnonymousReporting] <SEVERITY> security alert
Body: Alert <base32 alert-id> requires review in the administrator console.
```

Email contains no alert type, object/actor/source identifier, condition code,
report URL, one-click acknowledgement, attachment, or arbitrary string. The
base32 alert ID is system-generated and is not a bearer secret. Recipients are
selected only from version-controlled deployment configuration; the caller
cannot supply an address.

Durable Alert-Service acceptance means that both the inbox row and SMTP queue
item committed. It does not mean final SMTP delivery or human receipt. SMTP
failure therefore does not erase an accepted alert or falsify the protected
operation's precondition.

## Retry, escalation, and acknowledgement

SMTP delivery retries after approximately 1, 2, 5, 15, 30, and 60 minutes,
then hourly. Jitter of at most 10 percent is service-generated to avoid a
thundering herd. Retry continues until delivered or the alert expires under the
retention rule; no caller can shorten it.

For an unacknowledged CRITICAL alert, additional fixed-template wake-ups are
queued at 5 minutes, 15 minutes, and every 60 minutes thereafter. HIGH alerts
repeat at 30 minutes and every four hours. The administrator console shows
elapsed time and delivery state using Alert-Service time.

Acknowledgement requires a current strong-MFA Application Administrator
session, CSRF protection, a POST-only random action nonce, current alert
version, and a durable `ADMINISTRATOR_ALERT_ACKNOWLEDGED` audit event. It records
only administrator ID and server time. It does not mark the underlying
condition resolved, stop technical remediation, authorize report access, or
delete evidence. Duplicate concurrent acknowledgement has one database winner
and returns the existing result.

Configuration, template, recipient-group, retention, and routing changes require
step-up MFA, a durable `SECURITY_CONFIGURATION_CHANGED` audit receipt, and
separate-role approval under the operational hardening procedure. They cannot
take effect from the alert acknowledgement page.

## Per-operation failure policy

| Condition | Required behavior when Alert Service durable acceptance is unavailable |
|---|---|
| Emergency Export precondition | Fail closed before consuming authorization or creating the export job; no plaintext access, artifact, or release |
| Audit gap/fork/cessation/inclusion failure | Witness persists the closed alert intent locally and retries; Audit Service still stops protected receipt issuance on the `docs/23` deadline |
| Persistent original/response ciphertext deletion failure | Never recreate a key and never delay deletion retry; persist closed alert intent, continue cleanup, and retry alert delivery |
| Export encrypted-staging cleanup failure | Keep object inaccessible, continue deletion retry, persist alert intent, and never extend download capability |
| Key-state mismatch or expiry extension attempt | Deny key use immediately, quarantine the affected workflow, persist closed alert intent, and retry alert delivery |
| WebAuthn counter regression | Deny and disable the credential immediately, terminate applicable sessions, persist closed alert intent, and retry alert delivery |
| Privileged credential change requiring notification | Account remains disabled/pending; no enrollment, recovery, or replacement completion |

Persisted source alert intents use the same closed fields, contain no arbitrary
payload, and are inaccessible to operators/reporters. They are removed only
after byte-matching durable Alert-Service acceptance. They do not satisfy an
alert-gated precondition by themselves.

## Retention and expiry authority

Alert records, delivery attempts, and acknowledgement history are retained for
365 days from Alert-Service time. Only a separately credentialed retention job
may expire eligible records. Application, operator, administrator, alert-read,
SMTP, and source credentials cannot delete alerts or accelerate expiry.

The corresponding audit event and verification-evidence retention remain
governed by `docs/23`; deleting an eligible alert does not delete or rewrite
audit evidence. Source outbox intents accepted by the Alert Service are removed
promptly because the durable alert becomes authoritative.

## Prohibited data and observability

No alert, SMTP item, delivery error, metric, trace, application log, or source
outbox may contain:

- report or Response Note text or a content-derived digest;
- attachment bytes, metadata, or original filename;
- Recovery Secret, verifier, CAPTCHA answer, challenge, session handle, or URL;
- cryptographic key material;
- protected or arbitrary operator notes;
- reporter IP address, User-Agent, header, cookie, query, or request body;
- raw exception, SMTP response body, or parser output;
- caller-selected labels, addresses, templates, or headers.

Operational logs use only fixed codes, alert ID, source profile, attempt count,
and bounded timing/result fields. SMTP errors are mapped to a closed result
registry before storage or logging.

## Failure behavior

| Failure | Required result |
|---|---|
| Unknown caller/type/field/value/encoding | Reject with one controlled result |
| Alert database, trusted time, or synchronous durability unavailable | No acceptance confirmation |
| Commit outcome unknown | Retry only the same idempotency context; do not claim acceptance |
| Identical retry | Return original alert ID/time; no duplicate logical alert |
| Conflicting retry or operation/type duplicate | Reject; preserve controlled evidence |
| SMTP unavailable after durable acceptance | Keep inbox alert and queue; retry/escalate without leaking relay error text |
| Administrator console unavailable | Alert remains durable; SMTP wake-up continues; no report-content fallback channel |
| Acknowledgement audit unavailable | Do not acknowledge; alert remains unacknowledged |
| Retention job unavailable | Retain alerts longer; never delete early |
| Alert Service restored | Drain source intents idempotently in original source-time order where known |

## Required tests before enablement

Release-blocking tests must prove:

- closed-schema and deterministic-CBOR validation rejects unknown/extra fields,
  alternate types, wrong lengths, arbitrary strings, and caller/type mismatch;
- no accepted response is returned before the alert row and every outbound
  queue item commit durably;
- crash injection before/after commit/reply reaches only the documented state;
- 20–100 synchronized identical/conflicting submissions across PostgreSQL
  connections and processes create one logical alert and stable acceptance;
- Emergency Export cannot consume authorization, create a job, decrypt, stage,
  or release when alert durable acceptance is unavailable;
- alert failure never delays key denial/destruction or physical-deletion retry;
- audit cessation still stops protected receipts within `docs/23` limits when
  the Alert Service is unavailable;
- fixed templates and recipient configuration cannot be influenced by any
  request, report, filename, note, header, or exception;
- SMTP outage, mailbox rejection, restart, queue corruption, console outage,
  acknowledgement races, and retention failure preserve the required state;
- operator/reporter credentials cannot read or acknowledge alerts and
  administrator credentials cannot read reports or mutate alert history;
- every prohibited-data sentinel is absent from alert DB, source outbox, SMTP,
  logs, audit, metrics, traces, and errors;
- application/administrator credentials cannot shorten 365-day retention.

SQLite, an in-memory queue, a mock SMTP sink, one-process concurrency, or a
best-effort logging handler is insufficient for production acceptance.

## Consolidated decisions approved at the pre-code gate

The project owner approved the following on 2026-08-26:

1. a separately deployed self-hosted Alert Service with durable administrator
   inbox and organization-operated SMTP wake-up relay;
2. the exact closed alert request/record and initial alert registry;
3. synchronous durable acceptance with idempotent transaction semantics;
4. the retry/escalation/acknowledgement policy and 365-day retention;
5. the per-operation failure matrix, including fail-closed Emergency Export and
   non-blocking forward cleanup/key denial;
6. the fixed metadata-free SMTP template and no third-party delivery service.

Independent security/operations review, service authentication, PostgreSQL
durability/concurrency, SMTP/administrator mailbox deployment, administrator
access hardening, retention-job isolation, monitoring, and staffing/runbook
acceptance remain required after owner approval.

## External design references

- [RFC 8949 — Concise Binary Object Representation (CBOR)](https://www.rfc-editor.org/rfc/rfc8949.html)
- [RFC 5321 — Simple Mail Transfer Protocol](https://www.rfc-editor.org/rfc/rfc5321.html)
- [RFC 6531 — SMTP Extension for Internationalized Email](https://www.rfc-editor.org/rfc/rfc6531.html)
