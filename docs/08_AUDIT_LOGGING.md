# 08 — Audit Logging and Tamper Evidence

## Purpose

Because original report content is intentionally destroyed after processing, the audit trail is the durable evidence of who performed sensitive operations and when.

Audit integrity is therefore a primary security property.

## Separation

Audit storage must be separate from report content storage.

The report application should have append/send capability only.

It must not have historical UPDATE/DELETE/TRUNCATE authority.

Operators cannot read audit logs.

The Application Administrator can read authorized audit logs but cannot use that role to decrypt reports or impersonate an operator.

## Reporter-controlled data prohibition

No arbitrary reporter-controlled value may be written into audit or application logs.

This includes:

- report text;
- original filename;
- file metadata;
- file contents;
- Recovery Secret;
- request body;
- untrusted query values;
- arbitrary headers;
- arbitrary exception messages that embed user input.

Never log raw `str(exception)` from untrusted processing without controlled sanitization.

## Structured event design

Events use system-defined event codes and system-generated identifiers.

Example:

```text
ATTACHMENT_REJECTED
ticket_internal_id=<system id>
reason_code=PDF_ACTIVE_CONTENT
```

Not:

```text
Rejected dangerous file MarioRossi.pdf
```

## Required events

At minimum:

- SUBMISSION_RECEIVED
- CLAIM
- CLAIM_EXPIRED
- OPEN_REQUESTED
- OPEN_AUTHORIZED
- OPEN_COMPLETED
- OPEN_FAILED
- ATTACHMENT_VIEWED
- INTERRUPTED
- REOPEN_REQUESTED
- REOPEN_AUTHORIZED
- REOPEN_COMPLETED
- REOPEN_FAILED
- EMERGENCY_EXPORT_REQUESTED
- EMERGENCY_EXPORT_AUTHORIZED
- EMERGENCY_EXPORT_COMPLETED
- EMERGENCY_EXPORT_FAILED
- FINALIZATION_REQUESTED
- FINALIZATION_AUTHORIZED
- FINALIZATION_COMPLETED
- FINALIZATION_FAILED
- RESPONSE_AVAILABLE
- REPORT_KEY_DESTROYED
- CONTENT_DELETE_STARTED
- CONTENT_DELETE_COMPLETED
- CONTENT_DELETE_FAILED
- DELETE_REPORT_REQUESTED
- DELETE_REPORT_AUTHORIZED
- DELETE_REPORT_COMPLETED
- DELETE_REPORT_FAILED
- SECURITY_CONFIGURATION_CHANGED
- OPERATOR_AUTHENTICATION_EVENT
- ADMIN_AUDIT_ACCESS

`docs/20_SUBMISSION_ACCEPTANCE_PROTOCOL.md` approves the additional
`SUBMISSION_ACCEPTANCE_REQUESTED` and `SUBMISSION_ACCEPTANCE_FAILED` event
families as required controlled events for the submission protocol.

## Operator attribution

Every operator event records the authenticated operator identity.

Operator IP/workstation information may also be recorded, because operator accountability differs from reporter anonymity.

The exact REQUESTED/AUTHORIZED/COMPLETED/FAILED subset may vary by action only where the approved protocol demonstrates that the recorded events remain truthful and unambiguous.

## Reason codes and protected operator notes

Permanent audit stores only allowlisted, system-defined reason codes, for example:

- `WORKSTATION_FAILURE`;
- `NETWORK_INTERRUPTION`;
- `SESSION_TIMEOUT`;
- `NEED_MORE_PROCESSING_TIME`;
- `OTHER`.

The full arbitrary reopening note (maximum 150 characters) and Emergency Export note (maximum 1,000 characters):

- are not written to permanent audit;
- are encrypted as operational ticket history;
- are protected and destroyed with the ticket;
- may be included in Emergency Export where required.

Operator UI must warn:

"Do not include report content or identifying details in this reason."

This warning is defense-in-depth and does not replace the architectural separation from permanent audit.

## Durable audit receipt

For actions that expose, destroy, or export content, the forbidden sequence is:

```text
perform action -> attempt to audit
```

The required conceptual sequence is:

```text
ACTION_REQUESTED
  -> durable Audit Service acceptance
  -> verifiable durable audit receipt
  -> authorize/perform action
  -> ACTION_COMPLETED or ACTION_FAILED
```

The receipt must be bound to the applicable operator/service identity, report, operation, current state/version, and anti-replay context.

For OPEN and REOPEN, the Key Service must not release the report-decryption capability without the required valid receipt.

`docs/23_AUDIT_RECEIPT_AND_TRANSPARENCY_PROTOCOL.md` contains the
owner-approved exact event encoding, signed durable-acceptance receipt, atomic
idempotency rules, and per-operation authorization lifetimes. It remains
non-authorizing until independent cryptographic/protocol review and its
production gates are complete.

## Tamper evidence

Current proposed design:

- append-only event collector;
- an RFC 9162 SHA-256 Merkle tree over canonical event bytes;
- RFC 9942 inclusion and consistency receipts;
- periodic signed checkpoints and idle heartbeats;
- an independently authenticated witness with cessation detection.

Hash chaining alone is insufficient because an attacker controlling the store may truncate a valid suffix. The design must also detect gaps, truncation, and cessation through independently verifiable signed checkpoints or an equivalent control.

The exact owner-approved construction is specified in
`docs/23_AUDIT_RECEIPT_AND_TRANSPARENCY_PROTOCOL.md`; independent review,
signer/topology, alert transport, and deployment proof remain OPEN CRITICAL.

## Audit unavailability

For sensitive operations such as:

- OPEN;
- REOPEN;
- EMERGENCY EXPORT;
- SEND RESPONSE;
- DELETE REPORT;

if the required audit event cannot be durably accepted, the operation must fail closed.

The same rule applies before report plaintext is disclosed. A later audit attempt cannot retroactively protect an unaudited disclosure.

## Retention

Audit events retained for 365 days from generation under current baseline.

The log must remain useful after report content itself has been destroyed.

The owner-approved design retains verification evidence needed to prove
retained events for longer than the event row itself. Collector-controlled
expiry implementation and its legal, independent-review, and production proof
remain OPEN.
