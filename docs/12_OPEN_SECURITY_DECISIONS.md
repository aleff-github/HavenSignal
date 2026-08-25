# 12 — Open Security Decisions

Do not silently resolve these in code. An OPEN item blocks only the affected security component unless this document explicitly says otherwise.

## CRITICAL — Recovery credential encoding and verifier

The approved model is a random public Ticket ID plus an independent 256-bit Recovery Secret, with no short PIN.

Still OPEN:

- Recovery Secret generation location and the no-JavaScript-compatible generation/delivery flow;
- exact Ticket ID bit length and encoding;
- exact Recovery Secret encoding;
- exact copy/display behavior beyond the server-side display-once rule;
- exact keyed verifier construction, framing, domain separation, key lifecycle, and rotation.

The failure behavior when a report is durably accepted but the one-time
credential response does not reach the reporter is approved in
`docs/20_SUBMISSION_ACCEPTANCE_PROTOCOL.md`: accept the residual availability
loss, never reissue or replace credentials, and never duplicate the same
attempt.

`docs/21_RECOVERY_CREDENTIAL_CONSTRUCTION.md` contains the owner-approved exact
encoding, HMAC-SHA-256 verifier, key-separation, rotation, and failure policy.
Its five owner choices were approved on 2026-08-25. This gate remains OPEN for
implementation until the independent cryptographic review is complete.
Lost-response sequencing is governed separately by approved
`docs/20_SUBMISSION_ACCEPTANCE_PROTOCOL.md`.

## CRITICAL — Response Note cryptographic construction

The approved model uses an independent Response-DEK. The Recovery Secret is not the sole material sufficient to decrypt a retained/restored ciphertext indefinitely.

Still OPEN:

- exact AEAD construction;
- nonce strategy;
- AAD and format/version binding;
- key derivation and purpose separation;
- exact verifier construction;
- Response-DEK wrapping/unwrapping construction;
- Response-DEK representation and lifecycle protocol.

## CRITICAL — Key Service product, topology, and proof of non-resurrection

The policy is approved:

- live replication of active Report-DEKs and Response-DEKs is permitted;
- restorable historical per-object DEK backups/snapshots are forbidden;
- catastrophic loss of active reports is accepted rather than risking key resurrection.

Still OPEN:

- final Key Service product;
- exact topology and replication configuration;
- exact Key Service capability/policy implementation;
- exact Infrastructure / Key Custodian operational procedure.

OpenBao remains only a candidate. Approval requires a release-blocking proof of concept covering delete propagation, snapshot/restore, rollback, delayed/stale replicas, and disaster recovery.

## CRITICAL — Audit receipt and tamper-evidence construction

The approved lifecycle requires pre-action durable receipts and
REQUESTED/AUTHORIZED/COMPLETED/FAILED events where needed.

`docs/23_AUDIT_RECEIPT_AND_TRANSPARENCY_PROTOCOL.md` now proposes the exact
version-1 construction. It is **PROPOSED**, not approved or authorizing.

Project-owner decisions still required:

- deterministic CBOR, COSE Sign1/Ed25519, separated receipt/checkpoint keys,
  and the exact event/receipt schemas;
- idempotency/nonces and per-operation non-sliding receipt lifetimes;
- RFC 9162 Merkle and RFC 9942 proof profiles plus the 60-second/1,024-event
  merge rule;
- five-minute heartbeats, seven-minute witness alerting, and fail-closed
  cessation of protected receipt issuance within 90 seconds;
- key rotation and 365-day event / 730-day verification-evidence retention.

Independent cryptographic/protocol review remains mandatory after owner
approval. Audit topology, HSM/signer, service authentication, PostgreSQL
durability/concurrency, clock, alert transport, deployment, and dependent-flow
reviews also remain OPEN.

Hash chaining alone is not acceptable. The proposal instead uses independently
witnessed signed Merkle checkpoints to detect mutation, gaps, forks,
truncation, rollback, and cessation.

## CLOSED — Submission acceptance, audit, and credential-delivery sequencing

The failure-safe sequence between:

- durable audit acceptance;
- report encryption/key creation;
- metadata/ciphertext persistence;
- one-time Ticket ID/Recovery Secret delivery;
- retry after connection loss;

was approved by the project owner on 2026-08-25. The design must not accept an
unaudited report silently, leak plaintext, duplicate a submission through
unsafe retry, or claim that credentials were delivered when the one-time
response was lost.

`docs/20_SUBMISSION_ACCEPTANCE_PROTOCOL.md` is the approved authority for the
sequence, state model, audit phases, retry behavior, reconciliation timing, and
lost-response residual risk. The dependent CAPTCHA, recovery
encoding/verifier, AEAD, Key Service, audit receipt, aggregate-size, and
applicable file/sandbox gates remain independently blocking.

## CRITICAL — Emergency Export cryptographic formats

The organization public-key encryption and signed-manifest properties are approved.

Still OPEN:

- exact public-key encryption tool/format;
- exact manifest-signature construction;
- key identifiers and artifact format versioning;
- organization public-key rotation/revocation procedure;
- export-signing key lifecycle.

## HIGH — No-JavaScript anti-bot technology

The no-JavaScript path must be self-hosted, server-side, single-use, briefly expiring, use global abuse controls, and avoid IP/device fingerprinting and third-party tracking.

The project-owned no-JavaScript protocol and exact five-minute expiry are
owner-approved. ALTCHA remains only the JavaScript-enabled candidate.

`docs/22_NO_JAVASCRIPT_CHALLENGE_PROTOCOL.md` defines the owner-approved five-minute,
single-attempt, purpose/scope-bound protocol and global anonymous token buckets.
It rejects direct use of the reviewed `django-simple-captcha` validator because
its database consumption is not explicitly concurrency-atomic. This gate
remains OPEN for implementation until pinned Pillow/font, self-hosted
audio/accessibility, PostgreSQL concurrency, and production-boundary reviews
are complete.

## HIGH — PDF structural acceptance profile and sandbox

PDF upload remains blocked until approval of:

- maximum pages;
- maximum objects;
- maximum decompression ratio;
- maximum dimensions/resource limits;
- parser/toolchain;
- structural allowlist;
- render/CDR strategy;
- exact sandbox implementation;
- temporary-workspace lifecycle.

No accepted PDF may be described as absolutely safe.

## HIGH — Image resource limits and sandbox

Still OPEN:

- maximum decoded pixel count and dimensions;
- parser/decoder toolchain;
- re-decode/re-encode viewing policy;
- exact sandbox implementation and limits.

## HIGH — MFA step-up and credential lifecycle

The action-bound `StepUpAuthorization` properties are approved.

Still OPEN:

- exact step-up TTL;
- exact canonical byte representation and approved digest construction used for artifact binding;
- operator and administrator MFA enrollment;
- factor reset;
- lost-factor recovery;
- revocation and replacement procedure.

## HIGH — Operator workstation hardening specification

Need a concrete supported profile covering OS, browser, extensions, disk encryption, screen lock, clipboard, printing, cloud sync, local administrator rights, patching, and network controls.

## HIGH — Never-read Response Note retention

The 72-hour lifetime starts at first successful read. A maximum lifetime for a Response Note that is never read remains undecided and requires operational/legal approval.

## HIGH — SEALED report deletion during floods

The exceptional permission model, selection policy, safeguards, and race behavior remain OPEN. Automated classification/AI deletion remains forbidden.

## HIGH — Operator deletion without Response Note

`DELETED_WITH_REASON` is approved in principle, but the allowed source states, permission/step-up policy, protected-note behavior, Key Service/audit receipt sequence, recovery-endpoint behavior, and race handling remain OPEN.

## HIGH — Aggregate request and decoded-resource limits

Per-file size labels are approved. Still OPEN are the exact byte interpretation of `5 MB`, the aggregate HTTP/multipart body limit, and remaining parser-independent decoded-resource limits not covered by the PDF/image decisions above.

## MEDIUM — Administrator alert transport

Still OPEN:

- exact self-hosted delivery mechanism;
- durable-acceptance semantics;
- retry/escalation policy;
- behavior when notification is unavailable.

Alerts must contain only controlled metadata.

## HIGH — Audit retention expiry authority

Audit retention is 365 days, while the report application has no historical
delete authority. `docs/23_AUDIT_RECEIPT_AND_TRANSPARENCY_PROTOCOL.md` proposes
collector-controlled 365-day event retention and 730-day verification-evidence
retention. The durations, expiry mechanism, and proof that application/operator
roles cannot accelerate deletion remain unapproved and OPEN.

## HIGH — Administrator network/session access profile

The Application Administrator interface requires strong MFA and anti-impersonation controls. Exact network restrictions, session policy, and hardened access profile remain OPEN.

## MEDIUM — Infrastructure / Key Custodian operational procedure

The trust role is approved, but staffing, access ceremony, break-glass controls, monitoring, credential lifecycle, and periodic review remain OPEN.
