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

The failure behavior when a report is durably accepted but the one-time credential response does not reach the reporter also remains OPEN.

`docs/21_RECOVERY_CREDENTIAL_CONSTRUCTION.md` contains the current exact
encoding, HMAC-SHA-256 verifier, key-separation, rotation, and failure proposal.
It remains PROPOSED and does not close this gate until its five owner choices
and an independent cryptographic review are complete. Lost-response sequencing
remains governed separately by proposed `docs/20_SUBMISSION_ACCEPTANCE_PROTOCOL.md`.

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

The approved protocol requires pre-action durable receipts and REQUESTED/AUTHORIZED/COMPLETED/FAILED events where needed.

Still OPEN:

- exact receipt format and anti-replay binding;
- hash-chain/batch format;
- signed checkpoint format and cadence;
- independent verification mechanism and schedule;
- audit-signing key lifecycle;
- exact detection/alert behavior for gaps, truncation, and cessation.

Hash chaining alone is not acceptable.

## CRITICAL — Submission acceptance, audit, and credential-delivery sequencing

`SUBMISSION_RECEIVED` is required, but the exact failure-safe sequence between:

- durable audit acceptance;
- report encryption/key creation;
- metadata/ciphertext persistence;
- one-time Ticket ID/Recovery Secret delivery;
- retry after connection loss;

remains OPEN. The design must not accept an unaudited report silently, leak plaintext, duplicate a submission through unsafe retry, or claim that credentials were delivered when the one-time response was lost.

`docs/20_SUBMISSION_ACCEPTANCE_PROTOCOL.md` contains the current recommended
sequence, failure matrix, and residual-risk option. It remains PROPOSED. This
sequencing gate is not closed until the project owner explicitly decides its
five listed approval questions. Dependent construction gates remain
independently blocking even after sequencing approval.

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

The exact product/implementation and exact expiry remain OPEN. ALTCHA remains the JavaScript-enabled candidate.

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

Audit retention is 365 days, while the report application has no historical delete authority. The exact collector/store-controlled expiry mechanism, checkpoint retention behavior, and proof that application/operator roles cannot accelerate deletion remain OPEN.

## HIGH — Administrator network/session access profile

The Application Administrator interface requires strong MFA and anti-impersonation controls. Exact network restrictions, session policy, and hardened access profile remain OPEN.

## MEDIUM — Infrastructure / Key Custodian operational procedure

The trust role is approved, but staffing, access ceremony, break-glass controls, monitoring, credential lifecycle, and periodic review remain OPEN.
