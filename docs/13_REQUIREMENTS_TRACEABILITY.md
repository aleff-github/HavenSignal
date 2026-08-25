# 13 — Requirements Traceability and Superseded Decisions

`docs/01_SECURITY_BASELINE.md` is the normative requirement registry. This document maps every requirement family to its design authority, verification plan, and unresolved implementation gate.

The original questionnaire remains historical evidence under `/source` and is lower precedence than current Markdown decisions.

`docs/19_SECURITY_SERVICE_INTERFACES.md` is the approved cross-cutting capability and dependency map. Its approval does not close any implementation gate in `docs/12_OPEN_SECURITY_DECISIONS.md`.

`docs/20_SUBMISSION_ACCEPTANCE_PROTOCOL.md` is the approved submission
sequencing and retry model. Its approval authorizes only the internal state and
sequencing design; submission remains non-authorizing while dependent OPEN
constructions are unresolved.

`docs/21_RECOVERY_CREDENTIAL_CONSTRUCTION.md` is the owner-approved exact
Ticket ID, Recovery Secret, and keyed-verifier construction. It remains
non-authorizing until its independent cryptographic review is complete.

`docs/22_NO_JAVASCRIPT_CHALLENGE_PROTOCOL.md` is the owner-approved
no-JavaScript challenge and anonymous abuse-control protocol. It remains
non-authorizing until its dependent rendering, audio/accessibility,
PostgreSQL-concurrency, and production-boundary reviews are complete.

`docs/23_AUDIT_RECEIPT_AND_TRANSPARENCY_PROTOCOL.md` is the owner-approved
exact audit-event, durable-receipt, Merkle-checkpoint, witness, and anti-replay
construction. It is non-authorizing pending independent cryptographic/protocol
review and its named production gates.

`docs/24_RESPONSE_NOTE_CRYPTOGRAPHIC_PROTOCOL.md` is the owner-approved exact
Response Note AEAD, envelope, non-exportable Response-DEK, staging, first-read,
and expiry protocol. It is non-authorizing pending independent
cryptographic/protocol review and named production gates.

`docs/25_MFA_STEP_UP_AND_CREDENTIAL_LIFECYCLE.md` is the proposed WebAuthn,
single-use step-up, artifact-binding, enrollment, replacement, and recovery
protocol. It awaits consolidated pre-code owner approval and independent review.

`docs/26_REPORT_CONTENT_CRYPTOGRAPHIC_PROTOCOL.md` is the proposed exact
Report-DEK, per-object subkey, AEAD, fixed-length content framing, staging, and
narrow decryption protocol. It awaits consolidated approval and review.

`docs/27_KEY_SERVICE_ACCEPTANCE_AND_NON_RESURRECTION_POC.md` is the proposed
candidate-neutral Key Service capability and destructive acceptance plan. No
product/topology is approved until the real production-equivalent PoC passes.

## Traceability index

| Requirement IDs | Severity | Primary design documents | Verification | Current gate |
|---|---|---|---|---|
| SEC-CONF-001..008 | CRITICAL | 02 Threat Model; 04 Cryptographic Model; 15 Trust Boundaries; 20 Submission Protocol; 26 Report Crypto Proposal | 14: AEAD/context, key destruction, roles/capabilities, deployment checks | Exact report crypto PROPOSED; owner approval/review and Key Service gates OPEN |
| SEC-ANON-001..003 | CRITICAL | 00 Scope; 05 Recovery; 08 Audit; 10 Network Anonymity | 14: reporter logging, recovery enumeration, browser caching | End-to-end deployment validation required |
| SEC-ANON-004 | HIGH | 10 Network Anonymity; 11 Technology Decisions | 14: CAPTCHA and dependency/security checks | No-JS product OPEN |
| SEC-ANON-005 | CRITICAL | 10 Network Anonymity; 15 Trust Boundaries | Deployment/security acceptance test | Production deployment gate |
| SEC-ANON-006..007 | HIGH | 10 Network Anonymity | UI/deployment review | No design blocker |
| SEC-LOG-001..004 | CRITICAL | 08 Audit Logging; 15 Trust Boundaries; 23 Audit Receipt Protocol | 14: audit failure, durability, and privilege tests | Exact construction owner-approved; independent review and production gates OPEN |
| SEC-LOG-005 | CRITICAL | 08 Audit Logging; 16 Django Rules; 23 Audit Receipt Protocol | 14: reporter input/logging, closed-schema, and protected-note tests | Owner-approved schema is non-authorizing pending review |
| SEC-LOG-006..008 | HIGH | 08 Audit Logging; 23 Audit Receipt Protocol | 14: proofs, checkpoints, witness alerts, retention | Cadence/retention owner-approved; independent review and alert transport OPEN |
| SEC-LOG-009..012 | CRITICAL | 03 Lifecycle; 08 Audit Logging; 23 Audit Receipt Protocol | 14: receipt, replay, concurrency, truncation, cessation, and crash tests | Exact construction owner-approved; independent review and production gates OPEN |
| SEC-ACCESS-001..010 | CRITICAL/HIGH | 03 Lifecycle; 06 Operator Sessions | 14: session controls/finalization | Domain model may be specified; crypto/audit release remains gated |
| SEC-ACCESS-011..015 | CRITICAL | 03 Lifecycle; 06 Operator Sessions; 16 Django Rules | 14: lease generation, stale request, constraint tests | Exact schema may be designed without implementing decrypt |
| SEC-AUTH-001..004 | CRITICAL/HIGH | 06 Operator Sessions; 11 Technology Decisions; 25 MFA Proposal | 14: WebAuthn/password/session checks | WebAuthn and credential lifecycle PROPOSED; password/session specifics and review OPEN |
| SEC-AUTH-005..007 | CRITICAL | 06 Operator Sessions; 09 Emergency Export; 25 MFA Proposal | 14: exact binding, expiry, consumption, and replay tests | Exact protocol PROPOSED; consolidated owner approval and independent review OPEN |
| SEC-AUTH-008 | HIGH | 06 Operator Sessions; 12 Open Decisions; 25 MFA Proposal | Procedure/security review | Enrollment/reset/recovery PROPOSED; organizational procedure OPEN |
| SEC-AUTH-009 | CRITICAL | 06 Operator Sessions; 11 Technology Decisions; 15 Trust Boundaries; 25 MFA Proposal | 14: administrator MFA/anti-impersonation tests | Exact separation/recovery PROPOSED; approval/review OPEN |
| SEC-DEL-001..006 | CRITICAL/HIGH | 03 Lifecycle; 04 Cryptographic Model | 14: finalization/key-destruction/blob retry tests | Depends on Key Service and finalization gates |
| SEC-KEY-001..004 | CRITICAL | 04 Cryptographic Model; 11 Technology Decisions; 27 Key Service PoC Proposal | 14/27: destructive restore/rollback/stale-replica release gate | Acceptance plan PROPOSED; product/topology/real PoC OPEN |
| SEC-KEY-005 | HIGH | 04 Cryptographic Model; 27 Key Service PoC Proposal | Key inventory, separation, and lifecycle review | Application key roles specified; product procedures OPEN |
| SEC-KEY-006..007 | CRITICAL | 02 Threat Model; 04 Cryptographic Model; 15 Trust Boundaries; 27 Key Service PoC Proposal | 14/27: negative capability and combined-backup restoration tests | Capability policy PROPOSED; implementation and real proof OPEN |
| SEC-ROLE-001..003 | CRITICAL | 02 Threat Model; 15 Trust Boundaries | 14: role/capability tests | MFA/admin operational procedures OPEN |
| SEC-ROLE-004 | HIGH | 02 Threat Model | Threat-model review | Accepted limitation |
| SEC-RECOVERY-001..004 | CRITICAL | 05 Recovery Response; 20 Submission Protocol; 21 Recovery Credential Construction | 14: recovery enumeration/secret-handling tests | Owner choices approved; independent cryptographic review and dependent gates remain OPEN |
| SEC-RECOVERY-005 | CRITICAL | 05 Recovery Response; 12 Open Decisions; 21 Recovery Credential Construction | Owner decision and independent cryptographic design review | Owner-approved; independent review required before implementation |
| SEC-RESPONSE-001 | CRITICAL | 00 Scope; 05 Recovery Response | Response validation/no-draft tests | No design blocker |
| SEC-RESPONSE-002..008 | CRITICAL | 04 Cryptographic Model; 05 Recovery Response; 24 Response Crypto Protocol | 14: AEAD/context, Response-DEK lifecycle/restore/first-read race/expiry-denial tests | Exact construction owner-approved; independent review OPEN; unread lifetime separately OPEN |
| SEC-FINALIZE-001..004, SEC-FINALIZE-006 | CRITICAL | 03 Lifecycle; 04 Cryptographic Model; 06 Operator Sessions; 24 Response Crypto Protocol | 14: every crash point, retry, race, immutable staging, activation, visibility tests | Sequence and Response crypto owner-approved; external service gates remain |
| SEC-FINALIZE-005 | HIGH | 03 Lifecycle; 08 Audit Logging | 14: deletion retry/alert tests | Alert transport details OPEN |
| SEC-EXPORT-001..005 | CRITICAL/HIGH | 09 Emergency Export; 15 Trust Boundaries | 14: export safeguards, crypto, cleanup tests | Exact crypto format, signing, alert semantics OPEN |
| SEC-EXPORT-006 | HIGH | 02 Threat Model; 09 Emergency Export | Threat-model acceptance review | Accepted residual risk |
| SEC-CAPTCHA-001..002 | CRITICAL | 10 Network Anonymity; 11 Technology Decisions; 20 Submission Protocol; 22 No-JS Challenge | 14: self-hosting/mandatory-flow tests | No-JS protocol owner-approved; rendering/audio/accessibility and production reviews remain |
| SEC-CAPTCHA-003 | HIGH | 10 Network Anonymity; 12 Open Decisions; 22 No-JS Challenge | 14: no-JS expiry/replay/race/Tor tests | Owner-approved; dependent reviews and PostgreSQL concurrency proof required |
| SEC-CAPTCHA-004 | CRITICAL | 10 Network Anonymity | 14: dependency-failure tests | No fallback permitted |
| SEC-FILE-001..003 | CRITICAL | 07 File Security; 15 Trust Boundaries | 14: file/sandbox/CDR tests | PDF profile and sandbox OPEN |
| SEC-FILE-004..006 | HIGH | 07 File Security; 12 Open Decisions | 14: temporary lifecycle/resource tests | OPEN; PDF and image implementation blocked |
| SEC-ALERT-001 | HIGH | 08 Audit Logging; 09 Emergency Export; 23 Audit Receipt Protocol | 14: alert trigger and witness-liveness tests | Audit timing owner-approved; transport OPEN |
| SEC-ALERT-002 | CRITICAL | 08 Audit Logging | 14: allowlisted-payload tests | No content-bearing alerts permitted |
| SEC-ALERT-003 | HIGH | 12 Open Decisions | Procedure/failure tests | OPEN |
| SEC-BROWSER-001..002 | CRITICAL | 05 Recovery Response; 06 Operator Sessions; 16 Django Rules | 14: browser caching tests | Browser guarantee boundary documented |
| SEC-INPUT-001..006 | HIGH | 00 Scope; 07 File Security; 16 Django Rules; 20 Submission Protocol; 26 Report Crypto Proposal | 14: input/upload/body-limit and fixed-frame tests | Per-file byte interpretation PROPOSED; aggregate and decoded-resource limits OPEN |

## Cross-cutting interface mapping

The approved capability profiles, negative permissions, dependency edges, credential separation, and failure behavior in `19_SECURITY_SERVICE_INTERFACES.md` apply across:

- confidentiality and role separation: `SEC-CONF-001..008`, `SEC-ROLE-001..004`;
- audit append/read separation and durable receipts: `SEC-LOG-001..012`;
- state, lease, fencing, and server-authoritative time: `SEC-ACCESS-001..015`;
- authentication and action-bound step-up: `SEC-AUTH-001..009`;
- key lifecycle and non-resurrection: `SEC-DEL-001..006`, `SEC-KEY-001..007`;
- recovery and Response-DEK use: `SEC-RECOVERY-001..005`, `SEC-RESPONSE-001..008`;
- finalization and export orchestration: `SEC-FINALIZE-001..006`, `SEC-EXPORT-001..006`;
- CAPTCHA, sandboxing, alerts, and browser persistence: `SEC-CAPTCHA-001..004`, `SEC-FILE-001..006`, `SEC-ALERT-001..003`, `SEC-BROWSER-001..002`.

Every `GATED` capability in that document remains unavailable until its existing traceability gate is closed. The mapping introduces no new implementation approval.

## Superseded and clarified decisions

### CLAIM and OPEN timeouts

The historical 15-minute and midnight interpretations are superseded. CLAIMED expires after 5 minutes without OPEN. OPEN uses a 5-minute idle timeout and 60-minute absolute timeout, enforced server-side.

### Backend technology

Historical Rust discussion is superseded. Backend is Python; Django 5.2 LTS latest patched release is the approved direction.

### Reporter-controlled logging and filenames

No reporter-controlled input, original filename, request body, or arbitrary exception text may enter logs. Original filenames are used only for immediate validation and are never persisted or logged.

### Reopening and export reasons

The historical rule placing arbitrary free text in permanent audit is superseded. Permanent audit stores allowlisted system reason codes only. Full operator notes are encrypted operational ticket history, excluded from permanent audit, and destroyed with the ticket.

### Finalization

The historical description of finalization as one atomic distributed transaction is superseded. The approved protocol uses `FINALIZING`, durable audit receipts, staged invisible Response Note persistence, durable Report-DEK destruction confirmation, and only then `RESPONSE_AVAILABLE`.

### Per-object key resilience

The earlier unresolved backup trade-off is decided: active Report-DEKs and Response-DEKs may use live replication but no restorable historical per-object key backups/snapshots. Catastrophic active-report loss is accepted. Product/topology approval remains gated by non-resurrection testing.

### Administrative roles

The generic administrator role is split into Application Administrator and Infrastructure / Key Custodian. Neither role alone gains ordinary report-reading capability, and the Application Administrator cannot impersonate operators.

### Reporter Gateway compromise

Exposure of future plaintext submissions transiting a fully compromised Reporter Gateway is accepted. That gateway still has no general capability to decrypt all previously SEALED reports.

### Emergency Export

No second operator is required. The ability of a legitimate OPEN operator to deliberately create the authorized encrypted export is an accepted residual risk; safeguards provide attribution and detection.

### Recovery secret

The approved model is a public random Ticket ID plus an independent 256-bit Recovery Secret and no short PIN. Exact encodings and verifier construction remain OPEN.
