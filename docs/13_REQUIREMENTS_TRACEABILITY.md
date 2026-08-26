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
narrow decryption protocol. Its NFC/LF canonical-text/no-raw-copy subdecision
is owner-approved; the remaining protocol awaits consolidated approval and
review.

`docs/27_KEY_SERVICE_ACCEPTANCE_AND_NON_RESURRECTION_POC.md` is the proposed
candidate-neutral Key Service capability and destructive acceptance plan. No
product/topology is approved until the real production-equivalent PoC passes.

`docs/28_EMERGENCY_EXPORT_CRYPTOGRAPHIC_PROTOCOL.md` is the proposed exact
request binding, package, public-key encryption, manifest signature, key
separation, fenced generation, encrypted staging, delivery, and verification
protocol. It awaits consolidated approval and independent review.

`docs/29_FILE_ACCEPTANCE_SANDBOX_AND_SAFE_VIEW_PROTOCOL.md` is the proposed
exact JPEG/PNG/PDF admission, resource, parser, disposable-microVM, plaintext
lifecycle, and PNG-only operator-view protocol. It awaits consolidated approval
and independent parser/sandbox review.

`docs/30_REQUEST_AND_MULTIPART_ADMISSION_PROTOCOL.md` is the proposed exact
body/multipart/resource/time ceiling, streaming proxy, bounded Django upload
handler, and no-spool/failure protocol. It awaits consolidated approval and
independent HTTP/proxy/Django review.

`docs/31_ADMINISTRATOR_ALERT_PROTOCOL.md`,
`docs/32_RETENTION_AND_DELETION_PROTOCOL.md`, and
`docs/33_OPERATIONAL_ACCESS_AND_WORKSTATION_HARDENING.md` define the remaining
alert, retention/deletion, and operational access proposals.

`docs/34_PRE_CODE_SECURITY_GATE.md` is the non-authorizing owner review package
for `docs/25` through `docs/33`. Until its explicit decision is recorded, even
the metadata-only Stage A described there is not authorized.

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
| SEC-LOG-006..008 | HIGH | 08 Audit Logging; 23 Audit Receipt Protocol; 32 Retention Proposal | 14/32: proofs, checkpoints, witness alerts, retention authority | Cadence/durations owner-approved; exact expiry implementation PROPOSED and review OPEN |
| SEC-LOG-009..012 | CRITICAL | 03 Lifecycle; 08 Audit Logging; 23 Audit Receipt Protocol | 14: receipt, replay, concurrency, truncation, cessation, and crash tests | Exact construction owner-approved; independent review and production gates OPEN |
| SEC-ACCESS-001..010 | CRITICAL/HIGH | 03 Lifecycle; 06 Operator Sessions; 33 Operational Access Proposal | 14/33: session, workstation, stale access, finalization controls | Exact workstation/login profile PROPOSED; crypto/audit and production gates remain |
| SEC-ACCESS-011..015 | CRITICAL | 03 Lifecycle; 06 Operator Sessions; 16 Django Rules | 14: lease generation, stale request, constraint tests | Exact schema may be designed without implementing decrypt |
| SEC-AUTH-001..004 | CRITICAL/HIGH | 06 Operator Sessions; 11 Technology Decisions; 25 MFA Proposal; 33 Operational Access Proposal | 14/25/33: WebAuthn/password/session/workstation checks | WebAuthn and exact role sessions PROPOSED; approval/review and production gates OPEN |
| SEC-AUTH-005..007 | CRITICAL | 06 Operator Sessions; 09 Emergency Export; 25 MFA Proposal | 14: exact binding, expiry, consumption, and replay tests | Exact protocol PROPOSED; consolidated owner approval and independent review OPEN |
| SEC-AUTH-008 | HIGH | 06 Operator Sessions; 12 Open Decisions; 25 MFA Proposal | Procedure/security review | Enrollment/reset/recovery PROPOSED; organizational procedure OPEN |
| SEC-AUTH-009 | CRITICAL | 06 Operator Sessions; 11 Technology Decisions; 15 Trust Boundaries; 25 MFA Proposal; 33 Operational Access Proposal | 14/33: administrator MFA/session/network/anti-impersonation tests | Exact admin profile and v2 step-up PROPOSED; approval/review OPEN |
| SEC-DEL-001..006 | CRITICAL/HIGH | 03 Lifecycle; 04 Cryptographic Model; 32 Retention/Deletion Proposal | 14/32: finalization, key destruction/restore, deletion state/race, blob retry tests | Exact operator/flood/cleanup protocol PROPOSED; owner/review and Key Service gates OPEN CRITICAL |
| SEC-KEY-001..004 | CRITICAL | 04 Cryptographic Model; 11 Technology Decisions; 27 Key Service PoC Proposal | 14/27: destructive restore/rollback/stale-replica release gate | Acceptance plan PROPOSED; product/topology/real PoC OPEN |
| SEC-KEY-005 | HIGH | 04 Cryptographic Model; 27 Key Service PoC Proposal | Key inventory, separation, and lifecycle review | Application key roles specified; product procedures OPEN |
| SEC-KEY-006..007 | CRITICAL | 02 Threat Model; 04 Cryptographic Model; 15 Trust Boundaries; 27 Key Service PoC Proposal | 14/27: negative capability and combined-backup restoration tests | Capability policy PROPOSED; implementation and real proof OPEN |
| SEC-ROLE-001..003 | CRITICAL | 02 Threat Model; 15 Trust Boundaries; 19 Interfaces; 33 Operational Access Proposal | 14/33: cross-role device/network/credential/capability tests | Exact physical/operational separation PROPOSED; production proof OPEN |
| SEC-ROLE-004 | HIGH | 02 Threat Model | Threat-model review | Accepted limitation |
| SEC-RECOVERY-001..004 | CRITICAL | 05 Recovery Response; 20 Submission Protocol; 21 Recovery Credential Construction | 14: recovery enumeration/secret-handling tests | Owner choices approved; independent cryptographic review and dependent gates remain OPEN |
| SEC-RECOVERY-005 | CRITICAL | 05 Recovery Response; 12 Open Decisions; 21 Recovery Credential Construction | Owner decision and independent cryptographic design review | Owner-approved; independent review required before implementation |
| SEC-RESPONSE-001 | CRITICAL | 00 Scope; 05 Recovery Response | Response validation/no-draft tests | No design blocker |
| SEC-RESPONSE-002..008 | CRITICAL | 04 Cryptographic Model; 05 Recovery Response; 24 Response Crypto Protocol; 32 Retention Proposal | 14/24/32: AEAD/context, Response-DEK lifecycle/restore, read/unread expiry races | Existing construction owner-approved; 90-day unread extension PROPOSED; review and Key Service gates OPEN |
| SEC-FINALIZE-001..004, SEC-FINALIZE-006 | CRITICAL | 03 Lifecycle; 04 Cryptographic Model; 06 Operator Sessions; 24 Response Crypto Protocol | 14: every crash point, retry, race, immutable staging, activation, visibility tests | Sequence and Response crypto owner-approved; external service gates remain |
| SEC-FINALIZE-005 | HIGH | 03 Lifecycle; 08 Audit Logging | 14: deletion retry/alert tests | Alert transport details OPEN |
| SEC-EXPORT-001..005 | CRITICAL/HIGH | 09 Emergency Export; 15 Trust Boundaries; 28 Export Crypto Proposal | 14/28: binding, package, encryption, signature, fencing, delivery, cleanup tests | Exact protocol PROPOSED; owner/review, alert, Key Service, signer, custody, concurrency, and deployment gates OPEN |
| SEC-EXPORT-006 | HIGH | 02 Threat Model; 09 Emergency Export; 28 Export Crypto Proposal | Threat-model acceptance and workflow review | Accepted residual risk; proposed controls do not claim prevention |
| SEC-CAPTCHA-001..002 | CRITICAL | 10 Network Anonymity; 11 Technology Decisions; 20 Submission Protocol; 22 No-JS Challenge | 14: self-hosting/mandatory-flow tests | No-JS protocol owner-approved; rendering/audio/accessibility and production reviews remain |
| SEC-CAPTCHA-003 | HIGH | 10 Network Anonymity; 12 Open Decisions; 22 No-JS Challenge | 14: no-JS expiry/replay/race/Tor tests | Owner-approved; dependent reviews and PostgreSQL concurrency proof required |
| SEC-CAPTCHA-004 | CRITICAL | 10 Network Anonymity | 14: dependency-failure tests | No fallback permitted |
| SEC-FILE-001..003 | CRITICAL | 07 File Security; 15 Trust Boundaries; 29 File/Sandbox Proposal | 14/29: profile, parser differential, microVM, CDR and access tests | Exact protocol PROPOSED; owner/review and production sandbox gates OPEN |
| SEC-FILE-004..006 | HIGH | 07 File Security; 12 Open Decisions; 29 File/Sandbox Proposal | 14/29: plaintext lifecycle, resource, corpus, teardown tests | Exact profiles PROPOSED; artifact pinning and production validation OPEN |
| SEC-ALERT-001 | HIGH | 08 Audit Logging; 09 Emergency Export; 23 Audit Receipt Protocol; 31 Alert Proposal | 14/31: alert trigger, witness-liveness, deletion, and export tests | Exact transport and triggers PROPOSED; approval/review and deployment gates OPEN |
| SEC-ALERT-002 | CRITICAL | 08 Audit Logging; 31 Alert Proposal | 14/31: closed-schema and prohibited-data tests | Content-free schema PROPOSED; approval/review OPEN |
| SEC-ALERT-003 | HIGH | 12 Open Decisions; 31 Alert Proposal | 31: durability, retry, escalation, acknowledgement, and failure tests | Exact protocol PROPOSED; approval/review and production gates OPEN |
| SEC-BROWSER-001..002 | CRITICAL | 05 Recovery Response; 06 Operator Sessions; 16 Django Rules; 33 Operational Access Proposal | 14/33: cache, ephemeral profile, clipboard/print/download controls | Exact supported workstation/browser profile PROPOSED; physical acceptance OPEN |
| SEC-INPUT-001..006 | HIGH | 00 Scope; 07 File Security; 16 Django Rules; 20 Submission Protocol; 26 Report Crypto; 29 File/Sandbox; 30 Request Admission proposals | 14/29/30: canonical text, byte/body/multipart/decoded-resource/no-spool tests | Exact profiles PROPOSED; owner/review and production boundary gates OPEN |

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

### Authoritative original report text

The project owner decided that accepted report text is normalized to LF and
NFC, encoded as strict UTF-8, and retained only in that canonical form. That
canonical byte sequence is the authoritative “original report text” for
encryption, operator viewing, Emergency Export, and destruction. The transient
pre-normalization browser/wire representation is not a second original and is
not persisted. Accepted attachment bytes remain byte-for-byte unchanged.
