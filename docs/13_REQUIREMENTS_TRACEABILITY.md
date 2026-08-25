# 13 — Requirements Traceability and Superseded Decisions

`docs/01_SECURITY_BASELINE.md` is the normative requirement registry. This document maps every requirement family to its design authority, verification plan, and unresolved implementation gate.

The original questionnaire remains historical evidence under `/source` and is lower precedence than current Markdown decisions.

## Traceability index

| Requirement IDs | Severity | Primary design documents | Verification | Current gate |
|---|---|---|---|---|
| SEC-CONF-001..008 | CRITICAL | 02 Threat Model; 04 Cryptographic Model; 15 Trust Boundaries | 14: key destruction, roles/capabilities, deployment checks | Key Service/capability design OPEN for security component |
| SEC-ANON-001..003 | CRITICAL | 00 Scope; 05 Recovery; 08 Audit; 10 Network Anonymity | 14: reporter logging, recovery enumeration, browser caching | End-to-end deployment validation required |
| SEC-ANON-004 | HIGH | 10 Network Anonymity; 11 Technology Decisions | 14: CAPTCHA and dependency/security checks | No-JS product OPEN |
| SEC-ANON-005 | CRITICAL | 10 Network Anonymity; 15 Trust Boundaries | Deployment/security acceptance test | Production deployment gate |
| SEC-ANON-006..007 | HIGH | 10 Network Anonymity | UI/deployment review | No design blocker |
| SEC-LOG-001..004 | CRITICAL | 08 Audit Logging; 15 Trust Boundaries | 14: audit failure and privilege tests | Exact audit construction OPEN |
| SEC-LOG-005 | CRITICAL | 08 Audit Logging; 16 Django Rules | 14: reporter input/logging and protected-note tests | No design blocker for logging schema |
| SEC-LOG-006..008 | HIGH | 08 Audit Logging | 14: checkpoints, alerts, retention | Checkpoint/alert details OPEN |
| SEC-LOG-009..012 | CRITICAL | 08 Audit Logging; 03 Lifecycle | 14: receipt, replay, truncation, crash tests | Exact receipt/checkpoint construction OPEN |
| SEC-ACCESS-001..010 | CRITICAL/HIGH | 03 Lifecycle; 06 Operator Sessions | 14: session controls/finalization | Domain model may be specified; crypto/audit release remains gated |
| SEC-ACCESS-011..015 | CRITICAL | 03 Lifecycle; 06 Operator Sessions; 16 Django Rules | 14: lease generation, stale request, constraint tests | Exact schema may be designed without implementing decrypt |
| SEC-AUTH-001..004 | CRITICAL/HIGH | 06 Operator Sessions; 11 Technology Decisions | 14: authentication/session checks | Enrollment/reset/recovery OPEN |
| SEC-AUTH-005..007 | CRITICAL | 06 Operator Sessions; 09 Emergency Export | 14: step-up binding/replay tests | Exact TTL and artifact-byte/digest construction OPEN; model properties approved |
| SEC-AUTH-008 | HIGH | 06 Operator Sessions; 12 Open Decisions | Procedure/security review | OPEN |
| SEC-AUTH-009 | CRITICAL | 06 Operator Sessions; 11 Technology Decisions; 15 Trust Boundaries | 14: administrator MFA/anti-impersonation tests | Enrollment/reset/recovery OPEN |
| SEC-DEL-001..006 | CRITICAL/HIGH | 03 Lifecycle; 04 Cryptographic Model | 14: finalization/key-destruction/blob retry tests | Depends on Key Service and finalization gates |
| SEC-KEY-001..004 | CRITICAL | 04 Cryptographic Model; 11 Technology Decisions | 14: restore/rollback/stale-replica release gate | Product/topology/PoC OPEN |
| SEC-KEY-005 | HIGH | 04 Cryptographic Model | Key inventory and lifecycle review | Per-key operational procedures partially OPEN |
| SEC-KEY-006..007 | CRITICAL | 02 Threat Model; 04 Cryptographic Model; 15 Trust Boundaries | 14: negative capability and combined-backup restoration tests | Exact Key Service policy implementation OPEN |
| SEC-ROLE-001..003 | CRITICAL | 02 Threat Model; 15 Trust Boundaries | 14: role/capability tests | MFA/admin operational procedures OPEN |
| SEC-ROLE-004 | HIGH | 02 Threat Model | Threat-model review | Accepted limitation |
| SEC-RECOVERY-001..004 | CRITICAL | 05 Recovery Response | 14: recovery enumeration/secret-handling tests | Encoding/verifier construction still gates implementation |
| SEC-RECOVERY-005 | CRITICAL | 05 Recovery Response; 12 Open Decisions | Cryptographic design review | OPEN |
| SEC-RESPONSE-001 | CRITICAL | 00 Scope; 05 Recovery Response | Response validation/no-draft tests | No design blocker |
| SEC-RESPONSE-002..008 | CRITICAL | 04 Cryptographic Model; 05 Recovery Response | 14: Response-DEK lifecycle/restore/first-read race/expiry-denial tests | Exact crypto and unread lifetime OPEN |
| SEC-FINALIZE-001..004, SEC-FINALIZE-006 | CRITICAL | 03 Lifecycle; 04 Cryptographic Model; 06 Operator Sessions | 14: every crash point, retry, race, immutable staging, visibility tests | Protocol approved; external service interfaces gated by their designs |
| SEC-FINALIZE-005 | HIGH | 03 Lifecycle; 08 Audit Logging | 14: deletion retry/alert tests | Alert transport details OPEN |
| SEC-EXPORT-001..005 | CRITICAL/HIGH | 09 Emergency Export; 15 Trust Boundaries | 14: export safeguards, crypto, cleanup tests | Exact crypto format, signing, alert semantics OPEN |
| SEC-EXPORT-006 | HIGH | 02 Threat Model; 09 Emergency Export | Threat-model acceptance review | Accepted residual risk |
| SEC-CAPTCHA-001..002 | CRITICAL | 10 Network Anonymity; 11 Technology Decisions | 14: self-hosting/mandatory-flow tests | JS candidate only; no-JS product OPEN |
| SEC-CAPTCHA-003 | HIGH | 10 Network Anonymity; 12 Open Decisions | 14: no-JS expiry/replay/Tor tests | OPEN |
| SEC-CAPTCHA-004 | CRITICAL | 10 Network Anonymity | 14: dependency-failure tests | No fallback permitted |
| SEC-FILE-001..003 | CRITICAL | 07 File Security; 15 Trust Boundaries | 14: file/sandbox/CDR tests | PDF profile and sandbox OPEN |
| SEC-FILE-004..006 | HIGH | 07 File Security; 12 Open Decisions | 14: temporary lifecycle/resource tests | OPEN; PDF and image implementation blocked |
| SEC-ALERT-001 | HIGH | 08 Audit Logging; 09 Emergency Export | 14: alert trigger tests | Transport OPEN |
| SEC-ALERT-002 | CRITICAL | 08 Audit Logging | 14: allowlisted-payload tests | No content-bearing alerts permitted |
| SEC-ALERT-003 | HIGH | 12 Open Decisions | Procedure/failure tests | OPEN |
| SEC-BROWSER-001..002 | CRITICAL | 05 Recovery Response; 06 Operator Sessions; 16 Django Rules | 14: browser caching tests | Browser guarantee boundary documented |
| SEC-INPUT-001..006 | HIGH | 00 Scope; 07 File Security; 16 Django Rules | 14: input/upload/body-limit tests | Aggregate and decoded-resource limits OPEN |

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
