# 01 — Security Baseline

Requirement keywords use RFC-style meanings: MUST, MUST NOT, SHOULD, SHOULD NOT, MAY.

## Confidentiality

**SEC-CONF-001 — CRITICAL**  
Report text and accepted attachments MUST be encrypted before durable storage.

**SEC-CONF-002 — CRITICAL**  
Every report MUST have an independent report encryption key (DEK).

**SEC-CONF-003 — CRITICAL**  
The DEK for one report MUST protect that report's text and attachments without enabling decryption of other reports.

**SEC-CONF-004 — CRITICAL**  
Database compromise alone MUST NOT be sufficient to read report content.

**SEC-CONF-005 — CRITICAL**  
Attachment-storage compromise alone MUST NOT be sufficient to read attachment content.

**SEC-CONF-006 — CRITICAL**  
Normal application administration or normal infrastructure administration MUST NOT, by itself, confer the capability to read reports, obtain report DEKs, or invoke arbitrary unwrap/decrypt operations.

**SEC-CONF-007 — CRITICAL**  
A different operator who has not legitimately opened the report MUST NOT gain ordinary read access to it.

**SEC-CONF-008 — CRITICAL**  
If required confidentiality controls are unavailable, protected content MUST fail closed.

## Reporter anonymity / minimization

**SEC-ANON-001 — CRITICAL**  
Reporter account, email, phone number, or mandatory authentication MUST NOT be required.

**SEC-ANON-002 — CRITICAL**  
Reporter-facing HTTP access logs MUST NOT persist reporter IP addresses or User-Agent strings.

**SEC-ANON-003 — CRITICAL**  
Reporter-controlled input MUST NOT enter application or audit logs.

**SEC-ANON-004 — HIGH**  
Reporter-facing resources SHOULD be entirely self-hosted.

**SEC-ANON-005 — CRITICAL**  
The service MUST provide a Tor v3 Onion Service.

**SEC-ANON-006 — HIGH**  
A normal HTTPS site MAY coexist with the Onion Service, but MUST NOT be described as offering equivalent network anonymity.

**SEC-ANON-007 — HIGH**  
The normal HTTPS site SHOULD prominently encourage use of Tor for stronger anonymity.

## Logging

**SEC-LOG-001 — CRITICAL**  
Audit logging MUST be append-only or equivalently tamper-evident.

**SEC-LOG-002 — CRITICAL**  
The audit store MUST be logically and preferably operationally separated from the report database.

**SEC-LOG-003 — CRITICAL**  
The application MUST NOT have privileges to rewrite or delete historical audit events.

**SEC-LOG-004 — CRITICAL**  
Security-sensitive actions MUST fail closed if required audit recording is unavailable.

**SEC-LOG-005 — CRITICAL**  
Audit logs MUST NOT contain report text, attachment content, recovery secrets, cryptographic keys, original filenames, or arbitrary reporter-provided data.

**SEC-LOG-006 — HIGH**  
Audit integrity SHOULD use tamper-evident chaining and signed/checkpointed integrity evidence.

**SEC-LOG-007 — HIGH**  
Failure or interruption of audit ingestion MUST be detectable and alert the administrator.

**SEC-LOG-008 — HIGH**  
Audit events MUST be retained for 365 days from generation unless legal/security review defines a stricter policy.

**SEC-LOG-009 — CRITICAL**  
Before an action discloses, destroys, or exports report content, the required pre-action audit event MUST be durably accepted and represented by a verifiable audit receipt.

**SEC-LOG-010 — CRITICAL**  
Security-sensitive audit protocols MUST distinguish REQUESTED, AUTHORIZED, COMPLETED, and FAILED events where needed to represent the true outcome without falsely recording an unperformed action as successful.

**SEC-LOG-011 — CRITICAL**  
For OPEN and REOPEN, the Key Service MUST NOT release the required report-decryption capability unless the required pre-action audit receipt is valid for the operator, report, operation, and current state.

**SEC-LOG-012 — CRITICAL**  
Audit tamper evidence MUST detect alteration, gaps, cessation, and truncation; hash chaining alone is insufficient without independently verifiable signed checkpoints or an equivalent control.

## Sessions / operator access

**SEC-ACCESS-001 — CRITICAL**  
No report content may be disclosed before an operator performs CLAIM.

**SEC-ACCESS-002 — CRITICAL**  
An operator may have only one active report at a time; `CLAIMED`, `OPEN`, and an operator-initiated `FINALIZING` operation count as active until released/completed, while `INTERRUPTED` is not held by an operator.

**SEC-ACCESS-003 — HIGH**  
CLAIM MUST expire after 5 minutes if OPEN has not begun.

**SEC-ACCESS-004 — CRITICAL**  
OPEN MUST have a 5-minute idle timeout.

**SEC-ACCESS-005 — CRITICAL**  
OPEN MUST have a 60-minute absolute timeout.

**SEC-ACCESS-006 — CRITICAL**  
Idle and absolute timeouts MUST be enforced server-side.

**SEC-ACCESS-007 — HIGH**  
A refresh during the same still-valid lease MUST remain part of that lease and MUST NOT be treated as a reopening.

**SEC-ACCESS-008 — CRITICAL**  
After an interrupted/expired OPEN session, reopening requires an allowlisted system reason code and MAY include the protected operator note defined by SEC-ACCESS-009.

**SEC-ACCESS-009 — HIGH**  
An arbitrary reopening note, if collected, MUST be at most 150 characters, encrypted as operational ticket history, excluded from permanent audit, destroyed with the ticket, and accompanied by a warning not to include report content or unnecessary identifying data.

**SEC-ACCESS-010 — CRITICAL**  
Concurrent editing/opening MUST be prevented with server-authoritative locking and race-condition-safe state transitions.

**SEC-ACCESS-011 — CRITICAL**  
Every OPEN period MUST be represented by a persisted ReportLease containing the report identifier, operator identifier, random lease identifier, monotonically increasing generation/fencing token, `opened_at`, `last_activity_at`, `absolute_expires_at`, and state/version.

**SEC-ACCESS-012 — CRITICAL**  
Only server-side time MUST be treated as authoritative for claim, idle, absolute-expiry, and step-up validity decisions.

**SEC-ACCESS-013 — CRITICAL**  
Every sensitive OPEN operation MUST validate the authenticated operator, lease identifier, current generation, report state, idle expiry, and absolute expiry on the server.

**SEC-ACCESS-014 — CRITICAL**  
A new lease generation MUST invalidate stale tabs, earlier sessions, delayed requests, and late retries from every previous generation.

**SEC-ACCESS-015 — CRITICAL**  
Lease and report-state transitions MUST use database transactions, row-level locking and/or state-version checks, and database uniqueness constraints sufficient to enforce one active report per operator and one active lease per report.

## Operator authentication

**SEC-AUTH-001 — CRITICAL**  
Operator authentication MUST use a password plus a strong second factor. The supported production profile MUST use a phishing-resistant WebAuthn/FIDO2 factor; no weaker or password-only fallback may be introduced without explicit security approval.

**SEC-AUTH-002 — CRITICAL**  
Publishing the final Response Note MUST require step-up MFA immediately before irreversible finalization.

**SEC-AUTH-003 — CRITICAL**  
Emergency export MUST require step-up MFA immediately before export generation.

**SEC-AUTH-004 — HIGH**  
Operator session and authentication-key handling MUST follow current OWASP guidance.

**SEC-AUTH-005 — CRITICAL**  
A step-up authorization MUST be single-use, short-lived, non-replayable, and bound to the authenticated operator, ticket, operation, nonce, issue time, expiry time, and used state.

**SEC-AUTH-006 — CRITICAL**  
Where the protected operation acts on an exact artifact, including final Response Note publication, the step-up authorization MUST be bound to a digest of the exact artifact bytes.

**SEC-AUTH-007 — CRITICAL**  
A step-up authorization issued for one ticket, operation, or artifact MUST NOT authorize another ticket, operation, or artifact and MUST be irreversibly consumed on successful use.

**SEC-AUTH-008 — HIGH**  
The exact step-up TTL and the operator/administrator MFA enrollment, reset, and recovery procedures MUST receive explicit security approval before those functions are implemented.

**SEC-AUTH-009 — CRITICAL**  
The Application Administrator interface MUST require strong MFA, with phishing-resistant WebAuthn/FIDO2 in the supported production profile, and MUST NOT provide an enrollment/reset/recovery path that enables operator impersonation.

## Deletion

**SEC-DEL-001 — CRITICAL**  
After successful final publication of the Response Note, original report text and attachments MUST become cryptographically irrecoverable.

**SEC-DEL-002 — CRITICAL**  
Finalization MUST NOT destroy the report if the Response Note has not first been safely stored in its intended protected form.

**SEC-DEL-003 — CRITICAL**  
Finalization MUST use the fail-safe, idempotent, resumable `FINALIZING` protocol in SEC-FINALIZE-001 through SEC-FINALIZE-004; it MUST NOT claim one distributed atomic transaction across independent services.

**SEC-DEL-004 — CRITICAL**  
Report-key destruction MUST prevent later key restoration from backups or snapshots.

**SEC-DEL-005 — HIGH**  
Physical deletion of ciphertext blobs SHOULD occur promptly after key destruction.

**SEC-DEL-006 — HIGH**  
If physical blob deletion fails, the system MUST continue retrying and MUST alert the administrator if the failure persists.

## Key lifecycle

**SEC-KEY-001 — CRITICAL**  
Per-report DEKs for active reports MAY use live replication inside the approved Key Service trust domain, but MUST NOT be included in historical backups or snapshots from which a destroyed DEK can later be restored.

**SEC-KEY-002 — CRITICAL**  
Destruction of a Report-DEK or Response-DEK MUST propagate to every supported live replica and MUST prevent reappearance through restore, rollback, delayed replication, stale replicas, snapshot recovery, or disaster recovery.

**SEC-KEY-003 — CRITICAL**  
After a DEK is destroyed, every supported restore procedure MUST leave the associated ciphertext undecryptable.

**SEC-KEY-004 — CRITICAL**  
The guarantee in SEC-KEY-003 MUST be demonstrated by a release-blocking proof of concept and disaster-recovery test before a Key Service product or topology is approved for production.

**SEC-KEY-005 — HIGH**  
TLS/service keys, audit-signing keys, organization export keys, Key Service infrastructure keys, Report-DEKs, and Response-DEKs MUST use distinct purposes and independently documented lifecycles; infrastructure keys MAY use secure backups under their own approved policies.

**SEC-KEY-006 — CRITICAL**  
Key Service capabilities MUST be role-scoped, operation-scoped, report-scoped where applicable, state-aware, and server-authoritative; the Reporter Gateway MUST NOT possess a general `decrypt_report` or `unwrap_any_DEK` capability.

**SEC-KEY-007 — CRITICAL**  
The historical-backup prohibition MUST cover plaintext, wrapped, encrypted, derived, replicated, or otherwise represented per-object key material whenever its combination with retained infrastructure keys or backup data could restore a destroyed Report-DEK or Response-DEK.

## Roles and trust separation

**SEC-ROLE-001 — CRITICAL**  
Operator, Application Administrator, and Infrastructure / Key Custodian MUST be distinct trust roles without implicit privilege inheritance.

**SEC-ROLE-002 — CRITICAL**  
The Application Administrator MUST NOT read reports, obtain DEKs, invoke arbitrary unwrap/decrypt operations, or use account administration, reset, recovery, or session functions to impersonate an operator.

**SEC-ROLE-003 — CRITICAL**  
The Infrastructure / Key Custodian MAY operate Key Service infrastructure and infrastructure-key lifecycle but MUST NOT automatically become an Operator, Application Administrator, audit reader, or report reader.

**SEC-ROLE-004 — HIGH**  
The security claims MUST explicitly exclude an adversary that simultaneously controls application/operator-console code and deployment, operator credentials, and the Key Service; this is complete infrastructure compromise, not normal administration.

## Recovery credentials

**SEC-RECOVERY-001 — CRITICAL**  
Recovery MUST use an independently generated, non-sequential high-entropy public Ticket ID and an independent 256-bit Recovery Secret generated by a CSPRNG.

**SEC-RECOVERY-002 — CRITICAL**  
The Recovery Secret MUST NOT be derived from the Ticket ID, timestamps, report content, reporter metadata, or any low-entropy value.

**SEC-RECOVERY-003 — CRITICAL**  
The Recovery Secret MUST NOT be stored in plaintext, logged, placed in a URL/query string, recoverable by an administrator, or re-displayed by the server after its one explicit post-submission display.

**SEC-RECOVERY-004 — CRITICAL**  
Response retrieval MUST submit Ticket ID, Recovery Secret, and the required CAPTCHA through POST and MUST use generic externally indistinguishable non-success responses as far as reasonably practical.

**SEC-RECOVERY-005 — CRITICAL**  
The exact Ticket ID encoding, Recovery Secret encoding, and keyed verifier construction MUST receive explicit cryptographic review and approval before recovery implementation.

## Response Note

**SEC-RESPONSE-001 — CRITICAL**  
Exactly one immutable Response Note MAY be published; it MUST be plain text, at most 5,000 characters, contain no HTML/images/attachments/active links, and have no persistent server-side draft.

**SEC-RESPONSE-002 — CRITICAL**  
Every Response Note MUST be encrypted under an independent Response-DEK; the Recovery Secret MUST NOT be the sole material sufficient to decrypt a retained or restored ciphertext indefinitely.

**SEC-RESPONSE-003 — CRITICAL**  
The system MUST make a Response-DEK usable only after valid Ticket ID and Recovery Secret credentials authorize recovery under the approved verifier, wrapping, and lifecycle construction.

**SEC-RESPONSE-004 — CRITICAL**  
The first successful read MUST set `first_read_at` from server-side time and establish Response-DEK expiry at 72 hours after that instant.

**SEC-RESPONSE-005 — CRITICAL**  
At Response-DEK expiry, the system MUST destroy the Response-DEK across all supported replicas, invalidate the recovery verifier/state, make all residual Response Note ciphertext unusable, and separately retry physical ciphertext deletion.

**SEC-RESPONSE-006 — CRITICAL**  
The Response-DEK and its ciphertext MUST satisfy SEC-KEY-002 through SEC-KEY-004, including non-resurrection after every supported restore.

**SEC-RESPONSE-007 — CRITICAL**  
Concurrent first-read attempts MUST establish exactly one immutable `first_read_at` and Response-DEK expiry using server-authoritative concurrency control; later reads MUST reuse that same expiry and MUST NOT extend it.

**SEC-RESPONSE-008 — CRITICAL**  
After the server-authoritative Response-DEK expiry, the Key Service and recovery path MUST refuse every further use even if replica cleanup or physical ciphertext/key-material deletion is still retrying.

## Finalization

**SEC-FINALIZE-001 — CRITICAL**  
Final response publication MUST use an explicit persisted FINALIZING state and MUST NOT be represented as one atomic transaction spanning PostgreSQL, the Audit Service, the Key Service, and blob storage.

**SEC-FINALIZE-002 — CRITICAL**  
The finalization protocol MUST require valid CAPTCHA, action-bound step-up authorization, and a durable `FINALIZATION_REQUESTED` audit receipt before persisting the protected Response Note.

**SEC-FINALIZE-003 — CRITICAL**  
The protected Response Note MUST be durably verified but MUST remain unavailable to the reporter until the Key Service has durably confirmed Report-DEK destruction and `REPORT_KEY_DESTROYED` has been durably audited.

**SEC-FINALIZE-004 — CRITICAL**  
Finalization MUST be idempotent, resumable after crash, safe for retry, fenced/versioned, resistant to double submit, and concurrency-safe against Emergency Export and deletion.

**SEC-FINALIZE-005 — HIGH**  
After Response Note availability, physical original-ciphertext deletion MUST be initiated; failures MUST be retried, audited using controlled metadata, and alerted according to SEC-DEL-006.

**SEC-FINALIZE-006 — CRITICAL**  
The exact protected Response Note bytes MUST be durably staged no later than the committed transition to `FINALIZING`; entering `FINALIZING` freezes those bytes and terminates ordinary operator content access, editing, reopening, and export for that report while only the scoped finalization protocol may resume.

## Emergency Export

**SEC-EXPORT-001 — CRITICAL**  
Only an authenticated operator holding the current valid OPEN lease for a report MAY initiate Emergency Export.

**SEC-EXPORT-002 — CRITICAL**  
Emergency Export MUST require CAPTCHA, action-bound step-up MFA, a system-defined reason code, a mandatory protected operator note of at most 1,000 characters, a durable pre-action audit receipt, and administrator notification.

**SEC-EXPORT-003 — CRITICAL**  
The final export artifact MUST use an approved public-key encryption format and the preconfigured organization public key; its manifest MUST be signed using an independently managed organization/instance signing key.

**SEC-EXPORT-004 — CRITICAL**  
Export processing MUST minimize plaintext lifetime and MUST NOT leave unnecessary plaintext package, report, attachment, manifest, or temporary-file persistence.

**SEC-EXPORT-005 — HIGH**  
Audit MUST retain the encrypted artifact hash and structured outcome metadata but MUST NOT retain the artifact, report content, attachment content, or full operator note.

**SEC-EXPORT-006 — HIGH**  
The system MUST document as an accepted residual risk that a legitimately authorized operator with a valid OPEN lease can deliberately create the authorized encrypted export; controls provide attribution and detection, not mathematical prevention.

## CAPTCHA and abuse resistance

**SEC-CAPTCHA-001 — CRITICAL**  
All CAPTCHA/challenge generation and verification MUST be self-hosted and MUST NOT use third-party tracking, remote challenge infrastructure, or IP/device fingerprinting.

**SEC-CAPTCHA-002 — CRITICAL**  
CAPTCHA MUST be enforced for anonymous submission, Response Note retrieval, final Response Note publication, and Emergency Export as required by the approved flows.

**SEC-CAPTCHA-003 — HIGH**  
The no-JavaScript reporter path MUST use a server-side, single-use, briefly expiring challenge with global abuse controls and no IP fingerprinting; its weaker anti-automation properties MUST be documented honestly.

**SEC-CAPTCHA-004 — CRITICAL**  
Operations for which CAPTCHA is mandatory MUST fail closed when challenge generation or validation is unavailable or invalid.

## File sandbox and CDR

**SEC-FILE-001 — CRITICAL**  
Untrusted PDF/JPEG/PNG parsing and transformation MUST occur only in a separate sandbox with no network, no production credentials, minimal filesystem access, disposable temporary workspace, and enforced CPU, memory, and time limits.

**SEC-FILE-002 — CRITICAL**  
Attachment acceptance MUST use an approved structural allowlist and MUST fail closed on uncertainty, parser error, profile violation, or resource-limit violation; no attachment may be described as absolutely safe.

**SEC-FILE-003 — CRITICAL**  
Normal operator viewing MUST use only the approved CDR/safe representation; original attachment bytes MUST NOT be directly opened or ordinarily downloaded.

**SEC-FILE-004 — HIGH**  
Plaintext temporary files and safe representations MUST have a defined creation, access, crash-cleanup, lease-expiry, and deletion lifecycle and MUST NOT use reporter-controlled names or paths.

**SEC-FILE-005 — HIGH**  
PDF upload MUST NOT be implemented until the structural profile, page/object/decompression/dimension limits, parser/toolchain, render strategy, and sandbox boundary are explicitly approved.

**SEC-FILE-006 — HIGH**  
Image upload/processing MUST NOT be implemented until decoded pixel/dimension limits, decoder/toolchain, viewing transformation policy, and sandbox/resource limits are explicitly approved.

## Alerts

**SEC-ALERT-001 — HIGH**  
Audit interruption/gaps, persistent ciphertext deletion failures, and Emergency Export MUST generate administrator alerts through an approved self-hosted mechanism.

**SEC-ALERT-002 — CRITICAL**  
Alerts MUST contain only system-defined event codes, system-generated identifiers, and explicitly allowlisted metadata; they MUST NOT contain report content, attachment data, Recovery Secrets, cryptographic keys, original filenames, full operator notes, or untrusted headers.

**SEC-ALERT-003 — HIGH**  
The alert transport, durable-acceptance semantics, retry policy, and behavior when notification is unavailable MUST be documented and approved before alert-dependent operations are implemented.

## Browser storage

**SEC-BROWSER-001 — CRITICAL**  
Sensitive report/operator pages MUST use no-store caching policy.

**SEC-BROWSER-002 — CRITICAL**  
Report content MUST NOT be intentionally stored in localStorage, IndexedDB, service workers, or persistent browser caches.

## Input limits

**SEC-INPUT-001 — HIGH**  
Report text MUST NOT exceed 5,000 characters.

**SEC-INPUT-002 — HIGH**  
A report MUST NOT contain more than one PDF and three images.

**SEC-INPUT-003 — HIGH**  
An accepted PDF MUST NOT exceed 5 MB.

**SEC-INPUT-004 — HIGH**  
Each accepted image MUST NOT exceed 5 MB.

**SEC-INPUT-005 — HIGH**  
The baseline MUST accept only PDF, JPEG, and PNG attachment formats.

**SEC-INPUT-006 — HIGH**  
Reverse proxy and application layers MUST enforce an explicitly approved aggregate HTTP/multipart body limit in addition to per-file limits before attachment upload is enabled.
