# Anonymous Reporting — Security-First Handoff

This package transfers the current project knowledge into a form suitable for Codex and future developers.

The project is **not** a chat platform and **not** an authenticated whistleblowing portal. It is a minimal anonymous disclosure and one-response system designed around strong confidentiality and controlled operator access.

## Core flow

1. A reporter submits:
   - one text field;
   - optionally one PDF and/or up to three images.
2. The submission is stored encrypted.
3. An operator claims the report before seeing any content.
4. The operator processes the report in a tightly controlled session.
5. The operator publishes exactly one plain-text Response Note.
6. The original report encryption key is destroyed.
7. Report text and attachments become irrecoverable.
8. The reporter later retrieves only the Response Note using high-entropy recovery credentials.

## Security principle

The system is designed so that highly sensitive content is retained for the minimum necessary period and access is exceptional, attributable, and auditable.

The project owner explicitly prioritizes security over availability, convenience, and visual design.

## Start here

Read, in order:

1. `AGENTS.md`
2. `docs/00_PROJECT_SCOPE.md`
3. `docs/01_SECURITY_BASELINE.md`
4. `docs/02_THREAT_MODEL.md`
5. `docs/03_DATA_LIFECYCLE.md`
6. `docs/12_OPEN_SECURITY_DECISIONS.md`
7. `docs/19_SECURITY_SERVICE_INTERFACES.md`
8. `docs/20_SUBMISSION_ACCEPTANCE_PROTOCOL.md`
9. `docs/21_RECOVERY_CREDENTIAL_CONSTRUCTION.md`
10. `docs/22_NO_JAVASCRIPT_CHALLENGE_PROTOCOL.md`
11. `docs/23_AUDIT_RECEIPT_AND_TRANSPARENCY_PROTOCOL.md`
12. `docs/24_RESPONSE_NOTE_CRYPTOGRAPHIC_PROTOCOL.md`
13. `docs/25_MFA_STEP_UP_AND_CREDENTIAL_LIFECYCLE.md`
14. `docs/26_REPORT_CONTENT_CRYPTOGRAPHIC_PROTOCOL.md`
15. `docs/27_KEY_SERVICE_ACCEPTANCE_AND_NON_RESURRECTION_POC.md`
16. `docs/28_EMERGENCY_EXPORT_CRYPTOGRAPHIC_PROTOCOL.md`
17. `docs/29_FILE_ACCEPTANCE_SANDBOX_AND_SAFE_VIEW_PROTOCOL.md`
18. `docs/30_REQUEST_AND_MULTIPART_ADMISSION_PROTOCOL.md`
19. `docs/31_ADMINISTRATOR_ALERT_PROTOCOL.md`
20. `docs/32_RETENTION_AND_DELETION_PROTOCOL.md`
21. `docs/33_OPERATIONAL_ACCESS_AND_WORKSTATION_HARDENING.md`
22. `docs/34_PRE_CODE_SECURITY_GATE.md`
23. `START-CODEX.md`

## Source material

`source/Questionario_requisiti_sicurezza_segnalazioni_anonime_v0.1.pdf` is the completed original questionnaire.

The Markdown specification incorporates later clarifications and therefore takes precedence where the source questionnaire differs.

## Current implementation status

The repository contains a Django 5.2.17 development scaffold, one inert,
read-only reporter landing page, and an internal metadata-only submission
state model. The page has no form, JavaScript, analytics, third-party
resources, report storage, authentication, or business logic.

`submission_workflow/` defines only the approved attempt states, database
shape, constraints, and a pure monotonic transition planner. It has no HTTP
route or database transition executor and stores no reporter content,
credential, key, verifier, filename, request metadata, or audit receipt.

`report_lifecycle/` implements the owner-authorized inert Stage A for
metadata-only Report, ReportLease, and SecurityOperation concepts. It provides
explicit state edges, monotonically versioned pure planners, server-time lease
validation, and database constraints for one active report/lease/operation
fence. Immutable descriptors additionally reject cross-report, cross-actor,
stale-version, stale-generation, wrong-lease, and expired-lease bindings. The
persistence boundary rejects SQLite and remains write-disabled even for a
nominally capable backend until the PostgreSQL executor is independently
reviewed and tested. A test-only concurrency scaffold defines six closed
metadata races, generates only ephemeral UUIDs for 20–100 contenders, and keeps
its runner unavailable even for a capability-shaped backend. It is not
PostgreSQL evidence. The app has no views, URLs, authentication, content, file,
recovery, cryptographic, audit, alert, export, deletion, or background-job
capability.

Mandatory security integrations whose designs remain OPEN are represented only
by explicit deny-by-default placeholders under `security_interfaces/`. Every
placeholder operation raises a controlled failure and provides no plaintext,
cryptographic, audit-receipt, CAPTCHA, recovery, sandbox, MFA, or alert fallback.
The same package now contains inert audit-v1 structural types for the exact
event/actor registries, replay identifiers, and acceptance-claim lifetimes
already fixed by `docs/23`. They do not encode CBOR, parse or verify COSE,
append an event, or authorize an operation.
It also contains inert alert-v1 components for the fixed alert/severity and
delivery-state registries, actor/operation identifiers, acceptance response,
and acknowledgement pairing from `docs/31`. They do not send, persist, queue,
deliver, or acknowledge an alert.
Inert report-bound step-up-v1 components model only approved identifier shapes,
lease/state counters, the 120-second non-sliding lifetime, allowed COSE
algorithm codes, and artifact-binding profile metadata. They contain no
challenge, browser handle, WebAuthn credential, artifact bytes, or HMAC output.

`architecture_checks/` statically enforces the current Reporter Gateway and
root-URL import allowlists without importing or executing scanned source. It
also fixes the inert Django app/middleware settings, single reporter-home route,
passive template subset, and no-resource-loading CSS profile without importing
or rendering them. The exact initial lifecycle migration graph, field/type
profile, and closed operation set are likewise checked without importing the
migration, alongside Django's no-drift check. These are review guards for the
inert codebase, not a runtime, browser, database, process, network, or
deployment security boundary.

Security-sensitive components remain blocked by their applicable OPEN decisions. The service interfaces and negative capability boundaries are approved as the implementation boundary, without closing those decisions.

The submission acceptance, audit, retry, and one-time credential-delivery
sequence in `docs/20_SUBMISSION_ACCEPTANCE_PROTOCOL.md` is approved. This
closes only the sequencing decision: dependent CAPTCHA, credential, AEAD, Key
Service, audit-receipt, request-size, and file/sandbox gates still prevent a
report form, endpoint, or protected database transition executor.

The exact Ticket ID, Recovery Secret, and keyed-verifier construction in
`docs/21_RECOVERY_CREDENTIAL_CONSTRUCTION.md` is owner-approved. Recovery
remains disabled until its independent cryptographic review and every
dependent gate are complete.

The self-hosted no-JavaScript challenge, atomic consumption, and anonymous
global abuse limits in `docs/22_NO_JAVASCRIPT_CHALLENGE_PROTOCOL.md` are
owner-approved. No CAPTCHA dependency or endpoint is enabled until the pinned
rendering, audio/accessibility, PostgreSQL-concurrency, and production-boundary
reviews are complete.

The exact audit-event encoding, durable-acceptance receipt, replay controls,
Merkle proofs, independently witnessed checkpoints, and signing-key separation
in `docs/23_AUDIT_RECEIPT_AND_TRANSPARENCY_PROTOCOL.md` are owner-approved.
The inert structural types deliberately reject the context-dependent
`REPORT_KEY_DESTROYED` lifetime until the exact operation profile can
distinguish response publication from other destruction outcomes. No Audit
Service, receipt gate, or protected operation is authorized until the
independent protocol review and production gates are complete.

The exact Response Note byte profile, AEAD envelope, non-exportable
Response-DEK operations, staging, and first-read expiry sequence in
`docs/24_RESPONSE_NOTE_CRYPTOGRAPHIC_PROTOCOL.md` are owner-approved. No
finalization or recovery-decryption implementation is authorized before the
independent protocol review and Key Service production gates are complete.

The production WebAuthn profile, exact artifact binding, server-side one-time
step-up authorization, and factor lifecycle in
`docs/25_MFA_STEP_UP_AND_CREDENTIAL_LIFECYCLE.md` were owner-approved on
2026-08-26. Authentication and protected operations remain disabled pending
independent review and their production gates.

The exact Report-DEK, per-object subkey, fixed-length text/attachment framing,
AEAD envelope, staging, and narrow decryption model in
`docs/26_REPORT_CONTENT_CRYPTOGRAPHIC_PROTOCOL.md` were owner-approved on
2026-08-26. Report submission and content access remain disabled pending
independent review and Key Service/file/deployment gates.

`docs/27_KEY_SERVICE_ACCEPTANCE_AND_NON_RESURRECTION_POC.md` is the
owner-approved candidate-neutral Key Service capability and destructive
acceptance plan. No product, including OpenBao, is approved without a real
production-equivalent snapshot/rollback/stale-replica/disaster-recovery PoC
and independent review.

The exact Emergency Export request binding, closed `ustar` package, binary
single-recipient X25519 `age` encryption, RFC 8785 manifest, detached COSE
Sign1/Ed25519 signature, fenced workflow, encrypted staging, and one-shot
delivery in `docs/28_EMERGENCY_EXPORT_CRYPTOGRAPHIC_PROTOCOL.md` were
owner-approved on 2026-08-26. Export remains disabled pending independent
review and the named alert, Key Service, signer, custody, concurrency,
workstation, and deployment gates.

The exact PDF/JPEG/PNG structural profiles, resource ceilings, parser families,
fresh Firecracker microVM isolation, transient plaintext lifecycle, and
PNG-only operator view in
`docs/29_FILE_ACCEPTANCE_SANDBOX_AND_SAFE_VIEW_PROTOCOL.md` were owner-approved
on 2026-08-26. Attachment upload and viewing remain disabled pending
independent review, exact artifact pinning, and production sandbox/integration
gates.

The exact 21 MiB request ceiling, closed multipart grammar, streaming/no-spool
proxy behavior, bounded Django sandbox upload handler, and failure tests in
`docs/30_REQUEST_AND_MULTIPART_ADMISSION_PROTOCOL.md` were owner-approved on
2026-08-26. Submission remains disabled pending independent HTTP/proxy/Django
review and all dependent gates.

The self-hosted Alert Service, durable administrator inbox, local SMTP wake-up
queue, closed metadata-only schema, idempotent durable acceptance,
retry/escalation, acknowledgement, retention, and per-operation failure policy
in `docs/31_ADMINISTRATOR_ALERT_PROTOCOL.md` were owner-approved on 2026-08-26.
Alert-dependent operations remain disabled pending independent
security/operations review and production deployment gates.

The 90-day never-read response expiry, OPEN-only operator deletion without a
Response Note, exceptional multi-person SEALED flood-deletion ceremony,
receipt-gated forward key destruction, ciphertext cleanup, terminal metadata
minimization, and isolated audit-retention authority in
`docs/32_RETENTION_AND_DELETION_PROTOCOL.md` were owner-approved on 2026-08-26.
They remain disabled pending legal/operational approval, independent review,
and all named Key Service/audit/MFA/alert and deployment gates.

The physically separate Operator, Application Administrator, and Key Custodian
workstation classes, Ubuntu/Firefox hardened builds, ephemeral browser and
peripheral/network controls, exact role sessions, encrypted-only export
transfer broker, administrative step-up, custodian quorum/bastion, break-glass,
patching, and periodic reviews in
`docs/33_OPERATIONAL_ACCESS_AND_WORKSTATION_HARDENING.md` were owner-approved
on 2026-08-26. Production access remains disabled pending independent review,
exact hardware/software/infrastructure selection, and physical acceptance
testing.

`docs/34_PRE_CODE_SECURITY_GATE.md` records the 2026-08-26 owner approval for
`docs/25` through `docs/33`, preserves all external and production gates, and
authorizes only the metadata-only Stage A. It does not authorize protected
workflows or close any external gate.

## Local preview

From this repository directory, using the prepared virtual environment:

```powershell
.\.venv\Scripts\python.exe manage.py check
.\.venv\Scripts\python.exe manage.py test -v 2
.\.venv\Scripts\python.exe manage.py runserver 127.0.0.1:8000
```

Then open `http://127.0.0.1:8000/`. If that port is already occupied, choose a
different local port such as `8001`. The Django development server is for local
testing only and must not be used as the production server.
