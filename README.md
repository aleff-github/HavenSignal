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
12. `START-CODEX.md`

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

Mandatory security integrations whose designs remain OPEN are represented only
by explicit deny-by-default placeholders under `security_interfaces/`. Every
placeholder operation raises a controlled failure and provides no plaintext,
cryptographic, audit-receipt, CAPTCHA, recovery, sandbox, MFA, or alert fallback.

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
No Audit Service, receipt gate, or
protected operation is authorized until the independent protocol review and
production gates are complete.

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
