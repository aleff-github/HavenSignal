# Security Constitution

HavenSignal is a security-critical anonymous reporting system intended to
receive highly sensitive disclosures.

## Priority order

1. Confidentiality of report text and attachments.
2. Integrity and tamper-evidence of the audit trail.
3. Reporter anonymity and metadata minimization.
4. Operator authentication, accountability, and least privilege.
5. Correct cryptographic deletion and non-resurrection of destroyed reports.
6. Availability.
7. Maintainability.
8. UX and visual design.

Security must not be weakened to improve convenience, speed, aesthetics,
developer ergonomics, or availability.

## Security-sensitive implementation baseline

Before changing authentication, authorization, cryptography, storage, files,
logging, sessions, reporting, response retrieval, deletion, export, networking,
or deployment behavior, the implementation must be checked against:

- `docs/01_SECURITY_BASELINE.md`
- `docs/02_THREAT_MODEL.md`
- `docs/03_DATA_LIFECYCLE.md`
- the domain-specific document for the component being modified.

## Scope constraints

The system must not introduce:

- reporter accounts;
- reporter authentication;
- email or phone collection;
- chat or two-way messaging;
- reply threads;
- analytics or third-party telemetry on reporter-facing surfaces;
- report aggregation, scoring, rankings, or automated accusation counting;
- AI-based decision making;
- guided questionnaires in the submission form;
- external CAPTCHA/tracking dependencies;
- ordinary operator download of report attachments;
- server-side drafts of the Response Note.

The reporter-facing baseline is:

`anonymous submission -> human processing -> one Response Note -> cryptographic destruction of the original report`

## Security coding rules

- Never invent cryptographic protocols.
- Use mature, standard cryptographic libraries and documented constructions.
- Never place reporter-controlled input in application logs or audit logs.
- Never log request bodies from reporter-facing endpoints.
- Never log recovery secrets, cryptographic keys, original filenames, report
  text, attachment contents, or untrusted headers.
- Fail closed for security-sensitive operations when required security
  dependencies are unavailable.
- Do not silently fall back to a weaker security mode.
- Treat every file upload as hostile until validated.
- Do not trust filename, extension, MIME type, Content-Type, or metadata
  supplied by the client.
- Do not use user-controlled data as a filesystem path.
- Do not expose report identifiers sequentially.
- Do not put secrets in URLs or query strings.
- Do not cache sensitive operator/report pages.
- Do not use localStorage, IndexedDB, service workers, or browser persistence
  for report content.
- Preserve strict separation of administrator and operator privileges.
- Preserve strict separation between Operator, Application Administrator, and
  Infrastructure / Key Custodian privileges.
- Normal application or infrastructure administration must not, by itself,
  confer report-decryption capability.
- The Application Administrator must not impersonate an operator through
  account-management or recovery functions.
- The Reporter Gateway must not possess a general capability to decrypt
  existing reports or unwrap arbitrary report DEKs.
- Per-report DEKs and Response-DEKs must not be placed in historical backups
  or snapshots that can resurrect a destroyed key.
- Security-sensitive disclosure, destruction, and export actions must obtain
  the required durable audit receipt before the protected action occurs.
- Security-sensitive transitions must be server-authoritative and
  concurrency-safe.
- Finalization across PostgreSQL, the Audit Service, the Key Service, and blob
  storage must use the approved idempotent, resumable `FINALIZING` protocol;
  it must not be described or implemented as one atomic transaction.

## Conflict handling

If code, documentation, tests, or requested implementation behavior conflict:

1. stop the change;
2. identify the conflict;
3. do not choose a weaker interpretation autonomously;
4. require an explicit project-owner decision.

Contradictions must not be silently reconciled.

## Specification precedence

From highest to lowest authority:

1. explicit project-owner decisions made after the latest documentation update;
2. current Markdown documents under `/docs`;
3. `docs/13_REQUIREMENTS_TRACEABILITY.md`;
4. original questionnaire under `/source`.

The questionnaire is historical evidence and may contain decisions later
superseded.

## Development workflow

Before implementing a security-sensitive feature:

1. state which requirements apply;
2. state trust boundaries touched;
3. state failure behavior;
4. state what data is created, persisted, logged, encrypted, or deleted;
5. add tests for abuse cases and failure cases, not just the happy path;
6. run the relevant security checklist;
7. do not merge while an unresolved critical item affects the implementation.

## Framework decision

Backend language: Python.

Preferred framework: Django, unless a documented technical reason approved by
the project owner justifies another Python framework.

Current candidate baseline: Django 5.2 LTS.

Do not replace Python/Django with Rust, Node.js, PHP, or another backend stack
without explicit approval.
