# 11 — Technology Decisions and Candidates

## Approved direction

Backend language: **Python**

Preferred web framework: **Django**

Reason:

- maintainability;
- mature security controls;
- CSRF protection;
- templating/escaping;
- ORM/query parameterization;
- session/auth foundations;
- middleware ecosystem;
- fewer security-critical primitives to rebuild manually.

Current version candidate: **Django 5.2 LTS**, latest supported security patch at implementation time.

Do not pin to an old patch version in documentation; lock the exact dependency in the repository when implementation begins.

## Rendering

Reporter-facing flow should prefer server-rendered HTML with minimal JavaScript rather than a SPA.

Candidate:

- Django Templates.

## Database

Candidate:

- PostgreSQL.

## Application serving

Candidates:

- Gunicorn/WSGI for the Django application;
- hardened reverse proxy such as nginx.

Final deployment topology must prioritize service separation rather than running everything as one privileged process.

## Cryptography

Candidate:

- libsodium through a maintained Python binding such as PyNaCl.

No home-grown crypto.

Final constructions require dedicated review.

## Key management

Candidate:

- OpenBao or another dedicated key service / vault / HSM-capable component.

NOT YET APPROVED.

Must demonstrate:

- separation from report DB;
- operator/admin privilege boundaries;
- deletion semantics;
- active-key resilience;
- non-resurrection after backups/snapshots;
- auditability;
- failure-closed behavior.

The approved per-object key policy permits live replication of active Report-DEKs and Response-DEKs but forbids restorable historical backups/snapshots of those keys. Catastrophic loss of active reports is accepted rather than risking resurrection of destroyed keys.

Approval requires a release-blocking proof of concept covering replication, delete, snapshot/restore, rollback, delayed/stale replicas, and disaster recovery. OpenBao is not presumed compliant.

## Operator MFA

Preferred:

- WebAuthn/FIDO2 hardware-backed or passkey-capable authentication;
- Python library candidates such as `python-fido2` or an appropriately reviewed Django integration.

The custom operator/admin interfaces must enforce MFA.

Do not assume Django Admin automatically inherits a separate MFA layer.

## Password hashing

Preferred:

- Argon2id using Django-supported configuration reviewed against current OWASP guidance.

## CAPTCHA

JavaScript-enabled candidate:

- ALTCHA, self-hosted.

The no-JavaScript path must be a self-hosted server-side, single-use, briefly expiring challenge with global abuse controls and no IP/device fingerprinting. The exact product/implementation remains OPEN.

Do not use Google reCAPTCHA.

Do not introduce third-party tracking CAPTCHA.

## File processing

Must be separated from the main Django process.

Candidate tools may include:

- qpdf/pikepdf for structural inspection as appropriate;
- robust PDF rendering tooling in an isolated sandbox;
- self-hosted ClamAV as an additional defense, not as sole validation;
- CDR/rasterization strategy where appropriate.

Tool choice must be validated against sandboxing and parser-risk requirements.

PDF upload is blocked until the structural acceptance profile, page/object/decompression/dimension limits, parser/toolchain, rendering strategy, and sandbox technology are approved.

## Audit

Implement as a separate collector/store or equivalent boundary.

Django report application should not own permission to rewrite/delete audit history.

The collector must durably accept pre-action events and return verifiable receipts. Tamper evidence must detect alteration, gaps, cessation, and truncation through hash chaining or equivalent plus independently verifiable signed checkpoints or equivalent controls.

## Deployment

Single organization per instance.

Production should separate at least:

- reporter-facing web/application boundary;
- operator-facing application boundary or privilege profile;
- key service;
- audit collector/store;
- file-processing sandbox worker;
- PostgreSQL/report metadata;
- encrypted blob storage.

Exact VM/container/process boundaries require architecture review.

Application Administrator and Infrastructure / Key Custodian are separate trust roles. The Reporter Gateway must not possess arbitrary existing-report decrypt/unwrap capability.

Finalization uses an explicit persisted `FINALIZING` state and an idempotent, resumable protocol; it is not one atomic transaction across PostgreSQL, Audit Service, Key Service, and blob storage.

## Telemetry

External telemetry and cloud crash-reporting are disabled or self-hosted.

No sensitive content may leave the trusted deployment boundary.
