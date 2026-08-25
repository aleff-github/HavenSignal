# 16 — Django Development Rules

## Framework

Use Django 5.2 LTS (latest patched release at implementation time) unless explicitly revised.

## Settings

Production must:

- `DEBUG = False`;
- use a strong, externally supplied `SECRET_KEY`;
- define strict `ALLOWED_HOSTS`;
- enforce secure cookies;
- enforce HttpOnly;
- use SameSite according to the final flow;
- enforce HTTPS on conventional web endpoint;
- use HSTS only after deployment review;
- use clickjacking protection;
- use CSRF protection;
- use restrictive CSP;
- avoid verbose error exposure.

Exact settings must be reviewed against current Django and OWASP documentation at implementation time.

## Authentication

Do not use Django Admin as the primary security-sensitive operator interface unless MFA integration is explicitly proven.

Prefer purpose-built operator and administrator views with explicit authorization checks.

Never rely on "hidden URL" as access control.

## ORM / transactions

Use ORM parameterization.

For state transitions use proper transactions and row locking/version checks where needed.

Never trust client-side state flags.

## Sessions

Django session configuration must support the required:

- 5-minute idle semantics;
- 60-minute absolute OPEN lease;
- step-up MFA state;
- server-side invalidation.

Do not assume default Django session expiry directly implements all report-lease requirements.

Report OPEN lease should be an explicit server-side domain object/state, not merely the login session cookie.

The persisted lease must carry a random lease identifier and monotonically increasing generation/fencing token. Every sensitive operation validates the current generation and server-side time so stale tabs, sessions, and retries cannot reactivate access.

## Uploads

Django upload handlers and reverse proxy must enforce hard body-size limits.

Do not process untrusted files in the web worker.

Move validation/rendering into isolated workers.

Do not implement PDF upload until the approved structural profile and sandbox/CDR design exist. The web/proxy/worker pipeline must not durably spool unencrypted reporter files.

## Logging

Create explicit structured logging schemas.

Do not attach raw request bodies or broad request-context serializers.

Implement log redaction by design, not as an afterthought.

Permanent audit accepts only system-defined reason codes. Arbitrary reopening/export notes are encrypted operational ticket data and are destroyed with the ticket.

## Error handling

Generic reporter-facing errors.

Internal error identifiers may be system-generated.

Never render stack traces to users.

Never log sensitive locals automatically.

## Dependencies

Use pinned/locked dependencies.

Avoid unnecessary packages.

For every security-sensitive dependency record:

- purpose;
- maintenance status;
- security history;
- update policy.

## Tests

Every security requirement must have at least one negative/failure test where technically testable.

## Finalization and external services

Do not model finalization as one Django/PostgreSQL transaction spanning external services.

Use explicit persisted `FINALIZING` state, idempotency identifiers, state version/fencing, durable audit receipts, durable Key Service destruction confirmation, and safe retry/resume behavior.

The Response Note must remain reporter-invisible until Report-DEK destruction is confirmed and durably audited.

## Security interfaces before implementation

Security-sensitive components whose exact construction remains OPEN must be represented only by explicit failing interfaces/placeholders. Do not add a convenience fallback, development plaintext mode, or provisional cryptographic construction.
