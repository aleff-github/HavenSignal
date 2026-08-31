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

`docs/30_REQUEST_AND_MULTIPART_ADMISSION_PROTOCOL.md` defines the owner-approved exact 21 MiB
request/multipart profile, streaming proxy behavior, and a single bounded
`SandboxStreamingUploadHandler`. Django's default memory and temporary upload
handlers remain forbidden for the submission endpoint. The design is
non-authorizing until independent review and production no-spool gates close.

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

Recovery credential code is currently limited to inert structural descriptors.
It may validate the exact owner-approved Ticket ID and Recovery Secret encoding
shapes, but it must not generate credentials, compute or compare verifier tags,
persist or log plaintext secrets, perform lookup, expose endpoints, call a
Recovery Verifier Service, or authorize access to a Response Note until the
cryptographic-review and dependent gates are closed.

Response Note cryptographic code is currently limited to inert structural
descriptors. It may validate only the exact approved version, algorithm,
content-profile, size, AAD-purpose, immutable-context, envelope, and
Response-DEK operation profile shapes. It must not canonicalize Response Note
text, construct frames or CBOR, encrypt, decrypt, parse ciphertext envelopes,
hold real nonces/key handles/DEKs, persist protected bytes, call a Key Service,
or authorize response use until independent review and all dependent gates are
closed.

## Inert bootstrap evidence

The current `manage.py`, ASGI/WSGI entrypoints, and installed metadata-app
configurations are guarded by a non-executing exact-AST policy. The reviewed
settings module, standard Django application factories, command-line boundary,
app identities, and absence of startup hooks are fixed. Alternate settings,
wrappers, logging, network/file effects, early execution, and `ready()` hooks
require explicit review.

This evidence does not execute the entrypoints and does not prove runtime,
process, proxy, environment, dependency, network, or production isolation.

The current application and migration package initializers are guarded by the
same non-executing exact-AST pattern. Passive package markers and the reviewed
`security_interfaces.__init__` re-export surface must not gain imports,
exports, startup effects, migration initializer code, or dynamic behavior
without an explicit policy update.

CI must run `python -m architecture_checks .` as the aggregate static policy
gate. This command only consolidates the existing non-executing checks; passing
it is not browser, PostgreSQL, process-isolation, external-service, deployment,
or production evidence.

The aggregate policy must include a content-free repository-hygiene check for
tracked local databases, logs, virtual environments, secret/config material,
export artifacts, temporary workspaces, quarantine areas, user media, collected
static output, and cache/test artifacts. The check may inspect path names and
`.gitignore` rules only; it must not read or print candidate file contents and
does not replace dedicated secret scanning.

Local verification should use `scripts/verify`. That script is itself guarded
by a non-executing source policy and must retain the reviewed sequence:
architecture policies, Django system check, migration drift check, Django test
suite, Python compilation, and manifest validation. The script is developer
tooling only and is not production evidence.

CI must install dependencies from `requirements.lock` with `--require-hashes`
and then run `scripts/verify`. The CI workflow must keep read-only repository
permissions and pinned GitHub Action commit SHAs. Moving action refs, write or
OIDC permissions, un-hashed dependency installation, and `continue-on-error`
require explicit review and must fail the static workflow policy by default.
