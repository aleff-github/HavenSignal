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

Request-admission code is currently limited to inert structural descriptors. It
may validate only the exact owner-approved body, file, text, control, header,
part, boundary, streaming-buffer, timing, method, content-type, and file-slot
metadata. It must not parse HTTP or multipart bodies, install upload handlers,
read file bytes, expose filenames, create sandbox jobs, persist plaintext, log
request material, expose endpoints, or accept submissions until the proxy,
Django handler, CSRF, CAPTCHA, sandbox, audit, Key Service, no-spool,
request-smuggling, review, and production gates are closed.

Attachment-admission code is currently limited to inert structural descriptors.
It may validate only the approved common count, size, kind, slot, extension,
transient-filename, and trust-denial metadata. It must not inspect file bytes,
trust filenames or MIME types, parse JPEG/PNG/PDF, create sandbox jobs, persist
originals, retain original filenames, log request material, expose upload or
safe-view endpoints, or authorize uploads until parser, sandbox, encryption,
safe-view, review, and production gates are closed.

Safe-view code is currently limited to inert structural descriptors. It may
validate only the approved PNG output, 8-bit sRGB, 144 DPI, output/resource
limit, no-store/nosniff response, binding, non-durability, and
ordinary-download-denial metadata. It must not decrypt attachments, render
files, validate PNG bytes, call a sandbox, persist output, serve responses,
inspect leases, expose endpoints, or authorize operator access until decrypt,
renderer, restricted-PNG verifier, sandbox, lease, response, review, and
production gates are closed.

File-sandbox code is currently limited to inert structural descriptors. It may
validate only the approved Firecracker reference, compute limits, isolation
denials, authenticated-vsock metadata, filesystem/workspace profile, and
credential-denial metadata. It must not boot microVMs, execute parsers, open
files, create jobs, exchange vsock messages, inspect attachment bytes, persist
plaintext, expose endpoints, or authorize file processing until Firecracker,
jailer, kernel/rootfs, broker, parser, renderer, review, and production gates
are closed.

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

No-JavaScript CAPTCHA code is currently limited to inert structural descriptors.
It may validate only the exact owner-approved version, identifier encoding,
answer alphabet/length, anonymous form-scope size, expiry/cleanup timing,
purpose/state registries, PNG bounds, global anonymous token-bucket limits, and
open production gates. It must not generate challenges, render image/audio,
persist challenge records, compare expected answers, use IP/User-Agent/device
keys, expose endpoints, call a Challenge Service, or authorize a protected
operation until the Pillow/font, audio/accessibility, PostgreSQL concurrency,
Challenge Service, gateway, and production-boundary gates are closed.

Original-report crypto code is currently limited to inert structural
descriptors. It may validate only the exact owner-approved Report-DEK,
object-subkey, algorithm, nonce/tag, fixed plaintext-frame,
ciphertext-and-tag, object-kind/slot, immutable-context, AAD/KDF purpose, and
allowlisted operation metadata. It must not canonicalize report text, inspect
attachment bytes, frame plaintext, generate keys/nonces, derive HKDF subkeys,
encrypt, decrypt, encode/parse CBOR, persist protected material, stream
attachments, call a Key Service, expose endpoints, log request material, or
authorize report use until the independent crypto review, Key Service,
storage, audit, sandbox, concurrency, and production gates are closed.

Original-report text code is currently limited to transient inert profile
validation. It may reject NUL/unpaired surrogate values and validate only the
approved UTF-8/NFC/LF, 5,000-scalar, 20,000-byte, and canonical-original
metadata profile. It must not retain browser/wire text, return canonical bytes,
construct frames, encrypt, persist, log, expose endpoints, create a submission,
or authorize acceptance until submission, audit, Key Service, storage,
request-admission, and production gates are closed.

Original-report frame code is currently limited to inert structural
descriptors. It may validate only the approved report-text and attachment
plaintext-frame layout metadata, version byte, public kind codes, big-endian
length markers, fixed frame sizes, payload markers, and zero-padding
requirements. It must not accept plaintext bytes, construct or parse frames,
validate padding bytes, inspect attachments, encrypt, decrypt, persist, expose
endpoints, or authorize submission until the cryptographic, Key Service,
storage, sandbox, request-admission, and production gates are closed.

Submission-audit code is currently limited to inert structural descriptors. It
may validate only the exact approved `SUBMISSION_ACCEPTANCE_REQUESTED`,
`SUBMISSION_RECEIVED`, and `SUBMISSION_ACCEPTANCE_FAILED` ordering, timing
labels, authorization windows, durable-receipt flags, and allowed/forbidden
payload metadata. It must not append audit events, create or verify receipts,
inspect attempt state, call the Audit Service, create report keys, persist
submission metadata, expose endpoints, or authorize submission until the audit
receipt, Key Service, submission, concurrency, deployment, and production gates
are closed.

Submission acceptance checkpoint code is currently limited to inert structural
descriptors. It may validate only the exact approved Phase 0-6 order,
checkpoint names, requirement labels, and forbidden runtime capability
metadata. It must not parse requests, validate credentials, claim attempts,
append audit events, verify receipts, call the Key Service, encrypt content,
write storage, commit database state, render responses, run reconciliation,
expose endpoints, or authorize submission until endpoint, credential,
PostgreSQL concurrency, audit, Key Service, storage, logging, reconciliation,
deployment, and production gates are closed.

Submission-attempt credential code is currently limited to inert structural
descriptors. It may validate only the approved single-use semantics, two-hour
non-sliding pre-claim lifetime, POST body/protected same-site cookie transport
labels, URL/query/referrer/header-log denials, forbidden report/recovery/
network/account/device bindings, minimum verifier/index representation,
database uniqueness/state-version metadata, and no-log/no-audit persistence
denials. It must not generate or verify credentials, persist credential
material, install cookies, inspect requests, claim attempts, log or audit the
credential, create reporter accounts, expose endpoints, authorize submission,
or authorize report read until the exact encoding, verifier, cookie/form
binding, endpoint, concurrency, logging, storage, and production gates are
closed.

Submission-reconciliation code is currently limited to inert structural
descriptors. It may validate only the exact approved scan interval, progress
deadline, cleanup retry cap, persistent-cleanup-alert threshold, candidate
states, terminal outcomes, action names, alert type, and allowed/forbidden
payload metadata. It must not scan report content, decrypt plaintext, create
credentials, append audit events, verify receipts, call the Audit/Key/Alert
services, delete ciphertext, mutate attempt state, schedule jobs, expose
endpoints, or authorize submission until submission, audit, Key Service,
storage, concurrency, scheduler, deployment, and production gates are closed.

Submission retry code is currently limited to inert structural descriptors. It
may validate only the exact approved retry source labels, required
one-database-winner/no-second-pipeline outcomes, controlled indeterminate
response behavior, no credential redisplay, and forbidden signal metadata. It
must not parse requests, verify attempt credentials, claim attempts, inspect
database state, create reports or Report-DEKs, append audit events, redisplay
credentials, expose status oracles, call services, expose endpoints, or
authorize submission until endpoint, credential verifier, PostgreSQL
concurrency, audit, Key Service, storage, logging, and production gates are
closed.

Submission failure-matrix code is currently limited to inert structural
descriptors. It may validate only the exact approved failure-boundary labels,
required-result labels, content-free flags, and fail-closed flags. It must not
handle requests, start submission pipelines, call services, write storage,
create keys, persist plaintext, append audit events, mutate state, return
credentials, expose endpoints, or authorize submission until endpoint,
pipeline, audit, Key Service, storage, cleanup, reconciliation, logging,
deployment, and production gates are closed.

Submission idempotency code is currently limited to inert structural
descriptors. It may validate only the exact approved concurrency/idempotency
scenario labels, invariant labels, and forbidden runtime capability metadata.
It must not run parallel requests, handle requests, inspect attempt state, lock
database rows, write storage, create Report-DEKs, append audit events,
reconcile artifacts, log reporter input, expose endpoints, or authorize
submission until endpoint, PostgreSQL concurrency, audit, Key Service, storage,
reconciliation, logging, deployment, and production gates are closed.

Submission credential-response code is currently limited to inert structural
descriptors. It may validate only the approved one live post-acceptance display
opportunity, controlled indeterminate retry result, permitted Ticket ID and
Recovery Secret field names for that live response, and forbidden persistence
categories. It must not generate credentials, persist or redisplay the Recovery
Secret, issue replacements, record `credentials_delivered`, deduplicate by
content, render responses, inspect requests, mutate attempts, expose endpoints,
or authorize recovery/submission until the credential, verifier, endpoint,
storage, logging, recovery, and production gates are closed.

Recovery credential code is currently limited to inert structural descriptors.
It may validate the exact owner-approved Ticket ID and Recovery Secret encoding
shapes, but it must not generate credentials, compute or compare verifier tags,
persist or log plaintext secrets, perform lookup, expose endpoints, call a
Recovery Verifier Service, or authorize access to a Response Note until the
cryptographic-review and dependent gates are closed.

Recovery failure-behavior code is currently limited to inert structural
descriptors. It may validate only the exact approved recovery failure-boundary
labels, required-result labels, generic external-result flags, fail-closed
flags, and forbidden runtime capability metadata. It must not generate
randomness, decode credentials, call a verifier, compare HMAC tags, read
response state, call the Key Service, mutate first-read state, log
credentials, expose endpoints, or authorize recovery until verifier, response
eligibility, first-read concurrency, Key Service, logging, deployment, and
production gates are closed.

Recovery Verifier key-lifecycle code is currently limited to inert structural
descriptors. It may validate only the exact approved 32-byte verifier-key size,
state registry, separated key purposes, forbidden locations, and lifecycle
requirements. It must not generate keys, store key material, select keys for
requests, rotate or destroy keys, rewrite verifier records, call a Key Service,
authorize Response-DEK use, expose endpoints, or authorize recovery until the
verifier service, rotation/incident procedure, restore proof, Key Service,
logging, deployment, and production gates are closed.

Recovery verification code is currently limited to inert structural
descriptors. It may validate only the exact approved full-length HMAC-SHA-256,
constant-time full-tag comparison, boolean-only result, necessary-not-
sufficient HMAC success, canonical input, dummy-verification, generic-response,
timing-test, and no-perfect-indistinguishability metadata. It must not compute
HMACs, compare tags, execute dummy verification, return tags or partial-match
details, read response state, validate CAPTCHA, call a Key Service, authorize
Response-DEK use, log credentials, expose endpoints, or authorize recovery
until verifier execution, timing, response eligibility, CAPTCHA, Key Service,
logging, deployment, independent-review, and production gates are closed.

Recovery verifier-record code is currently limited to inert structural
descriptors. It may validate only the exact approved persisted field labels,
32-byte tag size, server-controlled key ID, no-secret/no-raw-key/no-database-
alone-test requirements, removal/invalidation metadata, and forbidden-material
categories. It must not create database rows, persist real verifier records,
compute verifiers, test candidate secrets, perform lookups, expose endpoints,
or authorize recovery until verifier, metadata-store, recovery-state,
Response-DEK, logging, deployment, independent-review, and production gates are
closed.

Response Note cryptographic code is currently limited to inert structural
descriptors. It may validate only the exact approved version, algorithm,
content-profile, size, AAD-purpose, immutable-context, envelope, and
Response-DEK operation profile shapes. It must not canonicalize Response Note
text, construct frames or CBOR, encrypt, decrypt, parse ciphertext envelopes,
hold real nonces/key handles/DEKs, persist protected bytes, call a Key Service,
or authorize response use until independent review and all dependent gates are
closed.

Response Note text code is currently limited to inert, content-free descriptor
validation. It may transiently reject malformed synthetic text according to the
approved scalar, NUL, line-ending, NFC, UTF-8 limit, plain-text, no-HTML, and
no-link-marker profile, but it must not return or persist the text, normalized
text, canonical bytes, previews, drafts, digests, frames, audit bindings, or
state transitions until the finalization and cryptographic gates are closed.

Response Note schema code is currently limited to inert, content-free metadata
descriptors. It may validate only the ordered AAD and ciphertext-envelope field
names, primitive categories, fixed byte sizes, and public constant values. It
must not encode or parse CBOR, retain actual identifiers, key handles, nonces,
ciphertext, AAD bytes, or plaintext, call services, inspect state, persist
anything, expose endpoints, or authorize response use.

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
