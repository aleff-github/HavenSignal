# Current Project Status

**Status: security-first pre-alpha / metadata-only implementation stage.**

This document keeps the implementation boundary visible without requiring the top-level README to reproduce the full handoff narrative.

HavenSignal is initially intended for universities and higher-education
institutions. Each deployment serves one approved organization while the
software remains configurable rather than hard-coded to a specific
institution's identity system, hierarchy, terminology, or internal policy.

## Reporter surface

The repository contains a Django 5.2.17 development scaffold, one inert
reporter landing page, one inert `/status/` page, one fail-closed `/submit/`
surface, one separate fail-closed `/response/` recovery-gateway surface, and
one inert fail-closed `/operator/` console entry point.

These pages have no:

- submission form;
- JavaScript;
- analytics;
- third-party resources;
- report storage;
- authentication;
- production business logic.

The current surface must not be used for real sensitive reports.

The `/status/` route is a static public status page. It reads no request body,
queries no database, calls no services, exposes no runtime health detail, and
does not create or mutate application state.

The `/submit/` route is intentionally disabled. GET renders static guidance.
POST returns a controlled `503` without reading `request.body`, `request.POST`,
or `request.FILES`, and without creating any report, attempt, audit event,
credential, key, upload, or database transition.

POST `/submit/` requests with an absent, non-decimal, zero, or
greater-than-22,020,096-byte `Content-Length` are rejected by the
browser-facing middleware before the view is called. This preliminary guard
reads no request body, installs no upload handler, parses no multipart data,
and does not accept submissions.

The `/response/` route is intentionally disabled and served by the separate
Recovery Gateway app. GET renders static guidance. POST returns a controlled
`503` without reading `request.body`, `request.POST`, or `request.FILES`, and
without creating any credential verification, lookup, audit event, key
operation, decryption, plaintext rendering, recovery-state mutation, or
database transition.

The `/operator/` route is intentionally disabled. GET renders a static
operator-console unavailable page. POST returns a controlled `503` without
reading `request.body`, `request.POST`, or `request.FILES`, and without
creating any authentication session, WebAuthn challenge, report lookup, audit
event, lease, key operation, decryption, export, or database transition.

## Submission workflow

`submission_workflow/` defines only the approved attempt states, database
shape, constraints, and a pure monotonic transition planner.

It has no accepting public submission endpoint or database transition executor
and stores no reporter content, credential, key, verifier, filename, request
metadata, or audit receipt.

Its sole initial migration is locked by a non-executing exact-AST policy that
also rejects additional numbered migrations. Schema, state/version,
constraint, timestamp, import, dynamic, data, SQL, or custom-code changes
require explicit review; passing provides no PostgreSQL or runtime evidence.

The complete executable AST of its controlled error, state graph, pure planner,
and metadata model is likewise locked without importing or executing those
modules. New states, edges, sensitive fields, caller-selected time, logging,
weakened constraints, mutation success, or database capability fail closed.

## Report lifecycle

`report_lifecycle/` implements the owner-authorized inert Stage A for metadata-only `Report`, `ReportLease`, and `SecurityOperation` concepts.

It includes:

- explicit state edges;
- monotonically versioned pure planners;
- server-time lease validation;
- database constraints;
- immutable binding validation;
- stale-version/stale-generation/wrong-lease/expired-lease rejection;
- a fail-closed persistence boundary.
- pure, non-persisting sequence contracts for the approved finalization order
  and OPEN-only operator-deletion order;
- pure planners for Response Note retention, ciphertext-cleanup retry timing,
  terminal-metadata retention review, and isolated audit-retention review.

SQLite remains a development/test scaffold and is not accepted as evidence for security-sensitive concurrency.

A test-only PostgreSQL concurrency scaffold exists, but it is not itself PostgreSQL acceptance evidence and does not enable protected transition execution.

The complete executable AST of the lifecycle errors, state graphs, transition
and lease planners, operation bindings, metadata models, and persistence gate
is locked without importing or executing those modules. State, timing, fencing,
field, constraint, backend, logging, write, and success-path changes require
explicit review.

## Security interfaces

Mandatory security integrations whose production designs or evidence remain gated are represented by deny-by-default interfaces under `security_interfaces/`.

Unavailable operations fail explicitly rather than providing weaker fallbacks.
Their controlled errors and unavailable adapters are also locked by a
non-executing exact-AST policy, so a success path, development fallback, added
method, logging operation, or other side effect requires explicit review.

The package includes inert structural descriptors for approved audit, alert,
step-up, recovery-credential, Response Note crypto, and Response Note schema
concepts, but these types do not themselves:

- encode/verify production audit artifacts;
- append audit events;
- send alerts;
- persist alert delivery;
- perform WebAuthn;
- create or verify production step-up authorization artifacts;
- generate recovery credentials;
- compute or verify recovery HMAC/verifier tags;
- store or look up recovery material;
- canonicalize, encrypt, decrypt, parse, or persist Response Note material;
- hold real Response-DEK, nonce, AAD, key-handle, or ciphertext values;
- encode or parse deterministic-CBOR AAD/envelope data;
- hold real report/response/finalization IDs;
- retain Response Note text, normalized text, canonical bytes, digests, drafts,
  or previews;
- authorize protected operations.

The administrative step-up-v2 foundations are limited to content-free internal
identity shapes, binding-purpose/key-epoch metadata, the exact non-sliding
120-second lifetime, and an unused-only state. Operation, target and artifact
registries, WebAuthn material, binding bytes, persistence, consumption and all
authorization capabilities remain absent.

## Architecture checks

`architecture_checks/` statically constrains the current Reporter Gateway,
Recovery Gateway, operator-console entry point, and root URL surface, including
import allowlists, passive page expectations, and the exact executable AST of
the read-only and fail-closed views and restrictive response-header middleware.

`python -m architecture_checks .` runs the current static policy set as one
aggregate fail-closed CI gate and reports only controlled, content-free
violations.

The aggregate gate also includes a content-free repository-hygiene policy for
tracked path names and `.gitignore` rules. It rejects committed local
databases, logs, virtual environments, secret/config material, export
artifacts, temporary workspaces, quarantine areas, user media, collected static
output, and cache/test artifacts without reading or echoing candidate file
contents.

`scripts/verify` runs the reviewed local verification sequence. A non-executing
source policy locks that script to architecture checks, Django system checks,
migration drift checks, the Django test suite, Python compilation, and manifest
validation. This is developer tooling only, not production readiness evidence.

The GitHub Actions CI workflow installs the locked dependency set and delegates
verification to `scripts/verify`. A non-executing text policy locks the workflow
to read-only repository permissions, pinned checkout/setup-python actions,
Python 3.13, hash-checked dependency installation, and the reviewed script
entrypoint. This does not replace independent supply-chain or release review.

The same package statically locks the initial lifecycle migration and the inert
finalization, operator-deletion and retention planners to closed imports,
members, immutable metadata-only fields, false capability flags and
always-unavailable executors. Scanned target modules are parsed but never
imported or executed.

It also locks the administrative step-up-v2 descriptor to its exact imports,
constants, immutable classes, validators, and closed call profile without
executing the descriptor source.

The audit-v1 descriptor module is likewise locked to its complete reviewed
executable AST. Registry, field, validator, authorization-window, success-return,
import, dynamic, or side-effect changes require an explicit policy update; the
target is never imported or executed by the check.

The alert-v1 descriptors have the same non-executing exact-AST guard. Their
fixed registries, content-free fields, validators and false durability and
authorization results cannot change without an explicit policy update.

The no-JavaScript CAPTCHA descriptor module is locked to its exact executable
AST as content-free protocol metadata only. Identifier and answer shapes,
anonymous form scope, expiry/cleanup timing, purpose/state registries, PNG
bounds, global anonymous bucket limits, open production gates, validators, and
false capability flags cannot change without explicit review. The check never
imports or executes the target and proves no challenge generation, answer
comparison, persistence, media rendering, network-identity binding, endpoint,
service call, or protected-operation authorization capability.

The request-admission descriptor module is locked to its exact executable AST
as content-free request/multipart metadata only. Body, file, report-text,
control-field, part-header, part-count, boundary, streaming-buffer, deadline,
method, content-type, file-slot, and false capability profiles cannot change
without explicit review. The check never imports or executes the target and
proves no HTTP/multipart parsing, Django upload-handler installation, file-byte
access, filename exposure, sandbox-job creation, plaintext persistence,
endpoint, or submission-acceptance capability.

The attachment-admission descriptor module is locked to its exact executable
AST as content-free common file metadata only. Count, size, kind, slot,
extension, transient-filename, trust-denial, validators, and false capability
profiles cannot change without explicit review. The check never imports or
executes the target and proves no file-byte inspection, JPEG/PNG/PDF parsing,
sandbox-job creation, original-byte persistence, original-filename retention,
request-material logging, upload endpoint, safe-view, encryption, or upload
authorization capability.

The safe-view descriptor module is locked to its exact executable AST as
content-free operator-view metadata only. PNG/sRGB/render-DPI, output limits,
response headers, required bindings, non-durability, ordinary-download denial,
validators, and false capability profiles cannot change without explicit
review. The check never imports or executes the target and proves no attachment
decryption, rendering, PNG validation, sandbox call, output persistence,
response serving, endpoint, lease inspection, or operator-access authorization
capability.

The file-sandbox descriptor module is locked to its exact executable AST as
content-free microVM-boundary metadata only. Firecracker reference, compute
limits, isolation denials, transport profile, filesystem/workspace profile,
credential-denial profile, validators, and false capability profiles cannot
change without explicit review. The check never imports or executes the target
and proves no microVM boot, parser execution, file access, job creation, vsock
exchange, attachment inspection, plaintext persistence, endpoint, or
file-processing authorization capability.

The report-bound step-up-v1 descriptor module is also locked to its complete
reviewed executable AST, including timing, registries, content-free context,
unused state, validators, and false WebAuthn/binding/authorization results.

The recovery credential descriptor module is locked to its exact executable AST
as content-free shape validation only. Ticket ID and Recovery Secret sizes,
encodings, alphabets, metadata-only verifier purpose, validators, and false
capability flags cannot change without explicit policy review. The check never
imports or executes the target and proves no generation, verifier, storage,
lookup, endpoint, or recovery authorization capability.

The Response Note crypto descriptor module is locked to its exact executable
AST as static profile validation only. Algorithm/profile identifiers, key,
nonce, tag, frame, envelope, immutable-context-size, AAD-purpose, and
Response-DEK operation names cannot change without explicit review. The check
never imports or executes the target and proves no canonicalization, CBOR,
AEAD, Key Service, storage, endpoint, or response-use authorization capability.

The Response Note text descriptor module is locked to its exact executable AST
as content-free transient validation only. Unicode/NFC/LF/UTF-8 rules,
scalar/byte limits, plain-text restrictions, conservative no-link/no-HTML
markers, validators, and false capability flags cannot change without explicit
review. The check never imports or executes the target and proves no preview,
draft, canonical byte freezing, digest binding, staging, endpoint, or
finalization capability.

The Response Note schema descriptor module is locked to its exact executable
AST as ordered metadata validation only. AAD and ciphertext-envelope field
order, primitive categories, fixed byte sizes, public constant values,
validators, and false capability flags cannot change without explicit review.
The check never imports or executes the target and proves no deterministic
CBOR, context-value retention, ciphertext handling, service call, persistence,
endpoint, or response-use authorization capability.

The controlled security-interface errors and unavailable external-service
adapters are likewise parsed but never imported or executed and must retain
their exact generic fail-closed behavior.

These checks are review guards, not production network/process security boundaries.

The Django management, ASGI/WSGI, and installed metadata-app bootstrap modules
are also locked to their exact executable AST without being imported. Alternate
settings, startup hooks, wrappers, logging, network, file, and other early
side-effect changes require explicit review; this is not deployment evidence.

Application and migration package initializers are also locked to their exact
executable AST. Passive package markers and the reviewed
`security_interfaces.__init__` re-export surface cannot gain imports, exports,
startup effects, migration initializer code, or dynamic behavior without an
explicit policy update.

## Approved designs versus enabled capability

The repository contains detailed approved protocol documents covering areas including:

- submission acceptance;
- recovery credentials;
- self-hosted no-JavaScript challenge;
- audit receipts and transparency;
- Response Note cryptography;
- MFA step-up;
- report-content cryptography;
- Key Service non-resurrection testing;
- emergency export;
- file acceptance/sandbox/safe view;
- request and multipart admission;
- administrator alerts;
- retention/deletion;
- operational access and workstation hardening.

Approval of a design document does **not** mean its protected workflow is enabled.

`docs/34_PRE_CODE_SECURITY_GATE.md` authorizes only the bounded metadata-only Stage A and preserves external, independent-review, and production gates.

## Not currently implemented as production capability

The repository does not currently provide a production-ready:

- report submission workflow;
- report plaintext storage/decryption flow;
- reporter recovery flow;
- operator authentication flow;
- file-processing service;
- audit service;
- alert service;
- Key Service;
- emergency export workflow;
- retention/deletion executor;
- background job system;
- production deployment profile.

## Development commands

```bash
python manage.py check
python manage.py test -v 2
python manage.py runserver 127.0.0.1:8000
```

The development server is for local testing only.

## Latest Stage A slice — original-report crypto descriptors

The current repository adds inert original-report crypto descriptors for the
owner-approved `docs/26` profile. The descriptor validates only static
Report-DEK/object-subkey, algorithm, nonce/tag, fixed-frame, ciphertext-size,
object-kind/slot, immutable-context, AAD/KDF purpose, and allowlisted operation
metadata.

The descriptor and its exact-AST source policy intentionally do not implement
canonicalization, framing, HKDF, AEAD, CBOR, Key Service calls, attachment
streaming, protected persistence, endpoints, audit/state authorization,
deletion, or recovery of report content. All cryptographic, Key Service,
storage, sandbox, audit, export, deletion, independent-review, deployment, and
production gates remain open.

## Latest Stage A slice — original-report schema descriptors

The current repository adds inert original-report schema descriptors for the
owner-approved `docs/26` AAD/envelope metadata. The descriptor validates only
ordered field names, primitive categories, fixed byte sizes, public constant
values, allowed public object kinds/slots, and allowed public frame/ciphertext
sizes.

The descriptor and its exact-AST source policy intentionally do not implement
deterministic CBOR, context binding, context-value retention, ciphertext
handling, Key Service calls, attachment streaming, protected persistence,
endpoints, or report-use authorization. Deterministic-CBOR, Key Service,
sandbox-streaming, persistence, independent-review, deployment, and production
gates remain open.

## Latest Stage A slice — original-report text descriptors

The current repository adds inert original-report text descriptors for the
owner-approved `docs/26` canonical text metadata. The descriptor transiently
validates only Unicode scalar policy, NUL and unpaired-surrogate rejection,
CRLF/CR-to-LF profile, NFC, strict UTF-8, 5,000-scalar limit, 20,000-byte
limit, and canonical UTF-8 authoritative-original metadata.

The descriptor and its exact-AST source policy intentionally do not retain
browser/wire text, return normalized text or canonical bytes, construct
frames, encrypt, persist, log, create submissions, expose endpoints, or
authorize acceptance. Submission, request-admission integration, audit, Key
Service, storage, deployment, independent-review, and production gates remain
open.

## Latest Stage A slice — original-report frame descriptors

The current repository adds inert original-report frame descriptors for the
owner-approved `docs/26` plaintext-frame layout metadata. The descriptor
validates only the version byte, uint32/uint64 big-endian length-field markers,
canonical UTF-8 report-text payload marker, accepted-original attachment byte
marker, public PDF/JPEG/PNG kind codes, fixed text and attachment frame sizes,
and zero-padding requirements.

The descriptor and its exact-AST source policy intentionally do not accept
plaintext bytes, canonicalize text, construct frames, parse frames, validate
padding bytes, inspect attachments, encrypt, decrypt, persist content, call a
Key Service, expose endpoints, or authorize submission. Frame construction,
padding verification, encryption, submission staging, request admission, Key
Service, storage, independent-review, deployment, and production gates remain
open.

## Latest Stage A slice — submission-audit descriptors

The current repository adds inert submission-audit descriptors for the
owner-approved `docs/20` submission acceptance protocol. The descriptor
validates only the exact `SUBMISSION_ACCEPTANCE_REQUESTED`,
`SUBMISSION_RECEIVED`, and `SUBMISSION_ACCEPTANCE_FAILED` phase order,
event-family mapping, timing labels, authorization windows,
durable-receipt-required flags, and closed allowed/forbidden payload-field
metadata.

The descriptor and its exact-AST source policy intentionally do not append
audit events, create or verify receipts, inspect attempt state, call the Audit
Service, create report keys, persist submission metadata, expose endpoints, or
authorize acceptance. Durable-audit, receipt/checkpoint, submission acceptance,
Key Service, storage, concurrency, independent-review, deployment, and
production gates remain open.

## Latest Stage A slice — submission-reconciliation descriptors

The current repository adds inert submission-reconciliation descriptors for the
owner-approved `docs/20` crash-reconciliation policy. The descriptor validates
only the approved maximum scan interval, progress deadline, cleanup retry cap,
persistent-cleanup-alert threshold, nonterminal candidate states, terminal
outcome labels, action registry, alert type, and closed allowed/forbidden
payload-field metadata.

The descriptor and its exact-AST source policy intentionally do not scan report
content, decrypt plaintext, create credentials, append audit events, verify
receipts, call the Audit/Key/Alert services, delete ciphertext, mutate attempt
state, schedule jobs, expose endpoints, or authorize acceptance. Reconciler,
scheduler, durable-audit, Key Service, Alert Service, cleanup, storage,
concurrency, independent-review, deployment, and production gates remain open.

## Latest Stage A slice — submission credential-response descriptors

The current repository adds inert submission credential-response descriptors
for the owner-approved `docs/20` lost-response policy. The descriptor validates
only the one live post-acceptance display opportunity, controlled indeterminate
retry result, permitted Ticket ID and Recovery Secret response-field names, and
forbidden persistence categories for plaintext Recovery Secret,
redisplay/replacement state, `credentials_delivered` claims, content
hashing/deduplication, request headers, and raw errors.

The descriptor and its exact-AST source policy intentionally do not generate
credentials, persist or redisplay secrets, issue replacements, record delivery,
deduplicate by content, render responses, inspect requests, mutate attempts,
expose endpoints, or authorize recovery/submission. Credential generation,
verifier, response endpoint, recovery, submission acceptance, storage, logging,
independent-review, deployment, and production gates remain open.

## Latest Stage A slice — submission-attempt credential descriptors

The current repository adds inert submission-attempt credential descriptors for
the owner-approved `docs/20` attempt policy. The descriptor validates only the
approved single-use semantics, two-hour non-sliding pre-claim lifetime, POST
body/protected same-site cookie transport labels, URL/query/referrer/header-log
denials, forbidden report-content, Ticket ID, Recovery Secret, IP address,
User-Agent, reporter-account, and device-fingerprint bindings, minimum
verifier/index durable representation, database uniqueness/state-version
metadata, and no-log/no-audit persistence denials.

The descriptor and its exact-AST source policy intentionally do not generate or
verify credentials, persist credential material, install cookies, inspect
requests, claim attempts, call services, expose endpoints, authorize
submission, or authorize report read. Exact encoding, verifier, cookie/form
binding, endpoint, persistence, concurrency, logging, audit, submission
acceptance, independent-review, deployment, and production gates remain open.

## Latest Stage A slice — submission retry descriptors

The current repository adds inert submission retry descriptors for the
owner-approved `docs/20` duplicate/retry outcome policy. The descriptor
validates only the approved retry source labels, required one-database-winner
and no-second-pipeline outcomes, controlled indeterminate response behavior,
no credential redisplay, and forbidden signal categories.

The descriptor and its exact-AST source policy intentionally do not parse
requests, verify attempt credentials, claim attempts, inspect database state,
create reports or Report-DEKs, append audit events, redisplay credentials,
expose status oracles, call services, expose endpoints, or authorize
submission. Endpoint, credential verifier, PostgreSQL concurrency, duplicate
suppression executor, audit, Key Service, storage, logging, independent-review,
deployment, and production gates remain open.

## Latest Stage A slice — submission acceptance checkpoint descriptors

The current repository adds inert submission acceptance checkpoint descriptors
for the owner-approved `docs/20` Phase 0-6 submission acceptance sequence. The
descriptor validates only the approved phase order, checkpoint labels,
requirement labels, and forbidden runtime capability categories.

The descriptor and its exact-AST source policy intentionally do not parse
requests, validate credentials, claim attempts, append audit events, verify
receipts, call the Key Service, encrypt content, write storage, commit
database state, render responses, run reconciliation, expose endpoints, or
authorize submission. Endpoint, credential verifier, PostgreSQL concurrency,
audit, Key Service, storage, logging, reconciliation, independent-review,
deployment, and production gates remain open.

## Latest Stage A slice — submission failure descriptors

The current repository adds inert submission failure descriptors for the
owner-approved `docs/20` failure matrix. The descriptor validates only the
approved failure-boundary labels, required-result labels, content-free flags,
and fail-closed flags.

The descriptor and its exact-AST source policy intentionally do not handle
requests, start submission pipelines, call services, write storage, create
keys, persist plaintext, append audit events, mutate state, return
credentials, expose endpoints, or authorize submission. Endpoint, pipeline
executor, audit, Key Service, storage, cleanup, reconciliation, logging,
independent-review, deployment, and production gates remain open.

## Latest Stage A slice — submission idempotency descriptors

The current repository adds inert submission idempotency descriptors for the
owner-approved `docs/20` concurrency/idempotency test requirements. The
descriptor validates only the approved retry/concurrency scenario labels,
invariant labels, and forbidden runtime capability categories.

The descriptor and its exact-AST source policy intentionally do not run
parallel requests, handle requests, inspect attempt state, lock database rows,
write storage, create Report-DEKs, append audit events, reconcile artifacts,
log reporter input, expose endpoints, or authorize submission. Endpoint,
PostgreSQL concurrency runner, database locking implementation, audit, Key
Service, storage, reconciliation, logging, independent-review, deployment, and
production gates remain open.

## Latest Stage A slice — recovery failure descriptors

The current repository adds inert recovery failure descriptors for the
owner-approved `docs/21` recovery credential failure behavior. The descriptor
validates only the approved random-source, collision, encoding, verifier/key,
unknown version/key, HMAC mismatch, unavailable/expired/destroyed response,
concurrent first-read, Response-DEK expiry, and credential logging/telemetry
failure labels, required generic/fail-closed results, and forbidden runtime
capability categories.

The descriptor and its exact-AST source policy intentionally do not generate
randomness, decode credentials, call a verifier, compare HMAC tags, read
response state, call the Key Service, mutate first-read state, log
credentials, expose endpoints, or authorize recovery. Recovery endpoint,
verifier service, constant-time comparison implementation, response
eligibility, first-read concurrency, Key Service, logging, independent-review,
deployment, and production gates remain open.

## Latest Stage A slice — recovery key lifecycle descriptors

The current repository adds inert Recovery Verifier key-lifecycle descriptors
for the owner-approved `docs/21` lifecycle and rotation boundaries. The
descriptor validates only the approved 32-byte verifier-key size,
active/retired/destroyed states, separated key purposes, forbidden
source/settings/database/log/audit/browser/response locations, and lifecycle
requirements for service-selected key IDs, one active creation version, no
silent fallback, restore proof before destruction, fail-closed loss, and no
Response-DEK authority.

The descriptor and its exact-AST source policy intentionally do not generate
keys, store raw key material, select keys for requests, rotate or destroy keys,
rewrite verifier records, call the Key Service, expose endpoints, authorize
Response-DEK use, or authorize recovery. Verifier service, key inventory,
rotation/incident procedure, restore proof, Response-DEK lifecycle, Key
Service, independent-review, deployment, and production gates remain open.

## Latest Stage A slice — recovery verification descriptors

The current repository adds inert Recovery Verifier verification descriptors
for the owner-approved `docs/21` verification semantics. The descriptor
validates only the approved full-length HMAC-SHA-256, 32-byte tag,
constant-time full-tag comparison, boolean-only result, necessary-not-
sufficient HMAC success, canonical input, unknown-ticket dummy-verification,
generic-response, timing-test, no-perfect-indistinguishability, and forbidden
capability metadata.

The descriptor and its exact-AST source policy intentionally do not compute
HMACs, compare tags, execute dummy verification, return expected tags or
partial-match detail, read response state, validate CAPTCHA, call the Key
Service, authorize Response-DEK use, log credentials, expose endpoints, or
authorize recovery. Verifier implementation, constant-time comparison, timing
proof, response eligibility, CAPTCHA, Key Service, independent-review,
deployment, and production gates remain open.

## Latest Stage A slice — recovery verifier-record descriptors

The current repository adds inert Recovery Verifier record descriptors for the
owner-approved `docs/21` persisted verifier-record shape. The descriptor
validates only the approved `scheme_version`, `verifier_key_id`, and
`verifier_tag` field labels, 32-byte tag size, server-controlled key ID,
no-secret/no-raw-key/no-database-alone-test requirements, removal with recovery
state, terminal invalidation, and forbidden material categories.

The descriptor and its exact-AST source policy intentionally do not persist
records, compute verifiers, test candidate secrets, perform lookups, write a
database, expose endpoints, or authorize recovery. Metadata-store schema,
verifier construction, lookup, recovery-state lifecycle, Response-DEK
lifecycle, independent-review, deployment, and production gates remain open.

## Latest Stage A slice — recovery HMAC-message descriptors

The current repository adds inert Recovery Verifier HMAC-message descriptors
for the owner-approved `docs/21` canonical message layout. The descriptor
validates only the approved ASCII domain label, zero separator, 16-byte Ticket
ID field, 32-byte Recovery Secret field, fixed order, fixed lengths, domain
separation, version-bound purpose label, and unambiguous purpose-specific
framing metadata.

The descriptor and its exact-AST source policy intentionally do not accept
credential values, concatenate bytes, compute HMACs, store canonical messages,
store Recovery Secrets, access verifier keys, return verifier tags, log
message material, expose endpoints, or authorize recovery. Byte construction,
verifier construction, secret handling, HMAC execution, logging,
independent-review, deployment, and production gates remain open.

## Latest Stage A slice — Recovery Verifier Service descriptors

The current repository adds inert Recovery Verifier Service descriptors for the
owner-approved `docs/21` service operation boundary. The descriptor validates
only the approved create-only and boolean-verify operation labels,
authenticated/encrypted/bounded channel requirements, body/credential log
exclusions, create-output and verify-output rules, and forbidden capability
metadata.

The descriptor and its exact-AST source policy intentionally do not implement
service calls, generate credentials, compute HMACs, compare tags, persist
verifier records, perform lookups, accept reporter-supplied key IDs, return
raw keys, expected tags, or partial-match detail, read response state, call the
Key Service, authorize Response-DEK use, log credentials, expose endpoints, or
authorize recovery. Service topology, network transport, verifier
construction, persistence, lookup, response eligibility, Response-DEK
lifecycle, Key Service, independent-review, deployment, and production gates
remain open.

## Latest Stage A slice — recovery eligibility descriptors

The current repository adds inert recovery eligibility descriptors for the
owner-approved Response Note eligibility boundaries in `docs/05`, `docs/24`,
and `docs/32`. The descriptor validates only the approved unavailable,
available-unread, read-window-open, read-window-expired, never-read-expired,
destroyed, 90-day unread-expiry, 72-hour first-read-expiry, server-
authoritative, verifier-success-is-not-sufficient, Response-DEK authorization,
generic-result, and forbidden-capability metadata.

The descriptor and its exact-AST source policy intentionally do not perform
lookup, validate credentials or CAPTCHA, call the Recovery Verifier Service or
Key Service, read response state/ciphertext, decrypt, mutate first-read state,
destroy Response-DEKs, invalidate recovery state, expose endpoints, extend
response windows, log credentials, return distinct failures, or authorize
recovery. Recovery Gateway, State Authority, first-read concurrency, expiry
workflow, Key Service authorization, independent-review, deployment, and
production gates remain open.

## Latest Stage A slice — recovery retrieval descriptors

The current repository adds inert recovery retrieval descriptors for the
owner-approved Response Note retrieval order in `docs/05`, `docs/21`, and
`docs/24`. The descriptor validates only the approved POST input, CAPTCHA/
verifier, `RESPONSE_RETRIEVAL_REQUESTED` receipt, server-time state/version
lock, immutable expiry arm/conversion, scoped Key Service decrypt, fixed-
frame/no-store rendering, content-free outcome, and forbidden-capability
metadata.

The descriptor and its exact-AST source policy intentionally do not handle
requests, validate CAPTCHA or credentials, append audit events, verify
receipts, query state, mutate first-read state, call the Key Service, decrypt,
validate plaintext frames, render responses, persist plaintext, log
credentials/plaintext, expose endpoints, return distinct failures, or
authorize recovery. Recovery Gateway implementation, audit integration, State
Authority locking, first-read concurrency, Key Service client, decrypt path,
renderer, independent-review, deployment, and production gates remain open.

## Latest Stage A slice — fail-closed submission surface

The current repository adds a concrete but disabled reporter submission
surface at `/submit/`. GET renders only static no-form guidance. POST returns a
controlled `503` fail-closed response without reading request body/form/file
data and without persisting content, invoking submission workflow, audit,
CAPTCHA, Key Service, upload handling, credential generation, or storage.

The reporter surface policy now locks the exact home and `/submit/` URL
patterns, the updated view AST, and both passive templates. Tests verify
headers, no cookies, no forms/scripts, fail-closed POST behavior, no reporter
content echo, and that the POST branch does not require request-body access.
The accepting submission endpoint, CAPTCHA, upload handler, audit, Key
Service, crypto, concurrency, deployment, and production gates remain open.
