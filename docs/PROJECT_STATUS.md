# Current Project Status

**Status: security-first pre-alpha / metadata-only implementation stage.**

This document keeps the implementation boundary visible without requiring the top-level README to reproduce the full handoff narrative.

## Reporter surface

The repository contains a Django 5.2.17 development scaffold and one inert, read-only reporter landing page.

The page has no:

- submission form;
- JavaScript;
- analytics;
- third-party resources;
- report storage;
- authentication;
- production business logic.

The current surface must not be used for real sensitive reports.

## Submission workflow

`submission_workflow/` defines only the approved attempt states, database shape, constraints, and a pure monotonic transition planner.

It has no public submission endpoint or database transition executor and stores no reporter content, credential, key, verifier, filename, request metadata, or audit receipt.

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

`architecture_checks/` statically constrains the current Reporter Gateway and
root URL surface, including import allowlists, passive page expectations, and
the exact executable AST of the read-only view and restrictive response-header
middleware.

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
