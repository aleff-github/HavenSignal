# 34 — Consolidated Pre-Code Security Gate

Status: **OWNER APPROVED — STAGE A ONLY (2026-08-26)**
Prepared: 2026-08-26

This document was the owner review package. The explicit decision recorded in
section 7 authorizes only the inert Stage A boundary. It does not authorize
protected endpoints, cryptographic operations, report content handling,
authentication, file handling, export, deletion, or production deployment.

Its purpose is to replace fragmented approvals with one explicit project-owner
decision and to define the narrow code boundary that may follow that decision.

## 1. Decisions already approved

The following decisions remain approved and are not reopened by this package:

- `docs/20_SUBMISSION_ACCEPTANCE_PROTOCOL.md`: submission sequencing, retry,
  reconciliation, and lost one-time credential response behavior;
- `docs/21_RECOVERY_CREDENTIAL_CONSTRUCTION.md`: Ticket ID, Recovery Secret,
  display-once behavior, and keyed verifier construction;
- `docs/22_NO_JAVASCRIPT_CHALLENGE_PROTOCOL.md`: self-hosted no-JavaScript
  challenge, atomic consumption, and anonymous global abuse controls;
- `docs/23_AUDIT_RECEIPT_AND_TRANSPARENCY_PROTOCOL.md`: event encoding, durable
  receipts, replay controls, Merkle checkpoints, witnessing, and retention;
- `docs/24_RESPONSE_NOTE_CRYPTOGRAPHIC_PROTOCOL.md`: Response Note framing,
  AEAD envelope, non-exportable Response-DEK, staging, first read, and expiry;
- the contained decision in `docs/26_REPORT_CONTENT_CRYPTOGRAPHIC_PROTOCOL.md`
  that accepted report text is strict UTF-8 normalized to NFC and LF and no raw
  pre-normalization copy is retained.

These approvals remain non-authorizing wherever independent review, selected
products, production-equivalent proof, or another named dependency is still
OPEN.

## 2. Decisions approved by the project owner

Approval of this package means approval of the exact versioned profiles and
failure behavior in the following documents, not merely their general intent.

### 2.1 MFA, step-up, and credential lifecycle — `docs/25`

- device-bound hardware WebAuthn credentials, two per person, with no weaker
  fallback;
- separate Operator and Application Administrator RP/origin/session profiles;
- 120-second non-sliding challenge and authorization lifetime;
- deterministic-CBOR HMAC-SHA-256 action/artifact binding with a separately
  held binding key;
- single-use, concurrency-safe consumption with resumable committed workflows;
- in-person, quorum-controlled enrollment, replacement, and recovery.

### 2.2 Original report cryptography — `docs/26`

- one random, non-exportable Report-DEK per report;
- RFC 5869 HKDF-SHA-256 per-object and per-purpose subkeys;
- libsodium XChaCha20-Poly1305-IETF with random nonces;
- deterministic-CBOR context, AAD, envelope, and strict version rejection;
- constant-size canonical text and attachment framing, including the exact
  interpretation of 5 MB as 5 MiB;
- provisional staging, narrow state/lease-bound decryption, and activation only
  after every required durable condition succeeds.

### 2.3 Key Service acceptance — `docs/27`

- candidate-neutral negative capability and workload-authentication matrix;
- non-exportable per-object keys and forward-only lifecycle states;
- prohibition on restorable historical per-object key material;
- production-equivalent destructive snapshot, rollback, stale-replica,
  restore, and disaster-recovery tests;
- binary acceptance with no silent weakening or product exception;
- continued product/topology rejection until the real PoC passes.

### 2.4 Emergency Export — `docs/28`

- exact immutable request binding and single-use authorization;
- closed, deterministic, uncompressed `ustar` package profile;
- RFC 8785 manifest and detached tagged COSE Sign1/Ed25519 signature;
- binary `age` v1 with exactly one native X25519 organization recipient;
- strict recipient/signing key separation and external recipient private-key
  custody;
- fenced and resumable generation with one concurrency winner;
- plaintext-only-in-memory processing and encrypted-only staging;
- one-shot, hash-bound delivery after durable audit and alert acceptance.

### 2.5 File admission, sandbox, and safe view — `docs/29`

- closed JPEG, PNG, and PDF structural acceptance profiles;
- exact decoded size, dimension, page, object, decompression, and time ceilings;
- independent parser/scanner families and fail-closed disagreement behavior;
- fresh Firecracker microVM isolation for each untrusted object;
- bounded transient plaintext with no host filesystem, swap, core, or backup
  persistence;
- metadata-free PNG rasterization as the only ordinary operator view;
- no ordinary original-attachment download capability;
- exact cleanup, crash, fuzz-corpus, and production acceptance gates.

### 2.6 Request and multipart admission — `docs/30`

- exact 21 MiB outer request ceiling and component limits;
- closed multipart grammar and cardinality;
- streaming proxy enforcement before application dispatch;
- bounded Django upload handling inside the designated sandbox boundary;
- no implicit disk spooling or weaker parser fallback;
- independent decoded-resource limits after transport acceptance;
- fixed timeout/rate behavior without reporter fingerprinting;
- failure tests covering truncation, ambiguity, smuggling, exhaustion, and
  cleanup.

### 2.7 Administrator alerts — `docs/31`

- separate self-hosted Alert Service;
- closed, metadata-only alert schema;
- durable administrator inbox plus local SMTP wake-up queue;
- idempotent durable acceptance before acknowledgement;
- Emergency Export failure before artifact work if alert acceptance is
  unavailable;
- retry/escalation/acknowledgement and 365-day alert retention, while deletion
  cleanup and key denial continue independently.

### 2.8 Retention and deletion — `docs/32`

- 90-day expiry for a never-read Response Note and a full 72-hour window when
  its first valid read occurs before that deadline;
- ordinary operator deletion only from OPEN, without a Response Note, using a
  closed reason code and encrypted protected note;
- exceptional content-blind SEALED flood deletion only through the specified
  administrator declaration, infrastructure attestation, two-operator quorum,
  30-minute/100-report cap, and newest-first order;
- durable per-report audit receipt before forward key destruction;
- authoritative key denial/destruction independent of retrying physical
  ciphertext cleanup;
- 30-day minimized terminal metadata, 365-day audit events, and 730-day
  verification evidence under their separately controlled retention authority.

### 2.9 Operational access and workstation hardening — `docs/33`

- physically separate Operator, Application Administrator, and Infrastructure /
  Key Custodian device classes, accounts, credentials, routes, and origins;
- current patched Ubuntu LTS hardened baseline with Secure Boot, passphrase
  LUKS2, no automatic TPM unlock, no swap/hibernate/core dumps, mandatory
  confinement, and drift quarantine;
- current patched Firefox ESR single-origin ephemeral kiosk with persistence,
  extension, telemetry, developer-tool, print, clipboard, capture, external
  protocol, and ordinary download controls;
- role-specific VPN/device identity, strong authentication, session ceilings,
  revocation, and single-session enforcement;
- encrypted-artifact-only Emergency Export transfer broker;
- version-2 administrator step-up bound to actor, device, session, operation,
  target, artifact, and exceptional batch parameters;
- at least three named Key Custodians, two-person ceremonies, hardware-backed
  short-lived SSH certificates, isolated bastion, and command wrappers;
- break-glass limited to isolation, revocation, and availability recovery,
  never report decryption, per-object key restore, or MFA bypass.

## 3. Cross-document effects accepted by this decision

- The 90-day never-read Response Note rule extends the approved `docs/24`
  lifecycle without changing its first-read concurrency or +72-hour rule.
- Exceptional flood deletion uses the administrator step-up version defined in
  `docs/33`; it never binds dummy report identifiers or creates a content-reading
  capability.
- `docs/31` supplies the alert acceptance and delivery semantics referenced by
  export, audit cessation, and persistent deletion-cleanup failures.
- `docs/33` supplies the physical and operational role separation assumed by
  the MFA, export, and Key Service proposals.

No unresolved contradiction has been identified among these effects. Rejecting
or changing any one of them requires re-review of every dependent decision; a
weaker interpretation must not be selected silently.

## 4. Gates that remain OPEN after owner approval

Owner approval is necessary but not sufficient for a protected implementation
or release. At minimum, the following remain blocking where applicable:

- independent cryptographic, authentication, protocol, HTTP/proxy, parser,
  sandbox, network, and operations review;
- exact dependency, tool, font, kernel, root-image, browser, and operating-system
  artifact pinning and vulnerability review;
- selection and production-equivalent destructive PoC of the Key Service;
- selection and acceptance of Audit Service, Alert Service, HSM/signers,
  PostgreSQL, proxy, KVM/Firecracker, trusted clock, service PKI, and workload
  identity implementations;
- legal approval of retention and deletion periods and exceptional flood
  procedure;
- organization recipient-key custody, hardware inventory, staffing, quorum,
  physical security, recovery ceremonies, and production acceptance tests;
- abuse/failure/concurrency tests in `docs/14_SECURITY_TEST_PLAN.md` and the
  release checklist in `docs/18_SECURITY_REVIEW_CHECKLIST.md`.

No placeholder may become an availability-oriented fallback while a required
dependency is unavailable.

## 5. Code authorization matrix after approval

### Stage A — inert implementation permitted

The first implementation stage may create only structures that cannot receive,
persist, decrypt, display, export, or destroy protected content:

- metadata-only Report lifecycle enums, schema, constraints, and migrations;
- metadata-only ReportLease and SecurityOperation fencing structures;
- pure state-transition planners and denial-by-default orchestration shells;
- typed request/receipt descriptors and strict schema validators that do not
  handle reporter-controlled content;
- unavailable adapters for every external security service;
- PostgreSQL integration-test scaffolding and concurrency tests that use only
  synthetic non-sensitive identifiers;
- inert pages and security headers with no report form or protected action.

Stage A data must exclude report text, attachment bytes, original filenames,
recovery credentials, verifier material, cryptographic keys, raw request
metadata, untrusted headers, operator protected notes, and audit/alert free
text.

### Still prohibited

Until each dependent gate is closed, Stage A does not authorize:

- a reporter form or submission POST endpoint;
- plaintext or ciphertext report/attachment persistence;
- file upload, parsing, rasterization, CDR, or sandbox execution;
- actual encryption, decryption, key creation, unwrap, expiry, or destruction;
- reporter recovery, operator login/MFA, claim, OPEN, or content display;
- Response Note staging/finalization/retrieval;
- Emergency Export, administrator alerts, or report deletion;
- production deployment or a claim that the system is ready for real reports.

## 6. First authorized implementation slice

After explicit approval, the recommended first slice is a separate Django
`report_lifecycle` app containing metadata-only Report, ReportLease, and
SecurityOperation concepts, their server-authoritative transitions, database
constraints, and abuse/concurrency tests. It must not duplicate the existing
`submission_workflow` attempt model and must not add any protected endpoint.

SQLite tests may verify pure logic and simple constraints but cannot constitute
the PostgreSQL concurrency or release proof.

## 7. Recorded project-owner decision

The project owner recorded the following decision on 2026-08-26:

> Approvo integralmente le decisioni consolidate in docs/34 e autorizzo lo
> Stage A inerte; mantengo tutti i gate esterni e di produzione indicati.

No exception was recorded. Any future change must identify the document,
subsection, and replacement decision. Implementation may proceed only within
the inert Stage A boundary in section 5.

## 8. Stage A implementation record

The first metadata-only slice adds the `report_lifecycle` Django app with:

- explicit Report, ReportLease, and SecurityOperation enums and allowed edges;
- internal UUID/state/version/generation/timestamp-only models;
- uniqueness and shape constraints for active operator ownership, leases, and
  operation fences;
- pure server-time transition and lease-activity planners;
- negative tests for unknown/skipped states, stale generations, timeout
  boundaries, invalid shapes, duplicate active ownership, and duplicate fences.

No route, view, authentication flow, protected service call, persistence
executor, content field, file handler, cryptographic operation, audit/alert
payload, export/deletion workflow, or background worker is added. The local
SQLite suite is development evidence only; PostgreSQL multi-process
concurrency remains an explicit external gate.

The second Stage A slice adds immutable, content-free operation/report/lease
descriptors and a closed operation-binding policy. Validation requires exact
report ID/state/version, actor, active lease ID/owner/state/generation, current
report generation, and server-authoritative idle/absolute time. Reopen and
exceptional flood-delete metadata profiles reject an existing lease; OPEN-only
profiles require the exact current lease. Validation is necessary metadata
evidence and never an authorization grant.

The persistence boundary rejects any backend without PostgreSQL transactions,
row locking, and partial indexes. It remains deliberately write-disabled even
when those capability flags are present: no PostgreSQL driver or
production-equivalent test service is currently configured, so implementing a
write path would falsely elevate SQLite/unit evidence. The reviewed executor,
lock ordering, retry behavior, and 20–100 synchronized multi-process tests
remain OPEN.

The third Stage A slice adds content-free audit-v1 structural descriptors for
the exact 40-event registry, four actor kinds, 16-byte idempotency IDs, 32-byte
action nonces, acceptance-claim byte lengths/unsigned-integer bounds, and the
unambiguous non-sliding authorization lifetimes in `docs/23`. These frozen
types do not contain caller/object/operation/reason/outcome free text.

The slice does not implement deterministic CBOR, COSE, Ed25519, receipt
verification, append/durability/idempotency storage, an Audit Service adapter,
or a protected consumer. Structural validation always remains
non-authorizing. `REPORT_KEY_DESTROYED` stays denied because its five-minute
lifetime is conditional on use before response publication and the complete
per-operation profile needed to distinguish that context is not yet closed.
The incomplete object/operation/state/reason/outcome registries are not guessed.

The fourth Stage A slice adds content-free alert-v1 structural descriptors for
the exact ten alert types and fixed severities, three delivery states, four
actor kinds, 16-byte operation/idempotency/source-event identifiers, the
Alert-Service-controlled acceptance response shape, and the exact nil/present
acknowledgement-field pairing in `docs/31`.

No full submit request is created because the exact `source-profile`,
`object-kind`, `condition-code`, and per-type field/source combinations are not
fully enumerated as formal registries. No CBOR, service authentication,
PostgreSQL/outbox persistence, SMTP delivery, retry/escalation, inbox,
acknowledgement mutation, retention job, or real Alert Service adapter exists.
A structurally valid response proves no durable acceptance and authorizes
nothing.

The fifth Stage A slice adds report-bound step-up-v1 structural components for
the explicit 16-byte authorization/operator/session/report/response/
finalization/lease identifier shapes, lease/state counters, exact 120-second
non-sliding lifetime, ES256 (`-7`) and EdDSA (`-8`) registry, and the approved
artifact-binding purpose/key-epoch metadata from `docs/25`.

To preserve the Stage A prohibition on verifier/authentication material, these
types cannot contain the HMAC binding itself, artifact bytes, a WebAuthn
challenge or credential, the browser handle, or a consumed authorization. The
closed operation/report-state/artifact-kind profiles are not fully enumerated
and are therefore omitted rather than guessed. No CBOR, HMAC, WebAuthn,
password/session flow, database row, issuance, consumption, endpoint, or real
Step-Up service exists. The administrative v2 profile is likewise not modeled
with dummy report/lease context or incomplete target/operation registries.

The sixth Stage A slice adds a static AST architecture guard for the current
inert Reporter Gateway and reporter-only root URL configuration. The policy is
an exact allowlist of the existing HTTP/rendering imports, with single-level
local relative imports permitted only inside `reporter_gateway`. Every other
absolute import, parent-relative import, star import, direct `__import__`,
`eval`, or `exec` call fails the test suite.

The scanner never imports or executes target source and returns controlled
violations for parse, read, or out-of-root path failure. The allowlist is
intentionally narrow: a future approved capability must change it explicitly.
It is not a runtime sandbox and does not replace credential, process, network,
deployment, or service-policy separation.

The seventh Stage A slice adds non-executing source policies for the current
development Django settings, root URL patterns, reporter landing template, and
CSS. Exact literal app/middleware lists keep authentication, administrator,
session, and protected-domain components absent; targeted post-assignment
mutation is rejected. The root URL configuration remains exactly one inert
home route and rejects later mutation or dynamic construction.

The template policy accepts only the present passive tags, attributes, meta
profile, and first-party static stylesheet directive. It rejects interactive
or active tags, template variables/includes, event/style attributes, external
schemes, malformed structure, processing instructions, and altered head
resources. The CSS policy rejects resource loading and legacy active-content
constructs. Missing, unreadable, dynamic, malformed, mutated, and out-of-root
inputs fail closed with controlled content-free violations.

This slice does not render a template, run a browser, make development settings
production-safe, prove CSP/network isolation, or add a route, form, protected
action, credential, persistence, or service capability. All external and
production gates remain OPEN.

The eighth Stage A slice adds a test-only PostgreSQL concurrency scaffold for
the current metadata constraints and fences. Its closed registry covers one
active report per operator, one active lease per report/operator, one active
security operation per report, stale report-version rejection, and stale
lease-generation rejection. Cases contain only fresh ephemeral UUIDs for
20–100 unique contenders, request at least two processes, and describe a
synchronized start with a dedicated connection per contender.

The scaffold contains no PostgreSQL driver, DSN, credential, transition
executor, row-lock implementation, retry loop, process launcher, or database
write. The runner always fails with one controlled unavailable result on
SQLite, backend/configuration failure, and even a capability-shaped PostgreSQL
mock. No test is skipped and then counted as proof. The real lock ordering,
isolation level, executor review, multi-process run, cleanup, and result
evidence remain OPEN and release-blocking.

The ninth Stage A slice adds a non-executing source policy for the inert
`report_lifecycle` migration graph. It requires exactly the single initial
migration, an empty dependency graph, the exact three metadata-only models and
field constructor types, and the reviewed create/index/constraint operation
sequence. It rejects added numbered migrations, imports, callables, dynamic
expressions, data/SQL operations, models, fields, or type substitutions. A
separate dry Django migration check requires no pending model drift.

No migration is generated or changed by this slice, and no PostgreSQL instance,
driver, credential, write executor, production DDL, rollback, or deployment is
introduced or proven. The policy is source-level review evidence only; all
database execution, concurrency, durability, and production gates remain OPEN.

The tenth Stage A slice adds a pure, non-persisting finalization sequence
contract for the exact request-plus-twelve-action order already approved in
`docs/03`. It accepts only the existing structurally validated
`FINALIZE_RESPONSE` binding for an OPEN report and matching active lease, and
rejects every skipped, reversed, repeated, unknown, wrong-operation,
wrong-state, internally inconsistent version, forged-idempotency, or
malformed-binding edge. Returned plans retain the internal operation
idempotency UUID alongside the existing internal UUIDs and counters and
explicitly authorize no execution.

The checkpoints are not lifecycle/database states or evidence that CAPTCHA,
step-up, audit, staging, key destruction, publication, invalidation, or cleanup
occurred. They are not persisted. The executor always raises the same
controlled unavailable error and calls no database or external service. The
real finalization/resume workflow and every dependent review and production
gate remain OPEN.

The eleventh Stage A slice adds a pure, non-persisting sequence contract for
the exact request-plus-ten-action OPEN-only operator-deletion order already
approved in `docs/32`. It accepts only the existing structurally validated
`DELETE_REPORT` binding for an OPEN report and matching active lease, and
rejects every skipped, reversed, repeated, unknown, flood/finalization,
wrong-state, internally inconsistent version, forged-idempotency, or
malformed-binding edge. Returned plans contain only internal UUIDs and counters
and explicitly authorize no execution, persist no checkpoint, and destroy no
key or content.

The checkpoints are not lifecycle/database states or evidence that input,
CAPTCHA, step-up, audit, locking, `DELETING`, key destruction, recovery
invalidation, terminal transition, or cleanup occurred. The executor always
raises the same controlled unavailable error and calls no database or external
service. The real deletion/resume workflow and every legal, independent-review,
PostgreSQL, MFA, CAPTCHA, Audit Service, Key Service, Alert Service, cleanup,
and production gate remain OPEN.

The twelfth Stage A slice adds a non-executing AST purity policy for the two
current inert orchestration modules. It requires their exact target paths,
imports, top-level members, UUID/counter/checkpoint-only immutable plan fields,
false capability flags, closed calls and raises, and executors that can only
raise the reviewed controlled unavailable errors.

The scanner never imports or executes `finalization.py` or `deletion.py`.
Nested/star imports, database/network/cryptographic/I/O or self-selected-time
calls, dynamic/effectful syntax, mutating targets, content/authorizing fields,
and altered executor bodies fail closed. Passing is source-level conformance
only: it does not implement or authorize CAPTCHA, MFA, audit receipts,
persistence, staging, key destruction, recovery invalidation, cleanup,
finalization, deletion, or production use.

The thirteenth Stage A slice adds a pure, metadata-only Response Note retention
planner for the exact owner-approved rules in `docs/32`. It accepts only
internal UUIDs, `RESPONSE_AVAILABLE`, state/version, and trusted timestamps. It
requires the immutable unread deadline to be exactly 90 times 24 hours after
availability, never proposes a first read, recognizes an already stored first
read strictly before that deadline only with one full non-sliding 72-hour
window, and treats equality at either deadline as expired.

Returned plans are immutable and explicitly authorize no recovery, persist no
deadline, decrypt no response, and destroy no key or content. The executor
always raises one controlled unavailable error. No PostgreSQL first-read race,
recovery validation, audit receipt, Key Service conversion/destruction,
verifier invalidation, cleanup, endpoint, or background worker is added; every
legal/operational, independent, external-service, concurrency, and production
gate remains OPEN.

The fourteenth Stage A slice extends the non-executing orchestration-source
policy to `report_lifecycle/retention.py`. It fixes the exact target/import/
top-level-member set, both immutable content-free dataclasses, all four false
capability flags, the closed call/raise profile, and the executor whose only
outcome is the controlled unavailable error. Imported types/constants,
top-level members, and allowed call names cannot be shadowed.

The scanner permits retention to obtain server time and convert an already
aware timestamp to UTC only through its exact timezone calls. Database, Key
Service, network, cryptographic, I/O, logging, mutation, dynamic syntax,
content/recovery/verifier fields, and executable executor changes fail closed.
The target is parsed but never imported or executed. Passing remains static
source evidence only and closes no recovery, expiry, audit, persistence,
concurrency, cleanup, external-service, or production gate.

The fifteenth Stage A slice adds a pure metadata-only planner for the ciphertext
cleanup timing in `docs/32`. It fixes base delays of 5 seconds, 30 seconds,
2 minutes, five minutes during the first hour, one hour through the 24-hour
boundary, and six hours thereafter without a policy maximum. It exposes only
the 10% maximum jitter, one-minute reconciler ceiling, and the transition to an
alert-due classification at exactly 15 minutes after the first failure.

The snapshot and immutable plan contain only internal cleanup/idempotency UUIDs,
a bounded failure counter, trusted timestamps, closed tier/disposition enums,
and durations. There is no target object ID, path, filename, provider error,
receipt, key, or protected content. The planner chooses no jitter, schedules or
persists nothing, submits no alert, calls no external service, and authorizes no
deletion; its executor always raises one controlled unavailable error. Audit,
alert, storage, exactly-once, concurrency, worker/reconciler, deletion, and
production gates remain OPEN.

The sixteenth Stage A slice extends the non-executing orchestration-source policy
to `report_lifecycle/cleanup.py`. It fixes the exact target/import/top-level
timing-member set, closed retry/alert enums, both immutable content-free
dataclasses, all five false capability flags, the closed call/raise profile, and
the executor whose only outcome is the controlled unavailable error. Imported
types/constants, top-level members, and allowed call names cannot be shadowed.

Only the exact server-time and aware-to-UTC calls used by the pure planner are
allowed. Database/storage deletion, scheduler, Audit Service, Alert Service,
network, cryptographic, I/O, logging, mutation, dynamic syntax, path/object/
provider/content fields, and executable executor changes fail closed. The target
is parsed but never imported or executed. Passing is static source evidence only
and closes no receipt, storage, alert, exactly-once, concurrency, worker,
reconciler, cleanup, deletion, or production gate.

The seventeenth Stage A slice adds a pure terminal application metadata
retention planner for the exact minimum in `docs/32`. It accepts only internal
retention/cleanup UUIDs and an optional trusted cleanup-confirmation timestamp.
Incomplete cleanup is retained with no removal time. A durable confirmation
starts exactly 30 times 24 elapsed hours in UTC, and equality produces only a
`REMOVAL_REVIEW_DUE` classification.

The immutable plan explicitly authorizes no removal, deletes no public Ticket
ID lookup, persists no state, schedules no job, and calls no external service.
It contains no public Ticket ID, Recovery Secret, verifier, content, filename,
path, key, or provider error; its executor always raises one controlled
unavailable error. No cleanup proof, separately credentialed retention job,
database mutation, generic recovery behavior, audit expiry, or Key Service
tombstone handling is implemented. Legal/operational, independent-review,
external-service, concurrency, and production gates remain OPEN.

The eighteenth Stage A slice extends the non-executing orchestration-source
policy to `report_lifecycle/metadata_retention.py`. It fixes the exact target,
imports, top-level members, closed disposition enum, immutable content-free
snapshot and plan, all five false capability flags, closed call/raise profile,
protected binding names, and the executor whose only outcome is the controlled
unavailable error.

Only the exact server-time and aware-to-UTC calls used by the pure planner are
allowed. Database deletion, scheduler, Audit Service, Key Service, network,
cryptographic, I/O, logging, mutation, dynamic syntax, public-ticket/recovery/
path/content fields, and executable executor changes fail closed. The target is
parsed but never imported or executed. Passing is static source evidence only
and closes no cleanup-proof, retention-job, database, recovery, Key Service,
legal/operational, external-service, concurrency, or production gate.

The nineteenth Stage A slice adds a pure audit-retention planner for the exact
minima in `docs/23` and `docs/32`. It accepts only internal retention/evidence
UUIDs, a closed evidence class, a trusted collector timestamp, and a strict
verification-dependency flag. It computes 365 times 24 elapsed hours for event/
receipt/proof material and 730 times 24 elapsed hours for checkpoint,
consistency, public-key-manifest, and witness evidence.

Before the minimum boundary the classification retains. At or after it, a
required verification dependency still retains; otherwise the result marks only
`EXPIRY_REVIEW_DUE`. The immutable plan authorizes no expiry, deletes no audit
evidence, persists no retention batch, exposes no witness evidence, and calls no
external service; its executor always raises one controlled unavailable error.
No isolated credential, daily job, dependency graph, database mutation,
controlled retention evidence, witness integration, legal policy, Audit Service,
or production capability is implemented. Every dependent gate remains OPEN.

The twentieth Stage A slice extends the non-executing orchestration-source policy
to `report_lifecycle/audit_retention.py`. It fixes the exact target, imports,
top-level timing/type members, both closed enums, immutable content-free snapshot
and plan, all five false capability flags, closed call/raise profile, protected
binding names, and the executor whose only outcome is the controlled unavailable
error.

Only the exact server-time, aware-to-UTC, and closed retention-limit calls used
by the pure planner are allowed. Database expiry, scheduler, witness, network,
cryptographic, I/O, logging, mutation, dynamic syntax, receipt/content/key fields,
and executable executor changes fail closed. The target is parsed but never
imported or executed. Passing is static source evidence only and closes no
trusted-clock, isolated-identity, dependency, persistence, retention-batch,
witness, legal/operational, Audit Service, or production gate.

The twenty-first Stage A slice adds inert foundations for the owner-approved
`AdministrativeStepUpAuthorization v2` in `docs/33`. It validates exact 16-byte
authorization, administrator, session, and device identifiers; the existing
binding purpose and unsigned key epoch; a non-sliding 120-second lifetime; and
an unused-only state.

The immutable structural result explicitly has no complete operation profile,
does not verify WebAuthn or artifact binding, and authorizes neither an
administrative action nor flood deletion. Operation, target kind/ID, artifact
kind/binding, credential-row ID, challenge, opaque handle, persistence,
consumption, actor-role-specific flood approvals, authentication/session/device
proof, database concurrency, external services, independent review, and
production capability remain absent and OPEN.

The twenty-second Stage A slice adds a non-executing source policy for the
administrative step-up-v2 foundation. It fixes the exact target and imports,
protocol version `2`, the `120 * 1000` millisecond lifetime expression, complete
top-level member set, immutable class profiles, false capability results,
validator bodies, and closed constructor/validator/type/timing call profile.

Nested imports, dynamic constructs, added members or fields, persistence,
network, file, logging, cryptographic, and authorization behavior fail closed.
Missing, unreadable, malformed, and out-of-root inputs produce controlled,
content-free violations. The target is parsed but never imported or executed.
Passing is static source evidence only and closes no administrator-identity,
authentication, WebAuthn, session/device, operation/flood-profile, persistence,
consumption, concurrency, independent-review, external-service, or production
gate.

The twenty-third Stage A slice extends the non-executing reporter-surface policy
to the exact executable AST of `reporter_gateway/views.py` and
`reporter_gateway/middleware.py`. The view remains one safe-method-only render
of the passive landing template, with no request-derived context, input,
persistence, cookie, redirect, or added endpoint behavior. The middleware
retains the exact no-store, CSP, referrer, permissions, cross-origin, and
cross-domain response-header profile and performs no request logging or other
side effect.

Unknown targets, malformed source, and any executable AST change fail closed
with controlled, content-free violations. Both targets are parsed but never
imported or executed. Passing is static source evidence only and closes no
browser, proxy, logging, anonymity, process-isolation, submission, deployment,
independent-review, external-service, or production gate.

The twenty-fourth Stage A slice adds a non-executing source policy for the
mandatory negative-capability boundary. It fixes the exact executable AST of
`security_interfaces/errors.py` and `security_interfaces/unavailable.py`,
including the closed dependency registry, generic controlled error, exact
service families and public method set, dependency mapping, and deny-only
method bodies.

Success returns, plaintext or development fallbacks, new service methods,
dependency reassignment, input-bearing errors, logging/import side effects, and
all other executable changes fail closed. Missing roots, unknown targets,
malformed source, and unreadable inputs produce controlled content-free
violations. The targets are parsed but never imported or executed. Passing is
static source evidence only and closes no service-authentication, process,
network, credential, durability, cryptographic, external-service, independent-
review, or production gate.

The twenty-fifth Stage A slice adds a non-executing source policy for the inert
audit-v1 descriptor module. It fixes the exact target and complete executable
AST, including imports, protocol constants, closed event/actor registries,
authorization windows, context-dependent denial, immutable content-free fields,
validator logic, and the false protected-action authorization result.

Registry, field, lifetime, validator, success-return, import, dynamic, logging,
I/O, persistence, network, cryptographic, and other side-effect changes fail
closed. Missing, malformed, unreadable, and out-of-root targets produce only
controlled content-free violations. The target is parsed but never imported or
executed. Passing is static source evidence only and closes no CBOR/COSE,
receipt verification, audit append/durability, replay storage, protected
consumer, independent-review, external-service, or production gate.

The twenty-sixth Stage A slice adds the equivalent non-executing source policy
for the inert alert-v1 descriptor module. It fixes the exact target and complete
executable AST: alert/severity/delivery registries, immutable content-free
component fields, validators, acknowledgement pairing, and the false durable-
acceptance and protected-action authorization results.

Registry, field, validator, success-return, import, dynamic, SMTP, logging, I/O,
persistence, network, and other side-effect changes fail closed. Invalid paths
and malformed sources yield controlled content-free violations; the target is
never imported or executed. Passing closes no full request-profile, durable
acceptance, delivery, acknowledgement, service-authentication, PostgreSQL,
independent-review, Alert Service, external-service, or production gate.

The twenty-seventh Stage A slice adds the non-executing source policy for the
inert report-bound step-up-v1 descriptor module. It fixes the exact target and
complete executable AST: protocol/lifetime, algorithm and binding-purpose
registries, internal identifier/counter fields, timing, unused-only state,
validators, and every false operation-profile, WebAuthn, artifact-binding, and
protected-action result.

Field, registry, timing, validator, success-return, import, challenge,
credential, handle, binding, persistence, consumption, cryptographic, logging,
network, I/O, dynamic, and other side-effect changes fail closed. The scanner
never imports or executes the target and returns only controlled content-free
violations. Passing closes no authentication, WebAuthn, artifact binding,
session, database, concurrency, independent-review, external-service, or
production gate.

The twenty-eighth Stage A slice adds a non-executing exact-AST policy for the
sole inert `submission_workflow` initial migration. It fixes the empty
dependency graph, exact metadata-only fields, closed submission states,
state/version constraints, terminal timestamp pairing, imports, operations,
and absence of additional numbered migrations.

Reporter-data, credential, key, request-metadata, schema, state, constraint,
data/SQL/custom-code, import, dynamic, dependency, and graph changes fail
closed. Missing, malformed, unreadable, and out-of-root sources produce only
controlled content-free violations. The scanner never imports, executes, or
echoes the migration. Passing is static evidence only and closes no endpoint,
attempt-credential, persistence-executor, reconciler, audit, cryptographic,
external-service, PostgreSQL-concurrency, independent-review, or production
gate.

The twenty-ninth Stage A slice adds a non-executing exact-AST policy for the
current `submission_workflow` controlled error, state registry, transition
planner, and metadata model. It fixes the generic public failure, closed
one-way graph, exact single version increment, server-selected time, immutable
plan, metadata-only constraints, creation-only save behavior, and absence of a
protected persistence executor.

New states or edges, backward acceptance, sensitive fields, caller-selected
time, logging, weaker constraints, successful existing-row mutation, database
capability, dynamic behavior, unknown targets, malformed source, and missing
roots fail closed. The scanner never imports, executes, or echoes its targets.
Passing closes no endpoint, credential, concurrency, reconciliation, audit,
cryptographic, external-service, independent-review, or production gate.

The thirtieth Stage A slice adds a non-executing exact-AST policy for the
current lifecycle errors, state registries, transition/lease planners,
operation bindings, metadata models, and persistence boundary. It fixes the
closed state graphs, five-minute idle rule, server time, monotonic versions and
generations, exact report/lease/operation fencing, metadata-only constraints,
creation-only saves, PostgreSQL capability checks, and always-unavailable
executor.

New or backward state edges, relaxed timing, skipped fencing, sensitive fields,
weakened constraints, backend relaxation, logging, database writes, success
returns, dynamic behavior, unknown targets, malformed source, and missing roots
fail closed. The scanner never imports, executes, or echoes its targets.
Passing closes no protected transition, authentication, audit, cryptographic,
PostgreSQL-concurrency, external-service, independent-review, or production
gate.

The thirty-first Stage A slice adds a non-executing exact-AST policy for
`manage.py`, both Django application entrypoints, and the two installed
metadata-app configurations. It fixes the settings-module identity, standard
ASGI/WSGI factories, management-command boundary, app identities, and absence
of startup hooks.

Alternate settings, logging, network/file effects, application wrappers, early
command execution, `AppConfig.ready()` hooks, dynamic behavior, unknown
targets, malformed source, and missing roots fail closed. The scanner never
imports, executes, or echoes its targets. Passing closes no runtime, process,
proxy, dependency, network, deployment, independent-review, or production
gate.

The thirty-second Stage A slice adds a non-executing exact-AST policy for the
current application and migration package initializers. It fixes the passive
package markers for the Django project/apps, both empty migration package
markers, and the reviewed `security_interfaces.__init__` re-export surface.

Added imports, exports, startup side effects, migration initializer code,
dynamic behavior, unknown targets, malformed source, and missing roots fail
closed. The scanner never imports, executes, or echoes its targets. Passing
closes no runtime import isolation, process, dependency, service, deployment,
independent-review, or production gate.

The thirty-third Stage A slice adds an aggregate command-line runner for the
current static architecture-policy registry and wires CI to run it. The runner
normalizes controlled violations from dependency, import, surface, migration,
bootstrap, initializer, source-profile, orchestration, descriptor, and
negative-capability policies.

The runner adds no new protected policy semantics of its own and does not
import or execute scanned targets beyond the behavior of the already reviewed
individual scanners. Passing closes no browser, runtime, PostgreSQL,
process-isolation, external-service, deployment, independent-review, or
production gate.

The thirty-fourth Stage A slice adds a content-free repository-hygiene policy
to the aggregate architecture runner. It inspects only tracked path names and
the `.gitignore` rule set, rejecting committed local databases, logs, virtual
environments, secret/config material, export artifacts, temporary workspaces,
quarantine areas, user media, collected static output, and cache/test
artifacts.

Missing `.gitignore`, unavailable tracked-file enumeration, invalid tracked
path shapes, removed required ignore rules, and forbidden tracked paths fail
closed with controlled reason codes. The policy does not read or echo candidate
file contents and is not a substitute for dedicated secret scanning,
vulnerability scanning, deployment review, incident response, or production
data-handling controls.
