# Handoff Version

Version: 0.3
Prepared: 2026-08-26

This handoff consolidates:

- the completed project security questionnaire;
- later clarifications made after the questionnaire;
- the current Python/Django implementation direction;
- unresolved security decisions that must not be silently guessed by Codex.

Version 0.2 additionally incorporates:

- non-resurrectable live-replicated Report-DEK/Response-DEK policy;
- explicit Application Administrator and Infrastructure / Key Custodian trust roles;
- Reporter Gateway capability restrictions;
- idempotent `FINALIZING` protocol;
- durable pre-action audit receipts and truncation detection;
- protected operator notes outside permanent audit;
- persisted lease generation/fencing;
- action-bound step-up authorization;
- explicit requirement IDs and traceability for recovery, response, export, CAPTCHA, file sandbox/CDR, roles, keys, alerts, and finalization.

Version 0.3 additionally incorporates exact proposals for:

- WebAuthn MFA, action-bound step-up, and credential lifecycle;
- original-report cryptography and Key Service destructive acceptance;
- Emergency Export packaging, encryption, signature, and delivery;
- hostile file admission, disposable sandboxing, and bounded multipart input;
- durable content-free administrator alerts;
- Response Note retention and receipt-gated deletion, including exceptional
  content-blind flood handling;
- physically and operationally separated role workstations and access paths;
- one consolidated, non-authorizing pre-code owner gate and a narrow inert
  Stage A implementation boundary.

No production-capable security workflow is enabled. The included Django code
is an inert scaffold plus deny-by-default interfaces and metadata-only domain
structures whose protected integrations remain gated.

The project owner approved `docs/25` through `docs/34` on 2026-08-26 and
authorized only the inert metadata-only Stage A. All independent, product,
production-equivalent, legal, operational, and release gates remain in force.

The first Stage A slice now includes the inert `report_lifecycle` metadata
schema, pure transition/lease planners, database constraints, and negative
tests. It exposes no protected endpoint or content-handling capability.

The second Stage A slice adds immutable cross-object binding validators and a
PostgreSQL capability gate whose persistence entry point always fails closed.
No SQLite or mocked-backend result can enable metadata writes.

The third Stage A slice adds immutable, content-free audit-v1 registry/replay/
acceptance-claim descriptors and strict structural validation. It contains no
CBOR/COSE implementation, signature verification, audit append, durable
receipt, or authorization capability; incomplete context profiles fail closed.

The fourth Stage A slice adds immutable, content-free alert-v1 registry and
component descriptors. Structural acceptance proves no durable commit,
delivery, acknowledgement, or authorization; all Alert Service integrations
and incomplete source/object/condition profiles remain unavailable.

The fifth Stage A slice adds report-bound step-up-v1 metadata components and
strict 120-second timing/algorithm validation while excluding challenges,
handles, credentials, artifact/HMAC bytes, consumed state, persistence, and all
authentication or authorization capability.

The sixth Stage A slice adds non-executing AST import allowlists for the inert
Reporter Gateway and root URL configuration. The checks make new source-level
dependency edges explicit but do not claim runtime or deployment isolation.

The seventh Stage A slice adds non-executing static policies for the inert
Django settings, single reporter-home route, passive template subset, and
no-resource-loading CSS. It adds controlled fail-closed abuse tests but no
browser, runtime, protected workflow, or production capability.

The eighth Stage A slice adds a test-only, UUID-only plan for six future
PostgreSQL metadata-concurrency scenarios with 20–100 contenders. The runner
always remains unavailable, adds no driver or credentials, writes no rows, and
is explicitly not PostgreSQL concurrency or release evidence.

The ninth Stage A slice adds non-executing conformance checks for the exact
initial lifecycle migration plus a dry Django drift test. It makes new
migrations, fields, constructors, imports, dynamic/data/SQL operations, and
model drift explicit without changing or executing production database work.

The tenth Stage A slice adds the exact inert finalization sequence as immutable,
content-free, non-authorizing and non-persisting edges, retaining and strictly
checking the existing operation idempotency UUID. Its executor always fails
closed; no receipt, staging, key, publication, cleanup, or resume capability is
implemented.

The eleventh Stage A slice adds the exact OPEN-only operator-deletion sequence
as immutable, content-free, non-authorizing, non-persisting, and explicitly
non-destructive edges. Its executor always fails closed; no reason or protected
note, CAPTCHA, step-up, receipt, database transition, key destruction, recovery
invalidation, cleanup, or resume capability is implemented.

The twelfth Stage A slice adds non-executing AST purity checks for the inert
finalization and operator-deletion modules. Exact imports, members,
UUID/counter/checkpoint-only plans, false capability flags, closed calls, and
always-unavailable executors are required. The scanner imports and executes no
target and provides no runtime or protected-workflow authority.

The thirteenth Stage A slice adds immutable, metadata-only Response Note
retention planning for the exact 90-times-24-hour unread boundary and validation
of one stored non-sliding 72-hour window after a pre-deadline first read. It
never proposes a first read. Exact-boundary expiry wins, every capability flag
is false, and the executor always fails closed. No persistence, recovery,
decryption, destruction, cleanup, endpoint, external-service call, or
production authority is introduced.
