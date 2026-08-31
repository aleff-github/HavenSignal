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

The fourteenth Stage A slice extends the non-executing AST purity policy to the
retention module. Exact imports/members, immutable content-free snapshot and
plan fields, false capability flags, closed calls, protected binding names, and
the always-unavailable executor are required. The scanner never imports or
executes the target and provides no recovery, expiry, persistence, decryption,
destruction, cleanup, or production authority.

The fifteenth Stage A slice adds immutable UUID/counter/timestamp-only planning
for the exact ciphertext-cleanup retry tiers, 10% jitter ceiling, one-minute
reconciler ceiling, and 15-minute persistent-failure alert boundary. It chooses
no jitter, schedules/persists nothing, submits no alert, calls no service, and
authorizes no deletion. Its executor always fails closed; no cleanup runtime or
production evidence is introduced.

The sixteenth Stage A slice extends the non-executing AST purity policy to the
cleanup planner. Exact imports/timing members, closed enums, immutable
content-free snapshot/plan fields, false capability flags, closed calls,
protected bindings, and the always-unavailable executor are required. The
scanner never imports or executes the target and provides no scheduling, alert,
storage, deletion, cleanup, or production authority.

The seventeenth Stage A slice adds immutable UUID/timestamp-only terminal
application metadata retention planning. Incomplete cleanup is retained with no
removal time; durable cleanup confirmation starts exactly 30 times 24 elapsed
hours in UTC, after which only a removal review is marked due. All capability
flags are false and the executor always fails closed. No Ticket ID lookup or
metadata deletion, persistence, job, service call, recovery change, Key Service
tombstone handling, or production authority is introduced.

The eighteenth Stage A slice extends the non-executing AST purity policy to the
terminal-metadata retention planner. Exact imports/members, the closed
disposition enum, immutable content-free snapshot/plan fields, five false
capability flags, closed calls, protected bindings, and the always-unavailable
executor are required. The scanner never imports or executes the target and
provides no database deletion, retention job, recovery change, Key Service
tombstone handling, or production authority.

The nineteenth Stage A slice adds immutable UUID/class/dependency/timestamp-only
audit-retention planning. It fixes exact 365-times-24-hour event/receipt/proof
and 730-times-24-hour checkpoint/consistency/key-manifest/witness minima from
trusted collector time, while a required verification dependency retains longer.
Every capability flag is false and the executor always fails closed. No audit
expiry, retention batch, isolated credential, witness output, database write,
service integration, legal approval, or production authority is introduced.

The twentieth Stage A slice extends the non-executing AST purity policy to the
audit-retention planner. Exact imports/members, both closed enums, immutable
content-free snapshot/plan fields, five false capability flags, closed calls,
protected bindings, and the always-unavailable executor are required. The
scanner never imports or executes the target and provides no audit expiry,
trusted-clock proof, isolated credential, retention batch, witness integration,
legal approval, or production authority.

The twenty-first Stage A slice adds immutable administrative step-up-v2
foundations for exact internal identity shapes, binding-purpose/key-epoch
metadata, the 120-second non-sliding lifetime, and unused-only state. It omits
operation/target/artifact profiles, credentials, challenges, handles, binding
bytes, persistence, and consumption; it verifies nothing and authorizes neither
administrative action nor flood deletion. All authentication, batch-profile,
database, independent-review, and production gates remain OPEN.

The twenty-second Stage A slice adds a non-executing source policy for the
administrative step-up-v2 foundation. Exact target/imports, version and lifetime
constants, module members, immutable classes, false capabilities, validator
bodies, and closed calls are required. Added effectful or dynamic behavior
fails closed; the target is never imported or executed. This provides only
source-conformance evidence and no authentication, authorization, persistence,
concurrency, independent-review, or production authority.

The twenty-third Stage A slice locks the executable AST of the read-only
reporter view and restrictive response-header middleware without importing or
executing either target. Added endpoint/input/context/persistence/cookie/logging
behavior, unsafe methods, header relaxation, unknown targets, and malformed
source fail closed. This is source-conformance evidence only and provides no
browser, proxy, anonymity, submission, deployment, or production authority.

The twenty-fourth Stage A slice locks the executable AST of the controlled
security-interface errors and every mandatory unavailable adapter. Success
returns, plaintext/development fallbacks, new methods, dependency remapping,
input-bearing errors, logging/import side effects, unknown targets, and
malformed source fail closed without importing or executing either target.
This is negative-capability source evidence only and enables no real service or
production authority.

The twenty-fifth Stage A slice locks the complete executable AST of the inert
audit-v1 descriptor module. Changes to imports, constants, closed registries,
authorization windows, context-dependent denial, immutable fields, validators,
false authorization results, or added dynamic/effectful behavior fail closed.
The scanner never imports, executes, or echoes the target. This is source-
conformance evidence only and provides no CBOR/COSE, receipt verification,
audit append/durability, replay storage, protected-action, or production
authority.

The twenty-sixth Stage A slice locks the complete executable AST of the inert
alert-v1 descriptor module. Alert/severity/delivery registries, content-free
fields, validators, acknowledgement pairing, false durability/authorization
results, imports, and absence of dynamic/effectful behavior are fixed. The
scanner never imports, executes, or echoes the target. This provides no full
request profile, persistence, durable acceptance, delivery, acknowledgement,
Alert Service, or production authority.

The twenty-seventh Stage A slice locks the complete executable AST of the inert
report-bound step-up-v1 descriptor module. Protocol/lifetime, algorithms,
binding purpose, internal identifier/counter fields, timing, unused state,
validators, and every false verification/authorization result are fixed. The
scanner never imports, executes, or echoes the target. This provides no
challenge, credential, WebAuthn, artifact binding, session, persistence,
consumption, concurrency, external-service, or production authority.

The twenty-eighth Stage A slice locks the complete executable AST and sole-file
graph of the inert submission initial migration. Exact metadata-only fields,
states, state/version constraints, terminal timestamp pairing, imports, and
empty dependencies are fixed without importing or executing the source. This
provides no endpoint, credential, protected persistence, reconciliation,
PostgreSQL concurrency, external-service, or production authority.

The twenty-ninth Stage A slice locks the complete executable AST of the inert
submission error, state graph, pure transition planner, and metadata model. The
generic failure, one-way edges, single version increment, server time,
metadata-only constraints, and creation-only persistence boundary remain exact
without importing or executing target modules. This provides no endpoint,
credential, protected executor, reconciliation, concurrency, or production
authority.

The thirtieth Stage A slice locks the complete executable AST of the lifecycle
errors, closed state graphs, transition and lease planners, operation bindings,
metadata models, and persistence boundary. Server time, timeout and fencing
rules, constraints, creation-only saves, PostgreSQL checks, and the unavailable
executor remain exact without importing or executing targets. This provides no
protected transition, database write, concurrency proof, or production
authority.

The thirty-first Stage A slice locks the complete executable AST of `manage.py`,
the ASGI/WSGI entrypoints, and both installed metadata-app configurations. The
settings-module identity, Django factories, management boundary, app identities,
and absence of startup hooks remain exact without importing or executing the
targets. This provides no runtime, process, proxy, network, deployment, or
production authority.

The thirty-second Stage A slice locks the complete executable AST of the
application and migration package initializers. Passive package markers and the
reviewed `security_interfaces.__init__` re-export surface remain exact without
importing or executing the targets. This provides no runtime import isolation,
process, dependency, service, deployment, or production authority.

The thirty-third Stage A slice adds `python -m architecture_checks .` as an
aggregate fail-closed runner for the current static policy registry and wires
CI to call it. The command normalizes content-free violations from the existing
non-executing checks and provides no new runtime, browser, database,
external-service, deployment, or production authority.
