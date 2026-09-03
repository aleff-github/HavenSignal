# Report lifecycle — inert Stage A

This Django app implements only the owner-authorized metadata boundary in
`docs/34_PRE_CODE_SECURITY_GATE.md`.

It contains:

- lifecycle enums and explicit allowed edges;
- metadata-only `Report`, `ReportLease`, and `SecurityOperation` schemas;
- database uniqueness/check constraints for active operators, leases, and
  operation fences;
- pure transition and lease-activity planners using server time;
- immutable operation/report/lease descriptors with exact cross-binding
  validation.

It intentionally contains no views, URLs, forms, authentication, content,
attachments, filenames, recovery data, keys, cryptography, protected notes,
audit/alert payloads, service calls, or background jobs. Existing-row `save()`
mutation remains denied because a protected transition executor does not yet
exist.

`bindings.py` verifies exact actor, report/state version, lease identifier,
lease generation, lease ownership, and server-time expiry. A validated binding
is necessary metadata evidence only; it is never an authorization grant.

`persistence.py` requires PostgreSQL transactions, row locking, and partial
indexes. Preparation locks the report and optional lease in that order,
reconstructs and revalidates their database-authoritative snapshots, rejects
an existing nonterminal operation, assigns the next monotonic fence, and
inserts one metadata-only `PREPARED` operation. Activation repeats that
authoritative validation while locking report, optional lease, and operation
in a fixed order; it requires an exact untampered preparation descriptor and
performs one compare-and-set transition to `ACTIVE`. A separate abort path uses
the same locks and validation to transition only `PREPARED` metadata to
`ABORTED`; it cannot interrupt an `ACTIVE` operation. None of these paths
executes a protected operation, updates report/lease state, or calls another
service.

SQLite tests validate pure behavior and ordinary constraints only. They are not
PostgreSQL concurrency or release evidence. Protected workflows remain blocked
by the independent and production gates in `docs/34`.

`tests/postgresql_concurrency_scaffold.py` is a test-only, content-free
multi-process harness. It fixes the current constraint/version/fence scenarios,
generates fresh UUID-only cases for 20–100 contenders, requires one process and
one dedicated connection per contender, and contains no database credentials
or reporter fields. On PostgreSQL it verifies exact winners for active report,
lease, and operation constraints and exact rejection for stale report versions
and lease generations. A seventh case verifies one winner when 20 processes use
the preparation executor against one report; an eighth verifies one winner when
20 processes attempt to activate the same prepared operation; a ninth races
activation against abort and requires one total winner. Every synthetic row is
removed and other backends fail closed. This is evidence for the present
metadata schema and reviewed metadata-only executors; it is not protected
operation execution, durability proof, or release authorization.

`architecture_checks/migrations.py` locks the current single initial migration
to its empty dependency graph, exact three-model field/type profile, and closed
`CreateModel`/`AddIndex`/`AddConstraint` operation sequence without importing
the migration. Tests also run Django's dry no-drift check. This makes schema
changes explicit for review but is not PostgreSQL execution, concurrency,
durability, rollback, or production migration evidence.

`finalization.py` represents only the approved request-plus-twelve-step
`FINALIZING` order as an immutable, content-free sequence. It accepts only the
existing structurally validated `FINALIZE_RESPONSE`/OPEN/lease binding, rejects
every skipped, reversed, unknown, forged-idempotency, or malformed edge, and
returns plans that retain only content-free operation context and explicitly
neither authorize execution nor persist a checkpoint. The executor
always raises a controlled unavailable error and performs no database or
external-service operation. The sequence is conformance metadata, not current
lease/receipt/key/staging evidence or a resumable workflow implementation.

`deletion.py` represents only the approved request-plus-ten-step OPEN-only
operator-deletion order as immutable, content-free sequence metadata. It
accepts only the existing structurally validated `DELETE_REPORT`/OPEN/current-
lease binding, rejects every skipped, reversed, unknown, flood/finalization, or
malformed edge, and returns plans that explicitly authorize nothing, persist
nothing, and destroy no key or content. Its executor always raises one
controlled unavailable error and performs no database or external-service
operation. No reason, protected note, CAPTCHA, step-up, receipt, state write,
key operation, recovery change, cleanup, or resumable workflow exists.

`emergency_export.py` represents only the approved eleven-checkpoint
Emergency Export order as immutable, content-free sequence metadata. It
accepts only the existing structurally validated `EMERGENCY_EXPORT`/OPEN/
current-lease binding, rejects every skipped, reversed, repeated, unknown, or
malformed edge, and returns plans that authorize and persist nothing, create
no artifact, and release no plaintext. Its executor always raises a controlled
unavailable error. No request descriptor, protected note, step-up, receipt,
alert, key operation, archive, signature, encryption, staging, delivery, or
cleanup capability is implemented.

`architecture_checks/orchestration.py` statically parses `finalization.py`,
`deletion.py`, `emergency_export.py`, `retention.py`, `cleanup.py`, and
`metadata_retention.py` without importing any target, and applies the same
boundary to `audit_retention.py`.

The exact import/member/call, enum, snapshot/plan-field/capability-flag,
mutation/dynamic-syntax/shadowing, and always-unavailable executor profiles are
closed. A change outside that reviewed source profile fails the test suite;
passing it is source conformance only, never protected workflow authorization
or runtime isolation.

`retention.py` validates only internal UUID/state/version/timestamp metadata and
describes the exact 90-day unread or stored non-sliding 72-hour read-window
boundary using server time. It never proposes or commits a first read. Its
immutable plans authorize no recovery, persist no deadline, decrypt no
response, and destroy no key or content. The executor is always unavailable.
No response row, recovery verifier, Key Service call, audit receipt, cleanup
job, or reporter endpoint is implemented.

`cleanup.py` describes only the owner-approved ciphertext-cleanup retry tiers,
10% maximum jitter, one-minute reconciler ceiling, and the exact 15-minute alert
boundary from internal UUID/counter/timestamp metadata. It selects no random
jitter and has no object identifier, filename, path, provider error, receipt,
key, or content field. Its plans schedule nothing, persist nothing, call no
service, submit no alert, and authorize no deletion; its executor is always
unavailable.

`metadata_retention.py` describes only the minimum terminal application
metadata period from internal retention/cleanup UUIDs and trusted timestamps.
Cleanup that is not durably confirmed is retained without a removal time. A
confirmed cleanup uses exactly 30 times 24 elapsed hours in UTC, after which the
plan marks only a removal review as due. It does not hold a public Ticket ID,
Recovery Secret, verifier, content, filename, path, key, or provider error; it
cannot remove lookup state or metadata, persist, schedule, or call a service,
and its executor is always unavailable.

`audit_retention.py` describes only the exact 365-times-24-hour event/receipt/
proof minimum and 730-times-24-hour checkpoint/consistency/key-manifest/witness
minimum from internal UUIDs, closed evidence classes, a dependency flag, and
trusted Audit Collector timestamps. A required verification dependency retains
evidence after its minimum period. Its plan authorizes no expiry, deletes no
audit evidence, persists no retention batch, exposes no witness evidence, and
calls no service; its executor is always unavailable.

The executable AST of the lifecycle errors, states, transitions, bindings,
models, and persistence boundary is locked by a non-executing source policy.
State edges, lease timing, fencing generations, immutable binding profiles,
metadata-only constraints, creation-only saves, backend requirements, and the
preparation/activation/abort executors cannot change silently. Passing is
static source evidence only and is not PostgreSQL concurrency or runtime
isolation proof.
