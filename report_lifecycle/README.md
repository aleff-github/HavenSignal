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
mutation is denied because the reviewed PostgreSQL persistence executor does
not yet exist.

`bindings.py` verifies exact actor, report/state version, lease identifier,
lease generation, lease ownership, and server-time expiry. A validated binding
is necessary metadata evidence only; it is never an authorization grant.

`persistence.py` requires PostgreSQL transactions, row locking, and partial
indexes, but still denies every write. Passing backend capability checks cannot
replace the missing reviewed executor and multi-process integration evidence.

SQLite tests validate pure behavior and ordinary constraints only. They are not
PostgreSQL concurrency or release evidence. Protected workflows remain blocked
by the independent and production gates in `docs/34`.

`tests/postgresql_concurrency_scaffold.py` is a test-only, content-free plan for
the future multi-process proof. It fixes the current constraint/version/fence
scenarios, generates fresh UUID-only cases for 20–100 contenders, requires at
least two requested processes and one dedicated connection per contender, and
contains no database credentials or reporter fields. Its runner always returns
a controlled unavailable failure, including on a capability-shaped backend;
therefore it runs no PostgreSQL test and supplies no release evidence.

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

`architecture_checks/orchestration.py` statically parses `finalization.py`,
`deletion.py`, `retention.py`, and `cleanup.py` without importing any target.
The exact import/member/call, snapshot/plan-field/capability-flag,
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
