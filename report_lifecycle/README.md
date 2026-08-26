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
