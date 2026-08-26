# Report lifecycle — inert Stage A

This Django app implements only the owner-authorized metadata boundary in
`docs/34_PRE_CODE_SECURITY_GATE.md`.

It contains:

- lifecycle enums and explicit allowed edges;
- metadata-only `Report`, `ReportLease`, and `SecurityOperation` schemas;
- database uniqueness/check constraints for active operators, leases, and
  operation fences;
- pure transition and lease-activity planners using server time.

It intentionally contains no views, URLs, forms, authentication, content,
attachments, filenames, recovery data, keys, cryptography, protected notes,
audit/alert payloads, service calls, or background jobs. Existing-row `save()`
mutation is denied because the reviewed PostgreSQL persistence executor does
not yet exist.

SQLite tests validate pure behavior and ordinary constraints only. They are not
PostgreSQL concurrency or release evidence. Protected workflows remain blocked
by the independent and production gates in `docs/34`.
