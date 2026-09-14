# Metadata-only Stage A exit record

Recorded: 2026-09-14. **Verdict: PASS for the bounded local Stage A exit.**

Implementation revision: `dfb7a0f04d34346ec6cacda78ebd7520ece6eaf6`.
This record evaluates Phase 1 of the [alpha checklist](ALPHA_DEVELOPMENT_TODO.md)
against the boundary in [docs/34](34_PRE_CODE_SECURITY_GATE.md). It is automated
local verification evidence, not an independent security review, service
acceptance, alpha release, or production authorization.

## Executed verification

| Command | Environment | Observed result |
|---|---|---|
| `python3 scripts/verify` | Local virtualenv, Python 3.14.4, SQLite | PASS; 799 tests; architecture, system, migration-drift, compilation, and manifest checks passed. |
| `./scripts/docker-local test` | Docker 29.5.1 / Compose 5.1.3, pinned Python 3.13.15 image and PostgreSQL 17.11 image | PASS; 799 tests on real PostgreSQL, followed by successful fresh-volume preparation, container restart, rehydration, and cleanup. |

The PostgreSQL image is
`postgres:17.11-bookworm@sha256:051f7b7b3abdd564d5d1bd1e8c4b9c1b6e77087d1dd22020ede611c096a272e0`.
Application dependencies are hash-locked in `requirements.lock`; the Python
image digest is pinned in `Dockerfile`. GitHub native CI additionally exercises
the supported Python 3.13 profile. A local Python 3.14 pass does not replace it.

Both commands returned exit status 0. The test count is not multiplied into a
claim of independent cases: the suites share tests, and PostgreSQL-specific
tests execute denial checks on SQLite instead of concurrency success paths.

## Exit criteria and evidence

| Criterion | Executable evidence | Result |
|---|---|---|
| Metadata schema, constraints, and monotonic transitions | `tests/test_report_lifecycle.py`, migration policies, Django drift check | PASS |
| Nine contention scenarios, 20 processes each | `PostgreSQLConcurrencyAcceptanceTests.test_all_synthetic_metadata_fences_have_expected_winners` | PASS; expected winners/rejections, zero worker failures, synthetic-row cleanup |
| Fenced preparation, activation, and prepared abort | `LifecyclePersistenceBoundaryTests` preparation/activation/abort cases | PASS; stale state, forged bindings, expired leases, and replay denied |
| Rehydration after reconnection | `test_prepared_metadata_rehydrates_after_database_reconnection` | PASS |
| Rollback when result construction fails after writes | `test_result_construction_failures_rollback_every_write` | PASS for preparation, activation, and abort |
| Committed metadata survives application-process exit | `test_committed_preparation_survives_application_process_exit` | PASS on PostgreSQL |
| Application-process exit before commit leaves no operation | `test_process_exit_before_commit_rolls_back_preparation` | PASS on PostgreSQL |
| Committed metadata survives a controlled database-container restart | `tests/postgresql_restart_probe.py`, invoked by `scripts/docker-local test` | PASS on a fresh disposable volume, with a separate verification container |
| Malformed persisted preparation is rejected | `test_malformed_persisted_preparation_never_rehydrates` | PASS; constraint-valid corrupt shapes denied; invalid timestamp update rolled back |
| SQLite and mocked capabilities grant no write authority | `test_mocked_capabilities_do_not_enable_sqlite`, concurrency scaffold denial cases | PASS |
| Protected application surfaces and services remain disabled | Architecture policies, reporter/recovery/operator tests, unavailable-service tests | PASS |

Persistence test names above refer to
`tests/test_report_lifecycle_persistence.py`; the concurrency acceptance test is
in `tests/test_postgresql_concurrency_scaffold.py`. The restart probe prepares
only synthetic metadata; its operation label performs no report deletion.

## Failure found and corrected before acceptance

The first Docker run passed 799 tests but FAILED during fresh-volume migration:
the Unix-socket `pg_isready` check reported the temporary initialization server
healthy while other containers received TCP connection refusal. The complete
command returned nonzero; that run is not acceptance evidence.

Inspection of the pinned image's `docker_temp_server_start` confirmed that the
initialization server uses `listen_addresses=''`. The Compose healthcheck now
uses explicit TCP host `127.0.0.1` and port `5432`, with no shell interpolation.
The repeated complete Docker command then passed migration, preparation,
restart, rehydration, and removal of the uniquely scoped probe volume.

The ordinary contributor database volume was not removed. No real report,
credential, key, or protected content was used. Raw tool logs are local scratch
artifacts and are not committed as security evidence.

## What remains open

This PASS does not prove abrupt database crash, power-loss durability, failover,
disk loss/full behavior, backup/restore, orphan reconciliation policy, Key
Service non-resurrection, audit durability, authentication, claim/open,
protected execution, or any production trust boundary. The unavailable
adapters and sensitive application endpoints remain unchanged.

Source/metadata policy changes require their own reviewed verification; this
record cannot authorize later code merely because Stage A once passed.
Remote promotion must use the exact commit that passes native, PostgreSQL, and
CodeQL checks as required by the alpha workflow.

The next work is the [security-service review and proof packet](SECURITY_SERVICE_REVIEW_PACKET.md).
