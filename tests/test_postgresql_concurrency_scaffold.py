"""Negative tests for the inert PostgreSQL concurrency-test scaffold."""

from dataclasses import FrozenInstanceError, fields
from unittest.mock import patch
from uuid import UUID, uuid4

from django.db import connection
from django.test import TestCase, TransactionTestCase

from report_lifecycle.models import Report, ReportLease, SecurityOperation
from report_lifecycle.persistence import LifecycleBackendCapabilities
from tests.postgresql_concurrency_scaffold import (
    CONCURRENCY_EXPECTATIONS,
    MAX_CONTENDERS,
    MIN_CONTENDERS,
    MIN_PROCESSES,
    PROFILE_VERSION,
    ConcurrencyExpectation,
    ConcurrencyResult,
    ConcurrencyScenario,
    PostgreSQLConcurrencyHarnessUnavailable,
    _SyntheticConcurrencyCase,
    build_synthetic_concurrency_case,
    run_postgresql_concurrency_case,
)


class PostgreSQLConcurrencyScaffoldTests(TestCase):
    def test_scenario_registry_is_closed_and_exact(self) -> None:
        self.assertEqual(
            set(CONCURRENCY_EXPECTATIONS),
            {
                ConcurrencyScenario.ACTIVE_LEASE_PER_OPERATOR,
                ConcurrencyScenario.ACTIVE_LEASE_PER_REPORT,
                ConcurrencyScenario.ACTIVE_OPERATION_PER_REPORT,
                ConcurrencyScenario.PREPARED_OPERATION_PER_REPORT,
                ConcurrencyScenario.ACTIVE_REPORT_PER_OPERATOR,
                ConcurrencyScenario.STALE_LEASE_GENERATION,
                ConcurrencyScenario.STALE_REPORT_VERSION,
            },
        )
        self.assertEqual(
            CONCURRENCY_EXPECTATIONS[
                ConcurrencyScenario.STALE_LEASE_GENERATION
            ].maximum_successes,
            0,
        )
        self.assertTrue(
            all(
                expectation.maximum_successes in {0, 1}
                for expectation in CONCURRENCY_EXPECTATIONS.values()
            )
        )

    def test_builder_creates_only_bounded_unique_uuid_metadata(self) -> None:
        case = build_synthetic_concurrency_case(
            scenario=ConcurrencyScenario.ACTIVE_OPERATION_PER_REPORT,
            contender_count=MAX_CONTENDERS,
            process_count=4,
        )
        self.assertEqual(case.profile_version, PROFILE_VERSION)
        self.assertEqual(case.contender_count, MAX_CONTENDERS)
        self.assertEqual(case.dedicated_connection_count, MAX_CONTENDERS)
        self.assertEqual(case.requested_process_count, 4)
        self.assertTrue(case.synchronized_start)
        self.assertEqual(len(set(case.contender_ids)), MAX_CONTENDERS)
        self.assertTrue(
            all(type(identifier) is UUID for identifier in case.contender_ids)
        )
        self.assertEqual(
            {field.name for field in fields(case)},
            {
                "profile_version",
                "scenario",
                "run_id",
                "contention_target_id",
                "contender_ids",
                "requested_process_count",
                "synchronized_start",
            },
        )

    def test_separate_cases_never_reuse_generated_identifiers(self) -> None:
        first = build_synthetic_concurrency_case(
            scenario=ConcurrencyScenario.ACTIVE_LEASE_PER_REPORT
        )
        second = build_synthetic_concurrency_case(
            scenario=ConcurrencyScenario.ACTIVE_LEASE_PER_REPORT
        )
        first_ids = {first.run_id, first.contention_target_id, *first.contender_ids}
        second_ids = {
            second.run_id,
            second.contention_target_id,
            *second.contender_ids,
        }
        self.assertTrue(first_ids.isdisjoint(second_ids))

    def test_invalid_counts_scenario_and_boolean_integers_fail_closed(self) -> None:
        invalid_profiles = (
            (ConcurrencyScenario.ACTIVE_REPORT_PER_OPERATOR, MIN_CONTENDERS - 1, 2),
            (ConcurrencyScenario.ACTIVE_REPORT_PER_OPERATOR, MAX_CONTENDERS + 1, 2),
            (ConcurrencyScenario.ACTIVE_REPORT_PER_OPERATOR, MIN_CONTENDERS, 1),
            (
                ConcurrencyScenario.ACTIVE_REPORT_PER_OPERATOR,
                MIN_CONTENDERS,
                MIN_CONTENDERS + 1,
            ),
            ("ACTIVE_REPORT_PER_OPERATOR", MIN_CONTENDERS, 2),
            (ConcurrencyScenario.ACTIVE_REPORT_PER_OPERATOR, True, 2),
            (ConcurrencyScenario.ACTIVE_REPORT_PER_OPERATOR, MIN_CONTENDERS, True),
        )
        for scenario, contenders, processes in invalid_profiles:
            with self.subTest(
                scenario=scenario,
                contenders=contenders,
                processes=processes,
            ):
                with self.assertRaises(PostgreSQLConcurrencyHarnessUnavailable):
                    build_synthetic_concurrency_case(
                        scenario=scenario,
                        contender_count=contenders,
                        process_count=processes,
                    )

    def test_direct_case_shape_bypass_fails_closed(self) -> None:
        with self.assertRaises(PostgreSQLConcurrencyHarnessUnavailable):
            _SyntheticConcurrencyCase(
                profile_version=PROFILE_VERSION,
                scenario=ConcurrencyScenario.STALE_REPORT_VERSION,
                run_id=uuid4(),
                contention_target_id=uuid4(),
                contender_ids=tuple(uuid4() for _ in range(MIN_CONTENDERS - 1)),
                requested_process_count=MIN_PROCESSES,
                synchronized_start=True,
            )

    def test_scaffold_contracts_are_immutable(self) -> None:
        case = build_synthetic_concurrency_case(
            scenario=ConcurrencyScenario.STALE_REPORT_VERSION
        )
        expectation = ConcurrencyExpectation(
            maximum_successes=0,
            requirement_ids=("SEC-ACCESS-015",),
        )
        with self.assertRaises(FrozenInstanceError):
            case.requested_process_count = 1
        with self.assertRaises(FrozenInstanceError):
            expectation.maximum_successes = 1
        with self.assertRaises(TypeError):
            CONCURRENCY_EXPECTATIONS[
                ConcurrencyScenario.STALE_REPORT_VERSION
            ] = expectation

    def test_sqlite_runner_fails_closed_without_writes(self) -> None:
        case = build_synthetic_concurrency_case(
            scenario=ConcurrencyScenario.ACTIVE_REPORT_PER_OPERATOR
        )
        with self.assertRaises(PostgreSQLConcurrencyHarnessUnavailable) as raised:
            run_postgresql_concurrency_case(case=case)
        self.assertEqual(
            str(raised.exception),
            "postgresql_concurrency_harness_unavailable",
        )
        self.assertEqual(Report.objects.count(), 0)
        self.assertEqual(ReportLease.objects.count(), 0)
        self.assertEqual(SecurityOperation.objects.count(), 0)

    def test_capability_mock_cannot_bypass_actual_backend_check(self) -> None:
        case = build_synthetic_concurrency_case(
            scenario=ConcurrencyScenario.ACTIVE_OPERATION_PER_REPORT
        )
        capabilities = LifecycleBackendCapabilities(
            alias="default",
            vendor="postgresql",
            supports_transactions=True,
            supports_row_locks=True,
            supports_partial_indexes=True,
        )
        with (
            patch(
                "tests.postgresql_concurrency_scaffold.require_postgresql_transition_backend",
                return_value=capabilities,
            ),
            patch(
                "tests.postgresql_concurrency_scaffold._is_postgresql_backend",
                return_value=False,
            ),
        ):
            with self.assertRaises(PostgreSQLConcurrencyHarnessUnavailable):
                run_postgresql_concurrency_case(case=case)
        self.assertEqual(Report.objects.count(), 0)
        self.assertEqual(ReportLease.objects.count(), 0)
        self.assertEqual(SecurityOperation.objects.count(), 0)

    def test_backend_failure_is_controlled_without_error_detail(self) -> None:
        sentinel = "DATABASE_HOST_SENTINEL"
        case = build_synthetic_concurrency_case(
            scenario=ConcurrencyScenario.ACTIVE_LEASE_PER_OPERATOR
        )
        with patch(
            "tests.postgresql_concurrency_scaffold.require_postgresql_transition_backend",
            side_effect=RuntimeError(sentinel),
        ):
            with self.assertRaises(PostgreSQLConcurrencyHarnessUnavailable) as raised:
                run_postgresql_concurrency_case(case=case)
        self.assertNotIn(sentinel, repr(raised.exception))

    def test_invalid_case_never_reaches_backend_probe(self) -> None:
        with patch(
            "tests.postgresql_concurrency_scaffold.require_postgresql_transition_backend"
        ) as backend_probe:
            with self.assertRaises(PostgreSQLConcurrencyHarnessUnavailable):
                run_postgresql_concurrency_case(case=object())
        backend_probe.assert_not_called()


class PostgreSQLConcurrencyAcceptanceTests(TransactionTestCase):
    reset_sequences = False

    def test_all_synthetic_metadata_fences_have_expected_winners(self) -> None:
        for scenario, expectation in CONCURRENCY_EXPECTATIONS.items():
            with self.subTest(scenario=scenario):
                case = build_synthetic_concurrency_case(
                    scenario=scenario,
                    contender_count=MIN_CONTENDERS,
                    process_count=MIN_CONTENDERS,
                )
                if connection.vendor != "postgresql":
                    with self.assertRaises(PostgreSQLConcurrencyHarnessUnavailable):
                        run_postgresql_concurrency_case(case=case)
                    continue

                result = run_postgresql_concurrency_case(case=case)
                self.assertIsInstance(result, ConcurrencyResult)
                self.assertEqual(result.scenario, scenario)
                self.assertEqual(result.contender_count, MIN_CONTENDERS)
                self.assertEqual(result.failed_count, 0)
                self.assertEqual(
                    result.committed_count,
                    expectation.maximum_successes,
                )
                self.assertEqual(
                    result.rejected_count,
                    MIN_CONTENDERS - expectation.maximum_successes,
                )
                self.assertEqual(Report.objects.count(), 0)
                self.assertEqual(ReportLease.objects.count(), 0)
                self.assertEqual(SecurityOperation.objects.count(), 0)
