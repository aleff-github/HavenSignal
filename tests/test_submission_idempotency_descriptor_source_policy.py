"""Static abuse tests for inert submission idempotency descriptors."""

from pathlib import Path
from tempfile import TemporaryDirectory

from django.test import SimpleTestCase

from architecture_checks import (
    SUBMISSION_IDEMPOTENCY_DESCRIPTOR_PATH,
    SubmissionIdempotencyDescriptorSourceViolationCode,
    analyze_submission_idempotency_descriptor_source,
    scan_repository_submission_idempotency_descriptor,
    scan_submission_idempotency_descriptor_source,
)


BASE_DIR = Path(__file__).resolve().parent.parent
TARGET = BASE_DIR / SUBMISSION_IDEMPOTENCY_DESCRIPTOR_PATH


class SubmissionIdempotencyDescriptorSourcePolicyTests(SimpleTestCase):
    @classmethod
    def setUpClass(cls) -> None:
        super().setUpClass()
        cls.source = TARGET.read_text(encoding="utf-8")

    def test_current_source_matches_the_exact_inert_profile(self) -> None:
        self.assertEqual(
            scan_repository_submission_idempotency_descriptor(BASE_DIR),
            (),
        )

    def test_import_scenario_invariant_and_capability_changes_are_rejected(
        self,
    ) -> None:
        mutations = (
            self.source.replace(
                "from dataclasses import dataclass",
                "from dataclasses import dataclass\nimport requests",
            ),
            self.source.replace(
                "SUBMISSION_IDEMPOTENCY_PROFILE_VERSION = 1",
                "SUBMISSION_IDEMPOTENCY_PROFILE_VERSION = 2",
            ),
            self.source.replace(
                '    MULTIPLE_APPLICATION_PROCESSES = "MULTIPLE_APPLICATION_PROCESSES"',
                '    MULTIPLE_APPLICATION_PROCESSES = "MULTIPLE_APPLICATION_PROCESSES"\n    SINGLE_PROCESS_ONLY = "SINGLE_PROCESS_ONLY"',
            ),
            self.source.replace(
                '    STALE_VERSION_CANNOT_COMMIT_SEALED = "STALE_VERSION_CANNOT_COMMIT_SEALED"',
                '    STALE_VERSION_CANNOT_COMMIT_SEALED = "STALE_VERSION_CANNOT_COMMIT_SEALED"\n    STALE_VERSION_CAN_WIN = "STALE_VERSION_CAN_WIN"',
            ),
            self.source.replace(
                '    LOGS_REPORTER_INPUT = "LOGS_REPORTER_INPUT"',
                '    LOGS_REPORTER_INPUT = "LOGS_REPORTER_INPUT"\n    STORES_REPORTER_INPUT = "STORES_REPORTER_INPUT"',
            ),
        )
        for source in mutations:
            with self.subTest(source=source[:80]):
                violations = analyze_submission_idempotency_descriptor_source(
                    source=source
                )
                self.assertEqual(len(violations), 1)
                self.assertEqual(
                    violations[0].code,
                    (
                        SubmissionIdempotencyDescriptorSourceViolationCode.
                        SOURCE_PROFILE_MISMATCH
                    ),
                )

    def test_runtime_and_authorization_changes_are_rejected(self) -> None:
        mutations = (
            self.source.replace(
                "    def runs_parallel_requests(self) -> bool:\n        return False",
                "    def runs_parallel_requests(self) -> bool:\n        return True",
            ),
            self.source.replace(
                "    def locks_database_row(self) -> bool:\n        return False",
                "    def locks_database_row(self) -> bool:\n        return True",
            ),
            self.source.replace(
                "    def logs_reporter_input(self) -> bool:\n        return False",
                "    def logs_reporter_input(self) -> bool:\n        return True",
            ),
            self.source.replace(
                "    def authorizes_submission(self) -> bool:\n        return False",
                "    def authorizes_submission(self) -> bool:\n        return True",
            ),
            self.source.replace(
                "def _reject() -> Never:\n",
                "def _reject() -> Never:\n    open('idempotency.log', 'w')\n",
            ),
            self.source + "\nDYNAMIC = lambda request: request\n",
        )
        for source in mutations:
            with self.subTest(source=source[-80:]):
                violations = analyze_submission_idempotency_descriptor_source(
                    source=source
                )
                self.assertEqual(len(violations), 1)
                self.assertEqual(
                    violations[0].code,
                    (
                        SubmissionIdempotencyDescriptorSourceViolationCode.
                        SOURCE_PROFILE_MISMATCH
                    ),
                )

    def test_target_parse_and_path_failures_are_controlled(self) -> None:
        wrong_target = analyze_submission_idempotency_descriptor_source(
            source=self.source,
            relative_path="security_interfaces/other.py",
        )
        self.assertEqual(len(wrong_target), 1)
        self.assertEqual(
            wrong_target[0].code,
            SubmissionIdempotencyDescriptorSourceViolationCode.TARGET_SET_MISMATCH,
        )

        parse_failure = analyze_submission_idempotency_descriptor_source(
            source="def broken(\n"
        )
        self.assertEqual(len(parse_failure), 1)
        self.assertEqual(
            parse_failure[0].code,
            SubmissionIdempotencyDescriptorSourceViolationCode.SOURCE_PARSE_ERROR,
        )

        with TemporaryDirectory() as temporary_directory:
            violations = scan_repository_submission_idempotency_descriptor(
                Path(temporary_directory)
            )
        self.assertEqual(len(violations), 1)
        self.assertEqual(
            violations[0].code,
            SubmissionIdempotencyDescriptorSourceViolationCode.SOURCE_PARSE_ERROR,
        )

        violations = scan_submission_idempotency_descriptor_source(
            path=TARGET,
            relative_to=BASE_DIR / "tests",
        )
        self.assertEqual(len(violations), 1)
        self.assertEqual(violations[0].relative_path, "<invalid-scan-path>")

    def test_source_is_never_executed_or_echoed(self) -> None:
        sentinel = "SUBMISSION_IDEMPOTENCY_SENTINEL"
        violations = analyze_submission_idempotency_descriptor_source(
            source=self.source + f"\nraise RuntimeError('{sentinel}')\n"
        )
        self.assertEqual(len(violations), 1)
        self.assertNotIn(sentinel, repr(violations))

        parse_violations = analyze_submission_idempotency_descriptor_source(
            source=f"def broken({sentinel}\n"
        )
        self.assertEqual(len(parse_violations), 1)
        self.assertNotIn(sentinel, repr(parse_violations))
