"""Static abuse tests for inert submission failure descriptors."""

from pathlib import Path
from tempfile import TemporaryDirectory

from django.test import SimpleTestCase

from architecture_checks import (
    SUBMISSION_FAILURE_DESCRIPTOR_PATH,
    SubmissionFailureDescriptorSourceViolationCode,
    analyze_submission_failure_descriptor_source,
    scan_repository_submission_failure_descriptor,
    scan_submission_failure_descriptor_source,
)


BASE_DIR = Path(__file__).resolve().parent.parent
TARGET = BASE_DIR / SUBMISSION_FAILURE_DESCRIPTOR_PATH


class SubmissionFailureDescriptorSourcePolicyTests(SimpleTestCase):
    @classmethod
    def setUpClass(cls) -> None:
        super().setUpClass()
        cls.source = TARGET.read_text(encoding="utf-8")

    def test_current_source_matches_the_exact_inert_profile(self) -> None:
        self.assertEqual(scan_repository_submission_failure_descriptor(BASE_DIR), ())

    def test_import_boundary_and_required_result_changes_are_rejected(self) -> None:
        mutations = (
            self.source.replace(
                "from dataclasses import dataclass",
                "from dataclasses import dataclass\nimport requests",
            ),
            self.source.replace(
                "SUBMISSION_FAILURE_PROFILE_VERSION = 1",
                "SUBMISSION_FAILURE_PROFILE_VERSION = 2",
            ),
            self.source.replace(
                '    KEY_SERVICE_UNAVAILABLE = "KEY_SERVICE_UNAVAILABLE"',
                '    KEY_SERVICE_UNAVAILABLE = "KEY_SERVICE_UNAVAILABLE"\n    IGNORE_KEY_FAILURE = "IGNORE_KEY_FAILURE"',
            ),
            self.source.replace(
                '    NO_PLAINTEXT_PERSISTENCE_ATTEMPT_ABORTS = (',
                '    ALLOW_PLAINTEXT_CACHE = "ALLOW_PLAINTEXT_CACHE"\n    NO_PLAINTEXT_PERSISTENCE_ATTEMPT_ABORTS = (',
            ),
            self.source.replace(
                "        content_free=True,",
                "        content_free=False,",
                1,
            ),
        )
        for source in mutations:
            with self.subTest(source=source[:80]):
                violations = analyze_submission_failure_descriptor_source(
                    source=source
                )
                self.assertEqual(len(violations), 1)
                self.assertEqual(
                    violations[0].code,
                    (
                        SubmissionFailureDescriptorSourceViolationCode.
                        SOURCE_PROFILE_MISMATCH
                    ),
                )

    def test_runtime_and_authorization_changes_are_rejected(self) -> None:
        mutations = (
            self.source.replace(
                "    def handles_request(self) -> bool:\n        return False",
                "    def handles_request(self) -> bool:\n        return True",
            ),
            self.source.replace(
                "    def appends_audit_event(self) -> bool:\n        return False",
                "    def appends_audit_event(self) -> bool:\n        return True",
            ),
            self.source.replace(
                "    def returns_credentials(self) -> bool:\n        return False",
                "    def returns_credentials(self) -> bool:\n        return True",
            ),
            self.source.replace(
                "    def authorizes_submission(self) -> bool:\n        return False",
                "    def authorizes_submission(self) -> bool:\n        return True",
            ),
            self.source.replace(
                "def _reject() -> Never:\n",
                "def _reject() -> Never:\n    open('failure.log', 'w')\n",
            ),
            self.source + "\nDYNAMIC = lambda request: request\n",
        )
        for source in mutations:
            with self.subTest(source=source[-80:]):
                violations = analyze_submission_failure_descriptor_source(
                    source=source
                )
                self.assertEqual(len(violations), 1)
                self.assertEqual(
                    violations[0].code,
                    (
                        SubmissionFailureDescriptorSourceViolationCode.
                        SOURCE_PROFILE_MISMATCH
                    ),
                )

    def test_target_parse_and_path_failures_are_controlled(self) -> None:
        wrong_target = analyze_submission_failure_descriptor_source(
            source=self.source,
            relative_path="security_interfaces/other.py",
        )
        self.assertEqual(len(wrong_target), 1)
        self.assertEqual(
            wrong_target[0].code,
            SubmissionFailureDescriptorSourceViolationCode.TARGET_SET_MISMATCH,
        )

        parse_failure = analyze_submission_failure_descriptor_source(
            source="def broken(\n"
        )
        self.assertEqual(len(parse_failure), 1)
        self.assertEqual(
            parse_failure[0].code,
            SubmissionFailureDescriptorSourceViolationCode.SOURCE_PARSE_ERROR,
        )

        with TemporaryDirectory() as temporary_directory:
            violations = scan_repository_submission_failure_descriptor(
                Path(temporary_directory)
            )
        self.assertEqual(len(violations), 1)
        self.assertEqual(
            violations[0].code,
            SubmissionFailureDescriptorSourceViolationCode.SOURCE_PARSE_ERROR,
        )

        violations = scan_submission_failure_descriptor_source(
            path=TARGET,
            relative_to=BASE_DIR / "tests",
        )
        self.assertEqual(len(violations), 1)
        self.assertEqual(violations[0].relative_path, "<invalid-scan-path>")

    def test_source_is_never_executed_or_echoed(self) -> None:
        sentinel = "SUBMISSION_FAILURE_SENTINEL"
        violations = analyze_submission_failure_descriptor_source(
            source=self.source + f"\nraise RuntimeError('{sentinel}')\n"
        )
        self.assertEqual(len(violations), 1)
        self.assertNotIn(sentinel, repr(violations))

        parse_violations = analyze_submission_failure_descriptor_source(
            source=f"def broken({sentinel}\n"
        )
        self.assertEqual(len(parse_violations), 1)
        self.assertNotIn(sentinel, repr(parse_violations))
