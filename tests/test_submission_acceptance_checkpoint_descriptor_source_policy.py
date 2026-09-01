"""Static abuse tests for inert submission-acceptance checkpoint descriptors."""

from pathlib import Path
from tempfile import TemporaryDirectory

from django.test import SimpleTestCase

from architecture_checks import (
    SUBMISSION_ACCEPTANCE_CHECKPOINT_DESCRIPTOR_PATH,
    SubmissionAcceptanceCheckpointDescriptorSourceViolationCode,
    analyze_submission_acceptance_checkpoint_descriptor_source,
    scan_repository_submission_acceptance_checkpoint_descriptor,
    scan_submission_acceptance_checkpoint_descriptor_source,
)


BASE_DIR = Path(__file__).resolve().parent.parent
TARGET = BASE_DIR / SUBMISSION_ACCEPTANCE_CHECKPOINT_DESCRIPTOR_PATH


class SubmissionAcceptanceCheckpointDescriptorSourcePolicyTests(SimpleTestCase):
    @classmethod
    def setUpClass(cls) -> None:
        super().setUpClass()
        cls.source = TARGET.read_text(encoding="utf-8")

    def test_current_source_matches_the_exact_inert_profile(self) -> None:
        self.assertEqual(
            scan_repository_submission_acceptance_checkpoint_descriptor(BASE_DIR),
            (),
        )

    def test_import_phase_checkpoint_and_requirement_changes_are_rejected(
        self,
    ) -> None:
        mutations = (
            self.source.replace(
                "from dataclasses import dataclass",
                "from dataclasses import dataclass\nimport requests",
            ),
            self.source.replace(
                "SUBMISSION_ACCEPTANCE_CHECKPOINT_PROFILE_VERSION = 1",
                "SUBMISSION_ACCEPTANCE_CHECKPOINT_PROFILE_VERSION = 2",
            ),
            self.source.replace(
                '    ADMIT_REQUEST = "ADMIT_REQUEST"',
                '    ADMIT_REQUEST = "ADMIT_REQUEST"\n    SKIP_TO_SEALED = "SKIP_TO_SEALED"',
            ),
            self.source.replace(
                '    FORM_SURFACE_READY = "FORM_SURFACE_READY"',
                '    FORM_SURFACE_READY = "FORM_SURFACE_READY"\n    REPORT_VISIBLE = "REPORT_VISIBLE"',
            ),
            self.source.replace(
                '    SEALED_COMMIT_READY = "SEALED_COMMIT_READY"',
                '    SEALED_COMMIT_READY = "SEALED_COMMIT_READY"\n    OPERATOR_VISIBLE = "OPERATOR_VISIBLE"',
            ),
        )
        for source in mutations:
            with self.subTest(source=source[:80]):
                violations = (
                    analyze_submission_acceptance_checkpoint_descriptor_source(
                        source=source
                    )
                )
                self.assertEqual(len(violations), 1)
                self.assertEqual(
                    violations[0].code,
                    (
                        SubmissionAcceptanceCheckpointDescriptorSourceViolationCode.
                        SOURCE_PROFILE_MISMATCH
                    ),
                )

    def test_runtime_and_authorization_changes_are_rejected(self) -> None:
        mutations = (
            self.source.replace(
                "    def parses_request(self) -> bool:\n        return False",
                "    def parses_request(self) -> bool:\n        return True",
            ),
            self.source.replace(
                "    def appends_audit_event(self) -> bool:\n        return False",
                "    def appends_audit_event(self) -> bool:\n        return True",
            ),
            self.source.replace(
                "    def persists_records(self) -> bool:\n        return False",
                "    def persists_records(self) -> bool:\n        return True",
            ),
            self.source.replace(
                "    def authorizes_submission(self) -> bool:\n        return False",
                "    def authorizes_submission(self) -> bool:\n        return True",
            ),
            self.source.replace(
                "def _reject() -> Never:\n",
                "def _reject() -> Never:\n    open('checkpoint.log', 'w')\n",
            ),
            self.source + "\nDYNAMIC = lambda request: request\n",
        )
        for source in mutations:
            with self.subTest(source=source[-80:]):
                violations = (
                    analyze_submission_acceptance_checkpoint_descriptor_source(
                        source=source
                    )
                )
                self.assertEqual(len(violations), 1)
                self.assertEqual(
                    violations[0].code,
                    (
                        SubmissionAcceptanceCheckpointDescriptorSourceViolationCode.
                        SOURCE_PROFILE_MISMATCH
                    ),
                )

    def test_target_parse_and_path_failures_are_controlled(self) -> None:
        wrong_target = analyze_submission_acceptance_checkpoint_descriptor_source(
            source=self.source,
            relative_path="security_interfaces/other.py",
        )
        self.assertEqual(len(wrong_target), 1)
        self.assertEqual(
            wrong_target[0].code,
            (
                SubmissionAcceptanceCheckpointDescriptorSourceViolationCode.
                TARGET_SET_MISMATCH
            ),
        )

        parse_failure = analyze_submission_acceptance_checkpoint_descriptor_source(
            source="def broken(\n"
        )
        self.assertEqual(len(parse_failure), 1)
        self.assertEqual(
            parse_failure[0].code,
            (
                SubmissionAcceptanceCheckpointDescriptorSourceViolationCode.
                SOURCE_PARSE_ERROR
            ),
        )

        with TemporaryDirectory() as temporary_directory:
            violations = (
                scan_repository_submission_acceptance_checkpoint_descriptor(
                    Path(temporary_directory)
                )
            )
        self.assertEqual(len(violations), 1)
        self.assertEqual(
            violations[0].code,
            (
                SubmissionAcceptanceCheckpointDescriptorSourceViolationCode.
                SOURCE_PARSE_ERROR
            ),
        )

        violations = scan_submission_acceptance_checkpoint_descriptor_source(
            path=TARGET,
            relative_to=BASE_DIR / "tests",
        )
        self.assertEqual(len(violations), 1)
        self.assertEqual(violations[0].relative_path, "<invalid-scan-path>")

    def test_source_is_never_executed_or_echoed(self) -> None:
        sentinel = "SUBMISSION_ACCEPTANCE_CHECKPOINT_SENTINEL"
        violations = analyze_submission_acceptance_checkpoint_descriptor_source(
            source=self.source + f"\nraise RuntimeError('{sentinel}')\n"
        )
        self.assertEqual(len(violations), 1)
        self.assertNotIn(sentinel, repr(violations))

        parse_violations = analyze_submission_acceptance_checkpoint_descriptor_source(
            source=f"def broken({sentinel}\n"
        )
        self.assertEqual(len(parse_violations), 1)
        self.assertNotIn(sentinel, repr(parse_violations))
