"""Static abuse tests for inert recovery failure descriptors."""

from pathlib import Path
from tempfile import TemporaryDirectory

from django.test import SimpleTestCase

from architecture_checks import (
    RECOVERY_FAILURE_DESCRIPTOR_PATH,
    RecoveryFailureDescriptorSourceViolationCode,
    analyze_recovery_failure_descriptor_source,
    scan_recovery_failure_descriptor_source,
    scan_repository_recovery_failure_descriptor,
)


BASE_DIR = Path(__file__).resolve().parent.parent
TARGET = BASE_DIR / RECOVERY_FAILURE_DESCRIPTOR_PATH


class RecoveryFailureDescriptorSourcePolicyTests(SimpleTestCase):
    @classmethod
    def setUpClass(cls) -> None:
        super().setUpClass()
        cls.source = TARGET.read_text(encoding="utf-8")

    def test_current_source_matches_the_exact_inert_profile(self) -> None:
        self.assertEqual(scan_repository_recovery_failure_descriptor(BASE_DIR), ())

    def test_import_boundary_and_required_result_changes_are_rejected(self) -> None:
        mutations = (
            self.source.replace(
                "from dataclasses import dataclass",
                "from dataclasses import dataclass\nimport hmac",
            ),
            self.source.replace(
                "RECOVERY_FAILURE_PROFILE_VERSION = 1",
                "RECOVERY_FAILURE_PROFILE_VERSION = 2",
            ),
            self.source.replace(
                '    HMAC_MISMATCH = "HMAC_MISMATCH"',
                '    HMAC_MISMATCH = "HMAC_MISMATCH"\n    PARTIAL_MATCH = "PARTIAL_MATCH"',
            ),
            self.source.replace(
                '    SAME_GENERIC_NON_SUCCESS = "SAME_GENERIC_NON_SUCCESS"',
                '    SAME_GENERIC_NON_SUCCESS = "SAME_GENERIC_NON_SUCCESS"\n    DISTINCT_NOT_FOUND = "DISTINCT_NOT_FOUND"',
            ),
            self.source.replace(
                "        generic_external_result=True,",
                "        generic_external_result=False,",
                1,
            ),
        )
        for source in mutations:
            with self.subTest(source=source[:80]):
                violations = analyze_recovery_failure_descriptor_source(
                    source=source
                )
                self.assertEqual(len(violations), 1)
                self.assertEqual(
                    violations[0].code,
                    RecoveryFailureDescriptorSourceViolationCode.SOURCE_PROFILE_MISMATCH,
                )

    def test_runtime_and_authorization_changes_are_rejected(self) -> None:
        mutations = (
            self.source.replace(
                "    def decodes_credential(self) -> bool:\n        return False",
                "    def decodes_credential(self) -> bool:\n        return True",
            ),
            self.source.replace(
                "    def calls_verifier_service(self) -> bool:\n        return False",
                "    def calls_verifier_service(self) -> bool:\n        return True",
            ),
            self.source.replace(
                "    def logs_credential(self) -> bool:\n        return False",
                "    def logs_credential(self) -> bool:\n        return True",
            ),
            self.source.replace(
                "    def authorizes_recovery(self) -> bool:\n        return False",
                "    def authorizes_recovery(self) -> bool:\n        return True",
            ),
            self.source.replace(
                "def _reject() -> Never:\n",
                "def _reject() -> Never:\n    open('recovery-failure.log', 'w')\n",
            ),
            self.source + "\nDYNAMIC = lambda secret: secret\n",
        )
        for source in mutations:
            with self.subTest(source=source[-80:]):
                violations = analyze_recovery_failure_descriptor_source(
                    source=source
                )
                self.assertEqual(len(violations), 1)
                self.assertEqual(
                    violations[0].code,
                    RecoveryFailureDescriptorSourceViolationCode.SOURCE_PROFILE_MISMATCH,
                )

    def test_target_parse_and_path_failures_are_controlled(self) -> None:
        wrong_target = analyze_recovery_failure_descriptor_source(
            source=self.source,
            relative_path="security_interfaces/other.py",
        )
        self.assertEqual(len(wrong_target), 1)
        self.assertEqual(
            wrong_target[0].code,
            RecoveryFailureDescriptorSourceViolationCode.TARGET_SET_MISMATCH,
        )

        parse_failure = analyze_recovery_failure_descriptor_source(
            source="def broken(\n"
        )
        self.assertEqual(len(parse_failure), 1)
        self.assertEqual(
            parse_failure[0].code,
            RecoveryFailureDescriptorSourceViolationCode.SOURCE_PARSE_ERROR,
        )

        with TemporaryDirectory() as temporary_directory:
            violations = scan_repository_recovery_failure_descriptor(
                Path(temporary_directory)
            )
        self.assertEqual(len(violations), 1)
        self.assertEqual(
            violations[0].code,
            RecoveryFailureDescriptorSourceViolationCode.SOURCE_PARSE_ERROR,
        )

        violations = scan_recovery_failure_descriptor_source(
            path=TARGET,
            relative_to=BASE_DIR / "tests",
        )
        self.assertEqual(len(violations), 1)
        self.assertEqual(violations[0].relative_path, "<invalid-scan-path>")

    def test_source_is_never_executed_or_echoed(self) -> None:
        sentinel = "RECOVERY_FAILURE_SENTINEL"
        violations = analyze_recovery_failure_descriptor_source(
            source=self.source + f"\nraise RuntimeError('{sentinel}')\n"
        )
        self.assertEqual(len(violations), 1)
        self.assertNotIn(sentinel, repr(violations))

        parse_violations = analyze_recovery_failure_descriptor_source(
            source=f"def broken({sentinel}\n"
        )
        self.assertEqual(len(parse_violations), 1)
        self.assertNotIn(sentinel, repr(parse_violations))
