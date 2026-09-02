"""Static abuse tests for inert recovery eligibility descriptors."""

from pathlib import Path
from tempfile import TemporaryDirectory

from django.test import SimpleTestCase

from architecture_checks import (
    RECOVERY_ELIGIBILITY_DESCRIPTOR_PATH,
    RecoveryEligibilityDescriptorSourceViolationCode,
    analyze_recovery_eligibility_descriptor_source,
    scan_recovery_eligibility_descriptor_source,
    scan_repository_recovery_eligibility_descriptor,
)


BASE_DIR = Path(__file__).resolve().parent.parent
TARGET = BASE_DIR / RECOVERY_ELIGIBILITY_DESCRIPTOR_PATH


class RecoveryEligibilityDescriptorSourcePolicyTests(SimpleTestCase):
    @classmethod
    def setUpClass(cls) -> None:
        super().setUpClass()
        cls.source = TARGET.read_text(encoding="utf-8")

    def test_current_source_matches_the_exact_inert_profile(self) -> None:
        self.assertEqual(
            scan_repository_recovery_eligibility_descriptor(BASE_DIR),
            (),
        )

    def test_state_requirement_and_timing_changes_are_rejected(self) -> None:
        mutations = (
            self.source.replace(
                "from dataclasses import dataclass",
                "from dataclasses import dataclass\nfrom datetime import datetime",
            ),
            self.source.replace(
                "RECOVERY_ELIGIBILITY_PROFILE_VERSION = 1",
                "RECOVERY_ELIGIBILITY_PROFILE_VERSION = 2",
            ),
            self.source.replace(
                "RECOVERY_FIRST_READ_EXPIRY_SECONDS = 72 * 60 * 60",
                "RECOVERY_FIRST_READ_EXPIRY_SECONDS = 96 * 60 * 60",
            ),
            self.source.replace(
                "RECOVERY_UNREAD_RESPONSE_EXPIRY_SECONDS = 90 * 24 * 60 * 60",
                "RECOVERY_UNREAD_RESPONSE_EXPIRY_SECONDS = 365 * 24 * 60 * 60",
            ),
            self.source.replace(
                '    READ_WINDOW_OPEN = "READ_WINDOW_OPEN"',
                (
                    '    READ_WINDOW_OPEN = "READ_WINDOW_OPEN"\n'
                    '    DEBUG_ALWAYS_AVAILABLE = "DEBUG_ALWAYS_AVAILABLE"'
                ),
            ),
            self.source.replace(
                (
                    '    VERIFIER_SUCCESS_NOT_SUFFICIENT = '
                    '"VERIFIER_SUCCESS_NOT_SUFFICIENT"'
                ),
                (
                    '    VERIFIER_SUCCESS_NOT_SUFFICIENT = '
                    '"VERIFIER_SUCCESS_AUTHORIZES_RECOVERY"'
                ),
            ),
        )
        for source in mutations:
            with self.subTest(source=source[:80]):
                violations = analyze_recovery_eligibility_descriptor_source(
                    source=source
                )
                self.assertEqual(len(violations), 1)
                self.assertEqual(
                    violations[0].code,
                    (
                        RecoveryEligibilityDescriptorSourceViolationCode.
                        SOURCE_PROFILE_MISMATCH
                    ),
                )

    def test_runtime_authorization_and_disclosure_changes_are_rejected(self) -> None:
        mutations = (
            self.source.replace(
                "    def performs_lookup(self) -> bool:\n        return False",
                "    def performs_lookup(self) -> bool:\n        return True",
            ),
            self.source.replace(
                "    def validates_credentials(self) -> bool:\n        return False",
                "    def validates_credentials(self) -> bool:\n        return True",
            ),
            self.source.replace(
                "    def calls_key_service(self) -> bool:\n        return False",
                "    def calls_key_service(self) -> bool:\n        return True",
            ),
            self.source.replace(
                "    def decrypts_response(self) -> bool:\n        return False",
                "    def decrypts_response(self) -> bool:\n        return True",
            ),
            self.source.replace(
                "    def mutates_first_read(self) -> bool:\n        return False",
                "    def mutates_first_read(self) -> bool:\n        return True",
            ),
            self.source.replace(
                "    def returns_distinct_failure(self) -> bool:\n        return False",
                "    def returns_distinct_failure(self) -> bool:\n        return True",
            ),
            self.source.replace(
                "def _reject() -> Never:\n",
                "def _reject() -> Never:\n    open('eligibility.log', 'w')\n",
            ),
            self.source + "\nDYNAMIC = lambda first_read_at: first_read_at\n",
        )
        for source in mutations:
            with self.subTest(source=source[-80:]):
                violations = analyze_recovery_eligibility_descriptor_source(
                    source=source
                )
                self.assertEqual(len(violations), 1)
                self.assertEqual(
                    violations[0].code,
                    (
                        RecoveryEligibilityDescriptorSourceViolationCode.
                        SOURCE_PROFILE_MISMATCH
                    ),
                )

    def test_target_parse_and_path_failures_are_controlled(self) -> None:
        wrong_target = analyze_recovery_eligibility_descriptor_source(
            source=self.source,
            relative_path="security_interfaces/other.py",
        )
        self.assertEqual(len(wrong_target), 1)
        self.assertEqual(
            wrong_target[0].code,
            RecoveryEligibilityDescriptorSourceViolationCode.TARGET_SET_MISMATCH,
        )

        parse_failure = analyze_recovery_eligibility_descriptor_source(
            source="def broken(\n"
        )
        self.assertEqual(len(parse_failure), 1)
        self.assertEqual(
            parse_failure[0].code,
            RecoveryEligibilityDescriptorSourceViolationCode.SOURCE_PARSE_ERROR,
        )

        with TemporaryDirectory() as temporary_directory:
            violations = scan_repository_recovery_eligibility_descriptor(
                Path(temporary_directory)
            )
        self.assertEqual(len(violations), 1)
        self.assertEqual(
            violations[0].code,
            RecoveryEligibilityDescriptorSourceViolationCode.SOURCE_PARSE_ERROR,
        )

        violations = scan_recovery_eligibility_descriptor_source(
            path=TARGET,
            relative_to=BASE_DIR / "tests",
        )
        self.assertEqual(len(violations), 1)
        self.assertEqual(violations[0].relative_path, "<invalid-scan-path>")

    def test_source_is_never_executed_or_echoed(self) -> None:
        sentinel = "RECOVERY_ELIGIBILITY_SENTINEL"
        violations = analyze_recovery_eligibility_descriptor_source(
            source=self.source + f"\nraise RuntimeError('{sentinel}')\n"
        )
        self.assertEqual(len(violations), 1)
        self.assertNotIn(sentinel, repr(violations))

        parse_violations = analyze_recovery_eligibility_descriptor_source(
            source=f"def broken({sentinel}\n"
        )
        self.assertEqual(len(parse_violations), 1)
        self.assertNotIn(sentinel, repr(parse_violations))
