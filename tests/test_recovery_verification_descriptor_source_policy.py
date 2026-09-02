"""Static abuse tests for inert recovery verification descriptors."""

from pathlib import Path
from tempfile import TemporaryDirectory

from django.test import SimpleTestCase

from architecture_checks import (
    RECOVERY_VERIFICATION_DESCRIPTOR_PATH,
    RecoveryVerificationDescriptorSourceViolationCode,
    analyze_recovery_verification_descriptor_source,
    scan_recovery_verification_descriptor_source,
    scan_repository_recovery_verification_descriptor,
)


BASE_DIR = Path(__file__).resolve().parent.parent
TARGET = BASE_DIR / RECOVERY_VERIFICATION_DESCRIPTOR_PATH


class RecoveryVerificationDescriptorSourcePolicyTests(SimpleTestCase):
    @classmethod
    def setUpClass(cls) -> None:
        super().setUpClass()
        cls.source = TARGET.read_text(encoding="utf-8")

    def test_current_source_matches_the_exact_inert_profile(self) -> None:
        self.assertEqual(
            scan_repository_recovery_verification_descriptor(BASE_DIR),
            (),
        )

    def test_import_algorithm_input_uniformity_and_denial_changes_are_rejected(
        self,
    ) -> None:
        mutations = (
            self.source.replace(
                "from dataclasses import dataclass",
                "from dataclasses import dataclass\nimport hmac",
            ),
            self.source.replace(
                "from dataclasses import dataclass",
                "from dataclasses import dataclass\nimport hashlib",
            ),
            self.source.replace(
                "RECOVERY_VERIFICATION_PROFILE_VERSION = 1",
                "RECOVERY_VERIFICATION_PROFILE_VERSION = 2",
            ),
            self.source.replace(
                "RECOVERY_VERIFICATION_TAG_BYTES = 32",
                "RECOVERY_VERIFICATION_TAG_BYTES = 16",
            ),
            self.source.replace(
                '    HMAC_SHA256_FULL_LENGTH = "HMAC_SHA256_FULL_LENGTH"',
                (
                    '    HMAC_SHA256_FULL_LENGTH = "HMAC_SHA256_FULL_LENGTH"\n'
                    '    HMAC_SHA1_TRUNCATED = "HMAC_SHA1_TRUNCATED"'
                ),
            ),
            self.source.replace(
                '    CONSTANT_TIME_FULL_TAG = "CONSTANT_TIME_FULL_TAG"',
                (
                    '    CONSTANT_TIME_FULL_TAG = "CONSTANT_TIME_FULL_TAG"\n'
                    '    PREFIX_MATCH = "PREFIX_MATCH"'
                ),
            ),
            self.source.replace(
                '    STORED_FULL_LENGTH_TAG = "STORED_FULL_LENGTH_TAG"',
                (
                    '    STORED_FULL_LENGTH_TAG = "STORED_FULL_LENGTH_TAG"\n'
                    '    CLIENT_SUPPLIED_KEY_ID = "CLIENT_SUPPLIED_KEY_ID"'
                ),
            ),
            self.source.replace(
                '    GENERIC_EXTERNAL_NON_SUCCESS = "GENERIC_EXTERNAL_NON_SUCCESS"',
                (
                    '    GENERIC_EXTERNAL_NON_SUCCESS = "GENERIC_EXTERNAL_NON_SUCCESS"\n'
                    '    DISTINCT_NOT_FOUND = "DISTINCT_NOT_FOUND"'
                ),
            ),
        )
        for source in mutations:
            with self.subTest(source=source[:80]):
                violations = analyze_recovery_verification_descriptor_source(
                    source=source
                )
                self.assertEqual(len(violations), 1)
                self.assertEqual(
                    violations[0].code,
                    (
                        RecoveryVerificationDescriptorSourceViolationCode.
                        SOURCE_PROFILE_MISMATCH
                    ),
                )

    def test_runtime_and_authorization_changes_are_rejected(self) -> None:
        mutations = (
            self.source.replace(
                "    def computes_hmac(self) -> bool:\n        return False",
                "    def computes_hmac(self) -> bool:\n        return True",
            ),
            self.source.replace(
                "    def compares_tags(self) -> bool:\n        return False",
                "    def compares_tags(self) -> bool:\n        return True",
            ),
            self.source.replace(
                "    def executes_dummy_verification(self) -> bool:\n        return False",
                "    def executes_dummy_verification(self) -> bool:\n        return True",
            ),
            self.source.replace(
                "    def returns_partial_match_detail(self) -> bool:\n        return False",
                "    def returns_partial_match_detail(self) -> bool:\n        return True",
            ),
            self.source.replace(
                "    def authorizes_response_dek_use(self) -> bool:\n        return False",
                "    def authorizes_response_dek_use(self) -> bool:\n        return True",
            ),
            self.source.replace(
                "    def authorizes_recovery(self) -> bool:\n        return False",
                "    def authorizes_recovery(self) -> bool:\n        return True",
            ),
            self.source.replace(
                "def _reject() -> Never:\n",
                "def _reject() -> Never:\n    open('recovery-verification.log', 'w')\n",
            ),
            self.source + "\nDYNAMIC = lambda secret: secret\n",
        )
        for source in mutations:
            with self.subTest(source=source[-80:]):
                violations = analyze_recovery_verification_descriptor_source(
                    source=source
                )
                self.assertEqual(len(violations), 1)
                self.assertEqual(
                    violations[0].code,
                    (
                        RecoveryVerificationDescriptorSourceViolationCode.
                        SOURCE_PROFILE_MISMATCH
                    ),
                )

    def test_target_parse_and_path_failures_are_controlled(self) -> None:
        wrong_target = analyze_recovery_verification_descriptor_source(
            source=self.source,
            relative_path="security_interfaces/other.py",
        )
        self.assertEqual(len(wrong_target), 1)
        self.assertEqual(
            wrong_target[0].code,
            RecoveryVerificationDescriptorSourceViolationCode.TARGET_SET_MISMATCH,
        )

        parse_failure = analyze_recovery_verification_descriptor_source(
            source="def broken(\n"
        )
        self.assertEqual(len(parse_failure), 1)
        self.assertEqual(
            parse_failure[0].code,
            RecoveryVerificationDescriptorSourceViolationCode.SOURCE_PARSE_ERROR,
        )

        with TemporaryDirectory() as temporary_directory:
            violations = scan_repository_recovery_verification_descriptor(
                Path(temporary_directory)
            )
        self.assertEqual(len(violations), 1)
        self.assertEqual(
            violations[0].code,
            RecoveryVerificationDescriptorSourceViolationCode.SOURCE_PARSE_ERROR,
        )

        violations = scan_recovery_verification_descriptor_source(
            path=TARGET,
            relative_to=BASE_DIR / "tests",
        )
        self.assertEqual(len(violations), 1)
        self.assertEqual(violations[0].relative_path, "<invalid-scan-path>")

    def test_source_is_never_executed_or_echoed(self) -> None:
        sentinel = "RECOVERY_VERIFICATION_SENTINEL"
        violations = analyze_recovery_verification_descriptor_source(
            source=self.source + f"\nraise RuntimeError('{sentinel}')\n"
        )
        self.assertEqual(len(violations), 1)
        self.assertNotIn(sentinel, repr(violations))

        parse_violations = analyze_recovery_verification_descriptor_source(
            source=f"def broken({sentinel}\n"
        )
        self.assertEqual(len(parse_violations), 1)
        self.assertNotIn(sentinel, repr(parse_violations))
