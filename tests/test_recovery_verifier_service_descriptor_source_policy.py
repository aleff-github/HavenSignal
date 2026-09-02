"""Static abuse tests for inert Recovery Verifier Service descriptors."""

from pathlib import Path
from tempfile import TemporaryDirectory

from django.test import SimpleTestCase

from architecture_checks import (
    RECOVERY_VERIFIER_SERVICE_DESCRIPTOR_PATH,
    RecoveryVerifierServiceDescriptorSourceViolationCode,
    analyze_recovery_verifier_service_descriptor_source,
    scan_recovery_verifier_service_descriptor_source,
    scan_repository_recovery_verifier_service_descriptor,
)


BASE_DIR = Path(__file__).resolve().parent.parent
TARGET = BASE_DIR / RECOVERY_VERIFIER_SERVICE_DESCRIPTOR_PATH


class RecoveryVerifierServiceDescriptorSourcePolicyTests(SimpleTestCase):
    @classmethod
    def setUpClass(cls) -> None:
        super().setUpClass()
        cls.source = TARGET.read_text(encoding="utf-8")

    def test_current_source_matches_the_exact_inert_profile(self) -> None:
        self.assertEqual(
            scan_repository_recovery_verifier_service_descriptor(BASE_DIR),
            (),
        )

    def test_import_operation_channel_and_rule_changes_are_rejected(self) -> None:
        mutations = (
            self.source.replace(
                "from dataclasses import dataclass",
                "from dataclasses import dataclass\nimport hmac",
            ),
            self.source.replace(
                "RECOVERY_VERIFIER_SERVICE_PROFILE_VERSION = 1",
                "RECOVERY_VERIFIER_SERVICE_PROFILE_VERSION = 2",
            ),
            self.source.replace(
                '    BOOLEAN_VERIFY_FOR_RECOVERY = "BOOLEAN_VERIFY_FOR_RECOVERY"',
                (
                    '    BOOLEAN_VERIFY_FOR_RECOVERY = "BOOLEAN_VERIFY_FOR_RECOVERY"\n'
                    '    GENERAL_UNWRAP = "GENERAL_UNWRAP"'
                ),
            ),
            self.source.replace(
                '    ENCRYPTED = "ENCRYPTED"',
                '    ENCRYPTED = "ENCRYPTED"\n    PLAINTEXT = "PLAINTEXT"',
            ),
            self.source.replace(
                (
                    '        "CANNOT_PRODUCE_OR_REPLACE_EXISTING_TICKET_VERIFIER"'
                ),
                (
                    '        "REPLACE_EXISTING_TICKET_VERIFIER"'
                ),
            ),
            self.source.replace(
                '    NEVER_RETURNS_EXPECTED_TAG = "NEVER_RETURNS_EXPECTED_TAG"',
                (
                    '    NEVER_RETURNS_EXPECTED_TAG = "NEVER_RETURNS_EXPECTED_TAG"\n'
                    '    RETURNS_EXPECTED_TAG_ON_DEBUG = "RETURNS_EXPECTED_TAG_ON_DEBUG"'
                ),
            ),
        )
        for source in mutations:
            with self.subTest(source=source[:80]):
                violations = analyze_recovery_verifier_service_descriptor_source(
                    source=source
                )
                self.assertEqual(len(violations), 1)
                self.assertEqual(
                    violations[0].code,
                    (
                        RecoveryVerifierServiceDescriptorSourceViolationCode.
                        SOURCE_PROFILE_MISMATCH
                    ),
                )

    def test_runtime_and_authorization_changes_are_rejected(self) -> None:
        mutations = (
            self.source.replace(
                "    def implements_service_call(self) -> bool:\n        return False",
                "    def implements_service_call(self) -> bool:\n        return True",
            ),
            self.source.replace(
                "    def computes_hmac(self) -> bool:\n        return False",
                "    def computes_hmac(self) -> bool:\n        return True",
            ),
            self.source.replace(
                "    def persists_verifier_record(self) -> bool:\n        return False",
                "    def persists_verifier_record(self) -> bool:\n        return True",
            ),
            self.source.replace(
                "    def returns_expected_tag(self) -> bool:\n        return False",
                "    def returns_expected_tag(self) -> bool:\n        return True",
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
                "def _reject() -> Never:\n    open('verifier-service.log', 'w')\n",
            ),
            self.source + "\nDYNAMIC = lambda secret: secret\n",
        )
        for source in mutations:
            with self.subTest(source=source[-80:]):
                violations = analyze_recovery_verifier_service_descriptor_source(
                    source=source
                )
                self.assertEqual(len(violations), 1)
                self.assertEqual(
                    violations[0].code,
                    (
                        RecoveryVerifierServiceDescriptorSourceViolationCode.
                        SOURCE_PROFILE_MISMATCH
                    ),
                )

    def test_target_parse_and_path_failures_are_controlled(self) -> None:
        wrong_target = analyze_recovery_verifier_service_descriptor_source(
            source=self.source,
            relative_path="security_interfaces/other.py",
        )
        self.assertEqual(len(wrong_target), 1)
        self.assertEqual(
            wrong_target[0].code,
            RecoveryVerifierServiceDescriptorSourceViolationCode.TARGET_SET_MISMATCH,
        )

        parse_failure = analyze_recovery_verifier_service_descriptor_source(
            source="def broken(\n"
        )
        self.assertEqual(len(parse_failure), 1)
        self.assertEqual(
            parse_failure[0].code,
            RecoveryVerifierServiceDescriptorSourceViolationCode.SOURCE_PARSE_ERROR,
        )

        with TemporaryDirectory() as temporary_directory:
            violations = scan_repository_recovery_verifier_service_descriptor(
                Path(temporary_directory)
            )
        self.assertEqual(len(violations), 1)
        self.assertEqual(
            violations[0].code,
            RecoveryVerifierServiceDescriptorSourceViolationCode.SOURCE_PARSE_ERROR,
        )

        violations = scan_recovery_verifier_service_descriptor_source(
            path=TARGET,
            relative_to=BASE_DIR / "tests",
        )
        self.assertEqual(len(violations), 1)
        self.assertEqual(violations[0].relative_path, "<invalid-scan-path>")

    def test_source_is_never_executed_or_echoed(self) -> None:
        sentinel = "RECOVERY_VERIFIER_SERVICE_SENTINEL"
        violations = analyze_recovery_verifier_service_descriptor_source(
            source=self.source + f"\nraise RuntimeError('{sentinel}')\n"
        )
        self.assertEqual(len(violations), 1)
        self.assertNotIn(sentinel, repr(violations))

        parse_violations = analyze_recovery_verifier_service_descriptor_source(
            source=f"def broken({sentinel}\n"
        )
        self.assertEqual(len(parse_violations), 1)
        self.assertNotIn(sentinel, repr(parse_violations))
