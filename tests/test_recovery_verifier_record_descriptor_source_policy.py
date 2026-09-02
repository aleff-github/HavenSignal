"""Static abuse tests for inert recovery verifier record descriptors."""

from pathlib import Path
from tempfile import TemporaryDirectory

from django.test import SimpleTestCase

from architecture_checks import (
    RECOVERY_VERIFIER_RECORD_DESCRIPTOR_PATH,
    RecoveryVerifierRecordDescriptorSourceViolationCode,
    analyze_recovery_verifier_record_descriptor_source,
    scan_recovery_verifier_record_descriptor_source,
    scan_repository_recovery_verifier_record_descriptor,
)


BASE_DIR = Path(__file__).resolve().parent.parent
TARGET = BASE_DIR / RECOVERY_VERIFIER_RECORD_DESCRIPTOR_PATH


class RecoveryVerifierRecordDescriptorSourcePolicyTests(SimpleTestCase):
    @classmethod
    def setUpClass(cls) -> None:
        super().setUpClass()
        cls.source = TARGET.read_text(encoding="utf-8")

    def test_current_source_matches_the_exact_inert_profile(self) -> None:
        self.assertEqual(
            scan_repository_recovery_verifier_record_descriptor(BASE_DIR),
            (),
        )

    def test_import_field_requirement_and_forbidden_material_changes_rejected(
        self,
    ) -> None:
        mutations = (
            self.source.replace(
                "from dataclasses import dataclass",
                "from dataclasses import dataclass\nimport hmac",
            ),
            self.source.replace(
                "RECOVERY_VERIFIER_RECORD_PROFILE_VERSION = 1",
                "RECOVERY_VERIFIER_RECORD_PROFILE_VERSION = 2",
            ),
            self.source.replace(
                "RECOVERY_VERIFIER_RECORD_TAG_BYTES = 32",
                "RECOVERY_VERIFIER_RECORD_TAG_BYTES = 16",
            ),
            self.source.replace(
                '    VERIFIER_TAG = "VERIFIER_TAG"',
                (
                    '    VERIFIER_TAG = "VERIFIER_TAG"\n'
                    '    RECOVERY_SECRET = "RECOVERY_SECRET"'
                ),
            ),
            self.source.replace(
                '    SERVER_CONTROLLED_KEY_ID = "SERVER_CONTROLLED_KEY_ID"',
                (
                    '    SERVER_CONTROLLED_KEY_ID = "SERVER_CONTROLLED_KEY_ID"\n'
                    '    REPORTER_CONTROLLED_KEY_ID = "REPORTER_CONTROLLED_KEY_ID"'
                ),
            ),
            self.source.replace(
                '    RESPONSE_DEK = "RESPONSE_DEK"',
                (
                    '    RESPONSE_DEK = "RESPONSE_DEK"\n'
                    '    PUBLIC_TICKET_ID = "PUBLIC_TICKET_ID"'
                ),
            ),
        )
        for source in mutations:
            with self.subTest(source=source[:80]):
                violations = analyze_recovery_verifier_record_descriptor_source(
                    source=source
                )
                self.assertEqual(len(violations), 1)
                self.assertEqual(
                    violations[0].code,
                    (
                        RecoveryVerifierRecordDescriptorSourceViolationCode.
                        SOURCE_PROFILE_MISMATCH
                    ),
                )

    def test_runtime_and_authorization_changes_are_rejected(self) -> None:
        mutations = (
            self.source.replace(
                "    def stores_secret(self) -> bool:\n        return False",
                "    def stores_secret(self) -> bool:\n        return True",
            ),
            self.source.replace(
                "    def computes_verifier(self) -> bool:\n        return False",
                "    def computes_verifier(self) -> bool:\n        return True",
            ),
            self.source.replace(
                "    def tests_candidate_secret(self) -> bool:\n        return False",
                "    def tests_candidate_secret(self) -> bool:\n        return True",
            ),
            self.source.replace(
                "    def writes_database(self) -> bool:\n        return False",
                "    def writes_database(self) -> bool:\n        return True",
            ),
            self.source.replace(
                "    def authorizes_recovery(self) -> bool:\n        return False",
                "    def authorizes_recovery(self) -> bool:\n        return True",
            ),
            self.source.replace(
                "def _reject() -> Never:\n",
                "def _reject() -> Never:\n    open('verifier-record.log', 'w')\n",
            ),
            self.source + "\nDYNAMIC = lambda record: record\n",
        )
        for source in mutations:
            with self.subTest(source=source[-80:]):
                violations = analyze_recovery_verifier_record_descriptor_source(
                    source=source
                )
                self.assertEqual(len(violations), 1)
                self.assertEqual(
                    violations[0].code,
                    (
                        RecoveryVerifierRecordDescriptorSourceViolationCode.
                        SOURCE_PROFILE_MISMATCH
                    ),
                )

    def test_target_parse_and_path_failures_are_controlled(self) -> None:
        wrong_target = analyze_recovery_verifier_record_descriptor_source(
            source=self.source,
            relative_path="security_interfaces/other.py",
        )
        self.assertEqual(len(wrong_target), 1)
        self.assertEqual(
            wrong_target[0].code,
            RecoveryVerifierRecordDescriptorSourceViolationCode.TARGET_SET_MISMATCH,
        )

        parse_failure = analyze_recovery_verifier_record_descriptor_source(
            source="def broken(\n"
        )
        self.assertEqual(len(parse_failure), 1)
        self.assertEqual(
            parse_failure[0].code,
            RecoveryVerifierRecordDescriptorSourceViolationCode.SOURCE_PARSE_ERROR,
        )

        with TemporaryDirectory() as temporary_directory:
            violations = scan_repository_recovery_verifier_record_descriptor(
                Path(temporary_directory)
            )
        self.assertEqual(len(violations), 1)
        self.assertEqual(
            violations[0].code,
            RecoveryVerifierRecordDescriptorSourceViolationCode.SOURCE_PARSE_ERROR,
        )

        violations = scan_recovery_verifier_record_descriptor_source(
            path=TARGET,
            relative_to=BASE_DIR / "tests",
        )
        self.assertEqual(len(violations), 1)
        self.assertEqual(violations[0].relative_path, "<invalid-scan-path>")

    def test_source_is_never_executed_or_echoed(self) -> None:
        sentinel = "RECOVERY_VERIFIER_RECORD_SENTINEL"
        violations = analyze_recovery_verifier_record_descriptor_source(
            source=self.source + f"\nraise RuntimeError('{sentinel}')\n"
        )
        self.assertEqual(len(violations), 1)
        self.assertNotIn(sentinel, repr(violations))

        parse_violations = analyze_recovery_verifier_record_descriptor_source(
            source=f"def broken({sentinel}\n"
        )
        self.assertEqual(len(parse_violations), 1)
        self.assertNotIn(sentinel, repr(parse_violations))
