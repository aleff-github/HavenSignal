"""Static abuse tests for inert recovery HMAC message descriptors."""

from pathlib import Path
from tempfile import TemporaryDirectory

from django.test import SimpleTestCase

from architecture_checks import (
    RECOVERY_HMAC_MESSAGE_DESCRIPTOR_PATH,
    RecoveryHmacMessageDescriptorSourceViolationCode,
    analyze_recovery_hmac_message_descriptor_source,
    scan_recovery_hmac_message_descriptor_source,
    scan_repository_recovery_hmac_message_descriptor,
)


BASE_DIR = Path(__file__).resolve().parent.parent
TARGET = BASE_DIR / RECOVERY_HMAC_MESSAGE_DESCRIPTOR_PATH


class RecoveryHmacMessageDescriptorSourcePolicyTests(SimpleTestCase):
    @classmethod
    def setUpClass(cls) -> None:
        super().setUpClass()
        cls.source = TARGET.read_text(encoding="utf-8")

    def test_current_source_matches_the_exact_inert_profile(self) -> None:
        self.assertEqual(
            scan_repository_recovery_hmac_message_descriptor(BASE_DIR),
            (),
        )

    def test_import_layout_requirement_and_denial_changes_are_rejected(self) -> None:
        mutations = (
            self.source.replace(
                "from dataclasses import dataclass",
                "from dataclasses import dataclass\nimport hmac",
            ),
            self.source.replace(
                "RECOVERY_HMAC_MESSAGE_PROFILE_VERSION = 1",
                "RECOVERY_HMAC_MESSAGE_PROFILE_VERSION = 2",
            ),
            self.source.replace(
                "RECOVERY_HMAC_SEPARATOR_BYTE = 0",
                "RECOVERY_HMAC_SEPARATOR_BYTE = 1",
            ),
            self.source.replace(
                '    ZERO_SEPARATOR = "ZERO_SEPARATOR"',
                '    ZERO_SEPARATOR = "ZERO_SEPARATOR"\n    COLON = "COLON"',
            ),
            self.source.replace(
                '    FIXED_ORDER = "FIXED_ORDER"',
                '    FIXED_ORDER = "FIXED_ORDER"\n    VARIABLE_ORDER = "VARIABLE_ORDER"',
            ),
            self.source.replace(
                '    COMPUTES_HMAC = "COMPUTES_HMAC"',
                '    COMPUTES_HMAC = "COMPUTES_HMAC"\n    VERIFIES_SECRET = "VERIFIES_SECRET"',
            ),
        )
        for source in mutations:
            with self.subTest(source=source[:80]):
                violations = analyze_recovery_hmac_message_descriptor_source(
                    source=source
                )
                self.assertEqual(len(violations), 1)
                self.assertEqual(
                    violations[0].code,
                    (
                        RecoveryHmacMessageDescriptorSourceViolationCode.
                        SOURCE_PROFILE_MISMATCH
                    ),
                )

    def test_runtime_and_authorization_changes_are_rejected(self) -> None:
        mutations = (
            self.source.replace(
                "    def accepts_credential_values(self) -> bool:\n        return False",
                "    def accepts_credential_values(self) -> bool:\n        return True",
            ),
            self.source.replace(
                "    def concatenates_bytes(self) -> bool:\n        return False",
                "    def concatenates_bytes(self) -> bool:\n        return True",
            ),
            self.source.replace(
                "    def computes_hmac(self) -> bool:\n        return False",
                "    def computes_hmac(self) -> bool:\n        return True",
            ),
            self.source.replace(
                "    def accesses_verifier_key(self) -> bool:\n        return False",
                "    def accesses_verifier_key(self) -> bool:\n        return True",
            ),
            self.source.replace(
                "    def authorizes_recovery(self) -> bool:\n        return False",
                "    def authorizes_recovery(self) -> bool:\n        return True",
            ),
            self.source.replace(
                "def _reject() -> Never:\n",
                "def _reject() -> Never:\n    open('hmac-message.log', 'w')\n",
            ),
            self.source + "\nDYNAMIC = lambda secret: secret\n",
        )
        for source in mutations:
            with self.subTest(source=source[-80:]):
                violations = analyze_recovery_hmac_message_descriptor_source(
                    source=source
                )
                self.assertEqual(len(violations), 1)
                self.assertEqual(
                    violations[0].code,
                    (
                        RecoveryHmacMessageDescriptorSourceViolationCode.
                        SOURCE_PROFILE_MISMATCH
                    ),
                )

    def test_target_parse_and_path_failures_are_controlled(self) -> None:
        wrong_target = analyze_recovery_hmac_message_descriptor_source(
            source=self.source,
            relative_path="security_interfaces/other.py",
        )
        self.assertEqual(len(wrong_target), 1)
        self.assertEqual(
            wrong_target[0].code,
            RecoveryHmacMessageDescriptorSourceViolationCode.TARGET_SET_MISMATCH,
        )

        parse_failure = analyze_recovery_hmac_message_descriptor_source(
            source="def broken(\n"
        )
        self.assertEqual(len(parse_failure), 1)
        self.assertEqual(
            parse_failure[0].code,
            RecoveryHmacMessageDescriptorSourceViolationCode.SOURCE_PARSE_ERROR,
        )

        with TemporaryDirectory() as temporary_directory:
            violations = scan_repository_recovery_hmac_message_descriptor(
                Path(temporary_directory)
            )
        self.assertEqual(len(violations), 1)
        self.assertEqual(
            violations[0].code,
            RecoveryHmacMessageDescriptorSourceViolationCode.SOURCE_PARSE_ERROR,
        )

        violations = scan_recovery_hmac_message_descriptor_source(
            path=TARGET,
            relative_to=BASE_DIR / "tests",
        )
        self.assertEqual(len(violations), 1)
        self.assertEqual(violations[0].relative_path, "<invalid-scan-path>")

    def test_source_is_never_executed_or_echoed(self) -> None:
        sentinel = "RECOVERY_HMAC_MESSAGE_SENTINEL"
        violations = analyze_recovery_hmac_message_descriptor_source(
            source=self.source + f"\nraise RuntimeError('{sentinel}')\n"
        )
        self.assertEqual(len(violations), 1)
        self.assertNotIn(sentinel, repr(violations))

        parse_violations = analyze_recovery_hmac_message_descriptor_source(
            source=f"def broken({sentinel}\n"
        )
        self.assertEqual(len(parse_violations), 1)
        self.assertNotIn(sentinel, repr(parse_violations))
