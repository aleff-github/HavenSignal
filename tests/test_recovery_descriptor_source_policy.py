"""Static abuse tests for the inert recovery credential descriptor module."""

from pathlib import Path
from tempfile import TemporaryDirectory

from django.test import SimpleTestCase

from architecture_checks import (
    RECOVERY_DESCRIPTOR_PATH,
    RecoveryDescriptorSourceViolationCode,
    analyze_recovery_descriptor_source,
    scan_recovery_descriptor_source,
    scan_repository_recovery_descriptor,
)


BASE_DIR = Path(__file__).resolve().parent.parent
TARGET = BASE_DIR / RECOVERY_DESCRIPTOR_PATH


class RecoveryDescriptorSourcePolicyTests(SimpleTestCase):
    @classmethod
    def setUpClass(cls) -> None:
        super().setUpClass()
        cls.source = TARGET.read_text(encoding="utf-8")

    def test_current_source_matches_the_exact_inert_profile(self) -> None:
        self.assertEqual(scan_repository_recovery_descriptor(BASE_DIR), ())

    def test_import_encoding_and_size_changes_are_rejected(self) -> None:
        mutations = (
            self.source.replace(
                "import binascii",
                "import binascii\nimport hmac",
            ),
            self.source.replace(
                "RECOVERY_SECRET_RAW_BYTES = 32",
                "RECOVERY_SECRET_RAW_BYTES = 16",
            ),
            self.source.replace(
                'BASE64URL_UNPADDED = "BASE64URL_RFC4648_UNPADDED"',
                'BASE64URL_UNPADDED = "BASE64URL_RFC4648_UNPADDED"\n'
                '    LEGACY_BASE64 = "LEGACY_BASE64"',
            ),
            self.source.replace(
                "    recovery_secret_shape: CanonicalRecoverySecretShapeV1\n",
                "    recovery_secret_shape: CanonicalRecoverySecretShapeV1\n"
                "    recovery_secret: str\n",
            ),
        )
        for source in mutations:
            with self.subTest(source=source[:60]):
                violations = analyze_recovery_descriptor_source(source=source)
                self.assertEqual(len(violations), 1)
                self.assertEqual(
                    violations[0].code,
                    RecoveryDescriptorSourceViolationCode.SOURCE_PROFILE_MISMATCH,
                )

    def test_verifier_authorization_and_side_effect_changes_are_rejected(
        self,
    ) -> None:
        mutations = (
            self.source.replace(
                "    def computes_verifier(self) -> bool:\n        return False",
                "    def computes_verifier(self) -> bool:\n        return True",
            ),
            self.source.replace(
                "    def authorizes_recovery(self) -> bool:\n        return False",
                "    def authorizes_recovery(self) -> bool:\n        return True",
            ),
            self.source.replace(
                "def _reject() -> Never:\n",
                "def _reject() -> Never:\n    open('recovery.log', 'w')\n",
            ),
            self.source + "\nDYNAMIC = lambda secret: True\n",
        )
        for source in mutations:
            with self.subTest(source=source[-80:]):
                violations = analyze_recovery_descriptor_source(source=source)
                self.assertEqual(len(violations), 1)
                self.assertEqual(
                    violations[0].code,
                    RecoveryDescriptorSourceViolationCode.SOURCE_PROFILE_MISMATCH,
                )

    def test_target_parse_and_path_failures_are_controlled(self) -> None:
        wrong_target = analyze_recovery_descriptor_source(
            source=self.source,
            relative_path="security_interfaces/other.py",
        )
        self.assertEqual(len(wrong_target), 1)
        self.assertEqual(
            wrong_target[0].code,
            RecoveryDescriptorSourceViolationCode.TARGET_SET_MISMATCH,
        )

        parse_failure = analyze_recovery_descriptor_source(source="def broken(\n")
        self.assertEqual(len(parse_failure), 1)
        self.assertEqual(
            parse_failure[0].code,
            RecoveryDescriptorSourceViolationCode.SOURCE_PARSE_ERROR,
        )

        with TemporaryDirectory() as temporary_directory:
            violations = scan_repository_recovery_descriptor(
                Path(temporary_directory)
            )
        self.assertEqual(len(violations), 1)
        self.assertEqual(
            violations[0].code,
            RecoveryDescriptorSourceViolationCode.SOURCE_PARSE_ERROR,
        )

        violations = scan_recovery_descriptor_source(
            path=TARGET,
            relative_to=BASE_DIR / "tests",
        )
        self.assertEqual(len(violations), 1)
        self.assertEqual(violations[0].relative_path, "<invalid-scan-path>")

    def test_source_is_never_executed_or_echoed(self) -> None:
        sentinel = "RECOVERY_SECRET_SENTINEL"
        violations = analyze_recovery_descriptor_source(
            source=self.source + f"\nraise RuntimeError('{sentinel}')\n"
        )
        self.assertEqual(len(violations), 1)
        self.assertNotIn(sentinel, repr(violations))

        parse_violations = analyze_recovery_descriptor_source(
            source=f"def broken({sentinel}\n"
        )
        self.assertEqual(len(parse_violations), 1)
        self.assertNotIn(sentinel, repr(parse_violations))
