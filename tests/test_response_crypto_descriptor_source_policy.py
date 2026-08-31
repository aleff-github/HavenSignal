"""Static abuse tests for inert response crypto descriptors."""

from pathlib import Path
from tempfile import TemporaryDirectory

from django.test import SimpleTestCase

from architecture_checks import (
    RESPONSE_CRYPTO_DESCRIPTOR_PATH,
    ResponseCryptoDescriptorSourceViolationCode,
    analyze_response_crypto_descriptor_source,
    scan_repository_response_crypto_descriptor,
    scan_response_crypto_descriptor_source,
)


BASE_DIR = Path(__file__).resolve().parent.parent
TARGET = BASE_DIR / RESPONSE_CRYPTO_DESCRIPTOR_PATH


class ResponseCryptoDescriptorSourcePolicyTests(SimpleTestCase):
    @classmethod
    def setUpClass(cls) -> None:
        super().setUpClass()
        cls.source = TARGET.read_text(encoding="utf-8")

    def test_current_source_matches_the_exact_inert_profile(self) -> None:
        self.assertEqual(
            scan_repository_response_crypto_descriptor(BASE_DIR),
            (),
        )

    def test_import_constant_and_registry_changes_are_rejected(self) -> None:
        mutations = (
            self.source.replace(
                "from dataclasses import dataclass",
                "from dataclasses import dataclass\nimport nacl.secret",
            ),
            self.source.replace(
                "RESPONSE_DEK_BYTES = 32",
                "RESPONSE_DEK_BYTES = 16",
            ),
            self.source.replace(
                '    XCHACHA20_POLY1305_IETF = "XCHACHA20_POLY1305_IETF"',
                '    XCHACHA20_POLY1305_IETF = "XCHACHA20_POLY1305_IETF"\n'
                '    AES_GCM = "AES_GCM"',
            ),
            self.source.replace(
                "    response_dek_size_bytes: int\n",
                "    response_dek_size_bytes: int\n    response_dek: bytes\n",
            ),
        )
        for source in mutations:
            with self.subTest(source=source[:80]):
                violations = analyze_response_crypto_descriptor_source(
                    source=source
                )
                self.assertEqual(len(violations), 1)
                self.assertEqual(
                    violations[0].code,
                    ResponseCryptoDescriptorSourceViolationCode.SOURCE_PROFILE_MISMATCH,
                )

    def test_crypto_authorization_and_side_effect_changes_are_rejected(
        self,
    ) -> None:
        mutations = (
            self.source.replace(
                "    def decrypts_response(self) -> bool:\n        return False",
                "    def decrypts_response(self) -> bool:\n        return True",
            ),
            self.source.replace(
                "    def authorizes_response_use(self) -> bool:\n"
                "        return False",
                "    def authorizes_response_use(self) -> bool:\n"
                "        return True",
            ),
            self.source.replace(
                "def _reject() -> Never:\n",
                "def _reject() -> Never:\n    open('response.bin', 'wb')\n",
            ),
            self.source + "\nDYNAMIC = lambda plaintext: True\n",
        )
        for source in mutations:
            with self.subTest(source=source[-80:]):
                violations = analyze_response_crypto_descriptor_source(
                    source=source
                )
                self.assertEqual(len(violations), 1)
                self.assertEqual(
                    violations[0].code,
                    ResponseCryptoDescriptorSourceViolationCode.SOURCE_PROFILE_MISMATCH,
                )

    def test_target_parse_and_path_failures_are_controlled(self) -> None:
        wrong_target = analyze_response_crypto_descriptor_source(
            source=self.source,
            relative_path="security_interfaces/other.py",
        )
        self.assertEqual(len(wrong_target), 1)
        self.assertEqual(
            wrong_target[0].code,
            ResponseCryptoDescriptorSourceViolationCode.TARGET_SET_MISMATCH,
        )

        parse_failure = analyze_response_crypto_descriptor_source(
            source="def broken(\n"
        )
        self.assertEqual(len(parse_failure), 1)
        self.assertEqual(
            parse_failure[0].code,
            ResponseCryptoDescriptorSourceViolationCode.SOURCE_PARSE_ERROR,
        )

        with TemporaryDirectory() as temporary_directory:
            violations = scan_repository_response_crypto_descriptor(
                Path(temporary_directory)
            )
        self.assertEqual(len(violations), 1)
        self.assertEqual(
            violations[0].code,
            ResponseCryptoDescriptorSourceViolationCode.SOURCE_PARSE_ERROR,
        )

        violations = scan_response_crypto_descriptor_source(
            path=TARGET,
            relative_to=BASE_DIR / "tests",
        )
        self.assertEqual(len(violations), 1)
        self.assertEqual(violations[0].relative_path, "<invalid-scan-path>")

    def test_source_is_never_executed_or_echoed(self) -> None:
        sentinel = "RESPONSE_NOTE_SENTINEL"
        violations = analyze_response_crypto_descriptor_source(
            source=self.source + f"\nraise RuntimeError('{sentinel}')\n"
        )
        self.assertEqual(len(violations), 1)
        self.assertNotIn(sentinel, repr(violations))

        parse_violations = analyze_response_crypto_descriptor_source(
            source=f"def broken({sentinel}\n"
        )
        self.assertEqual(len(parse_violations), 1)
        self.assertNotIn(sentinel, repr(parse_violations))
