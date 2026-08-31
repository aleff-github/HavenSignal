"""Static abuse tests for inert response text descriptors."""

from pathlib import Path
from tempfile import TemporaryDirectory

from django.test import SimpleTestCase

from architecture_checks import (
    RESPONSE_TEXT_DESCRIPTOR_PATH,
    ResponseTextDescriptorSourceViolationCode,
    analyze_response_text_descriptor_source,
    scan_repository_response_text_descriptor,
    scan_response_text_descriptor_source,
)


BASE_DIR = Path(__file__).resolve().parent.parent
TARGET = BASE_DIR / RESPONSE_TEXT_DESCRIPTOR_PATH


class ResponseTextDescriptorSourcePolicyTests(SimpleTestCase):
    @classmethod
    def setUpClass(cls) -> None:
        super().setUpClass()
        cls.source = TARGET.read_text(encoding="utf-8")

    def test_current_source_matches_the_exact_inert_profile(self) -> None:
        self.assertEqual(scan_repository_response_text_descriptor(BASE_DIR), ())

    def test_import_limit_and_restriction_changes_are_rejected(self) -> None:
        mutations = (
            self.source.replace(
                "import unicodedata",
                "import unicodedata\nimport hashlib",
            ),
            self.source.replace(
                "RESPONSE_TEXT_MAX_SCALAR_VALUES = 5_000",
                "RESPONSE_TEXT_MAX_SCALAR_VALUES = 10_000",
            ),
            self.source.replace(
                '    PLAIN_TEXT = "PLAIN_TEXT"',
                '    PLAIN_TEXT = "PLAIN_TEXT"\n    HTML = "HTML"',
            ),
            self.source.replace(
                "    max_utf8_bytes: int\n",
                "    max_utf8_bytes: int\n    text: str\n",
            ),
        )
        for source in mutations:
            with self.subTest(source=source[:80]):
                violations = analyze_response_text_descriptor_source(
                    source=source
                )
                self.assertEqual(len(violations), 1)
                self.assertEqual(
                    violations[0].code,
                    ResponseTextDescriptorSourceViolationCode.SOURCE_PROFILE_MISMATCH,
                )

    def test_persistence_digest_and_authorization_changes_are_rejected(
        self,
    ) -> None:
        mutations = (
            self.source.replace(
                "    def retains_response_text(self) -> bool:\n"
                "        return False",
                "    def retains_response_text(self) -> bool:\n"
                "        return True",
            ),
            self.source.replace(
                "    def authorizes_finalization(self) -> bool:\n"
                "        return False",
                "    def authorizes_finalization(self) -> bool:\n"
                "        return True",
            ),
            self.source.replace(
                "def _reject() -> Never:\n",
                "def _reject() -> Never:\n    open('response.txt', 'w')\n",
            ),
            self.source + "\nDYNAMIC = lambda text: True\n",
        )
        for source in mutations:
            with self.subTest(source=source[-80:]):
                violations = analyze_response_text_descriptor_source(
                    source=source
                )
                self.assertEqual(len(violations), 1)
                self.assertEqual(
                    violations[0].code,
                    ResponseTextDescriptorSourceViolationCode.SOURCE_PROFILE_MISMATCH,
                )

    def test_target_parse_and_path_failures_are_controlled(self) -> None:
        wrong_target = analyze_response_text_descriptor_source(
            source=self.source,
            relative_path="security_interfaces/other.py",
        )
        self.assertEqual(len(wrong_target), 1)
        self.assertEqual(
            wrong_target[0].code,
            ResponseTextDescriptorSourceViolationCode.TARGET_SET_MISMATCH,
        )

        parse_failure = analyze_response_text_descriptor_source(
            source="def broken(\n"
        )
        self.assertEqual(len(parse_failure), 1)
        self.assertEqual(
            parse_failure[0].code,
            ResponseTextDescriptorSourceViolationCode.SOURCE_PARSE_ERROR,
        )

        with TemporaryDirectory() as temporary_directory:
            violations = scan_repository_response_text_descriptor(
                Path(temporary_directory)
            )
        self.assertEqual(len(violations), 1)
        self.assertEqual(
            violations[0].code,
            ResponseTextDescriptorSourceViolationCode.SOURCE_PARSE_ERROR,
        )

        violations = scan_response_text_descriptor_source(
            path=TARGET,
            relative_to=BASE_DIR / "tests",
        )
        self.assertEqual(len(violations), 1)
        self.assertEqual(violations[0].relative_path, "<invalid-scan-path>")

    def test_source_is_never_executed_or_echoed(self) -> None:
        sentinel = "RESPONSE_TEXT_SENTINEL"
        violations = analyze_response_text_descriptor_source(
            source=self.source + f"\nraise RuntimeError('{sentinel}')\n"
        )
        self.assertEqual(len(violations), 1)
        self.assertNotIn(sentinel, repr(violations))

        parse_violations = analyze_response_text_descriptor_source(
            source=f"def broken({sentinel}\n"
        )
        self.assertEqual(len(parse_violations), 1)
        self.assertNotIn(sentinel, repr(parse_violations))
