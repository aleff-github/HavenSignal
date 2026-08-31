"""Static abuse tests for inert response schema descriptors."""

from pathlib import Path
from tempfile import TemporaryDirectory

from django.test import SimpleTestCase

from architecture_checks import (
    RESPONSE_SCHEMA_DESCRIPTOR_PATH,
    ResponseSchemaDescriptorSourceViolationCode,
    analyze_response_schema_descriptor_source,
    scan_repository_response_schema_descriptor,
    scan_response_schema_descriptor_source,
)


BASE_DIR = Path(__file__).resolve().parent.parent
TARGET = BASE_DIR / RESPONSE_SCHEMA_DESCRIPTOR_PATH


class ResponseSchemaDescriptorSourcePolicyTests(SimpleTestCase):
    @classmethod
    def setUpClass(cls) -> None:
        super().setUpClass()
        cls.source = TARGET.read_text(encoding="utf-8")

    def test_current_source_matches_the_exact_inert_profile(self) -> None:
        self.assertEqual(
            scan_repository_response_schema_descriptor(BASE_DIR),
            (),
        )

    def test_import_schema_and_field_changes_are_rejected(self) -> None:
        mutations = (
            self.source.replace(
                "from dataclasses import dataclass",
                "from dataclasses import dataclass\nimport cbor2",
            ),
            self.source.replace(
                '"plaintext_frame_length"',
                '"frame_length"',
            ),
            self.source.replace(
                "    exact_value: int | str | None\n",
                "    exact_value: int | str | None\n    raw_value: bytes\n",
            ),
            self.source.replace(
                '    BYTES = "BYTES"',
                '    BYTES = "BYTES"\n    MAP = "MAP"',
            ),
        )
        for source in mutations:
            with self.subTest(source=source[:80]):
                violations = analyze_response_schema_descriptor_source(
                    source=source
                )
                self.assertEqual(len(violations), 1)
                self.assertEqual(
                    violations[0].code,
                    ResponseSchemaDescriptorSourceViolationCode.SOURCE_PROFILE_MISMATCH,
                )

    def test_cbor_context_and_authorization_changes_are_rejected(self) -> None:
        mutations = (
            self.source.replace(
                "    def encodes_cbor(self) -> bool:\n        return False",
                "    def encodes_cbor(self) -> bool:\n        return True",
            ),
            self.source.replace(
                "    def authorizes_response_use(self) -> bool:\n"
                "        return False",
                "    def authorizes_response_use(self) -> bool:\n"
                "        return True",
            ),
            self.source.replace(
                "def _reject() -> Never:\n",
                "def _reject() -> Never:\n    open('schema.cbor', 'wb')\n",
            ),
            self.source + "\nDYNAMIC = lambda envelope: True\n",
        )
        for source in mutations:
            with self.subTest(source=source[-80:]):
                violations = analyze_response_schema_descriptor_source(
                    source=source
                )
                self.assertEqual(len(violations), 1)
                self.assertEqual(
                    violations[0].code,
                    ResponseSchemaDescriptorSourceViolationCode.SOURCE_PROFILE_MISMATCH,
                )

    def test_target_parse_and_path_failures_are_controlled(self) -> None:
        wrong_target = analyze_response_schema_descriptor_source(
            source=self.source,
            relative_path="security_interfaces/other.py",
        )
        self.assertEqual(len(wrong_target), 1)
        self.assertEqual(
            wrong_target[0].code,
            ResponseSchemaDescriptorSourceViolationCode.TARGET_SET_MISMATCH,
        )

        parse_failure = analyze_response_schema_descriptor_source(
            source="def broken(\n"
        )
        self.assertEqual(len(parse_failure), 1)
        self.assertEqual(
            parse_failure[0].code,
            ResponseSchemaDescriptorSourceViolationCode.SOURCE_PARSE_ERROR,
        )

        with TemporaryDirectory() as temporary_directory:
            violations = scan_repository_response_schema_descriptor(
                Path(temporary_directory)
            )
        self.assertEqual(len(violations), 1)
        self.assertEqual(
            violations[0].code,
            ResponseSchemaDescriptorSourceViolationCode.SOURCE_PARSE_ERROR,
        )

        violations = scan_response_schema_descriptor_source(
            path=TARGET,
            relative_to=BASE_DIR / "tests",
        )
        self.assertEqual(len(violations), 1)
        self.assertEqual(violations[0].relative_path, "<invalid-scan-path>")

    def test_source_is_never_executed_or_echoed(self) -> None:
        sentinel = "RESPONSE_SCHEMA_SENTINEL"
        violations = analyze_response_schema_descriptor_source(
            source=self.source + f"\nraise RuntimeError('{sentinel}')\n"
        )
        self.assertEqual(len(violations), 1)
        self.assertNotIn(sentinel, repr(violations))

        parse_violations = analyze_response_schema_descriptor_source(
            source=f"def broken({sentinel}\n"
        )
        self.assertEqual(len(parse_violations), 1)
        self.assertNotIn(sentinel, repr(parse_violations))
