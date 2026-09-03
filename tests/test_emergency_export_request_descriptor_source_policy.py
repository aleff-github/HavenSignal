"""Static abuse tests for inert Emergency Export request descriptors."""

from pathlib import Path
from tempfile import TemporaryDirectory

from django.test import SimpleTestCase

from architecture_checks.emergency_export_request_descriptors import (
    EMERGENCY_EXPORT_REQUEST_DESCRIPTOR_PATH,
    EmergencyExportRequestDescriptorSourceViolationCode,
    analyze_emergency_export_request_descriptor_source,
    scan_emergency_export_request_descriptor_source,
    scan_repository_emergency_export_request_descriptor,
)


BASE_DIR = Path(__file__).resolve().parent.parent
TARGET = BASE_DIR / EMERGENCY_EXPORT_REQUEST_DESCRIPTOR_PATH


class EmergencyExportRequestDescriptorSourcePolicyTests(SimpleTestCase):
    @classmethod
    def setUpClass(cls) -> None:
        super().setUpClass()
        cls.source = TARGET.read_text(encoding="utf-8")

    def test_current_source_matches_the_exact_inert_profile(self) -> None:
        self.assertEqual(
            scan_repository_emergency_export_request_descriptor(BASE_DIR),
            (),
        )

    def test_schema_content_and_import_changes_are_rejected(self) -> None:
        mutations = (
            self.source.replace(
                "from dataclasses import dataclass",
                "from dataclasses import dataclass\nimport cbor2",
            ),
            self.source.replace(
                "EMERGENCY_EXPORT_REQUEST_ID_BYTES = 16",
                "EMERGENCY_EXPORT_REQUEST_ID_BYTES = 8",
            ),
            self.source.replace(
                '    _field("objects", EmergencyExportRequestFieldType.OBJECT_ARRAY),',
                '    _field("artifact", EmergencyExportRequestFieldType.BYTES),',
            ),
            self.source.replace(
                "    profile: EmergencyExportRequestProfileV1\n",
                "    profile: EmergencyExportRequestProfileV1\n"
                "    protected_note: bytes\n",
            ),
        )
        for source in mutations:
            with self.subTest(source=source[:80]):
                violations = analyze_emergency_export_request_descriptor_source(
                    source=source
                )
                self.assertEqual(len(violations), 1)
                self.assertEqual(
                    violations[0].code,
                    EmergencyExportRequestDescriptorSourceViolationCode.SOURCE_PROFILE_MISMATCH,
                )

    def test_capability_and_side_effect_changes_are_rejected(self) -> None:
        mutations = (
            self.source.replace(
                "    def holds_protected_note(self) -> bool:\n        return False",
                "    def holds_protected_note(self) -> bool:\n        return True",
            ),
            self.source.replace(
                "    def authorizes_export(self) -> bool:\n        return False",
                "    def authorizes_export(self) -> bool:\n        return True",
            ),
            self.source.replace(
                "def _reject() -> Never:\n",
                "def _reject() -> Never:\n    open('export.age', 'wb')\n",
            ),
            self.source + "\nENCODE = lambda protected_note: protected_note\n",
        )
        for source in mutations:
            with self.subTest(source=source[-80:]):
                violations = analyze_emergency_export_request_descriptor_source(
                    source=source
                )
                self.assertEqual(len(violations), 1)
                self.assertEqual(
                    violations[0].code,
                    EmergencyExportRequestDescriptorSourceViolationCode.SOURCE_PROFILE_MISMATCH,
                )

    def test_target_parse_and_path_failures_are_controlled(self) -> None:
        wrong_target = analyze_emergency_export_request_descriptor_source(
            source=self.source,
            relative_path="security_interfaces/other.py",
        )
        self.assertEqual(len(wrong_target), 1)
        self.assertEqual(
            wrong_target[0].code,
            EmergencyExportRequestDescriptorSourceViolationCode.TARGET_SET_MISMATCH,
        )
        parse_failure = analyze_emergency_export_request_descriptor_source(
            source="def broken(\n"
        )
        self.assertEqual(len(parse_failure), 1)
        self.assertEqual(
            parse_failure[0].code,
            EmergencyExportRequestDescriptorSourceViolationCode.SOURCE_PARSE_ERROR,
        )
        with TemporaryDirectory() as temporary_directory:
            violations = scan_repository_emergency_export_request_descriptor(
                Path(temporary_directory)
            )
        self.assertEqual(len(violations), 1)
        violations = scan_emergency_export_request_descriptor_source(
            path=TARGET,
            relative_to=BASE_DIR / "tests",
        )
        self.assertEqual(len(violations), 1)
        self.assertEqual(violations[0].relative_path, "<invalid-scan-path>")

    def test_source_is_never_executed_or_echoed(self) -> None:
        sentinel = "PROTECTED_NOTE_SENTINEL"
        violations = analyze_emergency_export_request_descriptor_source(
            source=self.source + f"\nraise RuntimeError('{sentinel}')\n"
        )
        self.assertEqual(len(violations), 1)
        self.assertNotIn(sentinel, repr(violations))
