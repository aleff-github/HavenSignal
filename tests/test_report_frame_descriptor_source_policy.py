"""Static abuse tests for inert original-report frame descriptors."""

from pathlib import Path
from tempfile import TemporaryDirectory

from django.test import SimpleTestCase

from architecture_checks import (
    REPORT_FRAME_DESCRIPTOR_PATH,
    ReportFrameDescriptorSourceViolationCode,
    analyze_report_frame_descriptor_source,
    scan_repository_report_frame_descriptor,
    scan_report_frame_descriptor_source,
)


BASE_DIR = Path(__file__).resolve().parent.parent
TARGET = BASE_DIR / REPORT_FRAME_DESCRIPTOR_PATH


class ReportFrameDescriptorSourcePolicyTests(SimpleTestCase):
    @classmethod
    def setUpClass(cls) -> None:
        super().setUpClass()
        cls.source = TARGET.read_text(encoding="utf-8")

    def test_current_source_matches_the_exact_inert_profile(self) -> None:
        self.assertEqual(scan_repository_report_frame_descriptor(BASE_DIR), ())

    def test_import_layout_and_code_changes_are_rejected(self) -> None:
        mutations = (
            self.source.replace(
                "from dataclasses import dataclass",
                "from dataclasses import dataclass\nimport struct",
            ),
            self.source.replace(
                "REPORT_FRAME_VERSION_BYTE = 0x01",
                "REPORT_FRAME_VERSION_BYTE = 0x02",
            ),
            self.source.replace(
                '    UINT32_BIG_ENDIAN = "UINT32_BIG_ENDIAN"',
                '    UINT32_BIG_ENDIAN = "UINT32_BIG_ENDIAN"\n'
                '    UINT16_BIG_ENDIAN = "UINT16_BIG_ENDIAN"',
            ),
            self.source.replace(
                "    max_payload_bytes: int | None\n",
                "    max_payload_bytes: int | None\n    frame_bytes: bytes\n",
            ),
        )
        for source in mutations:
            with self.subTest(source=source[:80]):
                violations = analyze_report_frame_descriptor_source(source=source)
                self.assertEqual(len(violations), 1)
                self.assertEqual(
                    violations[0].code,
                    ReportFrameDescriptorSourceViolationCode.SOURCE_PROFILE_MISMATCH,
                )

    def test_frame_construction_and_authorization_changes_are_rejected(
        self,
    ) -> None:
        mutations = (
            self.source.replace(
                "    def constructs_frame(self) -> bool:\n        return False",
                "    def constructs_frame(self) -> bool:\n        return True",
            ),
            self.source.replace(
                "    def authorizes_submission(self) -> bool:\n"
                "        return False",
                "    def authorizes_submission(self) -> bool:\n"
                "        return True",
            ),
            self.source.replace(
                "def _reject() -> Never:\n",
                "def _reject() -> Never:\n    open('frame.bin', 'wb')\n",
            ),
            self.source + "\nDYNAMIC = lambda plaintext: plaintext[:1]\n",
        )
        for source in mutations:
            with self.subTest(source=source[-80:]):
                violations = analyze_report_frame_descriptor_source(source=source)
                self.assertEqual(len(violations), 1)
                self.assertEqual(
                    violations[0].code,
                    ReportFrameDescriptorSourceViolationCode.SOURCE_PROFILE_MISMATCH,
                )

    def test_target_parse_and_path_failures_are_controlled(self) -> None:
        wrong_target = analyze_report_frame_descriptor_source(
            source=self.source,
            relative_path="security_interfaces/other.py",
        )
        self.assertEqual(len(wrong_target), 1)
        self.assertEqual(
            wrong_target[0].code,
            ReportFrameDescriptorSourceViolationCode.TARGET_SET_MISMATCH,
        )

        parse_failure = analyze_report_frame_descriptor_source(
            source="def broken(\n"
        )
        self.assertEqual(len(parse_failure), 1)
        self.assertEqual(
            parse_failure[0].code,
            ReportFrameDescriptorSourceViolationCode.SOURCE_PARSE_ERROR,
        )

        with TemporaryDirectory() as temporary_directory:
            violations = scan_repository_report_frame_descriptor(
                Path(temporary_directory)
            )
        self.assertEqual(len(violations), 1)
        self.assertEqual(
            violations[0].code,
            ReportFrameDescriptorSourceViolationCode.SOURCE_PARSE_ERROR,
        )

        violations = scan_report_frame_descriptor_source(
            path=TARGET,
            relative_to=BASE_DIR / "tests",
        )
        self.assertEqual(len(violations), 1)
        self.assertEqual(violations[0].relative_path, "<invalid-scan-path>")

    def test_source_is_never_executed_or_echoed(self) -> None:
        sentinel = "REPORT_FRAME_SENTINEL"
        violations = analyze_report_frame_descriptor_source(
            source=self.source + f"\nraise RuntimeError('{sentinel}')\n"
        )
        self.assertEqual(len(violations), 1)
        self.assertNotIn(sentinel, repr(violations))

        parse_violations = analyze_report_frame_descriptor_source(
            source=f"def broken({sentinel}\n"
        )
        self.assertEqual(len(parse_violations), 1)
        self.assertNotIn(sentinel, repr(parse_violations))
