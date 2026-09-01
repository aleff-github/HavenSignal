"""Static abuse tests for inert attachment-admission descriptors."""

from pathlib import Path
from tempfile import TemporaryDirectory

from django.test import SimpleTestCase

from architecture_checks import (
    ATTACHMENT_ADMISSION_DESCRIPTOR_PATH,
    AttachmentAdmissionDescriptorSourceViolationCode,
    analyze_attachment_admission_descriptor_source,
    scan_attachment_admission_descriptor_source,
    scan_repository_attachment_admission_descriptor,
)


BASE_DIR = Path(__file__).resolve().parent.parent
TARGET = BASE_DIR / ATTACHMENT_ADMISSION_DESCRIPTOR_PATH


class AttachmentAdmissionDescriptorSourcePolicyTests(SimpleTestCase):
    @classmethod
    def setUpClass(cls) -> None:
        super().setUpClass()
        cls.source = TARGET.read_text(encoding="utf-8")

    def test_current_source_matches_the_exact_inert_profile(self) -> None:
        self.assertEqual(
            scan_repository_attachment_admission_descriptor(BASE_DIR),
            (),
        )

    def test_file_parser_sandbox_and_persistence_changes_are_rejected(
        self,
    ) -> None:
        mutations = (
            self.source.replace(
                "from dataclasses import dataclass",
                "from dataclasses import dataclass\nimport magic",
            ),
            self.source.replace(
                "    def inspects_file_bytes(self) -> bool:\n        return False",
                "    def inspects_file_bytes(self) -> bool:\n        return True",
            ),
            self.source.replace(
                "    def creates_sandbox_job(self) -> bool:\n        return False",
                "    def creates_sandbox_job(self) -> bool:\n        return True",
            ),
            self.source.replace(
                "    def persists_original_bytes(self) -> bool:\n"
                "        return False",
                "    def persists_original_bytes(self) -> bool:\n"
                "        return True",
            ),
        )
        for source in mutations:
            with self.subTest(source=source[:80]):
                violations = analyze_attachment_admission_descriptor_source(
                    source=source
                )
                self.assertEqual(len(violations), 1)
                self.assertEqual(
                    violations[0].code,
                    AttachmentAdmissionDescriptorSourceViolationCode.SOURCE_PROFILE_MISMATCH,
                )

    def test_filename_trust_logging_and_authorization_changes_are_rejected(
        self,
    ) -> None:
        mutations = (
            self.source.replace(
                "            filename_is_storage_input=False,",
                "            filename_is_storage_input=True,",
            ),
            self.source.replace(
                "            client_content_type_trusted=False,",
                "            client_content_type_trusted=True,",
            ),
            self.source.replace(
                "    def logs_request_material(self) -> bool:\n        return False",
                "    def logs_request_material(self) -> bool:\n        return True",
            ),
            self.source.replace(
                "    def authorizes_upload(self) -> bool:\n        return False",
                "    def authorizes_upload(self) -> bool:\n        return True",
            ),
        )
        for source in mutations:
            with self.subTest(source=source[-80:]):
                violations = analyze_attachment_admission_descriptor_source(
                    source=source
                )
                self.assertEqual(len(violations), 1)
                self.assertEqual(
                    violations[0].code,
                    AttachmentAdmissionDescriptorSourceViolationCode.SOURCE_PROFILE_MISMATCH,
                )

    def test_target_parse_and_path_failures_are_controlled(self) -> None:
        wrong_target = analyze_attachment_admission_descriptor_source(
            source=self.source,
            relative_path="security_interfaces/other.py",
        )
        self.assertEqual(len(wrong_target), 1)
        self.assertEqual(
            wrong_target[0].code,
            AttachmentAdmissionDescriptorSourceViolationCode.TARGET_SET_MISMATCH,
        )

        parse_failure = analyze_attachment_admission_descriptor_source(
            source="def broken(\n"
        )
        self.assertEqual(len(parse_failure), 1)
        self.assertEqual(
            parse_failure[0].code,
            AttachmentAdmissionDescriptorSourceViolationCode.SOURCE_PARSE_ERROR,
        )

        with TemporaryDirectory() as temporary_directory:
            violations = scan_repository_attachment_admission_descriptor(
                Path(temporary_directory)
            )
        self.assertEqual(len(violations), 1)
        self.assertEqual(
            violations[0].code,
            AttachmentAdmissionDescriptorSourceViolationCode.SOURCE_PARSE_ERROR,
        )

        violations = scan_attachment_admission_descriptor_source(
            path=TARGET,
            relative_to=BASE_DIR / "tests",
        )
        self.assertEqual(len(violations), 1)
        self.assertEqual(violations[0].relative_path, "<invalid-scan-path>")

    def test_source_is_never_executed_or_echoed(self) -> None:
        sentinel = "ATTACHMENT_SENTINEL"
        violations = analyze_attachment_admission_descriptor_source(
            source=self.source + f"\nraise RuntimeError('{sentinel}')\n"
        )
        self.assertEqual(len(violations), 1)
        self.assertNotIn(sentinel, repr(violations))

        parse_violations = analyze_attachment_admission_descriptor_source(
            source=f"def broken({sentinel}\n"
        )
        self.assertEqual(len(parse_violations), 1)
        self.assertNotIn(sentinel, repr(parse_violations))
