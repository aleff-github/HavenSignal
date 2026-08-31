"""Static abuse tests for inert request-admission descriptors."""

from pathlib import Path
from tempfile import TemporaryDirectory

from django.test import SimpleTestCase

from architecture_checks import (
    REQUEST_ADMISSION_DESCRIPTOR_PATH,
    RequestAdmissionDescriptorSourceViolationCode,
    analyze_request_admission_descriptor_source,
    scan_repository_request_admission_descriptor,
    scan_request_admission_descriptor_source,
)


BASE_DIR = Path(__file__).resolve().parent.parent
TARGET = BASE_DIR / REQUEST_ADMISSION_DESCRIPTOR_PATH


class RequestAdmissionDescriptorSourcePolicyTests(SimpleTestCase):
    @classmethod
    def setUpClass(cls) -> None:
        super().setUpClass()
        cls.source = TARGET.read_text(encoding="utf-8")

    def test_current_source_matches_the_exact_inert_profile(self) -> None:
        self.assertEqual(
            scan_repository_request_admission_descriptor(BASE_DIR),
            (),
        )

    def test_parser_upload_and_persistence_changes_are_rejected(self) -> None:
        mutations = (
            self.source.replace(
                "from dataclasses import dataclass",
                "from dataclasses import dataclass\nfrom django.http import HttpRequest",
            ),
            self.source.replace(
                "    def parses_http(self) -> bool:\n        return False",
                "    def parses_http(self) -> bool:\n        return True",
            ),
            self.source.replace(
                "    def installs_upload_handler(self) -> bool:\n"
                "        return False",
                "    def installs_upload_handler(self) -> bool:\n"
                "        return True",
            ),
            self.source.replace(
                "    def persists_plaintext(self) -> bool:\n        return False",
                "    def persists_plaintext(self) -> bool:\n        return True",
            ),
        )
        for source in mutations:
            with self.subTest(source=source[:80]):
                violations = analyze_request_admission_descriptor_source(
                    source=source
                )
                self.assertEqual(len(violations), 1)
                self.assertEqual(
                    violations[0].code,
                    RequestAdmissionDescriptorSourceViolationCode.SOURCE_PROFILE_MISMATCH,
                )

    def test_django_spooling_and_submission_enablement_are_rejected(self) -> None:
        mutations = (
            self.source.replace(
                "            default_django_memory_handler_allowed=False,",
                "            default_django_memory_handler_allowed=True,",
            ),
            self.source.replace(
                "            request_body_disk_spooling_allowed=False,",
                "            request_body_disk_spooling_allowed=True,",
            ),
            self.source.replace(
                "    def accepts_submission(self) -> bool:\n        return False",
                "    def accepts_submission(self) -> bool:\n        return True",
            ),
            self.source + "\nDYNAMIC = lambda request: request.body\n",
        )
        for source in mutations:
            with self.subTest(source=source[-80:]):
                violations = analyze_request_admission_descriptor_source(
                    source=source
                )
                self.assertEqual(len(violations), 1)
                self.assertEqual(
                    violations[0].code,
                    RequestAdmissionDescriptorSourceViolationCode.SOURCE_PROFILE_MISMATCH,
                )

    def test_target_parse_and_path_failures_are_controlled(self) -> None:
        wrong_target = analyze_request_admission_descriptor_source(
            source=self.source,
            relative_path="security_interfaces/other.py",
        )
        self.assertEqual(len(wrong_target), 1)
        self.assertEqual(
            wrong_target[0].code,
            RequestAdmissionDescriptorSourceViolationCode.TARGET_SET_MISMATCH,
        )

        parse_failure = analyze_request_admission_descriptor_source(
            source="def broken(\n"
        )
        self.assertEqual(len(parse_failure), 1)
        self.assertEqual(
            parse_failure[0].code,
            RequestAdmissionDescriptorSourceViolationCode.SOURCE_PARSE_ERROR,
        )

        with TemporaryDirectory() as temporary_directory:
            violations = scan_repository_request_admission_descriptor(
                Path(temporary_directory)
            )
        self.assertEqual(len(violations), 1)
        self.assertEqual(
            violations[0].code,
            RequestAdmissionDescriptorSourceViolationCode.SOURCE_PARSE_ERROR,
        )

        violations = scan_request_admission_descriptor_source(
            path=TARGET,
            relative_to=BASE_DIR / "tests",
        )
        self.assertEqual(len(violations), 1)
        self.assertEqual(violations[0].relative_path, "<invalid-scan-path>")

    def test_source_is_never_executed_or_echoed(self) -> None:
        sentinel = "REQUEST_ADMISSION_SENTINEL"
        violations = analyze_request_admission_descriptor_source(
            source=self.source + f"\nraise RuntimeError('{sentinel}')\n"
        )
        self.assertEqual(len(violations), 1)
        self.assertNotIn(sentinel, repr(violations))

        parse_violations = analyze_request_admission_descriptor_source(
            source=f"def broken({sentinel}\n"
        )
        self.assertEqual(len(parse_violations), 1)
        self.assertNotIn(sentinel, repr(parse_violations))
