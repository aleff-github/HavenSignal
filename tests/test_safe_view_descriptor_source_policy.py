"""Static abuse tests for inert safe-view descriptors."""

from pathlib import Path
from tempfile import TemporaryDirectory

from django.test import SimpleTestCase

from architecture_checks import (
    SAFE_VIEW_DESCRIPTOR_PATH,
    SafeViewDescriptorSourceViolationCode,
    analyze_safe_view_descriptor_source,
    scan_repository_safe_view_descriptor,
    scan_safe_view_descriptor_source,
)


BASE_DIR = Path(__file__).resolve().parent.parent
TARGET = BASE_DIR / SAFE_VIEW_DESCRIPTOR_PATH


class SafeViewDescriptorSourcePolicyTests(SimpleTestCase):
    @classmethod
    def setUpClass(cls) -> None:
        super().setUpClass()
        cls.source = TARGET.read_text(encoding="utf-8")

    def test_current_source_matches_the_exact_inert_profile(self) -> None:
        self.assertEqual(scan_repository_safe_view_descriptor(BASE_DIR), ())

    def test_decrypt_render_sandbox_and_response_changes_are_rejected(
        self,
    ) -> None:
        mutations = (
            self.source.replace(
                "from dataclasses import dataclass",
                "from dataclasses import dataclass\nfrom PIL import Image",
            ),
            self.source.replace(
                "    def decrypts_attachment(self) -> bool:\n        return False",
                "    def decrypts_attachment(self) -> bool:\n        return True",
            ),
            self.source.replace(
                "    def calls_sandbox(self) -> bool:\n        return False",
                "    def calls_sandbox(self) -> bool:\n        return True",
            ),
            self.source.replace(
                "    def serves_response(self) -> bool:\n        return False",
                "    def serves_response(self) -> bool:\n        return True",
            ),
        )
        for source in mutations:
            with self.subTest(source=source[:80]):
                violations = analyze_safe_view_descriptor_source(source=source)
                self.assertEqual(len(violations), 1)
                self.assertEqual(
                    violations[0].code,
                    SafeViewDescriptorSourceViolationCode.SOURCE_PROFILE_MISMATCH,
                )

    def test_persistence_download_and_authorization_changes_are_rejected(
        self,
    ) -> None:
        mutations = (
            self.source.replace(
                "            range_requests_allowed=False,",
                "            range_requests_allowed=True,",
            ),
            self.source.replace(
                "            ordinary_original_download_allowed=False,",
                "            ordinary_original_download_allowed=True,",
            ),
            self.source.replace(
                "    def authorizes_operator_access(self) -> bool:\n"
                "        return False",
                "    def authorizes_operator_access(self) -> bool:\n"
                "        return True",
            ),
            self.source + "\nDYNAMIC = lambda safe_png: safe_png\n",
        )
        for source in mutations:
            with self.subTest(source=source[-80:]):
                violations = analyze_safe_view_descriptor_source(source=source)
                self.assertEqual(len(violations), 1)
                self.assertEqual(
                    violations[0].code,
                    SafeViewDescriptorSourceViolationCode.SOURCE_PROFILE_MISMATCH,
                )

    def test_target_parse_and_path_failures_are_controlled(self) -> None:
        wrong_target = analyze_safe_view_descriptor_source(
            source=self.source,
            relative_path="security_interfaces/other.py",
        )
        self.assertEqual(len(wrong_target), 1)
        self.assertEqual(
            wrong_target[0].code,
            SafeViewDescriptorSourceViolationCode.TARGET_SET_MISMATCH,
        )

        parse_failure = analyze_safe_view_descriptor_source(
            source="def broken(\n"
        )
        self.assertEqual(len(parse_failure), 1)
        self.assertEqual(
            parse_failure[0].code,
            SafeViewDescriptorSourceViolationCode.SOURCE_PARSE_ERROR,
        )

        with TemporaryDirectory() as temporary_directory:
            violations = scan_repository_safe_view_descriptor(
                Path(temporary_directory)
            )
        self.assertEqual(len(violations), 1)
        self.assertEqual(
            violations[0].code,
            SafeViewDescriptorSourceViolationCode.SOURCE_PARSE_ERROR,
        )

        violations = scan_safe_view_descriptor_source(
            path=TARGET,
            relative_to=BASE_DIR / "tests",
        )
        self.assertEqual(len(violations), 1)
        self.assertEqual(violations[0].relative_path, "<invalid-scan-path>")

    def test_source_is_never_executed_or_echoed(self) -> None:
        sentinel = "SAFE_VIEW_SENTINEL"
        violations = analyze_safe_view_descriptor_source(
            source=self.source + f"\nraise RuntimeError('{sentinel}')\n"
        )
        self.assertEqual(len(violations), 1)
        self.assertNotIn(sentinel, repr(violations))

        parse_violations = analyze_safe_view_descriptor_source(
            source=f"def broken({sentinel}\n"
        )
        self.assertEqual(len(parse_violations), 1)
        self.assertNotIn(sentinel, repr(parse_violations))
