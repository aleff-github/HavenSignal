"""Static abuse tests for inert no-JavaScript CAPTCHA descriptors."""

from pathlib import Path
from tempfile import TemporaryDirectory

from django.test import SimpleTestCase

from architecture_checks import (
    CAPTCHA_DESCRIPTOR_PATH,
    CaptchaDescriptorSourceViolationCode,
    analyze_captcha_descriptor_source,
    scan_captcha_descriptor_source,
    scan_repository_captcha_descriptor,
)


BASE_DIR = Path(__file__).resolve().parent.parent
TARGET = BASE_DIR / CAPTCHA_DESCRIPTOR_PATH


class CaptchaDescriptorSourcePolicyTests(SimpleTestCase):
    @classmethod
    def setUpClass(cls) -> None:
        super().setUpClass()
        cls.source = TARGET.read_text(encoding="utf-8")

    def test_current_source_matches_the_exact_inert_profile(self) -> None:
        self.assertEqual(scan_repository_captcha_descriptor(BASE_DIR), ())

    def test_generation_storage_and_validation_changes_are_rejected(self) -> None:
        mutations = (
            self.source.replace(
                "import base64",
                "import base64\nimport secrets",
            ),
            self.source.replace(
                "    def generates_challenge(self) -> bool:\n        return False",
                "    def generates_challenge(self) -> bool:\n        return True",
            ),
            self.source.replace(
                "    def persists_challenge_record(self) -> bool:\n"
                "        return False",
                "    def persists_challenge_record(self) -> bool:\n"
                "        return True",
            ),
            self.source.replace(
                "    def validates_answer(self) -> bool:\n        return False",
                "    def validates_answer(self) -> bool:\n        return True",
            ),
        )
        for source in mutations:
            with self.subTest(source=source[:80]):
                violations = analyze_captcha_descriptor_source(source=source)
                self.assertEqual(len(violations), 1)
                self.assertEqual(
                    violations[0].code,
                    CaptchaDescriptorSourceViolationCode.SOURCE_PROFILE_MISMATCH,
                )

    def test_tracking_third_party_and_enablement_changes_are_rejected(self) -> None:
        mutations = (
            self.source.replace(
                "    def binds_to_network_identity(self) -> bool:\n"
                "        return False",
                "    def binds_to_network_identity(self) -> bool:\n"
                "        return True",
            ),
            self.source.replace(
                "    def uses_third_party_captcha(self) -> bool:\n"
                "        return False",
                "    def uses_third_party_captcha(self) -> bool:\n"
                "        return True",
            ),
            self.source.replace(
                "    def enables_protected_endpoint(self) -> bool:\n"
                "        return False",
                "    def enables_protected_endpoint(self) -> bool:\n"
                "        return True",
            ),
            self.source.replace(
                "            production_enabled=False,",
                "            production_enabled=True,",
            ),
        )
        for source in mutations:
            with self.subTest(source=source[-80:]):
                violations = analyze_captcha_descriptor_source(source=source)
                self.assertEqual(len(violations), 1)
                self.assertEqual(
                    violations[0].code,
                    CaptchaDescriptorSourceViolationCode.SOURCE_PROFILE_MISMATCH,
                )

    def test_target_parse_and_path_failures_are_controlled(self) -> None:
        wrong_target = analyze_captcha_descriptor_source(
            source=self.source,
            relative_path="security_interfaces/other.py",
        )
        self.assertEqual(len(wrong_target), 1)
        self.assertEqual(
            wrong_target[0].code,
            CaptchaDescriptorSourceViolationCode.TARGET_SET_MISMATCH,
        )

        parse_failure = analyze_captcha_descriptor_source(
            source="def broken(\n"
        )
        self.assertEqual(len(parse_failure), 1)
        self.assertEqual(
            parse_failure[0].code,
            CaptchaDescriptorSourceViolationCode.SOURCE_PARSE_ERROR,
        )

        with TemporaryDirectory() as temporary_directory:
            violations = scan_repository_captcha_descriptor(
                Path(temporary_directory)
            )
        self.assertEqual(len(violations), 1)
        self.assertEqual(
            violations[0].code,
            CaptchaDescriptorSourceViolationCode.SOURCE_PARSE_ERROR,
        )

        violations = scan_captcha_descriptor_source(
            path=TARGET,
            relative_to=BASE_DIR / "tests",
        )
        self.assertEqual(len(violations), 1)
        self.assertEqual(violations[0].relative_path, "<invalid-scan-path>")

    def test_source_is_never_executed_or_echoed(self) -> None:
        sentinel = "CAPTCHA_SENTINEL"
        violations = analyze_captcha_descriptor_source(
            source=self.source + f"\nraise RuntimeError('{sentinel}')\n"
        )
        self.assertEqual(len(violations), 1)
        self.assertNotIn(sentinel, repr(violations))

        parse_violations = analyze_captcha_descriptor_source(
            source=f"def broken({sentinel}\n"
        )
        self.assertEqual(len(parse_violations), 1)
        self.assertNotIn(sentinel, repr(parse_violations))
