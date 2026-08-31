"""Static abuse tests for the inert alert-v1 descriptor module."""

from pathlib import Path

from django.test import SimpleTestCase

from architecture_checks import (
    ALERT_DESCRIPTOR_PATH,
    DescriptorViolationCode,
    analyze_alert_descriptor_source,
    scan_alert_descriptor_source,
)


BASE_DIR = Path(__file__).resolve().parent.parent
TARGET = BASE_DIR / ALERT_DESCRIPTOR_PATH


class AlertDescriptorSourcePolicyTests(SimpleTestCase):
    @classmethod
    def setUpClass(cls) -> None:
        super().setUpClass()
        cls.source = TARGET.read_text(encoding="utf-8")

    def analyze(self, source: str):
        return analyze_alert_descriptor_source(source=source)

    def test_current_source_matches_the_exact_inert_profile(self) -> None:
        self.assertEqual(
            scan_alert_descriptor_source(path=TARGET, relative_to=BASE_DIR),
            (),
        )

    def test_import_registry_field_and_validator_changes_are_rejected(self) -> None:
        mutations = (
            self.source.replace(
                "from dataclasses import dataclass",
                "from dataclasses import dataclass\nimport smtplib",
            ),
            self.source.replace(
                '    SECURITY_CREDENTIAL_CHANGE = "SECURITY_CREDENTIAL_CHANGE"',
                '    SECURITY_CREDENTIAL_CHANGE = "SECURITY_CREDENTIAL_CHANGE"\n'
                '    CALLER_DEFINED = "CALLER_DEFINED"',
            ),
            self.source.replace(
                "    accepted_at_ms: int\n",
                "    accepted_at_ms: int\n    report_text: str\n",
                1,
            ),
            self.source.replace(
                "    if ALERT_SEVERITY_BY_TYPE[alert_type] != severity:",
                "    if False:",
            ),
        )
        for source in mutations:
            with self.subTest(source=source[:60]):
                self.assertEqual(
                    {item.code for item in self.analyze(source)},
                    {DescriptorViolationCode.MODULE_PROFILE_MISMATCH},
                )

    def test_success_delivery_side_effect_and_dynamic_behavior_are_rejected(
        self,
    ) -> None:
        mutations = (
            self.source.replace(
                "    def proves_durable_acceptance(self) -> bool:\n"
                "        return False",
                "    def proves_durable_acceptance(self) -> bool:\n"
                "        return True",
            ),
            self.source.replace(
                "def _reject() -> Never:\n",
                "def _reject() -> Never:\n    open('alert.queue', 'wb')\n",
            ),
            self.source + "\nDELIVER = lambda: True\n",
        )
        for source in mutations:
            with self.subTest(source=source[-60:]):
                self.assertEqual(
                    {item.code for item in self.analyze(source)},
                    {DescriptorViolationCode.MODULE_PROFILE_MISMATCH},
                )

    def test_target_parse_and_path_failures_are_controlled(self) -> None:
        wrong_target = analyze_alert_descriptor_source(
            source=self.source,
            relative_path="security_interfaces/other.py",
        )
        self.assertEqual(len(wrong_target), 1)
        self.assertEqual(
            wrong_target[0].code,
            DescriptorViolationCode.TARGET_SET_MISMATCH,
        )

        parse_failure = self.analyze("def broken(\n")
        self.assertEqual(len(parse_failure), 1)
        self.assertEqual(
            parse_failure[0].code,
            DescriptorViolationCode.SOURCE_PARSE_ERROR,
        )

        for path, root in (
            (BASE_DIR / "missing.py", BASE_DIR),
            (TARGET, BASE_DIR / "tests"),
        ):
            with self.subTest(path=path):
                violations = scan_alert_descriptor_source(
                    path=path,
                    relative_to=root,
                )
                self.assertEqual(len(violations), 1)
                self.assertEqual(
                    violations[0].code,
                    DescriptorViolationCode.SOURCE_PARSE_ERROR,
                )
                self.assertEqual(
                    violations[0].relative_path,
                    "<invalid-scan-path>",
                )

    def test_source_is_never_executed_or_echoed(self) -> None:
        sentinel = "REPORT_TEXT_SENTINEL"
        violations = self.analyze(
            self.source + f"\nraise RuntimeError('{sentinel}')\n"
        )
        self.assertTrue(violations)
        self.assertNotIn(sentinel, repr(violations))

        parse_violations = self.analyze(f"def broken({sentinel}\n")
        self.assertEqual(len(parse_violations), 1)
        self.assertNotIn(sentinel, repr(parse_violations))
