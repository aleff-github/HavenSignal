"""Static abuse tests for the inert administrative step-up foundations."""

from dataclasses import FrozenInstanceError
from pathlib import Path

from django.test import SimpleTestCase

from architecture_checks import (
    ADMINISTRATIVE_STEP_UP_DESCRIPTOR_PATH,
    DescriptorSourceViolation,
    DescriptorViolationCode,
    analyze_administrative_step_up_descriptor_source,
    scan_administrative_step_up_descriptor_source,
)


BASE_DIR = Path(__file__).resolve().parent.parent
TARGET = BASE_DIR / ADMINISTRATIVE_STEP_UP_DESCRIPTOR_PATH


class AdministrativeStepUpSourcePolicyTests(SimpleTestCase):
    @classmethod
    def setUpClass(cls) -> None:
        super().setUpClass()
        cls.source = TARGET.read_text(encoding="utf-8")

    def analyze(self, source: str):
        return analyze_administrative_step_up_descriptor_source(source=source)

    def test_current_source_matches_the_exact_inert_profile(self) -> None:
        self.assertEqual(
            scan_administrative_step_up_descriptor_source(
                path=TARGET,
                relative_to=BASE_DIR,
            ),
            (),
        )

    def test_new_imports_and_nested_imports_are_rejected(self) -> None:
        sources = (
            self.source.replace(
                "from dataclasses import dataclass",
                "from dataclasses import dataclass\nimport socket",
            ),
            self.source.replace(
                "def _reject() -> Never:\n",
                "def _reject() -> Never:\n    import logging\n",
            ),
        )
        for source in sources:
            with self.subTest(source=source[:40]):
                codes = {item.code for item in self.analyze(source)}
                self.assertIn(
                    DescriptorViolationCode.IMPORT_PROFILE_MISMATCH,
                    codes,
                )

    def test_version_and_ttl_are_exact_source_contracts(self) -> None:
        replacements = (
            (
                "ADMINISTRATIVE_STEP_UP_PROTOCOL_VERSION = 2",
                "ADMINISTRATIVE_STEP_UP_PROTOCOL_VERSION = 3",
            ),
            (
                "ADMINISTRATIVE_STEP_UP_TTL_MS = 120 * 1000",
                "ADMINISTRATIVE_STEP_UP_TTL_MS = 121 * 1000",
            ),
            (
                "ADMINISTRATIVE_STEP_UP_TTL_MS = 120 * 1000",
                "ADMINISTRATIVE_STEP_UP_TTL_MS = 120000",
            ),
        )
        for old, new in replacements:
            with self.subTest(new=new):
                codes = {
                    item.code
                    for item in self.analyze(self.source.replace(old, new))
                }
                self.assertIn(
                    DescriptorViolationCode.CONSTANT_PROFILE_MISMATCH,
                    codes,
                )

    def test_class_fields_immutability_and_false_capabilities_are_locked(
        self,
    ) -> None:
        mutations = (
            self.source.replace(
                "    device_id: bytes\n",
                "    device_id: bytes\n    report_id: bytes\n",
                1,
            ),
            self.source.replace(
                "@dataclass(frozen=True, slots=True)\nclass AdministrativeStepUpIdentityV2",
                "@dataclass(slots=True)\nclass AdministrativeStepUpIdentityV2",
            ),
            self.source.replace(
                "    def verifies_webauthn(self) -> bool:\n        return False",
                "    def verifies_webauthn(self) -> bool:\n        return True",
            ),
            self.source.replace(
                "    consumed_at: None = None",
                "    consumed_at: object = None",
            ),
        )
        for source in mutations:
            with self.subTest(source=source[:40]):
                codes = {item.code for item in self.analyze(source)}
                self.assertIn(
                    DescriptorViolationCode.CLASS_PROFILE_MISMATCH,
                    codes,
                )

    def test_validator_logic_and_member_set_are_locked(self) -> None:
        mutations = (
            self.source.replace(
                "    if type(value) is not bytes or len(value) != size:",
                "    if type(value) is not bytes:",
            ),
            self.source.replace(
                "def _require_uint(value: object) -> int:",
                "def _require_counter(value: object) -> int:",
            ),
            self.source + "\ndef authenticate_administrator():\n    return True\n",
        )
        for source in mutations:
            with self.subTest(source=source[-50:]):
                codes = {item.code for item in self.analyze(source)}
                self.assertTrue(
                    {
                        DescriptorViolationCode.FUNCTION_PROFILE_MISMATCH,
                        DescriptorViolationCode.MODULE_PROFILE_MISMATCH,
                    }
                    & codes
                )

    def test_effectful_calls_and_dynamic_constructs_are_rejected(self) -> None:
        call_source = self.source.replace(
            "def _reject() -> Never:\n",
            "def _reject() -> Never:\n    open('authorization.db', 'wb')\n",
        )
        call_codes = {item.code for item in self.analyze(call_source)}
        self.assertIn(
            DescriptorViolationCode.CALL_PROFILE_MISMATCH,
            call_codes,
        )

        dynamic_source = self.source + "\nDYNAMIC = lambda: True\n"
        dynamic_codes = {item.code for item in self.analyze(dynamic_source)}
        self.assertIn(DescriptorViolationCode.DYNAMIC_CONSTRUCT, dynamic_codes)
        self.assertIn(
            DescriptorViolationCode.MODULE_PROFILE_MISMATCH,
            dynamic_codes,
        )

    def test_target_parse_and_path_failures_are_controlled(self) -> None:
        wrong_target = analyze_administrative_step_up_descriptor_source(
            source=self.source,
            relative_path="security_interfaces/other.py",
        )
        self.assertEqual(len(wrong_target), 1)
        self.assertEqual(
            wrong_target[0].code,
            DescriptorViolationCode.TARGET_SET_MISMATCH,
        )

        for path, root in (
            (BASE_DIR / "missing.py", BASE_DIR),
            (TARGET, BASE_DIR / "tests"),
        ):
            with self.subTest(path=path):
                violations = scan_administrative_step_up_descriptor_source(
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
        source = self.source + f"\nraise RuntimeError('{sentinel}')\n"
        violations = self.analyze(source)
        self.assertTrue(violations)
        self.assertNotIn(sentinel, repr(violations))

        parse_violations = self.analyze(f"def broken({sentinel}\n")
        self.assertEqual(len(parse_violations), 1)
        self.assertEqual(
            parse_violations[0].code,
            DescriptorViolationCode.SOURCE_PARSE_ERROR,
        )
        self.assertNotIn(sentinel, repr(parse_violations))

    def test_violation_contract_is_immutable(self) -> None:
        violation = DescriptorSourceViolation(
            code=DescriptorViolationCode.DYNAMIC_CONSTRUCT,
            relative_path=ADMINISTRATIVE_STEP_UP_DESCRIPTOR_PATH,
            line=1,
            detail_code="LAMBDA",
        )
        with self.assertRaises(FrozenInstanceError):
            violation.line = 2
