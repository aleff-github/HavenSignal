"""Static abuse tests for mandatory unavailable security controls."""

from dataclasses import FrozenInstanceError
from pathlib import Path

from django.test import SimpleTestCase

from architecture_checks import (
    NEGATIVE_CAPABILITY_SOURCE_DIGESTS,
    NegativeCapabilitySourceViolation,
    NegativeCapabilityViolationCode,
    analyze_negative_capability_source,
    scan_negative_capability_sources,
)


BASE_DIR = Path(__file__).resolve().parent.parent


class NegativeCapabilitySourcePolicyTests(SimpleTestCase):
    def source(self, relative_path: str) -> str:
        return (BASE_DIR / relative_path).read_text(encoding="utf-8")

    def test_current_sources_match_the_exact_fail_closed_profile(self) -> None:
        self.assertEqual(scan_negative_capability_sources(root=BASE_DIR), ())

    def test_unavailable_adapter_success_and_side_effects_are_rejected(self) -> None:
        relative_path = "security_interfaces/unavailable.py"
        source = self.source(relative_path)
        mutations = (
            source.replace(
                "    def _deny(self) -> Never:\n"
                "        raise SecurityControlUnavailable(self.dependency)",
                "    def _deny(self):\n        return True",
            ),
            source.replace(
                "    def _deny(self) -> Never:\n",
                "    def _deny(self) -> Never:\n        print(self.dependency)\n",
            ),
            source.replace(
                "from typing import ClassVar, Never",
                "from typing import ClassVar, Never\nimport logging",
            ),
            source
            + "\nclass DevelopmentKeyService:\n"
            + "    def decrypt_report(self):\n        return b'plaintext'\n",
        )
        for mutation in mutations:
            with self.subTest(mutation=mutation[-60:]):
                violations = analyze_negative_capability_source(
                    source=mutation,
                    relative_path=relative_path,
                )
                self.assertEqual(len(violations), 1)
                self.assertEqual(
                    violations[0].code,
                    NegativeCapabilityViolationCode.SOURCE_PROFILE_MISMATCH,
                )

    def test_dependency_and_controlled_error_changes_are_rejected(self) -> None:
        relative_path = "security_interfaces/errors.py"
        source = self.source(relative_path)
        mutations = (
            source.replace(
                'public_code = "security_control_unavailable"',
                'public_code = "key_service_unavailable"',
            ),
            source.replace(
                "        super().__init__(self.public_code)",
                "        super().__init__(str(dependency))",
                1,
            ),
            source.replace(
                '    STEP_UP_SERVICE = "step_up_service"',
                '    STEP_UP_SERVICE = "step_up_service"\n'
                '    PLAINTEXT_FALLBACK = "plaintext_fallback"',
            ),
        )
        for mutation in mutations:
            with self.subTest(mutation=mutation[-60:]):
                violations = analyze_negative_capability_source(
                    source=mutation,
                    relative_path=relative_path,
                )
                self.assertEqual(len(violations), 1)
                self.assertEqual(
                    violations[0].code,
                    NegativeCapabilityViolationCode.SOURCE_PROFILE_MISMATCH,
                )

    def test_unknown_target_parse_and_root_failures_are_controlled(self) -> None:
        unknown = analyze_negative_capability_source(
            source="pass",
            relative_path="security_interfaces/development_fallback.py",
        )
        self.assertEqual(len(unknown), 1)
        self.assertEqual(
            unknown[0].code,
            NegativeCapabilityViolationCode.TARGET_SET_MISMATCH,
        )

        sentinel = "REPORT_TEXT_SENTINEL"
        malformed = analyze_negative_capability_source(
            source=f"def broken({sentinel}\n",
            relative_path="security_interfaces/unavailable.py",
        )
        self.assertEqual(len(malformed), 1)
        self.assertEqual(
            malformed[0].code,
            NegativeCapabilityViolationCode.SOURCE_PARSE_ERROR,
        )
        self.assertNotIn(sentinel, repr(malformed))

        invalid_root = scan_negative_capability_sources(
            root=BASE_DIR / "missing-root"
        )
        self.assertEqual(len(invalid_root), 1)
        self.assertEqual(
            invalid_root[0].relative_path,
            "<invalid-scan-root>",
        )

    def test_source_is_never_executed_or_echoed(self) -> None:
        relative_path = "security_interfaces/unavailable.py"
        sentinel = "REPORT_TEXT_SENTINEL"
        source = self.source(relative_path) + f"\nraise RuntimeError('{sentinel}')\n"
        violations = analyze_negative_capability_source(
            source=source,
            relative_path=relative_path,
        )
        self.assertEqual(len(violations), 1)
        self.assertNotIn(sentinel, repr(violations))

    def test_policy_and_violation_contracts_are_immutable(self) -> None:
        with self.assertRaises(TypeError):
            NEGATIVE_CAPABILITY_SOURCE_DIGESTS["new.py"] = "digest"

        violation = NegativeCapabilitySourceViolation(
            code=NegativeCapabilityViolationCode.SOURCE_PROFILE_MISMATCH,
            relative_path="security_interfaces/unavailable.py",
            line=0,
            detail_code="EXACT_FAIL_CLOSED_EXECUTABLE_AST",
        )
        with self.assertRaises(FrozenInstanceError):
            violation.line = 1
