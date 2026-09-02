"""Static abuse tests for application package initializers."""

from dataclasses import FrozenInstanceError
from pathlib import Path
from tempfile import TemporaryDirectory

from django.test import SimpleTestCase

from architecture_checks import (
    EXPECTED_INITIALIZER_SOURCE_AST_DIGESTS,
    InitializerSourceViolation,
    InitializerSourceViolationCode,
    analyze_initializer_source,
    scan_initializer_sources,
)


BASE_DIR = Path(__file__).resolve().parent.parent


class InitializerSourcePolicyTests(SimpleTestCase):
    @classmethod
    def setUpClass(cls) -> None:
        super().setUpClass()
        cls.sources = {
            relative_path: (BASE_DIR / relative_path).read_text(encoding="utf-8")
            for relative_path in EXPECTED_INITIALIZER_SOURCE_AST_DIGESTS
        }

    def mutate(self, relative_path: str, suffix: str) -> None:
        violations = analyze_initializer_source(
            source=self.sources[relative_path] + suffix,
            relative_path=relative_path,
        )
        self.assertEqual(len(violations), 1)
        self.assertEqual(
            violations[0].code,
            InitializerSourceViolationCode.SOURCE_PROFILE_MISMATCH,
        )

    def test_current_sources_match_the_exact_reviewed_profiles(self) -> None:
        self.assertEqual(scan_initializer_sources(repository_root=BASE_DIR), ())

    def test_passive_package_side_effects_are_rejected(self) -> None:
        passive_targets = (
            "anonymous_reporting/__init__.py",
            "operator_console/__init__.py",
            "recovery_gateway/__init__.py",
            "report_lifecycle/__init__.py",
            "reporter_gateway/__init__.py",
            "submission_workflow/__init__.py",
        )
        suffixes = (
            "\nimport logging\n",
            "\nimport socket\n",
            "\nopen('package.log', 'w')\n",
            "\nDYNAMIC = lambda: True\n",
            "\nfrom django.conf import settings\n",
            "\nfrom pathlib import Path\n",
        )
        for relative_path, suffix in zip(passive_targets, suffixes, strict=True):
            with self.subTest(relative_path=relative_path):
                self.mutate(relative_path, suffix)

    def test_migration_initializer_code_is_rejected(self) -> None:
        for relative_path in (
            "report_lifecycle/migrations/__init__.py",
            "submission_workflow/migrations/__init__.py",
        ):
            with self.subTest(relative_path=relative_path):
                self.mutate(relative_path, "raise RuntimeError('MUST_NOT_RUN')\n")

    def test_security_interface_import_and_export_changes_are_rejected(self) -> None:
        relative_path = "security_interfaces/__init__.py"
        source = self.sources[relative_path]
        mutations = (
            source.replace(
                "from .unavailable import (",
                "from .production import ProductionKeyService\n"
                "from .unavailable import (",
                1,
            ),
            source.replace(
                '    "UnavailableKeyService",',
                '    "ProductionKeyService",\n    "UnavailableKeyService",',
                1,
            ),
            source + "\nopen('security-interface.log', 'w')\n",
        )
        for mutated in mutations:
            with self.subTest(source=mutated[-80:]):
                violations = analyze_initializer_source(
                    source=mutated,
                    relative_path=relative_path,
                )
                self.assertEqual(len(violations), 1)
                self.assertEqual(
                    violations[0].code,
                    InitializerSourceViolationCode.SOURCE_PROFILE_MISMATCH,
                )

    def test_unknown_parse_and_missing_root_failures_are_controlled(self) -> None:
        unknown = analyze_initializer_source(
            source="raise RuntimeError('MUST_NOT_RUN')",
            relative_path="unknown/__init__.py",
        )
        self.assertEqual(len(unknown), 1)
        self.assertEqual(
            unknown[0].code,
            InitializerSourceViolationCode.TARGET_SET_MISMATCH,
        )

        parse_failure = analyze_initializer_source(
            source="def broken(\n",
            relative_path="anonymous_reporting/__init__.py",
        )
        self.assertEqual(len(parse_failure), 1)
        self.assertEqual(
            parse_failure[0].code,
            InitializerSourceViolationCode.SOURCE_PARSE_ERROR,
        )

        with TemporaryDirectory() as temporary_directory:
            violations = scan_initializer_sources(
                repository_root=Path(temporary_directory),
            )
        self.assertEqual(
            len(violations),
            len(EXPECTED_INITIALIZER_SOURCE_AST_DIGESTS),
        )
        self.assertEqual(
            {item.code for item in violations},
            {InitializerSourceViolationCode.SOURCE_PARSE_ERROR},
        )

    def test_source_is_never_executed_or_echoed(self) -> None:
        sentinel = "REPORT_TEXT_SENTINEL"
        relative_path = "reporter_gateway/__init__.py"
        violations = analyze_initializer_source(
            source=self.sources[relative_path]
            + f"\nraise RuntimeError('{sentinel}')\n",
            relative_path=relative_path,
        )
        self.assertTrue(violations)
        self.assertNotIn(sentinel, repr(violations))

        parse_violations = analyze_initializer_source(
            source=f"def broken({sentinel}\n",
            relative_path=relative_path,
        )
        self.assertEqual(len(parse_violations), 1)
        self.assertNotIn(sentinel, repr(parse_violations))

    def test_policy_and_violation_are_immutable(self) -> None:
        with self.assertRaises(TypeError):
            EXPECTED_INITIALIZER_SOURCE_AST_DIGESTS[
                "anonymous_reporting/__init__.py"
            ] = "weakened"

        violation = InitializerSourceViolation(
            code=InitializerSourceViolationCode.SOURCE_PROFILE_MISMATCH,
            relative_path="anonymous_reporting/__init__.py",
            line=0,
            detail_code="EXECUTABLE_AST",
        )
        with self.assertRaises(FrozenInstanceError):
            violation.line = 1
