"""Static abuse tests for the inert Django bootstrap source."""

from dataclasses import FrozenInstanceError
from pathlib import Path
from tempfile import TemporaryDirectory

from django.test import SimpleTestCase

from architecture_checks import (
    EXPECTED_BOOTSTRAP_SOURCE_AST_DIGESTS,
    BootstrapSourceViolation,
    BootstrapSourceViolationCode,
    analyze_bootstrap_source,
    scan_bootstrap_sources,
)


BASE_DIR = Path(__file__).resolve().parent.parent


class BootstrapSourcePolicyTests(SimpleTestCase):
    @classmethod
    def setUpClass(cls) -> None:
        super().setUpClass()
        cls.sources = {
            relative_path: (BASE_DIR / relative_path).read_text(encoding="utf-8")
            for relative_path in EXPECTED_BOOTSTRAP_SOURCE_AST_DIGESTS
        }

    def mutate(self, relative_path: str, old: str, new: str) -> None:
        source = self.sources[relative_path]
        mutated = source.replace(old, new, 1)
        self.assertNotEqual(mutated, source)
        violations = analyze_bootstrap_source(
            source=mutated,
            relative_path=relative_path,
        )
        self.assertEqual(len(violations), 1)
        self.assertEqual(
            violations[0].code,
            BootstrapSourceViolationCode.SOURCE_PROFILE_MISMATCH,
        )

    def test_current_sources_match_the_exact_inert_profiles(self) -> None:
        self.assertEqual(scan_bootstrap_sources(repository_root=BASE_DIR), ())

    def test_management_entrypoint_changes_are_rejected(self) -> None:
        relative_path = "manage.py"
        mutations = (
            (
                '"anonymous_reporting.settings"',
                '"unreviewed.production_settings"',
            ),
            (
                "import os",
                "import logging\nimport os",
            ),
            (
                "    execute_from_command_line(sys.argv)",
                "    open('bootstrap.log', 'w')\n"
                "    execute_from_command_line(sys.argv)",
            ),
            (
                'if __name__ == "__main__":',
                "if True:",
            ),
        )
        for old, new in mutations:
            with self.subTest(new=new):
                self.mutate(relative_path, old, new)

    def test_asgi_and_wsgi_initialization_changes_are_rejected(self) -> None:
        for relative_path, getter in (
            ("anonymous_reporting/asgi.py", "get_asgi_application"),
            ("anonymous_reporting/wsgi.py", "get_wsgi_application"),
        ):
            mutations = (
                (
                    '"anonymous_reporting.settings"',
                    '"unreviewed.production_settings"',
                ),
                (
                    "import os",
                    "import socket\nimport os",
                ),
                (
                    f"application = {getter}()",
                    f"application = wrap_unreviewed({getter}())",
                ),
            )
            for old, new in mutations:
                with self.subTest(relative_path=relative_path, new=new):
                    self.mutate(relative_path, old, new)

    def test_app_config_identity_and_ready_hooks_are_rejected(self) -> None:
        mutations = (
            (
                "submission_workflow/apps.py",
                'name = "submission_workflow"',
                'name = "unreviewed_submission"',
            ),
            (
                "report_lifecycle/apps.py",
                'default_auto_field = "django.db.models.BigAutoField"',
                'default_auto_field = "django.db.models.AutoField"',
            ),
            (
                "report_lifecycle/apps.py",
                '    verbose_name = "Report lifecycle metadata"',
                '    verbose_name = "Report lifecycle metadata"\n\n'
                "    def ready(self):\n"
                "        open('ready.log', 'w')",
            ),
        )
        for relative_path, old, new in mutations:
            with self.subTest(relative_path=relative_path, new=new):
                self.mutate(relative_path, old, new)

    def test_unknown_parse_and_missing_root_failures_are_controlled(self) -> None:
        unknown = analyze_bootstrap_source(
            source="raise RuntimeError('MUST_NOT_RUN')",
            relative_path="anonymous_reporting/startup.py",
        )
        self.assertEqual(len(unknown), 1)
        self.assertEqual(
            unknown[0].code,
            BootstrapSourceViolationCode.TARGET_SET_MISMATCH,
        )

        parse_failure = analyze_bootstrap_source(
            source="def broken(\n",
            relative_path="manage.py",
        )
        self.assertEqual(len(parse_failure), 1)
        self.assertEqual(
            parse_failure[0].code,
            BootstrapSourceViolationCode.SOURCE_PARSE_ERROR,
        )

        with TemporaryDirectory() as temporary_directory:
            violations = scan_bootstrap_sources(
                repository_root=Path(temporary_directory),
            )
        self.assertEqual(
            len(violations),
            len(EXPECTED_BOOTSTRAP_SOURCE_AST_DIGESTS),
        )
        self.assertEqual(
            {item.code for item in violations},
            {BootstrapSourceViolationCode.SOURCE_PARSE_ERROR},
        )

    def test_source_is_never_executed_or_echoed(self) -> None:
        sentinel = "REPORT_TEXT_SENTINEL"
        relative_path = "anonymous_reporting/asgi.py"
        violations = analyze_bootstrap_source(
            source=self.sources[relative_path]
            + f"\nraise RuntimeError('{sentinel}')\n",
            relative_path=relative_path,
        )
        self.assertTrue(violations)
        self.assertNotIn(sentinel, repr(violations))

        parse_violations = analyze_bootstrap_source(
            source=f"def broken({sentinel}\n",
            relative_path=relative_path,
        )
        self.assertEqual(len(parse_violations), 1)
        self.assertNotIn(sentinel, repr(parse_violations))

    def test_policy_and_violation_are_immutable(self) -> None:
        with self.assertRaises(TypeError):
            EXPECTED_BOOTSTRAP_SOURCE_AST_DIGESTS["manage.py"] = "weakened"

        violation = BootstrapSourceViolation(
            code=BootstrapSourceViolationCode.SOURCE_PROFILE_MISMATCH,
            relative_path="manage.py",
            line=0,
            detail_code="EXECUTABLE_AST",
        )
        with self.assertRaises(FrozenInstanceError):
            violation.line = 1
