"""Static conformance tests for the inert submission migration graph."""

from io import StringIO
from pathlib import Path
from tempfile import TemporaryDirectory

from django.core.management import call_command
from django.test import SimpleTestCase, TestCase

from architecture_checks import (
    EXPECTED_SUBMISSION_MIGRATION_FIELDS,
    SUBMISSION_MIGRATION_PATH,
    MigrationViolationCode,
    analyze_submission_migration_source,
    scan_submission_migrations,
)


BASE_DIR = Path(__file__).resolve().parent.parent
MIGRATION_PATH = BASE_DIR / SUBMISSION_MIGRATION_PATH


class CurrentSubmissionMigrationPolicyTests(TestCase):
    def test_current_graph_matches_the_exact_inert_profile(self) -> None:
        self.assertEqual(
            scan_submission_migrations(
                migrations_root=MIGRATION_PATH.parent,
                relative_to=BASE_DIR,
            ),
            (),
        )

    def test_models_have_no_uncommitted_migration_drift(self) -> None:
        output = StringIO()
        call_command(
            "makemigrations",
            "submission_workflow",
            check=True,
            dry_run=True,
            stdout=output,
            verbosity=1,
        )
        self.assertIn("No changes detected", output.getvalue())

    def test_expected_fields_are_exact_content_free_and_immutable(self) -> None:
        self.assertEqual(
            EXPECTED_SUBMISSION_MIGRATION_FIELDS,
            {
                "SubmissionAttempt": (
                    "id",
                    "state",
                    "state_version",
                    "created_at",
                    "last_progress_at",
                    "accepted_at",
                    "aborting_at",
                    "aborted_at",
                )
            },
        )
        prohibited_fragments = {
            "attachment",
            "body",
            "content",
            "credential",
            "filename",
            "header",
            "ip",
            "key",
            "recovery",
            "report",
            "secret",
            "ticket",
            "user_agent",
            "verifier",
        }
        field_names = EXPECTED_SUBMISSION_MIGRATION_FIELDS["SubmissionAttempt"]
        for field_name in field_names:
            self.assertFalse(
                any(item in field_name.lower() for item in prohibited_fragments)
            )
        with self.assertRaises(TypeError):
            EXPECTED_SUBMISSION_MIGRATION_FIELDS["SubmissionAttempt"] = (
                "report_text",
            )


class SubmissionMigrationAbuseTests(SimpleTestCase):
    @classmethod
    def setUpClass(cls) -> None:
        super().setUpClass()
        cls.source = MIGRATION_PATH.read_text(encoding="utf-8")

    def analyze(self, source: str):
        return analyze_submission_migration_source(source=source)

    def test_schema_state_constraint_and_graph_changes_are_rejected(self) -> None:
        mutations = (
            self.source.replace(
                '                (\n                    "state_version",',
                '                ("report_text", models.TextField()),\n'
                '                (\n                    "state_version",',
                1,
            ),
            self.source.replace('("READY", "Ready"),', "", 1),
            self.source.replace(
                'name="submission_attempt_known_state"',
                'name="weakened_state_constraint"',
                1,
            ),
            self.source.replace("dependencies = []", "dependencies = [('x', '0001')]"),
        )
        for source in mutations:
            with self.subTest(source=source[:80]):
                violations = self.analyze(source)
                self.assertEqual(len(violations), 1)
                self.assertEqual(
                    violations[0].code,
                    MigrationViolationCode.MIGRATION_GRAPH_MISMATCH,
                )

    def test_import_data_sql_dynamic_and_execution_changes_are_rejected(self) -> None:
        mutations = (
            "import logging\n" + self.source,
            self.source.replace(
                "    operations = [",
                "    operations = [migrations.RunPython(run_unreviewed),",
                1,
            ),
            self.source.replace(
                "    operations = [",
                "    operations = [migrations.RunSQL('SELECT 1'),",
                1,
            ),
            self.source + "\nDYNAMIC = lambda: True\n",
            self.source + "\nraise RuntimeError('MUST_NOT_RUN')\n",
        )
        for source in mutations:
            with self.subTest(source=source[-80:]):
                self.assertTrue(self.analyze(source))

    def test_target_parse_and_path_failures_are_controlled(self) -> None:
        wrong_target = analyze_submission_migration_source(
            source=self.source,
            relative_path="other/migrations/0001_initial.py",
        )
        self.assertEqual(len(wrong_target), 1)
        self.assertEqual(
            wrong_target[0].code,
            MigrationViolationCode.MIGRATION_GRAPH_MISMATCH,
        )

        parse_failure = self.analyze("class Migration(\n")
        self.assertEqual(len(parse_failure), 1)
        self.assertEqual(
            parse_failure[0].code,
            MigrationViolationCode.SOURCE_PARSE_ERROR,
        )

        outside = scan_submission_migrations(
            migrations_root=MIGRATION_PATH.parent,
            relative_to=BASE_DIR / "tests",
        )
        self.assertEqual(len(outside), 1)
        self.assertEqual(
            outside[0].code,
            MigrationViolationCode.SOURCE_PARSE_ERROR,
        )

    def test_additional_numbered_migration_is_rejected(self) -> None:
        with TemporaryDirectory(dir=BASE_DIR) as temporary_directory:
            temporary_root = Path(temporary_directory)
            repository_root = temporary_root / "repository"
            migrations = (
                repository_root / "submission_workflow" / "migrations"
            )
            migrations.mkdir(parents=True)
            (migrations / "0001_initial.py").write_text(
                self.source,
                encoding="utf-8",
            )
            (migrations / "0002_unreviewed.py").write_text(
                "raise RuntimeError('MUST_NOT_RUN')\n",
                encoding="utf-8",
            )
            violations = scan_submission_migrations(
                migrations_root=migrations,
                relative_to=repository_root,
            )
        self.assertEqual(len(violations), 1)
        self.assertEqual(
            violations[0].detail_code,
            "NUMBERED_FILE_SET",
        )

    def test_source_is_never_executed_or_echoed(self) -> None:
        sentinel = "REPORT_TEXT_SENTINEL"
        violations = self.analyze(
            self.source + f"\nraise RuntimeError('{sentinel}')\n"
        )
        self.assertTrue(violations)
        self.assertNotIn(sentinel, repr(violations))

        parse_violations = self.analyze(f"class Migration({sentinel}\n")
        self.assertEqual(len(parse_violations), 1)
        self.assertNotIn(sentinel, repr(parse_violations))
