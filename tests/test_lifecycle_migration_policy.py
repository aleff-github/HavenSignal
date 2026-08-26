"""Static and drift checks for the inert lifecycle migration graph."""

from dataclasses import FrozenInstanceError
from io import StringIO
from pathlib import Path
from tempfile import TemporaryDirectory

from django.core.management import call_command
from django.test import SimpleTestCase, TestCase

from architecture_checks import (
    EXPECTED_LIFECYCLE_MIGRATION_FIELDS,
    MigrationViolation,
    MigrationViolationCode,
    analyze_lifecycle_migration_source,
    scan_lifecycle_migrations,
)


BASE_DIR = Path(__file__).resolve().parent.parent
MIGRATION_PATH = BASE_DIR / "report_lifecycle" / "migrations" / "0001_initial.py"


class CurrentLifecycleMigrationPolicyTests(TestCase):
    def test_current_migration_graph_matches_the_inert_profile(self) -> None:
        violations = scan_lifecycle_migrations(
            migrations_root=BASE_DIR / "report_lifecycle" / "migrations",
            relative_to=BASE_DIR,
        )
        self.assertEqual(violations, ())

    def test_models_have_no_uncommitted_migration_drift(self) -> None:
        output = StringIO()
        call_command(
            "makemigrations",
            "report_lifecycle",
            check=True,
            dry_run=True,
            stdout=output,
            verbosity=1,
        )
        self.assertIn("No changes detected", output.getvalue())

    def test_expected_field_profile_is_exact_and_immutable(self) -> None:
        self.assertEqual(
            set(EXPECTED_LIFECYCLE_MIGRATION_FIELDS),
            {"Report", "ReportLease", "SecurityOperation"},
        )
        prohibited = {
            "attachment",
            "content",
            "filename",
            "header",
            "key",
            "note",
            "request",
            "secret",
            "text",
            "verifier",
        }
        field_names = {
            field_name
            for profile in EXPECTED_LIFECYCLE_MIGRATION_FIELDS.values()
            for field_name in profile
        }
        self.assertTrue(field_names.isdisjoint(prohibited))
        with self.assertRaises(TypeError):
            EXPECTED_LIFECYCLE_MIGRATION_FIELDS["Report"] = ("id", "text")


class LifecycleMigrationAbuseTests(SimpleTestCase):
    def setUp(self) -> None:
        self.source = MIGRATION_PATH.read_text(encoding="utf-8")

    def analyze(self, source: str):
        return analyze_lifecycle_migration_source(
            source=source,
            relative_path="report_lifecycle/migrations/0001_initial.py",
        )

    def test_data_code_and_sql_operations_are_rejected(self) -> None:
        for operation in ("RunPython", "RunSQL", "SeparateDatabaseAndState"):
            source = self.source.replace(
                "migrations.AddIndex(",
                f"migrations.{operation}(",
                1,
            )
            with self.subTest(operation=operation):
                violations = self.analyze(source)
                self.assertIn(
                    MigrationViolationCode.OPERATION_DISALLOWED,
                    {item.code for item in violations},
                )

    def test_added_or_renamed_field_is_rejected(self) -> None:
        source = self.source.replace(
            "('state_version', models.PositiveBigIntegerField",
            "('report_text', models.TextField()),\n                "
            "('state_version', models.PositiveBigIntegerField",
            1,
        )
        violations = self.analyze(source)
        self.assertIn(
            MigrationViolationCode.FIELD_PROFILE_MISMATCH,
            {item.code for item in violations},
        )

    def test_unlisted_import_call_or_field_constructor_is_rejected(self) -> None:
        sources = (
            "import os\n" + self.source,
            self.source.replace(
                "models.UUIDField(default=uuid.uuid4",
                "models.TextField(default=uuid.uuid4",
                1,
            ),
            self.source.replace(
                "models.UUIDField(default=uuid.uuid4",
                "execute_unreviewed(default=uuid.uuid4",
                1,
            ),
        )
        for source in sources:
            with self.subTest(source=source):
                self.assertTrue(self.analyze(source))

    def test_dependency_or_noninitial_graph_is_rejected(self) -> None:
        sources = (
            self.source.replace("initial = True", "initial = False", 1),
            self.source.replace(
                "dependencies = [\n    ]",
                "dependencies = [('other', '0001_initial')]",
                1,
            ),
        )
        for source in sources:
            with self.subTest(source=source):
                violations = self.analyze(source)
                self.assertEqual(len(violations), 1)
                self.assertEqual(
                    violations[0].code,
                    MigrationViolationCode.MIGRATION_GRAPH_MISMATCH,
                )

    def test_dynamic_operation_list_fails_closed(self) -> None:
        start = self.source.index("    operations = [")
        end = self.source.rindex("    ]") + len("    ]")
        source = self.source[:start] + "    operations = build_operations()" + self.source[end:]
        violations = self.analyze(source)
        self.assertEqual(len(violations), 1)
        self.assertEqual(
            violations[0].code,
            MigrationViolationCode.MIGRATION_GRAPH_MISMATCH,
        )

    def test_additional_numbered_migration_is_rejected(self) -> None:
        with TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            migrations = root / "migrations"
            migrations.mkdir()
            (migrations / "0001_initial.py").write_text(
                self.source,
                encoding="utf-8",
            )
            (migrations / "0002_unreviewed.py").write_text(
                "raise RuntimeError('MUST_NOT_RUN')\n",
                encoding="utf-8",
            )
            violations = scan_lifecycle_migrations(
                migrations_root=migrations,
                relative_to=root,
            )
        self.assertEqual(len(violations), 1)
        self.assertEqual(
            violations[0].code,
            MigrationViolationCode.MIGRATION_GRAPH_MISMATCH,
        )

    def test_parse_path_and_error_details_fail_closed(self) -> None:
        sentinel = "REPORT_TEXT_SENTINEL"
        violations = self.analyze(f"class Migration({sentinel}\n")
        self.assertEqual(len(violations), 1)
        self.assertEqual(
            violations[0].code,
            MigrationViolationCode.SOURCE_PARSE_ERROR,
        )
        self.assertNotIn(sentinel, repr(violations[0]))

        outside = scan_lifecycle_migrations(
            migrations_root=BASE_DIR / "report_lifecycle" / "migrations",
            relative_to=BASE_DIR / "tests",
        )
        self.assertEqual(len(outside), 1)
        self.assertEqual(
            outside[0].code,
            MigrationViolationCode.SOURCE_PARSE_ERROR,
        )

    def test_violation_is_immutable(self) -> None:
        violation = MigrationViolation(
            code=MigrationViolationCode.OPERATION_DISALLOWED,
            relative_path="migration.py",
            line=1,
            detail_code="OPERATION_NOT_ALLOWLISTED",
        )
        with self.assertRaises(FrozenInstanceError):
            violation.line = 2
