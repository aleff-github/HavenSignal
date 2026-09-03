"""Tests for content-free repository hygiene policy checks."""

from pathlib import Path
from tempfile import TemporaryDirectory

from django.test import SimpleTestCase

from architecture_checks.repository_hygiene import (
    REQUIRED_GITIGNORE_RULES,
    RepositoryHygieneViolationCode,
    analyze_gitignore_source,
    analyze_tracked_paths,
    scan_repository_hygiene,
)


BASE_DIR = Path(__file__).resolve().parent.parent


class CurrentRepositoryHygienePolicyTests(SimpleTestCase):
    def test_current_repository_passes_repository_hygiene_policy(self) -> None:
        self.assertEqual(scan_repository_hygiene(BASE_DIR), ())


class RepositoryHygieneAbuseTests(SimpleTestCase):
    def test_tracked_sqlite_database_is_rejected_without_reading_contents(
        self,
    ) -> None:
        sentinel = "REPORT_TEXT_SENTINEL"
        violations = analyze_tracked_paths(("db.sqlite3",))
        self.assertEqual(len(violations), 1)
        self.assertEqual(
            violations[0].code,
            RepositoryHygieneViolationCode.FORBIDDEN_TRACKED_PATH,
        )
        self.assertEqual(violations[0].detail_code, "LOCAL_DATABASE")
        self.assertNotIn(sentinel, repr(violations[0]))

    def test_tracked_secret_and_export_artifact_paths_are_rejected(self) -> None:
        violations = analyze_tracked_paths(
            (
                "secrets/operator.key",
                ".docker/secrets/postgres_password",
                "exports/package.age",
                "tmp/plaintext.bin",
            )
        )
        self.assertEqual(
            {
                (violation.relative_path, violation.detail_code)
                for violation in violations
            },
            {
                ("secrets/operator.key", "SECRET_DIRECTORY"),
                (".docker/secrets/postgres_password", "SECRET_DIRECTORY"),
                ("exports/package.age", "EXPORT_ARTIFACT"),
                ("tmp/plaintext.bin", "TEMPORARY_WORKSPACE"),
            },
        )

    def test_tracked_local_instruction_and_session_paths_are_rejected(self) -> None:
        violations = analyze_tracked_paths(
            (
                "AGENTS.md",
                "START-CODEX.md",
                "docs/CODEX_USAGE.md",
                ".codex/session.json",
                "resume",
            )
        )
        self.assertEqual(len(violations), 5)
        self.assertEqual(
            {violation.detail_code for violation in violations},
            {
                "LOCAL_DEVELOPMENT_INSTRUCTION",
                "LOCAL_SESSION_ARTIFACT",
            },
        )

    def test_env_example_exception_remains_allowed(self) -> None:
        self.assertEqual(analyze_tracked_paths((".env.example",)), ())

    def test_unsafe_tracked_path_shape_is_rejected(self) -> None:
        violations = analyze_tracked_paths(("../outside.env",))
        self.assertEqual(len(violations), 1)
        self.assertEqual(
            violations[0].code,
            RepositoryHygieneViolationCode.TRACKED_PATH_INVALID,
        )
        self.assertEqual(violations[0].relative_path, "<repository>")

    def test_missing_required_gitignore_rule_is_rejected(self) -> None:
        source = "\n".join(
            sorted(REQUIRED_GITIGNORE_RULES - {"*.sqlite3"})
        )
        violations = analyze_gitignore_source(source)
        self.assertEqual(len(violations), 1)
        self.assertEqual(
            violations[0].code,
            RepositoryHygieneViolationCode.GITIGNORE_RULE_MISSING,
        )
        self.assertEqual(violations[0].relative_path, ".gitignore")

    def test_missing_gitignore_and_non_repository_fail_closed(self) -> None:
        with TemporaryDirectory() as temporary_directory:
            violations = scan_repository_hygiene(Path(temporary_directory))

        self.assertEqual(
            {
                violation.code
                for violation in violations
            },
            {
                RepositoryHygieneViolationCode.POLICY_INPUT_UNAVAILABLE,
                RepositoryHygieneViolationCode.TRACKED_FILES_UNAVAILABLE,
            },
        )
