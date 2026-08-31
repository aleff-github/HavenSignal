"""Tests for the local verification script source policy."""

from pathlib import Path
from tempfile import TemporaryDirectory

from django.test import SimpleTestCase

from architecture_checks.verification_script import (
    EXPECTED_COMMAND_SPECS,
    VERIFICATION_SCRIPT_PATH,
    VerificationScriptViolationCode,
    analyze_verification_script_source,
    scan_repository_verification_script,
    scan_verification_script_source,
)


BASE_DIR = Path(__file__).resolve().parent.parent


class CurrentVerificationScriptPolicyTests(SimpleTestCase):
    def test_current_verification_script_passes_source_policy(self) -> None:
        self.assertEqual(scan_repository_verification_script(BASE_DIR), ())


class VerificationScriptPolicyAbuseTests(SimpleTestCase):
    def test_removed_required_command_is_rejected(self) -> None:
        source = (BASE_DIR / VERIFICATION_SCRIPT_PATH).read_text(
            encoding="utf-8"
        )
        mutated = source.replace(
            '    ("Manifest validation", ("sha256sum", "-c", "MANIFEST.sha256")),\n',
            "",
        )
        violations = analyze_verification_script_source(mutated)
        self.assertIn(
            VerificationScriptViolationCode.COMMAND_PROFILE_MISMATCH,
            {violation.code for violation in violations},
        )

    def test_shell_execution_change_is_rejected_without_source_echo(self) -> None:
        sentinel = "REPORT_TEXT_SENTINEL"
        source = (BASE_DIR / VERIFICATION_SCRIPT_PATH).read_text(
            encoding="utf-8"
        )
        mutated = source.replace(
            "        check=False,\n",
            f"        check=False,\n        shell=True,  # {sentinel}\n",
        )
        violations = analyze_verification_script_source(mutated)
        self.assertIn(
            VerificationScriptViolationCode.AST_DIGEST_MISMATCH,
            {violation.code for violation in violations},
        )
        self.assertNotIn(sentinel, repr(violations))

    def test_expected_command_profile_is_complete_and_ordered(self) -> None:
        self.assertEqual(
            EXPECTED_COMMAND_SPECS,
            (
                (
                    "Architecture policies",
                    ("{python}", "-m", "architecture_checks", "."),
                ),
                ("Django system check", ("{python}", "manage.py", "check")),
                (
                    "Django migration drift check",
                    (
                        "{python}",
                        "manage.py",
                        "makemigrations",
                        "--check",
                        "--dry-run",
                    ),
                ),
                ("Django test suite", ("{python}", "manage.py", "test", "-v", "1")),
                (
                    "Python compile check",
                    (
                        "{python}",
                        "-m",
                        "compileall",
                        "anonymous_reporting",
                        "architecture_checks",
                        "reporter_gateway",
                        "report_lifecycle",
                        "security_interfaces",
                        "submission_workflow",
                        "tests",
                    ),
                ),
                ("Manifest validation", ("sha256sum", "-c", "MANIFEST.sha256")),
            ),
        )

    def test_malformed_source_is_rejected(self) -> None:
        violations = analyze_verification_script_source("def broken(:\n")
        self.assertEqual(len(violations), 1)
        self.assertEqual(
            violations[0].code,
            VerificationScriptViolationCode.SOURCE_MALFORMED,
        )

    def test_missing_script_fails_closed(self) -> None:
        with TemporaryDirectory() as temporary_directory:
            violations = scan_repository_verification_script(
                Path(temporary_directory)
            )
        self.assertEqual(len(violations), 1)
        self.assertEqual(
            violations[0].code,
            VerificationScriptViolationCode.SOURCE_UNAVAILABLE,
        )

    def test_out_of_root_path_fails_closed(self) -> None:
        with TemporaryDirectory() as root_dir:
            with TemporaryDirectory() as outside_dir:
                outside = Path(outside_dir) / "verify"
                outside.write_text("print('outside')\n", encoding="utf-8")
                violations = scan_verification_script_source(
                    path=outside,
                    relative_to=Path(root_dir),
                )
        self.assertEqual(len(violations), 1)
        self.assertEqual(
            violations[0].code,
            VerificationScriptViolationCode.PATH_OUT_OF_ROOT,
        )
