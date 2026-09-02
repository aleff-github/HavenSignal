"""Abuse tests for source-level Reporter Gateway dependency boundaries."""

from dataclasses import FrozenInstanceError
from pathlib import Path

from django.test import SimpleTestCase

from architecture_checks import (
    OPERATOR_CONSOLE_IMPORT_POLICY,
    REPORTER_GATEWAY_IMPORT_POLICY,
    REPORTER_ROOT_URL_IMPORT_POLICY,
    ImportViolationCode,
    analyze_python_source,
    scan_python_file,
    scan_python_package,
)


BASE_DIR = Path(__file__).resolve().parent.parent


class CurrentArchitectureBoundaryTests(SimpleTestCase):
    def test_reporter_gateway_uses_only_current_inert_imports(self) -> None:
        violations = scan_python_package(
            package_root=BASE_DIR / "reporter_gateway",
            policy=REPORTER_GATEWAY_IMPORT_POLICY,
            relative_to=BASE_DIR,
        )
        self.assertEqual(violations, ())

    def test_operator_console_uses_only_current_inert_imports(self) -> None:
        violations = scan_python_package(
            package_root=BASE_DIR / "operator_console",
            policy=OPERATOR_CONSOLE_IMPORT_POLICY,
            relative_to=BASE_DIR,
        )
        self.assertEqual(violations, ())

    def test_root_urlconf_exposes_only_the_current_reporter_import_edge(self) -> None:
        violations = scan_python_file(
            path=BASE_DIR / "anonymous_reporting" / "urls.py",
            policy=REPORTER_ROOT_URL_IMPORT_POLICY,
            relative_to=BASE_DIR,
        )
        self.assertEqual(violations, ())

    def test_file_outside_declared_scan_root_fails_closed(self) -> None:
        violations = scan_python_file(
            path=BASE_DIR / "anonymous_reporting" / "urls.py",
            policy=REPORTER_ROOT_URL_IMPORT_POLICY,
            relative_to=BASE_DIR / "reporter_gateway",
        )
        self.assertEqual(len(violations), 1)
        self.assertEqual(
            violations[0].code,
            ImportViolationCode.SOURCE_PARSE_ERROR,
        )
        self.assertEqual(violations[0].relative_path, "<invalid-scan-path>")

    def test_missing_package_root_fails_closed(self) -> None:
        violations = scan_python_package(
            package_root=BASE_DIR / "missing_architecture_package",
            policy=REPORTER_GATEWAY_IMPORT_POLICY,
            relative_to=BASE_DIR,
        )
        self.assertEqual(len(violations), 1)
        self.assertEqual(
            violations[0].code,
            ImportViolationCode.SOURCE_PARSE_ERROR,
        )
        self.assertEqual(
            violations[0].relative_path,
            "<invalid-package-path>",
        )

    def test_policies_are_immutable_and_exact(self) -> None:
        self.assertEqual(
            REPORTER_GATEWAY_IMPORT_POLICY.allowed_absolute_modules,
            frozenset(
                {
                    "collections.abc",
                    "django.http",
                    "django.shortcuts",
                    "django.views.decorators.http",
                }
            ),
        )
        self.assertEqual(
            REPORTER_ROOT_URL_IMPORT_POLICY.allowed_absolute_modules,
            frozenset(
                {
                    "django.urls",
                    "operator_console.views",
                    "reporter_gateway.views",
                }
            ),
        )
        self.assertEqual(
            OPERATOR_CONSOLE_IMPORT_POLICY.allowed_absolute_modules,
            frozenset(
                {
                    "django.apps",
                    "django.http",
                    "django.shortcuts",
                    "django.views.decorators.http",
                }
            ),
        )
        with self.assertRaises(FrozenInstanceError):
            REPORTER_GATEWAY_IMPORT_POLICY.name = "WEAKENED"


class ArchitectureImportAbuseTests(SimpleTestCase):
    def analyze(self, source: str):
        return analyze_python_source(
            source=source,
            relative_path="reporter_gateway/injected.py",
            policy=REPORTER_GATEWAY_IMPORT_POLICY,
        )

    def test_allowed_aliases_and_local_relative_imports_pass(self) -> None:
        source = """
from collections.abc import Callable as Handler
from django.http import HttpRequest as Request
from django.shortcuts import render as render_page
from django.views.decorators.http import require_safe
from .middleware import ReporterSecurityHeadersMiddleware
"""
        self.assertEqual(self.analyze(source), ())

    def test_sensitive_and_direct_network_imports_are_rejected(self) -> None:
        source = """
import security_interfaces as controls
from django.contrib.auth import authenticate as authenticate_operator
from report_lifecycle.models import Report
from submission_workflow import models as submission_models
import socket, django.http
"""
        violations = self.analyze(source)
        self.assertEqual(len(violations), 5)
        self.assertEqual(
            {violation.module for violation in violations},
            {
                "security_interfaces",
                "django.contrib.auth",
                "report_lifecycle.models",
                "submission_workflow",
                "socket",
            },
        )
        self.assertTrue(
            all(
                violation.code == ImportViolationCode.DISALLOWED_ABSOLUTE_IMPORT
                for violation in violations
            )
        )

    def test_star_and_parent_relative_imports_are_rejected(self) -> None:
        violations = self.analyze(
            "from django.http import *\nfrom ..security_interfaces import controls\n"
        )
        self.assertEqual(
            {violation.code for violation in violations},
            {
                ImportViolationCode.STAR_IMPORT,
                ImportViolationCode.PARENT_RELATIVE_IMPORT,
            },
        )

    def test_builtin_dynamic_import_and_code_execution_are_rejected(self) -> None:
        source = """
__import__("security_interfaces")
eval("1 + 1")
exec("pass")
builtins.__import__("report_lifecycle")
builtins.eval("1 + 1")
builtins.exec("pass")
"""
        violations = self.analyze(source)
        self.assertEqual(len(violations), 6)
        self.assertEqual(
            [violation.code for violation in violations].count(
                ImportViolationCode.DYNAMIC_IMPORT
            ),
            2,
        )
        self.assertEqual(
            [violation.code for violation in violations].count(
                ImportViolationCode.DYNAMIC_CODE_EXECUTION
            ),
            4,
        )

    def test_source_is_parsed_but_never_executed(self) -> None:
        source = "raise RuntimeError('THIS_MUST_NOT_RUN')\n"
        self.assertEqual(self.analyze(source), ())

    def test_parse_failure_returns_one_controlled_violation(self) -> None:
        sentinel = "REPORT_TEXT_SENTINEL"
        violations = self.analyze(f"def broken({sentinel}\n")
        self.assertEqual(len(violations), 1)
        self.assertEqual(
            violations[0].code,
            ImportViolationCode.SOURCE_PARSE_ERROR,
        )
        self.assertEqual(violations[0].line, 0)
        self.assertIsNone(violations[0].module)
        self.assertNotIn(sentinel, repr(violations[0]))

    def test_url_policy_rejects_any_unreviewed_surface_import(self) -> None:
        violations = analyze_python_source(
            source=(
                "from django.urls import path\n"
                "from unreviewed_console.views import endpoint\n"
            ),
            relative_path="anonymous_reporting/urls.py",
            policy=REPORTER_ROOT_URL_IMPORT_POLICY,
        )
        self.assertEqual(len(violations), 1)
        self.assertEqual(
            violations[0].module,
            "unreviewed_console.views",
        )
