"""Abuse tests for the inert reporter surface policy."""

from dataclasses import FrozenInstanceError
from pathlib import Path

from django.test import SimpleTestCase

from architecture_checks import (
    EXPECTED_REPORTER_PYTHON_AST_DIGESTS,
    EXPECTED_SETTINGS,
    SurfaceViolation,
    SurfaceViolationCode,
    analyze_css_source,
    analyze_reporter_python_source,
    analyze_settings_source,
    analyze_template_source,
    analyze_urlconf_source,
    scan_surface_file,
)


BASE_DIR = Path(__file__).resolve().parent.parent


class CurrentReporterSurfaceTests(SimpleTestCase):
    def test_current_reporter_python_modules_match_the_inert_profile(self) -> None:
        for relative_path in EXPECTED_REPORTER_PYTHON_AST_DIGESTS:
            with self.subTest(relative_path=relative_path):
                violations = scan_surface_file(
                    path=BASE_DIR / relative_path,
                    relative_to=BASE_DIR,
                    analyzer=analyze_reporter_python_source,
                )
                self.assertEqual(violations, ())

    def test_current_django_settings_match_the_inert_profile(self) -> None:
        violations = scan_surface_file(
            path=BASE_DIR / "anonymous_reporting" / "settings.py",
            relative_to=BASE_DIR,
            analyzer=analyze_settings_source,
        )
        self.assertEqual(violations, ())

    def test_current_urlconf_contains_only_the_inert_reporter_surfaces(self) -> None:
        violations = scan_surface_file(
            path=BASE_DIR / "anonymous_reporting" / "urls.py",
            relative_to=BASE_DIR,
            analyzer=analyze_urlconf_source,
        )
        self.assertEqual(violations, ())

    def test_current_templates_use_only_the_passive_profile(self) -> None:
        for template_name in (
            "home.html",
            "status.html",
            "submit_unavailable.html",
            "response_unavailable.html",
        ):
            with self.subTest(template_name=template_name):
                violations = scan_surface_file(
                    path=BASE_DIR / "templates" / "reporter_gateway" / template_name,
                    relative_to=BASE_DIR,
                    analyzer=analyze_template_source,
                )
                self.assertEqual(violations, ())

    def test_current_operator_template_uses_only_the_passive_profile(self) -> None:
        violations = scan_surface_file(
            path=BASE_DIR / "templates" / "operator_console" / "unavailable.html",
            relative_to=BASE_DIR,
            analyzer=analyze_template_source,
        )
        self.assertEqual(violations, ())

    def test_current_css_loads_no_resources_or_active_content(self) -> None:
        violations = scan_surface_file(
            path=BASE_DIR / "static" / "reporter_gateway" / "home.css",
            relative_to=BASE_DIR,
            analyzer=analyze_css_source,
        )
        self.assertEqual(violations, ())


class SettingsAndUrlSurfaceAbuseTests(SimpleTestCase):
    def settings_source(self, replacements: dict[str, str] | None = None) -> str:
        replacements = replacements or {}
        lines = []
        for name, value in EXPECTED_SETTINGS.items():
            if name in {"ALLOWED_HOSTS", "INSTALLED_APPS", "MIDDLEWARE"}:
                default_literal = repr(list(value))
            else:
                default_literal = repr(value)
            literal = replacements.get(name, default_literal)
            lines.append(f"{name} = {literal}")
        return "\n".join(lines)

    def test_auth_admin_and_session_additions_are_rejected(self) -> None:
        apps = list(EXPECTED_SETTINGS["INSTALLED_APPS"]) + ["django.contrib.auth"]
        middleware = list(EXPECTED_SETTINGS["MIDDLEWARE"]) + [
            "django.contrib.sessions.middleware.SessionMiddleware"
        ]
        violations = analyze_settings_source(
            source=self.settings_source(
                {
                    "INSTALLED_APPS": repr(apps),
                    "MIDDLEWARE": repr(middleware),
                }
            ),
            relative_path="anonymous_reporting/settings.py",
        )
        self.assertEqual(len(violations), 2)
        self.assertEqual(
            {item.detail_code for item in violations},
            {"INSTALLED_APPS", "MIDDLEWARE"},
        )
        self.assertTrue(
            all(
                item.code == SurfaceViolationCode.SETTINGS_VALUE_MISMATCH
                for item in violations
            )
        )

    def test_dynamic_or_missing_security_setting_fails_closed(self) -> None:
        source = self.settings_source({"ALLOWED_HOSTS": "load_hosts()"})
        source = "\n".join(
            line
            for line in source.splitlines()
            if not line.startswith("X_FRAME_OPTIONS =")
        )
        violations = analyze_settings_source(
            source=source,
            relative_path="anonymous_reporting/settings.py",
        )
        self.assertEqual(
            {item.code for item in violations},
            {
                SurfaceViolationCode.SETTINGS_ASSIGNMENT_DYNAMIC,
                SurfaceViolationCode.SETTINGS_ASSIGNMENT_MISSING,
            },
        )

    def test_post_assignment_settings_mutation_is_rejected(self) -> None:
        source = self.settings_source() + "\nINSTALLED_APPS.append('django.contrib.auth')"
        violations = analyze_settings_source(
            source=source,
            relative_path="anonymous_reporting/settings.py",
        )
        self.assertEqual(len(violations), 1)
        self.assertEqual(violations[0].detail_code, "INSTALLED_APPS")

    def test_settings_source_is_never_executed(self) -> None:
        source = self.settings_source() + "\nraise RuntimeError('MUST_NOT_RUN')\n"
        self.assertEqual(
            analyze_settings_source(
                source=source,
                relative_path="anonymous_reporting/settings.py",
            ),
            (),
        )

    def test_extra_or_dynamic_url_patterns_are_rejected(self) -> None:
        sources = (
            (
                "urlpatterns = [path('', home, name='reporter-home'), "
                "path('send/', send, name='send')]"
            ),
            "urlpatterns = build_patterns()",
            "urlpatterns = [re_path('', home, name='reporter-home')]",
            (
                "urlpatterns = [path('', home, name='reporter-home'), "
                "path('status/', status, name='reporter-status'), "
                "path('submit/', submit_unavailable, name='reporter-submit'), "
                "path('response/', response_unavailable, name='reporter-response'), "
                "path('operator/', operator_unavailable, name='operator-console')]\n"
                "urlpatterns.append(path('send/', send, name='send'))"
            ),
        )
        for source in sources:
            with self.subTest(source=source):
                violations = analyze_urlconf_source(
                    source=source,
                    relative_path="anonymous_reporting/urls.py",
                )
                self.assertEqual(len(violations), 1)
                self.assertEqual(
                    violations[0].code,
                    SurfaceViolationCode.URL_PATTERN_MISMATCH,
                )

    def test_python_parse_failures_are_controlled_and_content_free(self) -> None:
        sentinel = "REPORT_TEXT_SENTINEL"
        violations = analyze_settings_source(
            source=f"def broken({sentinel}\n",
            relative_path="anonymous_reporting/settings.py",
        )
        self.assertEqual(len(violations), 1)
        self.assertEqual(
            violations[0].code,
            SurfaceViolationCode.SOURCE_PARSE_ERROR,
        )
        self.assertNotIn(sentinel, repr(violations[0]))


class ReporterPythonSourceAbuseTests(SimpleTestCase):
    def source(self, relative_path: str) -> str:
        return (BASE_DIR / relative_path).read_text(encoding="utf-8")

    def test_view_behavior_changes_fail_closed(self) -> None:
        relative_path = "reporter_gateway/views.py"
        source = self.source(relative_path)
        mutations = (
            source.replace("@require_safe", "@require_safe\n@csrf_exempt"),
            source.replace(
                'return render(request, "reporter_gateway/home.html")',
                'return render(request, "reporter_gateway/home.html", '
                '{"request_body": request.body})',
            ),
            source + "\ndef submit(request):\n    return HttpResponse(request.body)\n",
            source.replace(
                'return HttpResponse(\n            "submission_unavailable",',
                'return HttpResponse(\n            request.body.decode("utf-8"),',
            ),
        )
        for mutation in mutations:
            with self.subTest(mutation=mutation[-60:]):
                violations = analyze_reporter_python_source(
                    source=mutation,
                    relative_path=relative_path,
                )
                self.assertEqual(len(violations), 1)
                self.assertEqual(
                    violations[0].code,
                    SurfaceViolationCode.REPORTER_PYTHON_SOURCE_MISMATCH,
                )

    def test_middleware_behavior_changes_fail_closed(self) -> None:
        relative_path = "reporter_gateway/middleware.py"
        source = self.source(relative_path)
        mutations = (
            source.replace(
                'response["Cache-Control"] = "no-store, max-age=0"',
                'response["Cache-Control"] = "public, max-age=3600"',
            ),
            source.replace(
                'response = self.get_response(request)',
                'print(request.headers)\n        response = self.get_response(request)',
            ),
            source.replace("script-src 'none'", "script-src 'self'"),
            source + "\nTRACKER = 'https://tracker.invalid'\n",
        )
        for mutation in mutations:
            with self.subTest(mutation=mutation[-60:]):
                violations = analyze_reporter_python_source(
                    source=mutation,
                    relative_path=relative_path,
                )
                self.assertEqual(len(violations), 1)
                self.assertEqual(
                    violations[0].code,
                    SurfaceViolationCode.REPORTER_PYTHON_SOURCE_MISMATCH,
                )

    def test_unknown_target_and_parse_failure_are_controlled(self) -> None:
        target_violations = analyze_reporter_python_source(
            source="pass",
            relative_path="reporter_gateway/submit.py",
        )
        self.assertEqual(len(target_violations), 1)
        self.assertEqual(
            target_violations[0].code,
            SurfaceViolationCode.REPORTER_PYTHON_TARGET_MISMATCH,
        )

        sentinel = "REPORT_TEXT_SENTINEL"
        parse_violations = analyze_reporter_python_source(
            source=f"def broken({sentinel}\n",
            relative_path="reporter_gateway/views.py",
        )
        self.assertEqual(len(parse_violations), 1)
        self.assertEqual(
            parse_violations[0].code,
            SurfaceViolationCode.SOURCE_PARSE_ERROR,
        )
        self.assertNotIn(sentinel, repr(parse_violations))

    def test_source_is_never_executed_or_echoed(self) -> None:
        relative_path = "reporter_gateway/views.py"
        sentinel = "REPORT_TEXT_SENTINEL"
        source = self.source(relative_path) + f"\nraise RuntimeError('{sentinel}')\n"
        violations = analyze_reporter_python_source(
            source=source,
            relative_path=relative_path,
        )
        self.assertEqual(len(violations), 1)
        self.assertNotIn(sentinel, repr(violations))


class TemplateAndCssSurfaceAbuseTests(SimpleTestCase):
    valid_template = """{% load static %}
<!doctype html><html lang="it"><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex, nofollow, noarchive">
<title>Inert</title>
<link rel="stylesheet" href="{% static 'reporter_gateway/home.css' %}">
</head><body><main><p>Passive text</p></main></body></html>"""

    def test_active_or_interactive_html_tags_are_rejected(self) -> None:
        for tag in ("form", "script", "iframe", "a", "img", "input"):
            source = self.valid_template.replace(
                "<p>Passive text</p>", f"<{tag}></{tag}>"
            )
            with self.subTest(tag=tag):
                violations = analyze_template_source(
                    source=source,
                    relative_path="templates/reporter_gateway/home.html",
                )
                self.assertIn(
                    SurfaceViolationCode.TEMPLATE_TAG_DISALLOWED,
                    {item.code for item in violations},
                )

    def test_event_style_and_external_resource_attributes_are_rejected(self) -> None:
        injected = (
            '<p onclick="submit()">Passive text</p>',
            '<p style="background: red">Passive text</p>',
            '<link rel="stylesheet" href="https://tracker.invalid/a.css">',
        )
        for markup in injected:
            source = self.valid_template.replace(
                "<p>Passive text</p>", markup
            )
            with self.subTest(markup=markup):
                violations = analyze_template_source(
                    source=source,
                    relative_path="templates/reporter_gateway/home.html",
                )
                self.assertTrue(violations)

    def test_dynamic_template_values_and_directives_are_rejected(self) -> None:
        injected = (
            "{{ report_text }}",
            "{% include 'fragment.html' %}",
            "{# hidden instruction #}",
            "<?xml version='1.0'?>",
        )
        for value in injected:
            source = self.valid_template.replace("Passive text", value)
            with self.subTest(value=value):
                violations = analyze_template_source(
                    source=source,
                    relative_path="templates/reporter_gateway/home.html",
                )
                self.assertTrue(violations)

    def test_invalid_nesting_and_required_head_changes_are_rejected(self) -> None:
        sources = (
            self.valid_template.replace("</main>", "</section>"),
            self.valid_template.replace("<!doctype html>", ""),
            self.valid_template.replace('name="robots"', 'name="referrer"'),
        )
        for source in sources:
            with self.subTest(source=source):
                violations = analyze_template_source(
                    source=source,
                    relative_path="templates/reporter_gateway/home.html",
                )
                self.assertTrue(violations)

    def test_css_resource_and_active_constructs_are_rejected(self) -> None:
        sources = (
            '@import "tracker.css";',
            "@font-face { src: local(font); }",
            ".x { background: url(https://tracker.invalid/pixel); }",
            '.x { background: image-set("tracker.png" 1x); }',
            '.x { background: "https://tracker.invalid/pixel"; }',
            r".x { background: u\72l(tracker.invalid); }",
            ".x { width: expression(alert(1)); }",
            ".x { behavior: url(active.htc); }",
            ".x { -moz-binding: url(active.xml); }",
            ".x { background: javascript:alert(1); }",
        )
        for source in sources:
            with self.subTest(source=source):
                self.assertTrue(
                    analyze_css_source(
                        source=source,
                        relative_path="static/reporter_gateway/home.css",
                    )
                )

    def test_violation_and_settings_contracts_are_immutable(self) -> None:
        violation = SurfaceViolation(
            code=SurfaceViolationCode.CSS_EXTERNAL_RESOURCE,
            relative_path="home.css",
            line=1,
            detail_code="RESOURCE_CONSTRUCT",
        )
        with self.assertRaises(FrozenInstanceError):
            violation.line = 2
        with self.assertRaises(TypeError):
            EXPECTED_SETTINGS["DEBUG"] = False

    def test_missing_or_out_of_root_files_fail_closed(self) -> None:
        for path, root in (
            (BASE_DIR / "missing.css", BASE_DIR),
            (
                BASE_DIR / "static" / "reporter_gateway" / "home.css",
                BASE_DIR / "templates",
            ),
        ):
            with self.subTest(path=path):
                violations = scan_surface_file(
                    path=path,
                    relative_to=root,
                    analyzer=analyze_css_source,
                )
                self.assertEqual(len(violations), 1)
                self.assertEqual(
                    violations[0].code,
                    SurfaceViolationCode.SOURCE_PARSE_ERROR,
                )
