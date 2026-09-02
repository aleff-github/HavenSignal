"""Static policies for the currently inert reporter-facing surface."""

import ast
import hashlib
import re
from dataclasses import dataclass
from enum import StrEnum
from html.parser import HTMLParser
from pathlib import Path
from types import MappingProxyType
from typing import Callable


class SurfaceViolationCode(StrEnum):
    CSS_ACTIVE_CONTENT = "CSS_ACTIVE_CONTENT"
    CSS_EXTERNAL_RESOURCE = "CSS_EXTERNAL_RESOURCE"
    SETTINGS_ASSIGNMENT_DYNAMIC = "SETTINGS_ASSIGNMENT_DYNAMIC"
    SETTINGS_ASSIGNMENT_MISSING = "SETTINGS_ASSIGNMENT_MISSING"
    SETTINGS_VALUE_MISMATCH = "SETTINGS_VALUE_MISMATCH"
    SOURCE_PARSE_ERROR = "SOURCE_PARSE_ERROR"
    REPORTER_PYTHON_SOURCE_MISMATCH = "REPORTER_PYTHON_SOURCE_MISMATCH"
    REPORTER_PYTHON_TARGET_MISMATCH = "REPORTER_PYTHON_TARGET_MISMATCH"
    TEMPLATE_ATTRIBUTE_DISALLOWED = "TEMPLATE_ATTRIBUTE_DISALLOWED"
    TEMPLATE_DYNAMIC_VALUE = "TEMPLATE_DYNAMIC_VALUE"
    TEMPLATE_EXTERNAL_RESOURCE = "TEMPLATE_EXTERNAL_RESOURCE"
    TEMPLATE_STRUCTURE_ERROR = "TEMPLATE_STRUCTURE_ERROR"
    TEMPLATE_TAG_DISALLOWED = "TEMPLATE_TAG_DISALLOWED"
    URL_PATTERN_MISMATCH = "URL_PATTERN_MISMATCH"


@dataclass(frozen=True, slots=True)
class SurfaceViolation:
    code: SurfaceViolationCode
    relative_path: str
    line: int
    detail_code: str


EXPECTED_SETTINGS = MappingProxyType({
    "ALLOWED_HOSTS": (),
    "DEBUG": True,
    "INSTALLED_APPS": (
        "django.contrib.staticfiles",
        "operator_console.apps.OperatorConsoleConfig",
        "recovery_gateway.apps.RecoveryGatewayConfig",
        "report_lifecycle.apps.ReportLifecycleConfig",
        "submission_workflow.apps.SubmissionWorkflowConfig",
    ),
    "MIDDLEWARE": (
        "django.middleware.security.SecurityMiddleware",
        "django.middleware.common.CommonMiddleware",
        "django.middleware.csrf.CsrfViewMiddleware",
        "django.middleware.clickjacking.XFrameOptionsMiddleware",
        "reporter_gateway.middleware.ReporterSecurityHeadersMiddleware",
    ),
    "ROOT_URLCONF": "anonymous_reporting.urls",
    "SECURE_CONTENT_TYPE_NOSNIFF": True,
    "X_FRAME_OPTIONS": "DENY",
})
_LIST_SETTINGS = frozenset({"ALLOWED_HOSTS", "INSTALLED_APPS", "MIDDLEWARE"})

_ALLOWED_TEMPLATE_TAGS = frozenset(
    {
        "article",
        "aside",
        "body",
        "footer",
        "h1",
        "h2",
        "head",
        "header",
        "html",
        "link",
        "main",
        "meta",
        "p",
        "section",
        "title",
    }
)
_VOID_TEMPLATE_TAGS = frozenset({"link", "meta"})
_ALLOWED_ATTRIBUTES = {
    "article": frozenset({"class"}),
    "aside": frozenset({"aria-labelledby", "class"}),
    "body": frozenset(),
    "footer": frozenset(),
    "h1": frozenset(),
    "h2": frozenset({"id"}),
    "head": frozenset(),
    "header": frozenset({"class"}),
    "html": frozenset({"lang"}),
    "link": frozenset({"href", "rel"}),
    "main": frozenset({"class"}),
    "meta": frozenset({"charset", "content", "name"}),
    "p": frozenset({"class"}),
    "section": frozenset({"aria-label", "aria-labelledby", "class"}),
    "title": frozenset(),
}
_ALLOWED_META_ATTRIBUTES = (
    {"charset": "utf-8"},
    {"content": "width=device-width, initial-scale=1", "name": "viewport"},
    {"content": "noindex, nofollow, noarchive", "name": "robots"},
)
_ALLOWED_TEMPLATE_DIRECTIVES = frozenset(
    {
        "load static",
        "static 'reporter_gateway/home.css'",
    }
)
_DJANGO_DIRECTIVE_PATTERN = re.compile(r"{%\s*(.*?)\s*%}", re.DOTALL)
_EXTERNAL_VALUE_PATTERN = re.compile(
    r"^\s*(?:data:|https?:|javascript:|//)", re.IGNORECASE
)
_CSS_EXTERNAL_PATTERNS = (
    re.compile(r"@import\b", re.IGNORECASE),
    re.compile(r"@font-face\b", re.IGNORECASE),
    re.compile(r"(?:https?:|data:|//)", re.IGNORECASE),
    re.compile(r"(?:image-set|src)\s*\(", re.IGNORECASE),
    re.compile(r"url\s*\(", re.IGNORECASE),
)
_CSS_ACTIVE_PATTERNS = (
    re.compile(r"\\"),
    re.compile(r"expression\s*\(", re.IGNORECASE),
    re.compile(r"javascript\s*:", re.IGNORECASE),
    re.compile(r"(?:^|[;{\s])behavior\s*:", re.IGNORECASE),
    re.compile(r"-moz-binding\s*:", re.IGNORECASE),
)

EXPECTED_REPORTER_PYTHON_AST_DIGESTS = MappingProxyType(
    {
        "operator_console/views.py": (
            "b6ab12b30737e431a3a7291f21c729943440c6f0fb091f5e0f9146497a4575c0"
        ),
        "reporter_gateway/middleware.py": (
            "fceaeddb1c56cdf0a67cd98e2c0aab94994590e18fd7eed08ee3ce197a0dd6dd"
        ),
        "reporter_gateway/views.py": (
            "dd6c7a1df7ae3895d458220395df95145907a9287b4b90911aa621875602d2db"
        ),
        "recovery_gateway/views.py": (
            "f42f0534695fb03acf5d178b734c7f20de62c926d08df4808006141497a04fc2"
        ),
    }
)


def _violation(
    *,
    code: SurfaceViolationCode,
    relative_path: str,
    line: int,
    detail_code: str,
) -> SurfaceViolation:
    return SurfaceViolation(
        code=code,
        relative_path=relative_path,
        line=line,
        detail_code=detail_code,
    )


def _sorted(
    violations: list[SurfaceViolation],
) -> tuple[SurfaceViolation, ...]:
    return tuple(
        sorted(
            violations,
            key=lambda item: (
                item.relative_path,
                item.line,
                item.code.value,
                item.detail_code,
            ),
        )
    )


def _assignment_name(node: ast.Assign | ast.AnnAssign) -> str | None:
    if isinstance(node, ast.AnnAssign):
        return node.target.id if isinstance(node.target, ast.Name) else None
    if len(node.targets) != 1 or not isinstance(node.targets[0], ast.Name):
        return None
    return node.targets[0].id


def analyze_settings_source(
    *, source: str, relative_path: str
) -> tuple[SurfaceViolation, ...]:
    """Check exact inert settings without importing or executing the module."""

    try:
        tree = ast.parse(source, filename=relative_path)
    except (SyntaxError, ValueError, TypeError):
        return (
            _violation(
                code=SurfaceViolationCode.SOURCE_PARSE_ERROR,
                relative_path=relative_path,
                line=0,
                detail_code="PYTHON_SOURCE_INVALID",
            ),
        )

    assignments: dict[str, list[ast.Assign | ast.AnnAssign]] = {
        name: [] for name in EXPECTED_SETTINGS
    }
    for node in tree.body:
        if isinstance(node, (ast.Assign, ast.AnnAssign)):
            name = _assignment_name(node)
            if name in assignments:
                assignments[name].append(node)

    violations: list[SurfaceViolation] = []
    for name, expected in EXPECTED_SETTINGS.items():
        nodes = assignments[name]
        if not nodes:
            violations.append(
                _violation(
                    code=SurfaceViolationCode.SETTINGS_ASSIGNMENT_MISSING,
                    relative_path=relative_path,
                    line=0,
                    detail_code=name,
                )
            )
            continue
        if len(nodes) != 1:
            violations.append(
                _violation(
                    code=SurfaceViolationCode.SETTINGS_VALUE_MISMATCH,
                    relative_path=relative_path,
                    line=nodes[-1].lineno,
                    detail_code=name,
                )
            )
            continue
        references = [
            node
            for node in ast.walk(tree)
            if isinstance(node, ast.Name) and node.id == name
        ]
        if len(references) != 1 or not isinstance(references[0].ctx, ast.Store):
            violations.append(
                _violation(
                    code=SurfaceViolationCode.SETTINGS_VALUE_MISMATCH,
                    relative_path=relative_path,
                    line=nodes[0].lineno,
                    detail_code=name,
                )
            )
            continue
        node = nodes[0]
        value_node = node.value
        if value_node is None:
            violations.append(
                _violation(
                    code=SurfaceViolationCode.SETTINGS_ASSIGNMENT_DYNAMIC,
                    relative_path=relative_path,
                    line=node.lineno,
                    detail_code=name,
                )
            )
            continue
        try:
            actual = ast.literal_eval(value_node)
        except (ValueError, TypeError, MemoryError, RecursionError):
            violations.append(
                _violation(
                    code=SurfaceViolationCode.SETTINGS_ASSIGNMENT_DYNAMIC,
                    relative_path=relative_path,
                    line=node.lineno,
                    detail_code=name,
                )
            )
            continue
        if name in _LIST_SETTINGS:
            matches = isinstance(actual, list) and tuple(actual) == expected
        else:
            matches = type(actual) is type(expected) and actual == expected
        if not matches:
            violations.append(
                _violation(
                    code=SurfaceViolationCode.SETTINGS_VALUE_MISMATCH,
                    relative_path=relative_path,
                    line=node.lineno,
                    detail_code=name,
                )
            )
    return _sorted(violations)


def analyze_reporter_python_source(
    *, source: str, relative_path: str
) -> tuple[SurfaceViolation, ...]:
    """Lock the executable AST of the inert reporter-facing modules."""

    expected_digest = EXPECTED_REPORTER_PYTHON_AST_DIGESTS.get(relative_path)
    if expected_digest is None:
        return (
            _violation(
                code=SurfaceViolationCode.REPORTER_PYTHON_TARGET_MISMATCH,
                relative_path=relative_path,
                line=0,
                detail_code="EXACT_REPORTER_PYTHON_TARGET",
            ),
        )
    try:
        tree = ast.parse(source, filename=relative_path)
    except (SyntaxError, ValueError, TypeError, MemoryError, RecursionError):
        return (
            _violation(
                code=SurfaceViolationCode.SOURCE_PARSE_ERROR,
                relative_path=relative_path,
                line=0,
                detail_code="PYTHON_SOURCE_INVALID",
            ),
        )
    payload = ast.dump(
        tree,
        annotate_fields=True,
        include_attributes=False,
    ).encode("utf-8")
    if hashlib.sha256(payload).hexdigest() != expected_digest:
        return (
            _violation(
                code=SurfaceViolationCode.REPORTER_PYTHON_SOURCE_MISMATCH,
                relative_path=relative_path,
                line=0,
                detail_code="EXACT_INERT_EXECUTABLE_AST",
            ),
        )
    return ()


def _is_path_pattern(
    node: ast.AST,
    *,
    route_value: str,
    view_name: str,
    url_name: str,
) -> bool:
    if not isinstance(node, ast.Call):
        return False
    if not isinstance(node.func, ast.Name) or node.func.id != "path":
        return False
    if len(node.args) != 2 or len(node.keywords) != 1:
        return False
    route, view = node.args
    keyword = node.keywords[0]
    return (
        isinstance(route, ast.Constant)
        and type(route.value) is str
        and route.value == route_value
        and isinstance(view, ast.Name)
        and view.id == view_name
        and keyword.arg == "name"
        and isinstance(keyword.value, ast.Constant)
        and type(keyword.value.value) is str
        and keyword.value.value == url_name
    )


def _is_include_path_pattern(
    node: ast.AST,
    *,
    route_value: str,
    included_urlconf: str,
) -> bool:
    if not isinstance(node, ast.Call):
        return False
    if not isinstance(node.func, ast.Name) or node.func.id != "path":
        return False
    if len(node.args) != 2 or node.keywords:
        return False
    route, include_call = node.args
    if (
        not isinstance(route, ast.Constant)
        or type(route.value) is not str
        or route.value != route_value
    ):
        return False
    return (
        isinstance(include_call, ast.Call)
        and isinstance(include_call.func, ast.Name)
        and include_call.func.id == "include"
        and len(include_call.args) == 1
        and not include_call.keywords
        and isinstance(include_call.args[0], ast.Constant)
        and type(include_call.args[0].value) is str
        and include_call.args[0].value == included_urlconf
    )


def analyze_urlconf_source(
    *, source: str, relative_path: str
) -> tuple[SurfaceViolation, ...]:
    """Require exactly the current inert URL patterns for each surface."""

    try:
        tree = ast.parse(source, filename=relative_path)
    except (SyntaxError, ValueError, TypeError):
        return (
            _violation(
                code=SurfaceViolationCode.SOURCE_PARSE_ERROR,
                relative_path=relative_path,
                line=0,
                detail_code="PYTHON_SOURCE_INVALID",
            ),
        )

    assignments: list[ast.Assign | ast.AnnAssign] = []
    for node in tree.body:
        if isinstance(node, (ast.Assign, ast.AnnAssign)):
            if _assignment_name(node) == "urlpatterns":
                assignments.append(node)
    if len(assignments) != 1:
        line = assignments[-1].lineno if assignments else 0
        return (
            _violation(
                code=SurfaceViolationCode.URL_PATTERN_MISMATCH,
                relative_path=relative_path,
                line=line,
                detail_code="URLPATTERNS_ASSIGNMENT",
            ),
        )

    references = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Name) and node.id == "urlpatterns"
    ]
    if len(references) != 1 or not isinstance(references[0].ctx, ast.Store):
        return (
            _violation(
                code=SurfaceViolationCode.URL_PATTERN_MISMATCH,
                relative_path=relative_path,
                line=assignments[0].lineno,
                detail_code="URLPATTERNS_MUTATION",
            ),
        )

    value = assignments[0].value
    valid = False
    detail_code = "PUBLIC_INERT_SURFACES_ONLY"
    if isinstance(value, (ast.List, ast.Tuple)):
        if relative_path == "anonymous_reporting/urls.py":
            valid = len(value.elts) == 3 and _is_include_path_pattern(
                value.elts[0],
                route_value="",
                included_urlconf="reporter_gateway.urls",
            ) and _is_include_path_pattern(
                value.elts[1],
                route_value="response/",
                included_urlconf="recovery_gateway.urls",
            ) and _is_include_path_pattern(
                value.elts[2],
                route_value="operator/",
                included_urlconf="operator_console.urls",
            )
            detail_code = "ROOT_INERT_SURFACE_INCLUDES_ONLY"
        elif relative_path == "reporter_gateway/urls.py":
            valid = len(value.elts) == 3 and _is_path_pattern(
                value.elts[0],
                route_value="",
                view_name="home",
                url_name="reporter-home",
            ) and _is_path_pattern(
                value.elts[1],
                route_value="status/",
                view_name="status",
                url_name="reporter-status",
            ) and _is_path_pattern(
                value.elts[2],
                route_value="submit/",
                view_name="submit_unavailable",
                url_name="reporter-submit",
            )
            detail_code = "REPORTER_INERT_ROUTES_ONLY"
        elif relative_path == "recovery_gateway/urls.py":
            valid = len(value.elts) == 1 and _is_path_pattern(
                value.elts[0],
                route_value="",
                view_name="response_unavailable",
                url_name="reporter-response",
            )
            detail_code = "RECOVERY_INERT_ROUTES_ONLY"
        elif relative_path == "operator_console/urls.py":
            valid = len(value.elts) == 1 and _is_path_pattern(
                value.elts[0],
                route_value="",
                view_name="operator_unavailable",
                url_name="operator-console",
            )
            detail_code = "OPERATOR_INERT_ROUTES_ONLY"
        else:
            detail_code = "URLCONF_TARGET_PROFILE"
    if valid:
        return ()
    return (
        _violation(
            code=SurfaceViolationCode.URL_PATTERN_MISMATCH,
            relative_path=relative_path,
            line=assignments[0].lineno,
            detail_code=detail_code,
        ),
    )


class _ClosedTemplateParser(HTMLParser):
    def __init__(self, *, relative_path: str) -> None:
        super().__init__(convert_charrefs=True)
        self.relative_path = relative_path
        self.violations: list[SurfaceViolation] = []
        self.stack: list[str] = []
        self.doctype_count = 0
        self.meta_profiles: list[dict[str, str | None]] = []
        self.link_profiles: list[dict[str, str | None]] = []

    def add_violation(
        self, code: SurfaceViolationCode, detail_code: str
    ) -> None:
        self.violations.append(
            _violation(
                code=code,
                relative_path=self.relative_path,
                line=self.getpos()[0],
                detail_code=detail_code,
            )
        )

    def handle_decl(self, decl: str) -> None:
        if decl.lower() == "doctype html":
            self.doctype_count += 1
        else:
            self.add_violation(
                SurfaceViolationCode.TEMPLATE_STRUCTURE_ERROR,
                "DECLARATION_DISALLOWED",
            )

    def handle_comment(self, data: str) -> None:
        self.add_violation(
            SurfaceViolationCode.TEMPLATE_STRUCTURE_ERROR,
            "COMMENT_DISALLOWED",
        )

    def handle_pi(self, data: str) -> None:
        self.add_violation(
            SurfaceViolationCode.TEMPLATE_STRUCTURE_ERROR,
            "PROCESSING_INSTRUCTION_DISALLOWED",
        )

    def unknown_decl(self, data: str) -> None:
        self.add_violation(
            SurfaceViolationCode.TEMPLATE_STRUCTURE_ERROR,
            "UNKNOWN_DECLARATION_DISALLOWED",
        )

    def handle_startendtag(
        self, tag: str, attrs: list[tuple[str, str | None]]
    ) -> None:
        self.add_violation(
            SurfaceViolationCode.TEMPLATE_STRUCTURE_ERROR,
            "SELF_CLOSING_TAG_DISALLOWED",
        )

    def handle_starttag(
        self, tag: str, attrs: list[tuple[str, str | None]]
    ) -> None:
        if tag not in _ALLOWED_TEMPLATE_TAGS:
            self.add_violation(
                SurfaceViolationCode.TEMPLATE_TAG_DISALLOWED,
                "TAG_NOT_ALLOWLISTED",
            )
            if tag not in _VOID_TEMPLATE_TAGS:
                self.stack.append(tag)
            return

        attr_names = [name for name, _ in attrs]
        if len(attr_names) != len(set(attr_names)):
            self.add_violation(
                SurfaceViolationCode.TEMPLATE_ATTRIBUTE_DISALLOWED,
                "DUPLICATE_ATTRIBUTE",
            )
        allowed = _ALLOWED_ATTRIBUTES[tag]
        for name, value in attrs:
            if name not in allowed:
                self.add_violation(
                    SurfaceViolationCode.TEMPLATE_ATTRIBUTE_DISALLOWED,
                    "ATTRIBUTE_NOT_ALLOWLISTED",
                )
            if value is not None and _EXTERNAL_VALUE_PATTERN.match(value):
                self.add_violation(
                    SurfaceViolationCode.TEMPLATE_EXTERNAL_RESOURCE,
                    "EXTERNAL_OR_ACTIVE_SCHEME",
                )

        profile = dict(attrs)
        if tag == "html" and profile != {"lang": "it"}:
            self.add_violation(
                SurfaceViolationCode.TEMPLATE_ATTRIBUTE_DISALLOWED,
                "HTML_LANGUAGE_PROFILE",
            )
        elif tag == "meta":
            self.meta_profiles.append(profile)
            if profile not in _ALLOWED_META_ATTRIBUTES:
                self.add_violation(
                    SurfaceViolationCode.TEMPLATE_ATTRIBUTE_DISALLOWED,
                    "META_PROFILE",
                )
        elif tag == "link":
            self.link_profiles.append(profile)
            if profile != {
                "href": "{% static 'reporter_gateway/home.css' %}",
                "rel": "stylesheet",
            }:
                self.add_violation(
                    SurfaceViolationCode.TEMPLATE_EXTERNAL_RESOURCE,
                    "STYLESHEET_PROFILE",
                )

        if tag not in _VOID_TEMPLATE_TAGS:
            self.stack.append(tag)

    def handle_endtag(self, tag: str) -> None:
        if tag in _VOID_TEMPLATE_TAGS or not self.stack or self.stack[-1] != tag:
            self.add_violation(
                SurfaceViolationCode.TEMPLATE_STRUCTURE_ERROR,
                "TAG_NESTING",
            )
            return
        self.stack.pop()


def analyze_template_source(
    *, source: str, relative_path: str
) -> tuple[SurfaceViolation, ...]:
    """Check a closed passive HTML/Django-template subset without rendering it."""

    violations: list[SurfaceViolation] = []
    if "{{" in source or "}}" in source or "{#" in source or "#}" in source:
        violations.append(
            _violation(
                code=SurfaceViolationCode.TEMPLATE_DYNAMIC_VALUE,
                relative_path=relative_path,
                line=0,
                detail_code="DYNAMIC_OR_COMMENT_SYNTAX",
            )
        )

    directives = [
        " ".join(directive.split())
        for directive in _DJANGO_DIRECTIVE_PATTERN.findall(source)
    ]
    for normalized in directives:
        if normalized not in _ALLOWED_TEMPLATE_DIRECTIVES:
            violations.append(
                _violation(
                    code=SurfaceViolationCode.TEMPLATE_DYNAMIC_VALUE,
                    relative_path=relative_path,
                    line=0,
                    detail_code="DIRECTIVE_NOT_ALLOWLISTED",
                )
            )
    if directives != [
        "load static",
        "static 'reporter_gateway/home.css'",
    ]:
        violations.append(
            _violation(
                code=SurfaceViolationCode.TEMPLATE_DYNAMIC_VALUE,
                relative_path=relative_path,
                line=0,
                detail_code="DIRECTIVE_PROFILE",
            )
        )
    remainder = _DJANGO_DIRECTIVE_PATTERN.sub("", source)
    if "{%" in remainder or "%}" in remainder:
        violations.append(
            _violation(
                code=SurfaceViolationCode.TEMPLATE_DYNAMIC_VALUE,
                relative_path=relative_path,
                line=0,
                detail_code="MALFORMED_DIRECTIVE",
            )
        )

    parser = _ClosedTemplateParser(relative_path=relative_path)
    try:
        parser.feed(source)
        parser.close()
    except (AssertionError, ValueError):
        violations.append(
            _violation(
                code=SurfaceViolationCode.SOURCE_PARSE_ERROR,
                relative_path=relative_path,
                line=0,
                detail_code="HTML_SOURCE_INVALID",
            )
        )
        return _sorted(violations)
    violations.extend(parser.violations)
    if parser.stack:
        violations.append(
            _violation(
                code=SurfaceViolationCode.TEMPLATE_STRUCTURE_ERROR,
                relative_path=relative_path,
                line=0,
                detail_code="UNCLOSED_TAG",
            )
        )
    if parser.doctype_count != 1:
        violations.append(
            _violation(
                code=SurfaceViolationCode.TEMPLATE_STRUCTURE_ERROR,
                relative_path=relative_path,
                line=0,
                detail_code="DOCTYPE_PROFILE",
            )
        )
    if parser.meta_profiles != list(_ALLOWED_META_ATTRIBUTES):
        violations.append(
            _violation(
                code=SurfaceViolationCode.TEMPLATE_STRUCTURE_ERROR,
                relative_path=relative_path,
                line=0,
                detail_code="REQUIRED_META_PROFILE",
            )
        )
    if parser.link_profiles != [
        {
            "href": "{% static 'reporter_gateway/home.css' %}",
            "rel": "stylesheet",
        }
    ]:
        violations.append(
            _violation(
                code=SurfaceViolationCode.TEMPLATE_STRUCTURE_ERROR,
                relative_path=relative_path,
                line=0,
                detail_code="REQUIRED_STYLESHEET_PROFILE",
            )
        )
    return _sorted(violations)


def analyze_css_source(
    *, source: str, relative_path: str
) -> tuple[SurfaceViolation, ...]:
    """Reject CSS constructs that load resources or execute legacy content."""

    violations: list[SurfaceViolation] = []
    for pattern in _CSS_EXTERNAL_PATTERNS:
        for match in pattern.finditer(source):
            violations.append(
                _violation(
                    code=SurfaceViolationCode.CSS_EXTERNAL_RESOURCE,
                    relative_path=relative_path,
                    line=source.count("\n", 0, match.start()) + 1,
                    detail_code="RESOURCE_CONSTRUCT",
                )
            )
    for pattern in _CSS_ACTIVE_PATTERNS:
        for match in pattern.finditer(source):
            violations.append(
                _violation(
                    code=SurfaceViolationCode.CSS_ACTIVE_CONTENT,
                    relative_path=relative_path,
                    line=source.count("\n", 0, match.start()) + 1,
                    detail_code="ACTIVE_CONSTRUCT",
                )
            )
    return _sorted(violations)


SurfaceAnalyzer = Callable[..., tuple[SurfaceViolation, ...]]


def scan_surface_file(
    *, path: Path, relative_to: Path, analyzer: SurfaceAnalyzer
) -> tuple[SurfaceViolation, ...]:
    """Read one in-root UTF-8 source file and fail closed on path/read errors."""

    try:
        resolved_root = relative_to.resolve(strict=True)
        resolved_path = path.resolve(strict=True)
        resolved_path.relative_to(resolved_root)
        relative_path = path.relative_to(relative_to).as_posix()
    except (OSError, ValueError):
        return (
            _violation(
                code=SurfaceViolationCode.SOURCE_PARSE_ERROR,
                relative_path="<invalid-scan-path>",
                line=0,
                detail_code="PATH_INVALID",
            ),
        )
    try:
        source = path.read_text(encoding="utf-8")
    except (OSError, UnicodeError):
        return (
            _violation(
                code=SurfaceViolationCode.SOURCE_PARSE_ERROR,
                relative_path=relative_path,
                line=0,
                detail_code="SOURCE_UNREADABLE",
            ),
        )
    return analyzer(source=source, relative_path=relative_path)
