"""Keep public test signing keys and proof tooling outside the application."""

import ast
import re
from pathlib import Path

from django.test import SimpleTestCase


ROOT = Path(__file__).resolve().parent.parent
APP_PACKAGES = (
    "anonymous_reporting", "operator_console", "recovery_gateway",
    "reporter_gateway", "report_lifecycle", "security_interfaces",
    "submission_workflow",
)
PROOF_IMPORTS = {"proofs", "cwt", "cbor2", "cryptography", "pycose"}


class AuditVectorIsolationTests(SimpleTestCase):
    def test_application_has_no_static_proof_imports(self) -> None:
        for package in APP_PACKAGES:
            for path in (ROOT / package).rglob("*.py"):
                with self.subTest(path=path.relative_to(ROOT)):
                    tree = ast.parse(path.read_text(encoding="utf-8"))
                    imports = set()
                    for node in ast.walk(tree):
                        if isinstance(node, ast.Import):
                            imports.update(alias.name.split(".")[0] for alias in node.names)
                        elif isinstance(node, ast.ImportFrom) and node.module:
                            imports.add(node.module.split(".")[0])
                    self.assertFalse(imports & PROOF_IMPORTS)

    def test_proof_files_are_excluded_from_runtime_build_context(self) -> None:
        rules = (ROOT / ".dockerignore").read_text(encoding="utf-8").splitlines()
        self.assertIn("proofs", rules)
        self.assertFalse(any(rule.startswith("!proofs") for rule in rules))

    def test_application_dependencies_exclude_the_proof_stack(self) -> None:
        for name in ("requirements.in", "requirements.lock"):
            with self.subTest(path=name):
                source = (ROOT / name).read_text(encoding="utf-8").lower()
                packages = set(re.findall(r"(?m)^([a-z0-9_-]+)==", source))
                self.assertFalse(packages & PROOF_IMPORTS)
