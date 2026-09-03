"""Static safety checks for the contributor-only Docker alpha environment."""

import re
from pathlib import Path

from django.test import SimpleTestCase


BASE_DIR = Path(__file__).resolve().parent.parent


class DockerAlphaEnvironmentTests(SimpleTestCase):
    def setUp(self) -> None:
        self.compose = (BASE_DIR / "compose.yaml").read_text(encoding="utf-8")
        self.dockerfile = (BASE_DIR / "Dockerfile").read_text(encoding="utf-8")

    def test_base_images_are_exactly_pinned(self) -> None:
        self.assertRegex(
            self.dockerfile,
            r"FROM python:3\.13\.15-slim-bookworm@sha256:[0-9a-f]{64} AS runtime",
        )
        self.assertRegex(
            self.compose,
            r"image: postgres:17\.11-bookworm@sha256:[0-9a-f]{64}",
        )

    def test_host_ports_are_loopback_only(self) -> None:
        published_ports = re.findall(r'^\s+- "([^\n]+:\d+)"$', self.compose, re.MULTILINE)
        self.assertEqual(
            published_ports,
            [
                "127.0.0.1:${HAVENSIGNAL_POSTGRES_PORT:-55432}:5432",
                "127.0.0.1:${HAVENSIGNAL_HTTP_PORT:-8000}:8000",
            ],
        )

    def test_runtime_is_non_root_and_read_only(self) -> None:
        self.assertIn("USER 10001:10001", self.dockerfile)
        self.assertIn("python -m pip install --require-hashes", self.dockerfile)
        web_section = self.compose.split("  web:\n", 1)[1].split("  test:\n", 1)[0]
        self.assertIn("read_only: true", web_section)
        self.assertIn("cap_drop:\n    - ALL", self.compose)

    def test_secrets_are_file_backed_and_not_embedded(self) -> None:
        self.assertIn("POSTGRES_PASSWORD_FILE: /run/secrets/postgres_password", self.compose)
        self.assertIn(
            "HAVENSIGNAL_DJANGO_SECRET_FILE: /run/secrets/django_secret_key",
            self.compose,
        )
        self.assertNotRegex(self.compose, r"(?m)^\s*(?:POSTGRES_PASSWORD|SECRET_KEY):")

    def test_postgresql_profile_remains_explicitly_local(self) -> None:
        settings = (BASE_DIR / "anonymous_reporting/settings_docker.py").read_text(
            encoding="utf-8"
        )
        self.assertIn('"ENGINE": "django.db.backends.postgresql"', settings)
        self.assertIn('"sslmode": "disable"', settings)
        self.assertEqual(
            (BASE_DIR / ".gitignore").read_text(encoding="utf-8").count(
                "/.docker/secrets/"
            ),
            1,
        )
