"""Smoke tests for the minimal Django project."""

from django.conf import settings
from django.test import SimpleTestCase
from django.urls import get_resolver


class BootstrapSmokeTest(SimpleTestCase):
    def test_project_has_required_security_middleware(self) -> None:
        required_middleware = {
            "django.middleware.security.SecurityMiddleware",
            "django.middleware.csrf.CsrfViewMiddleware",
            "django.middleware.clickjacking.XFrameOptionsMiddleware",
        }

        self.assertTrue(required_middleware.issubset(settings.MIDDLEWARE))
        self.assertEqual(
            {pattern.name for pattern in get_resolver().url_patterns},
            {"reporter-home", "reporter-submit", "reporter-response"},
        )
