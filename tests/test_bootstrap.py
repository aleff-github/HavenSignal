"""Smoke test for the intentionally empty Django project."""

from django.conf import settings
from django.test import SimpleTestCase
from django.urls import get_resolver


class BootstrapSmokeTest(SimpleTestCase):
    def test_empty_project_has_security_middleware_and_no_routes(self) -> None:
        required_middleware = {
            "django.middleware.security.SecurityMiddleware",
            "django.middleware.csrf.CsrfViewMiddleware",
            "django.middleware.clickjacking.XFrameOptionsMiddleware",
        }

        self.assertTrue(required_middleware.issubset(settings.MIDDLEWARE))
        self.assertEqual(get_resolver().url_patterns, [])
