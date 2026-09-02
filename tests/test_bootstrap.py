"""Smoke tests for the minimal Django project."""

from django.conf import settings
from django.test import SimpleTestCase
from django.urls import reverse


class BootstrapSmokeTest(SimpleTestCase):
    def test_project_has_required_security_middleware(self) -> None:
        required_middleware = {
            "django.middleware.security.SecurityMiddleware",
            "django.middleware.csrf.CsrfViewMiddleware",
            "django.middleware.clickjacking.XFrameOptionsMiddleware",
        }

        self.assertTrue(required_middleware.issubset(settings.MIDDLEWARE))
        self.assertEqual(reverse("reporter-home"), "/")
        self.assertEqual(reverse("reporter-status"), "/status/")
        self.assertEqual(reverse("reporter-submit"), "/submit/")
        self.assertEqual(reverse("reporter-response"), "/response/")
        self.assertEqual(reverse("operator-console"), "/operator/")
