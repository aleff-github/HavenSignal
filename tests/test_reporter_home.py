"""Security and behavior tests for the inert reporter landing page."""

from django.test import SimpleTestCase
from django.urls import reverse


class ReporterHomeTests(SimpleTestCase):
    def test_home_is_visible_but_explicitly_inert(self) -> None:
        response = self.client.get(reverse("reporter-home"))

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Ambiente in costruzione")
        self.assertContains(response, "Non ancora disponibile", count=2)
        self.assertNotContains(response, "<form")
        self.assertNotContains(response, "<script")
        self.assertFalse(response.cookies)

    def test_home_rejects_unsafe_http_methods(self) -> None:
        for method in ("post", "put", "patch", "delete"):
            with self.subTest(method=method):
                response = getattr(self.client, method)(reverse("reporter-home"))
                self.assertEqual(response.status_code, 405)

    def test_home_has_restrictive_browser_headers(self) -> None:
        response = self.client.get(reverse("reporter-home"))

        self.assertEqual(response.headers["Cache-Control"], "no-store, max-age=0")
        self.assertEqual(response.headers["Pragma"], "no-cache")
        self.assertEqual(response.headers["Referrer-Policy"], "no-referrer")
        self.assertEqual(response.headers["X-Frame-Options"], "DENY")
        self.assertEqual(response.headers["X-Content-Type-Options"], "nosniff")
        self.assertIn("default-src 'none'", response.headers["Content-Security-Policy"])
        self.assertIn("script-src 'none'", response.headers["Content-Security-Policy"])
        self.assertIn("frame-ancestors 'none'", response.headers["Content-Security-Policy"])

    def test_home_uses_only_a_same_origin_stylesheet(self) -> None:
        response = self.client.get(reverse("reporter-home"))
        html = response.content.decode("utf-8")

        self.assertIn('href="/static/reporter_gateway/home.css"', html)
        self.assertNotIn("http://", html)
        self.assertNotIn("https://", html)
