"""Security and behavior tests for the inert operator console surface."""

from django.http import HttpRequest
from django.test import SimpleTestCase
from django.urls import reverse

from operator_console.views import operator_unavailable


class OperatorConsoleUnavailableTests(SimpleTestCase):
    def test_operator_surface_is_visible_but_explicitly_disabled(self) -> None:
        response = self.client.get(reverse("operator-console"))

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Console operatore non ancora abilitata")
        self.assertContains(response, "Operator authentication fail-closed")
        self.assertNotContains(response, "<form")
        self.assertNotContains(response, "<script")
        self.assertFalse(response.cookies)

    def test_operator_post_fails_closed_without_echoing_credentials(self) -> None:
        sentinel = "OPERATOR_PASSWORD_SENTINEL_DO_NOT_ECHO"
        response = self.client.post(
            reverse("operator-console"),
            data=sentinel,
            content_type="text/plain",
        )

        self.assertEqual(response.status_code, 503)
        self.assertEqual(response.content, b"operator_authentication_unavailable")
        self.assertNotIn(sentinel, response.content.decode("utf-8"))
        self.assertFalse(response.cookies)

    def test_operator_view_does_not_need_request_body_for_post(self) -> None:
        class BodyExplodes(HttpRequest):
            @property
            def body(self) -> bytes:  # type: ignore[override]
                raise AssertionError("body must not be read")

        request = BodyExplodes()
        request.method = "POST"

        response = operator_unavailable(request)

        self.assertEqual(response.status_code, 503)
        self.assertEqual(response.content, b"operator_authentication_unavailable")

    def test_operator_rejects_other_unsafe_methods(self) -> None:
        for method in ("put", "patch", "delete"):
            with self.subTest(method=method):
                response = getattr(self.client, method)(reverse("operator-console"))
                self.assertEqual(response.status_code, 405)

    def test_operator_has_restrictive_browser_headers(self) -> None:
        response = self.client.get(reverse("operator-console"))

        self.assertEqual(response.headers["Cache-Control"], "no-store, max-age=0")
        self.assertEqual(response.headers["Pragma"], "no-cache")
        self.assertEqual(response.headers["Referrer-Policy"], "no-referrer")
        self.assertEqual(response.headers["X-Frame-Options"], "DENY")
        self.assertEqual(response.headers["X-Content-Type-Options"], "nosniff")
        self.assertIn("default-src 'none'", response.headers["Content-Security-Policy"])
        self.assertIn("script-src 'none'", response.headers["Content-Security-Policy"])
        self.assertIn("frame-ancestors 'none'", response.headers["Content-Security-Policy"])
