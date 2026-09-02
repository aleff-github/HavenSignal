"""Security and behavior tests for the inert recovery gateway surface."""

from django.http import HttpRequest
from django.test import SimpleTestCase
from django.urls import reverse

from recovery_gateway.views import response_unavailable


class RecoveryResponseUnavailableTests(SimpleTestCase):
    def test_response_surface_is_visible_but_explicitly_disabled(self) -> None:
        response = self.client.get(reverse("reporter-response"))

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Recupero risposta non ancora abilitato")
        self.assertContains(response, "Response retrieval fail-closed")
        self.assertNotContains(response, "<form")
        self.assertNotContains(response, "<script")
        self.assertFalse(response.cookies)

    def test_response_post_fails_closed_without_echoing_credentials(self) -> None:
        sentinel = "RECOVERY_SECRET_SENTINEL_DO_NOT_ECHO"
        response = self.client.post(
            reverse("reporter-response"),
            data=sentinel,
            content_type="text/plain",
        )

        self.assertEqual(response.status_code, 503)
        self.assertEqual(response.content, b"response_retrieval_unavailable")
        self.assertNotIn(sentinel, response.content.decode("utf-8"))
        self.assertFalse(response.cookies)

    def test_response_query_string_fails_before_view_without_echo(self) -> None:
        sentinel = "RECOVERY_SECRET_SENTINEL_DO_NOT_ECHO"
        for method in ("get", "post"):
            with self.subTest(method=method):
                response = getattr(self.client, method)(
                    reverse("reporter-response"),
                    query_params={"secret": sentinel},
                )

                self.assertEqual(response.status_code, 400)
                self.assertEqual(
                    response.content,
                    b"response_retrieval_unavailable",
                )
                self.assertNotIn(sentinel, response.content.decode("utf-8"))
                self.assertEqual(
                    response.headers["Cache-Control"],
                    "no-store, max-age=0",
                )
                self.assertFalse(response.cookies)

    def test_response_query_on_missing_slash_is_not_redirected(self) -> None:
        sentinel = "RECOVERY_SECRET_SENTINEL_DO_NOT_REDIRECT"
        for method in ("get", "post"):
            with self.subTest(method=method):
                response = getattr(self.client, method)(
                    "/response",
                    query_params={"secret": sentinel},
                )

                self.assertEqual(response.status_code, 400)
                self.assertEqual(
                    response.content,
                    b"response_retrieval_unavailable",
                )
                self.assertNotIn("Location", response.headers)
                self.assertNotIn(sentinel, response.content.decode("utf-8"))
                self.assertFalse(response.cookies)

    def test_response_view_does_not_need_request_body_for_post(self) -> None:
        class BodyExplodes(HttpRequest):
            @property
            def body(self) -> bytes:  # type: ignore[override]
                raise AssertionError("body must not be read")

        request = BodyExplodes()
        request.method = "POST"

        response = response_unavailable(request)

        self.assertEqual(response.status_code, 503)
        self.assertEqual(response.content, b"response_retrieval_unavailable")

    def test_response_rejects_other_unsafe_methods(self) -> None:
        for method in ("put", "patch", "delete"):
            with self.subTest(method=method):
                response = getattr(self.client, method)(reverse("reporter-response"))
                self.assertEqual(response.status_code, 405)

    def test_response_has_restrictive_browser_headers(self) -> None:
        response = self.client.get(reverse("reporter-response"))

        self.assertEqual(response.headers["Cache-Control"], "no-store, max-age=0")
        self.assertEqual(response.headers["Pragma"], "no-cache")
        self.assertEqual(response.headers["Referrer-Policy"], "no-referrer")
        self.assertEqual(response.headers["X-Frame-Options"], "DENY")
        self.assertEqual(response.headers["X-Content-Type-Options"], "nosniff")
        self.assertIn("default-src 'none'", response.headers["Content-Security-Policy"])
        self.assertIn("script-src 'none'", response.headers["Content-Security-Policy"])
