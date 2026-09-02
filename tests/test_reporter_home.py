"""Security and behavior tests for the inert reporter landing page."""

from django.http import HttpRequest, HttpResponse
from django.test import SimpleTestCase
from django.urls import reverse

from reporter_gateway.middleware import (
    SUBMISSION_MAX_CONTENT_LENGTH_BYTES,
    ReporterSecurityHeadersMiddleware,
)
from reporter_gateway.views import status, submit_unavailable


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


class ReporterStatusTests(SimpleTestCase):
    def test_status_surface_is_static_and_explicitly_inert(self) -> None:
        response = self.client.get(reverse("reporter-status"))

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Stato pubblico del servizio")
        self.assertContains(response, "Superfici abilitate")
        self.assertNotContains(response, "<form")
        self.assertNotContains(response, "<script")
        self.assertFalse(response.cookies)

    def test_status_rejects_unsafe_http_methods(self) -> None:
        for method in ("post", "put", "patch", "delete"):
            with self.subTest(method=method):
                response = getattr(self.client, method)(reverse("reporter-status"))
                self.assertEqual(response.status_code, 405)

    def test_status_view_does_not_need_request_body(self) -> None:
        class BodyExplodes(HttpRequest):
            @property
            def body(self) -> bytes:  # type: ignore[override]
                raise AssertionError("body must not be read")

        request = BodyExplodes()
        request.method = "GET"

        response = status(request)

        self.assertEqual(response.status_code, 200)

    def test_status_has_restrictive_browser_headers(self) -> None:
        response = self.client.get(reverse("reporter-status"))

        self.assertEqual(response.headers["Cache-Control"], "no-store, max-age=0")
        self.assertEqual(response.headers["Pragma"], "no-cache")
        self.assertEqual(response.headers["Referrer-Policy"], "no-referrer")
        self.assertEqual(response.headers["X-Frame-Options"], "DENY")
        self.assertEqual(response.headers["X-Content-Type-Options"], "nosniff")
        self.assertIn("default-src 'none'", response.headers["Content-Security-Policy"])
        self.assertIn("script-src 'none'", response.headers["Content-Security-Policy"])
        self.assertIn("frame-ancestors 'none'", response.headers["Content-Security-Policy"])


class ReporterSubmitUnavailableTests(SimpleTestCase):
    def test_submit_surface_is_visible_but_explicitly_disabled(self) -> None:
        response = self.client.get(reverse("reporter-submit"))

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Invio non ancora abilitato")
        self.assertContains(response, "Submission fail-closed")
        self.assertNotContains(response, "<form")
        self.assertNotContains(response, "<script")
        self.assertFalse(response.cookies)

    def test_submit_post_fails_closed_without_echoing_reporter_content(self) -> None:
        sentinel = "REPORT_TEXT_SENTINEL_DO_NOT_ECHO"
        response = self.client.post(
            reverse("reporter-submit"),
            data=sentinel,
            content_type="text/plain",
        )

        self.assertEqual(response.status_code, 503)
        self.assertEqual(response.content, b"submission_unavailable")
        self.assertNotIn(sentinel, response.content.decode("utf-8"))
        self.assertFalse(response.cookies)

    def test_submit_query_string_fails_before_view_without_echo(self) -> None:
        sentinel = "REPORT_SECRET_SENTINEL_DO_NOT_ECHO"
        response = self.client.get(
            reverse("reporter-submit"),
            query_params={"secret": sentinel},
        )

        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.content, b"submission_unavailable")
        self.assertNotIn(sentinel, response.content.decode("utf-8"))
        self.assertEqual(response.headers["Cache-Control"], "no-store, max-age=0")
        self.assertFalse(response.cookies)

    def test_submit_view_does_not_need_request_body_for_post(self) -> None:
        class BodyExplodes(HttpRequest):
            @property
            def body(self) -> bytes:  # type: ignore[override]
                raise AssertionError("body must not be read")

        request = BodyExplodes()
        request.method = "POST"

        response = submit_unavailable(request)

        self.assertEqual(response.status_code, 503)
        self.assertEqual(response.content, b"submission_unavailable")

    def test_submit_oversized_content_length_fails_before_view(self) -> None:
        class BodyExplodes(HttpRequest):
            @property
            def body(self) -> bytes:  # type: ignore[override]
                raise AssertionError("body must not be read")

        def reject_view_call(request: HttpRequest) -> HttpResponse:
            raise AssertionError("view must not be called")

        request = BodyExplodes()
        request.method = "POST"
        request.path_info = "/submit/"
        request.META["CONTENT_LENGTH"] = str(SUBMISSION_MAX_CONTENT_LENGTH_BYTES + 1)
        middleware = ReporterSecurityHeadersMiddleware(reject_view_call)

        response = middleware(request)

        self.assertEqual(response.status_code, 413)
        self.assertEqual(response.content, b"submission_unavailable")
        self.assertEqual(response.headers["Cache-Control"], "no-store, max-age=0")
        self.assertIn("default-src 'none'", response.headers["Content-Security-Policy"])

    def test_submit_invalid_content_length_fails_before_view(self) -> None:
        for content_length in ("", "0", "-1", "+1", "22 MiB"):
            with self.subTest(content_length=content_length):
                request = HttpRequest()
                request.method = "POST"
                request.path_info = "/submit/"
                request.META["CONTENT_LENGTH"] = content_length
                middleware = ReporterSecurityHeadersMiddleware(
                    lambda request: HttpResponse("unexpected")
                )

                response = middleware(request)

                self.assertEqual(response.status_code, 400)
                self.assertEqual(response.content, b"submission_unavailable")

    def test_submit_forbidden_framing_headers_fail_before_view(self) -> None:
        class BodyExplodes(HttpRequest):
            @property
            def body(self) -> bytes:  # type: ignore[override]
                raise AssertionError("body must not be read")

        def reject_view_call(request: HttpRequest) -> HttpResponse:
            raise AssertionError("view must not be called")

        sentinel = "UNTRUSTED_HEADER_VALUE_DO_NOT_ECHO"
        for meta_key in (
            "HTTP_CONTENT_ENCODING",
            "HTTP_EXPECT",
            "HTTP_TRAILER",
            "HTTP_TRANSFER_ENCODING",
        ):
            with self.subTest(meta_key=meta_key):
                request = BodyExplodes()
                request.method = "POST"
                request.path_info = "/submit/"
                request.META["CONTENT_LENGTH"] = "1"
                request.META[meta_key] = sentinel
                middleware = ReporterSecurityHeadersMiddleware(reject_view_call)

                response = middleware(request)

                self.assertEqual(response.status_code, 400)
                self.assertEqual(response.content, b"submission_unavailable")
                self.assertNotIn(sentinel, response.content.decode("utf-8"))
                self.assertEqual(
                    response.headers["Cache-Control"],
                    "no-store, max-age=0",
                )
                self.assertFalse(response.cookies)

    def test_submit_limit_content_length_continues_to_fail_closed_view(self) -> None:
        request = HttpRequest()
        request.method = "POST"
        request.path_info = "/submit/"
        request.META["CONTENT_LENGTH"] = str(SUBMISSION_MAX_CONTENT_LENGTH_BYTES)
        middleware = ReporterSecurityHeadersMiddleware(
            lambda request: HttpResponse(
                "submission_unavailable",
                content_type="text/plain; charset=utf-8",
                status=503,
            )
        )

        response = middleware(request)

        self.assertEqual(response.status_code, 503)
        self.assertEqual(response.content, b"submission_unavailable")

    def test_submit_rejects_other_unsafe_methods(self) -> None:
        for method in ("put", "patch", "delete"):
            with self.subTest(method=method):
                response = getattr(self.client, method)(reverse("reporter-submit"))
                self.assertEqual(response.status_code, 405)

    def test_submit_has_restrictive_browser_headers(self) -> None:
        response = self.client.get(reverse("reporter-submit"))

        self.assertEqual(response.headers["Cache-Control"], "no-store, max-age=0")
        self.assertEqual(response.headers["Pragma"], "no-cache")
        self.assertEqual(response.headers["Referrer-Policy"], "no-referrer")
        self.assertEqual(response.headers["X-Frame-Options"], "DENY")
        self.assertEqual(response.headers["X-Content-Type-Options"], "nosniff")
        self.assertIn("default-src 'none'", response.headers["Content-Security-Policy"])
        self.assertIn("script-src 'none'", response.headers["Content-Security-Policy"])
