"""Browser-facing headers for the public reporter surface."""

from collections.abc import Callable

from django.http import HttpRequest, HttpResponse


SUBMISSION_MAX_CONTENT_LENGTH_BYTES = 22_020_096


class ReporterSecurityHeadersMiddleware:
    """Apply restrictive, persistence-minimizing headers to every response."""

    def __init__(self, get_response: Callable[[HttpRequest], HttpResponse]) -> None:
        self.get_response = get_response

    def __call__(self, request: HttpRequest) -> HttpResponse:
        response = self._admit_request(request)
        if response is None:
            response = self.get_response(request)
        return self._apply_headers(response)

    def _admit_request(self, request: HttpRequest) -> HttpResponse | None:
        if request.path_info in ("/submit/", "/response/") and request.META.get(
            "QUERY_STRING", ""
        ):
            response_code = (
                "submission_unavailable"
                if request.path_info == "/submit/"
                else "response_retrieval_unavailable"
            )
            return HttpResponse(
                response_code,
                content_type="text/plain; charset=utf-8",
                status=400,
            )
        if request.method != "POST" or request.path_info != "/submit/":
            return None
        content_length = request.META.get("CONTENT_LENGTH", "")
        if not content_length.isdecimal() or int(content_length) < 1:
            return HttpResponse(
                "submission_unavailable",
                content_type="text/plain; charset=utf-8",
                status=400,
            )
        if int(content_length) > SUBMISSION_MAX_CONTENT_LENGTH_BYTES:
            return HttpResponse(
                "submission_unavailable",
                content_type="text/plain; charset=utf-8",
                status=413,
            )
        return None

    def _apply_headers(self, response: HttpResponse) -> HttpResponse:
        response["Cache-Control"] = "no-store, max-age=0"
        response["Pragma"] = "no-cache"
        response["Content-Security-Policy"] = "; ".join(
            (
                "default-src 'none'",
                "style-src 'self'",
                "script-src 'none'",
                "img-src 'self'",
                "font-src 'self'",
                "connect-src 'self'",
                "object-src 'none'",
                "base-uri 'none'",
                "form-action 'self'",
                "frame-ancestors 'none'",
            )
        )
        response["Referrer-Policy"] = "no-referrer"
        response["Permissions-Policy"] = (
            "camera=(), geolocation=(), microphone=(), payment=(), usb=()"
        )
        response["Cross-Origin-Opener-Policy"] = "same-origin"
        response["Cross-Origin-Resource-Policy"] = "same-origin"
        response["X-Permitted-Cross-Domain-Policies"] = "none"
        return response
