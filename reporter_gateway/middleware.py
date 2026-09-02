"""Browser-facing headers for the public reporter surface."""

from collections.abc import Callable

from django.http import HttpRequest, HttpResponse


SUBMISSION_MAX_CONTENT_LENGTH_BYTES = 22_020_096
SUBMISSION_MAX_CONTENT_LENGTH_DECIMAL = str(SUBMISSION_MAX_CONTENT_LENGTH_BYTES)
FORBIDDEN_SUBMISSION_META_KEYS = frozenset(
    {
        "HTTP_CONTENT_ENCODING",
        "HTTP_EXPECT",
        "HTTP_TRAILER",
        "HTTP_TRANSFER_ENCODING",
    }
)
SENSITIVE_QUERY_PATH_RESPONSE_CODES = (
    (("/submit", "/submit/"), "submission_unavailable"),
    (("/response", "/response/"), "response_retrieval_unavailable"),
    (("/operator", "/operator/"), "operator_authentication_unavailable"),
)


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
        query_path_response = next(
            (
                (paths, code)
                for paths, code in SENSITIVE_QUERY_PATH_RESPONSE_CODES
                if request.path_info in paths
            ),
            None,
        )
        if query_path_response is not None:
            paths, response_code = query_path_response
            if (
                request.path_info != paths[1]
                or request.META.get("QUERY_STRING", "")
            ):
                return HttpResponse(
                    response_code,
                    content_type="text/plain; charset=utf-8",
                    status=400,
                )
        if request.method != "POST" or request.path_info != "/submit/":
            return None
        if any(key in request.META for key in FORBIDDEN_SUBMISSION_META_KEYS):
            return HttpResponse(
                "submission_unavailable",
                content_type="text/plain; charset=utf-8",
                status=400,
            )
        content_length = request.META.get("CONTENT_LENGTH", "")
        if (
            not isinstance(content_length, str)
            or not content_length.isascii()
            or not content_length.isdecimal()
        ):
            return HttpResponse(
                "submission_unavailable",
                content_type="text/plain; charset=utf-8",
                status=400,
            )
        normalized_content_length = content_length.lstrip("0")
        if not normalized_content_length:
            return HttpResponse(
                "submission_unavailable",
                content_type="text/plain; charset=utf-8",
                status=400,
            )
        normalized_digits = len(normalized_content_length)
        maximum_digits = len(SUBMISSION_MAX_CONTENT_LENGTH_DECIMAL)
        if normalized_digits > maximum_digits or (
            normalized_digits == maximum_digits
            and normalized_content_length > SUBMISSION_MAX_CONTENT_LENGTH_DECIMAL
        ):
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
