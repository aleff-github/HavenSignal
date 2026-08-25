"""Browser-facing headers for the public reporter surface."""

from collections.abc import Callable

from django.http import HttpRequest, HttpResponse


class ReporterSecurityHeadersMiddleware:
    """Apply restrictive, persistence-minimizing headers to every response."""

    def __init__(self, get_response: Callable[[HttpRequest], HttpResponse]) -> None:
        self.get_response = get_response

    def __call__(self, request: HttpRequest) -> HttpResponse:
        response = self.get_response(request)
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
