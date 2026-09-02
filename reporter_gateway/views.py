"""Fail-closed views for the public reporter surface."""

from django.http import HttpRequest, HttpResponse
from django.shortcuts import render
from django.views.decorators.http import require_http_methods, require_safe


@require_safe
def home(request: HttpRequest) -> HttpResponse:
    """Show project status without accepting or persisting reporter input."""

    return render(request, "reporter_gateway/home.html")


@require_safe
def status(request: HttpRequest) -> HttpResponse:
    """Show a static public status page without reading runtime state."""

    return render(request, "reporter_gateway/status.html")


@require_http_methods(["GET", "POST"])
def submit_unavailable(request: HttpRequest) -> HttpResponse:
    """Expose the submission surface while intake dependencies remain closed."""

    if request.method == "POST":
        return HttpResponse(
            "submission_unavailable",
            content_type="text/plain; charset=utf-8",
            status=503,
        )
    return render(request, "reporter_gateway/submit_unavailable.html")


@require_http_methods(["GET", "POST"])
def response_unavailable(request: HttpRequest) -> HttpResponse:
    """Expose recovery routing while response retrieval remains closed."""

    if request.method == "POST":
        return HttpResponse(
            "response_retrieval_unavailable",
            content_type="text/plain; charset=utf-8",
            status=503,
        )
    return render(request, "reporter_gateway/response_unavailable.html")
