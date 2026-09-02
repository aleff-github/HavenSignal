"""Fail-closed views for the public recovery surface."""

from django.http import HttpRequest, HttpResponse
from django.shortcuts import render
from django.views.decorators.http import require_http_methods


@require_http_methods(["GET", "POST"])
def response_unavailable(request: HttpRequest) -> HttpResponse:
    """Expose recovery routing while response retrieval remains closed."""

    if request.method == "POST":
        return HttpResponse(
            "response_retrieval_unavailable",
            content_type="text/plain; charset=utf-8",
            status=503,
        )
    return render(request, "recovery_gateway/response_unavailable.html")
