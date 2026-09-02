"""Fail-closed views for the operator console surface."""

from django.http import HttpRequest, HttpResponse
from django.shortcuts import render
from django.views.decorators.http import require_http_methods


@require_http_methods(["GET", "POST"])
def operator_unavailable(request: HttpRequest) -> HttpResponse:
    """Expose operator-console routing while authentication remains closed."""

    if request.method == "POST":
        return HttpResponse(
            "operator_authentication_unavailable",
            content_type="text/plain; charset=utf-8",
            status=503,
        )
    return render(request, "operator_console/unavailable.html")
