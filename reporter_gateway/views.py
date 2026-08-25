"""Read-only views for the public reporter surface."""

from django.http import HttpRequest, HttpResponse
from django.shortcuts import render
from django.views.decorators.http import require_safe


@require_safe
def home(request: HttpRequest) -> HttpResponse:
    """Show project status without accepting or persisting reporter input."""

    return render(request, "reporter_gateway/home.html")
