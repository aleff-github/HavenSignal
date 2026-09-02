"""Root URL configuration."""

from django.urls import URLPattern, URLResolver, path

from reporter_gateway.views import (
    home,
    response_unavailable,
    status,
    submit_unavailable,
)


urlpatterns: list[URLPattern | URLResolver] = [
    path("", home, name="reporter-home"),
    path("status/", status, name="reporter-status"),
    path("submit/", submit_unavailable, name="reporter-submit"),
    path("response/", response_unavailable, name="reporter-response"),
]
