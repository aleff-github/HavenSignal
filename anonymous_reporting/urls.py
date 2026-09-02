"""Root URL configuration."""

from django.urls import URLPattern, URLResolver, path

from reporter_gateway.views import home, response_unavailable, submit_unavailable


urlpatterns: list[URLPattern | URLResolver] = [
    path("", home, name="reporter-home"),
    path("submit/", submit_unavailable, name="reporter-submit"),
    path("response/", response_unavailable, name="reporter-response"),
]
