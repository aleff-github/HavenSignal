"""Root URL configuration."""

from django.urls import URLPattern, URLResolver, path

from reporter_gateway.views import home, submit_unavailable


urlpatterns: list[URLPattern | URLResolver] = [
    path("", home, name="reporter-home"),
    path("submit/", submit_unavailable, name="reporter-submit"),
]
