"""URL configuration for the inert public recovery gateway."""

from django.urls import URLPattern, URLResolver, path

from .views import response_unavailable


urlpatterns: list[URLPattern | URLResolver] = [
    path("", response_unavailable, name="reporter-response"),
]
