"""URL configuration for the inert operator console."""

from django.urls import URLPattern, URLResolver, path

from .views import operator_unavailable


urlpatterns: list[URLPattern | URLResolver] = [
    path("", operator_unavailable, name="operator-console"),
]
