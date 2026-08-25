"""Root URL configuration for the empty project."""

from django.urls import URLPattern, URLResolver


# Product endpoints are intentionally absent from this bootstrap.
urlpatterns: list[URLPattern | URLResolver] = []
