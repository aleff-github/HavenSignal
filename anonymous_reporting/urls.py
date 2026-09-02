"""Root URL configuration."""

from django.urls import URLPattern, URLResolver, include, path


urlpatterns: list[URLPattern | URLResolver] = [
    path("", include("reporter_gateway.urls")),
    path("response/", include("recovery_gateway.urls")),
    path("operator/", include("operator_console.urls")),
]
