"""Root URL configuration."""

from django.urls import URLPattern, URLResolver, path

from reporter_gateway.views import home


urlpatterns: list[URLPattern | URLResolver] = [
    path("", home, name="reporter-home"),
]
