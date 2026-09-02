"""Django application configuration for the inert recovery gateway."""

from django.apps import AppConfig


class RecoveryGatewayConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "recovery_gateway"
    verbose_name = "Recovery gateway"
