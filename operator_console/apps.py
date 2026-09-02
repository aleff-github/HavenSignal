"""Django application configuration for the inert operator console."""

from django.apps import AppConfig


class OperatorConsoleConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "operator_console"
    verbose_name = "Operator console"
