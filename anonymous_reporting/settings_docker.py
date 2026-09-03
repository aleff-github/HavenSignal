"""Local Docker alpha settings backed by an isolated PostgreSQL service."""

import os
from pathlib import Path

from .settings import *  # noqa: F403


def _read_local_secret(environment_name: str, default_path: str) -> str:
    path = Path(os.environ.get(environment_name, default_path))
    try:
        value = path.read_text(encoding="utf-8").strip()
    except (OSError, UnicodeError):
        raise RuntimeError("local_docker_secret_unavailable") from None
    if len(value) < 32:
        raise RuntimeError("local_docker_secret_invalid")
    return value


SECRET_KEY = _read_local_secret(  # noqa: F405
    "HAVENSIGNAL_DJANGO_SECRET_FILE",
    "/run/secrets/django_secret_key",
)
ALLOWED_HOSTS = ["127.0.0.1", "localhost"]  # noqa: F405

DATABASES = {  # noqa: F405
    "default": {
        "ENGINE": "django.db.backends.postgresql",
        "NAME": os.environ.get("HAVENSIGNAL_DB_NAME", "havensignal"),
        "USER": os.environ.get("HAVENSIGNAL_DB_USER", "havensignal"),
        "PASSWORD": _read_local_secret(
            "HAVENSIGNAL_DB_PASSWORD_FILE",
            "/run/secrets/postgres_password",
        ),
        "HOST": os.environ.get("HAVENSIGNAL_DB_HOST", "postgres"),
        "PORT": os.environ.get("HAVENSIGNAL_DB_PORT", "5432"),
        "CONN_MAX_AGE": 0,
        "CONN_HEALTH_CHECKS": True,
        "OPTIONS": {
            "connect_timeout": 5,
            "sslmode": "disable",
        },
        "TEST": {
            "NAME": "test_havensignal",
        },
    }
}
