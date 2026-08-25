"""Development-only settings for the empty Django project.

This module is intentionally not suitable for production deployment. A future
production settings module must fail closed unless its secret key and host
allowlist are supplied externally and all deployment controls are approved.
"""

from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent.parent

# Development-only key. It protects no production or reporter data and must
# never be reused by a production settings module.
SECRET_KEY = "django-insecure-development-only-not-for-production"

DEBUG = True
ALLOWED_HOSTS: list[str] = []

# No product or Django-contrib application is enabled in this bootstrap.
INSTALLED_APPS: list[str] = []

# Preserve Django's core request, CSRF, and clickjacking protections even in the
# empty development scaffold.
MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
]

ROOT_URLCONF = "anonymous_reporting.urls"

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [],
        "APP_DIRS": True,
        "OPTIONS": {"context_processors": []},
    }
]

WSGI_APPLICATION = "anonymous_reporting.wsgi.application"
ASGI_APPLICATION = "anonymous_reporting.asgi.application"

# SQLite is used only for local development scaffolding. No application models
# or business schema are present, and the generated file is ignored by Git.
DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.sqlite3",
        "NAME": BASE_DIR / "db.sqlite3",
    }
}

LANGUAGE_CODE = "en-us"
TIME_ZONE = "UTC"
USE_I18N = True
USE_TZ = True

X_FRAME_OPTIONS = "DENY"
SECURE_CONTENT_TYPE_NOSNIFF = True
