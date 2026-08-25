"""WSGI config for the AnonymousReporting project."""

import os

from django.core.wsgi import get_wsgi_application


os.environ.setdefault("DJANGO_SETTINGS_MODULE", "anonymous_reporting.settings")

application = get_wsgi_application()
