"""
WSGI config for Project project.

It exposes the WSGI callable as a module-level variable named ``application``.

For more information on this file, see
https://docs.djangoproject.com/en/6.0/howto/deployment/wsgi/
"""

import os

from django.core.wsgi import get_wsgi_application

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'Project.settings')

application = get_wsgi_application()

# Log key runtime settings in PaaS logs (Railway) so misconfigurations are obvious.
try:
    import logging
    from django.conf import settings

    logger = logging.getLogger("prolean.startup")
    release = os.getenv("RAILWAY_GIT_COMMIT_SHA") or os.getenv("GIT_SHA") or "unknown"
    logger.info(
        "Prolean startup release=%s DEBUG=%s ALLOWED_HOSTS=%s CSRF_TRUSTED_ORIGINS=%s",
        release,
        settings.DEBUG,
        getattr(settings, "ALLOWED_HOSTS", None),
        getattr(settings, "CSRF_TRUSTED_ORIGINS", None),
    )
except Exception:
    # Never block startup on logging issues.
    pass
