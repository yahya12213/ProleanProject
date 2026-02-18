from __future__ import annotations

from django.http import JsonResponse
from django.shortcuts import redirect

from .integration.authz import ExternalAuthorizationService


class ExternalAuthorityGuardMiddleware:
    """
    Enforces external authority checks on authenticated mutation requests.
    """

    SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}
    SKIP_PREFIXES = ("/admin/", "/static/", "/media/")
    SKIP_MUTATION_PATHS = ("/logout/",)

    def __init__(self, get_response):
        self.get_response = get_response
        self.authz = ExternalAuthorizationService()

    def __call__(self, request):
        if request.path.startswith(self.SKIP_PREFIXES):
            return self.get_response(request)

        if request.method not in self.SAFE_METHODS:
            if request.path in self.SKIP_MUTATION_PATHS:
                return self.get_response(request)
            if request.path.startswith("/external/live/") and request.path.endswith("/leave/"):
                return self.get_response(request)

        if request.user.is_authenticated and request.method not in self.SAFE_METHODS:
            subject_id = getattr(request.user, "username", "") or str(request.user.id)
            bearer_token = request.session.get("barka_token") if hasattr(request, "session") else None
            decision = self.authz.evaluate(
                subject_id=subject_id,
                mutation=True,
                allow_local_fallback=False,
                bearer_token=bearer_token,
            )
            request.integration_auth_decision = decision

            if not decision.allowed:
                if request.path.startswith("/api/"):
                    return JsonResponse(
                        {
                            "status": "error",
                            "reason": decision.reason,
                            "source": decision.source,
                            "read_only": decision.is_read_only,
                        },
                        status=403,
                    )
                return redirect("Prolean:account_status")

        return self.get_response(request)
