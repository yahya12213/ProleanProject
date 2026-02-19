from __future__ import annotations

from django.http import JsonResponse
from django.shortcuts import redirect
from django.utils import translation

from .integration.authz import ExternalAuthorizationService


class ExternalAuthorityGuardMiddleware:
    """
    Enforces external authority checks on authenticated mutation requests.
    """

    SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}
    SKIP_PREFIXES = ("/admin/", "/static/", "/media/")
    SKIP_MUTATION_PATHS = (
        "/logout/",
        "/i18n/setlang/",
        "/i18n/set/",
        "/api/presence/heartbeat/",
    )

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


class AutoLanguageMiddleware:
    """
    Auto-detect user language (fr/en/ar) from browser headers when no language
    has been selected yet. It keeps user choice stable via session + cookie.
    """

    SUPPORTED = ("fr", "en", "ar")

    def __init__(self, get_response):
        self.get_response = get_response

    def _pick_language(self, request) -> str:
        header = str(request.META.get("HTTP_ACCEPT_LANGUAGE", "") or "").lower()
        if not header:
            return "fr"
        chunks = [p.split(";")[0].strip() for p in header.split(",") if p.strip()]
        for chunk in chunks:
            base = chunk.split("-")[0]
            if base in self.SUPPORTED:
                return base
        return "fr"

    def __call__(self, request):
        cookie_lang = request.COOKIES.get("django_language")
        if cookie_lang in self.SUPPORTED:
            selected = cookie_lang
        else:
            selected = self._pick_language(request)
        translation.activate(selected)
        request.LANGUAGE_CODE = selected
        response = self.get_response(request)
        # Don't clobber an explicit language change performed by a view.
        final_lang = (
            str(getattr(request, "LANGUAGE_CODE", "") or "").strip().lower()
            or str(translation.get_language() or "").strip().lower()
            or selected
        )
        if "-" in final_lang:
            final_lang = final_lang.split("-", 1)[0]
        if final_lang not in self.SUPPORTED:
            final_lang = selected
        response.set_cookie("django_language", final_lang, max_age=31536000, samesite="Lax")
        return response
