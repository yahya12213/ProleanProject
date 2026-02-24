from __future__ import annotations

from typing import Any

import requests
from django.core.cache import cache

from .exceptions import ContractError, UpstreamUnavailable
from .settings import get_contract_settings


class ManagementContractClient:
    """HTTP client for the external authority contract."""

    def __init__(self) -> None:
        self.config = get_contract_settings()

    def is_configured(self) -> bool:
        return bool(self.config.base_url)

    def _looks_like_jwt(self, token: str) -> bool:
        return token.count(".") == 2

    def _service_token_cache_key(self) -> str:
        return "integration:service:barka_token"

    def _get_service_bearer_token(self) -> str:
        """
        Resolve a bearer token for server-to-server calls.
        Priority:
        1) PROLEAN_MANAGEMENT_API_TOKEN if it looks like a JWT
        2) cached token obtained via PROLEAN_MANAGEMENT_SERVICE_USERNAME/PASSWORD
        """
        api_token = (self.config.api_token or "").strip()
        if api_token and self._looks_like_jwt(api_token):
            return api_token

        cached = cache.get(self._service_token_cache_key())
        if isinstance(cached, str) and cached.strip():
            return cached.strip()

        username = (self.config.service_username or "").strip()
        password = (self.config.service_password or "").strip()
        if not username or not password:
            return ""

        payload = self._request(
            "POST",
            f"{self.config.base_url}/auth/login",
            json={"username": username, "password": password},
            skip_auth=True,
        )
        token = str(payload.get("token", "")).strip()
        if token and self._looks_like_jwt(token):
            cache.set(self._service_token_cache_key(), token, timeout=22 * 60 * 60)  # 22h
            return token
        return ""

    def get_service_bearer_token(self) -> str:
        """Public wrapper to obtain a server-to-server bearer token when needed."""
        return self._get_service_bearer_token()

    def get_access_snapshot(self, subject_id: str) -> dict[str, Any]:
        if not self.is_configured():
            raise ContractError("Management contract URL is not configured.")
        # Backward compatible: prefer dedicated snapshot endpoint if available.
        endpoint = f"{self.config.base_url}/access/snapshot/{subject_id}"
        return self._request("GET", endpoint)

    def sync_updates(self, cursor: str = "") -> dict[str, Any]:
        if not self.is_configured():
            raise ContractError("Management contract URL is not configured.")
        endpoint = f"{self.config.base_url}/sync/updates"
        params = {"cursor": cursor} if cursor else {}
        return self._request("GET", endpoint, params=params)

    def get_health(self) -> dict[str, Any]:
        if not self.is_configured():
            return {"status": "not_configured"}
        endpoint = f"{self.config.base_url}/health"
        try:
            return self._request("GET", endpoint)
        except UpstreamUnavailable:
            return {"status": "down"}

    # ------------------------------------------------------------------
    # Barka-compatible endpoints (Prolean consumes Barka as authority)
    # NOTE: These paths assume PROLEAN_MANAGEMENT_API_BASE_URL ends with "/api".
    # Example: https://your-barka-domain.up.railway.app/api
    # ------------------------------------------------------------------

    def login(self, username: str, password: str) -> dict[str, Any]:
        if not self.is_configured():
            raise ContractError("Management contract URL is not configured.")
        endpoint = f"{self.config.base_url}/auth/login"
        return self._request("POST", endpoint, json={"username": username, "password": password}, skip_auth=True)

    def get_current_user(self, bearer_token: str) -> dict[str, Any]:
        if not self.is_configured():
            raise ContractError("Management contract URL is not configured.")
        endpoint = f"{self.config.base_url}/auth/me"
        return self._request("GET", endpoint, bearer_token=bearer_token)

    def list_formations(self, *, bearer_token: str | None = None) -> list[dict[str, Any]]:
        if not self.is_configured():
            raise ContractError("Management contract URL is not configured.")
        resolved = bearer_token or self._get_service_bearer_token()
        endpoint = f"{self.config.base_url}/cours/formations"
        data = self._request("GET", endpoint, bearer_token=resolved)
        # Barka returns a JSON array for this endpoint.
        if isinstance(data, list):
            return data
        raise ContractError("Unexpected formations payload (expected list).")

    def get_formation(self, formation_id: str, *, bearer_token: str | None = None) -> dict[str, Any]:
        if not self.is_configured():
            raise ContractError("Management contract URL is not configured.")
        resolved = bearer_token or self._get_service_bearer_token()
        endpoint = f"{self.config.base_url}/cours/formations/{formation_id}"
        return self._request("GET", endpoint, bearer_token=resolved)

    def list_cities(self, *, bearer_token: str | None = None) -> list[dict[str, Any]]:
        if not self.is_configured():
            raise ContractError("Management contract URL is not configured.")
        resolved = bearer_token or self._get_service_bearer_token()
        endpoint = f"{self.config.base_url}/cities"
        data = self._request("GET", endpoint, bearer_token=resolved)
        if isinstance(data, list):
            return data
        # Some APIs wrap results.
        if isinstance(data, dict) and isinstance(data.get("cities"), list):
            return data["cities"]
        raise ContractError("Unexpected cities payload (expected list).")

    def create_student(self, payload: dict[str, Any], *, bearer_token: str | None = None) -> dict[str, Any]:
        """
        Create a student in Barka.
        Note: Barka endpoint may accept JSON or multipart. We try JSON first.
        """
        if not self.is_configured():
            raise ContractError("Management contract URL is not configured.")
        resolved = bearer_token or self._get_service_bearer_token()
        endpoint = f"{self.config.base_url}/students"
        return self._request("POST", endpoint, bearer_token=resolved, json=payload)

    def get_student_me_profile(self, *, bearer_token: str) -> dict[str, Any]:
        """
        Get current student profile + assignments (formations, schedule) from Barka.
        Requires a user bearer token (student token).
        """
        if not self.is_configured():
            raise ContractError("Management contract URL is not configured.")
        endpoint = f"{self.config.base_url}/students/me/profile"
        data = self._request("GET", endpoint, bearer_token=bearer_token)
        if isinstance(data, dict) and data.get("success") is True:
            return data
        if isinstance(data, dict) and data.get("error"):
            raise ContractError(str(data.get("error")))
        raise ContractError("Unexpected student profile payload.")

    def list_students_with_sessions(self, *, bearer_token: str | None = None) -> list[dict[str, Any]]:
        """
        Service-level fallback to resolve student assignments by CIN when
        student token payload is incomplete.
        """
        if not self.is_configured():
            raise ContractError("Management contract URL is not configured.")
        resolved = bearer_token or self._get_service_bearer_token()
        endpoint = f"{self.config.base_url}/students/with-sessions"
        data = self._request("GET", endpoint, bearer_token=resolved)
        if isinstance(data, list):
            return data
        raise ContractError("Unexpected students-with-sessions payload (expected list).")

    def list_sessions_formation(self, *, bearer_token: str | None = None) -> list[dict[str, Any]]:
        """
        List sessions visible to the current authenticated user.
        """
        if not self.is_configured():
            raise ContractError("Management contract URL is not configured.")
        resolved = bearer_token or self._get_service_bearer_token()
        endpoint = f"{self.config.base_url}/sessions-formation"
        data = self._request("GET", endpoint, bearer_token=resolved)
        if isinstance(data, dict) and isinstance(data.get("sessions"), list):
            return data["sessions"]
        if isinstance(data, list):
            return data
        raise ContractError("Unexpected sessions payload (expected list).")

    def get_session_formation_detail(self, session_id: str, *, bearer_token: str) -> dict[str, Any]:
        """
        Get session details with enrolled students and assigned professors.
        """
        if not self.is_configured():
            raise ContractError("Management contract URL is not configured.")
        endpoint = f"{self.config.base_url}/sessions-formation/{session_id}"
        data = self._request("GET", endpoint, bearer_token=bearer_token)
        if isinstance(data, dict) and isinstance(data.get("session"), dict):
            return data["session"]
        if isinstance(data, dict):
            return data
        raise ContractError("Unexpected session detail payload.")

    def list_my_professor_sessions(self, *, bearer_token: str) -> list[dict[str, Any]]:
        if not self.is_configured():
            raise ContractError("Management contract URL is not configured.")
        endpoint = f"{self.config.base_url}/sessions-formation/my-sessions"
        data = self._request("GET", endpoint, bearer_token=bearer_token)
        if isinstance(data, dict) and isinstance(data.get("sessions"), list):
            return data["sessions"]
        if isinstance(data, list):
            return data
        raise ContractError("Unexpected my-sessions payload (expected list).")

    def get_my_professor_session_detail(self, session_id: str, *, bearer_token: str) -> dict[str, Any]:
        if not self.is_configured():
            raise ContractError("Management contract URL is not configured.")
        endpoint = f"{self.config.base_url}/sessions-formation/my-sessions/{session_id}"
        data = self._request("GET", endpoint, bearer_token=bearer_token)
        if isinstance(data, dict) and isinstance(data.get("session"), dict):
            return data["session"]
        if isinstance(data, dict):
            return data
        raise ContractError("Unexpected my-session detail payload.")

    def get_session_live_state(self, session_id: str, *, bearer_token: str) -> dict[str, Any] | None:
        if not self.is_configured():
            raise ContractError("Management contract URL is not configured.")
        endpoint = f"{self.config.base_url}/sessions-formation/{session_id}/live"
        data = self._request("GET", endpoint, bearer_token=bearer_token)
        if isinstance(data, dict):
            live = data.get("live")
            return live if isinstance(live, dict) else None
        raise ContractError("Unexpected live state payload.")

    def start_session_live(self, session_id: str, *, bearer_token: str) -> dict[str, Any]:
        if not self.is_configured():
            raise ContractError("Management contract URL is not configured.")
        endpoint = f"{self.config.base_url}/sessions-formation/{session_id}/live/start"
        data = self._request("POST", endpoint, bearer_token=bearer_token, json={})
        if isinstance(data, dict):
            return data
        raise ContractError("Unexpected start-live payload.")

    def pause_session_live(self, session_id: str, *, bearer_token: str) -> dict[str, Any]:
        if not self.is_configured():
            raise ContractError("Management contract URL is not configured.")
        endpoint = f"{self.config.base_url}/sessions-formation/{session_id}/live/pause"
        data = self._request("POST", endpoint, bearer_token=bearer_token, json={})
        if isinstance(data, dict):
            return data
        raise ContractError("Unexpected pause-live payload.")

    def end_session_live(self, session_id: str, *, bearer_token: str, recording_url: str | None = None) -> dict[str, Any]:
        if not self.is_configured():
            raise ContractError("Management contract URL is not configured.")
        endpoint = f"{self.config.base_url}/sessions-formation/{session_id}/live/end"
        payload: dict[str, Any] = {}
        if recording_url:
            payload["recording_url"] = recording_url
        data = self._request("POST", endpoint, bearer_token=bearer_token, json=payload)
        if isinstance(data, dict):
            return data
        raise ContractError("Unexpected end-live payload.")

    def join_session_live(self, session_id: str, *, bearer_token: str) -> dict[str, Any]:
        if not self.is_configured():
            raise ContractError("Management contract URL is not configured.")
        endpoint = f"{self.config.base_url}/sessions-formation/{session_id}/live/join"
        data = self._request("POST", endpoint, bearer_token=bearer_token, json={})
        if isinstance(data, dict):
            return data
        raise ContractError("Unexpected join-live payload.")

    def leave_session_live(self, session_id: str, *, bearer_token: str) -> dict[str, Any]:
        if not self.is_configured():
            raise ContractError("Management contract URL is not configured.")
        endpoint = f"{self.config.base_url}/sessions-formation/{session_id}/live/leave"
        data = self._request("POST", endpoint, bearer_token=bearer_token, json={})
        if isinstance(data, dict):
            return data
        raise ContractError("Unexpected leave-live payload.")

    def _request(self, method: str, url: str, **kwargs: Any) -> Any:
        headers = kwargs.pop("headers", {})
        bearer_token = kwargs.pop("bearer_token", None)
        skip_auth = bool(kwargs.pop("skip_auth", False))
        bearer_token = bearer_token.strip() if isinstance(bearer_token, str) else bearer_token
        if bearer_token:
            headers["Authorization"] = f"Bearer {bearer_token}"
        elif not skip_auth and self.config.api_token and self._looks_like_jwt(str(self.config.api_token).strip()):
            headers["Authorization"] = f"Bearer {str(self.config.api_token).strip()}"
        headers["Accept"] = "application/json"

        last_exception: Exception | None = None
        refreshed_service_token = False
        cached_service_token = None
        try:
            cached_service_token = cache.get(self._service_token_cache_key())
        except Exception:
            cached_service_token = None
        for _ in range(self.config.max_retries + 1):
            try:
                response = requests.request(
                    method=method,
                    url=url,
                    timeout=self.config.timeout_seconds,
                    headers=headers,
                    **kwargs,
                )
            except requests.RequestException as exc:
                last_exception = exc
                continue

            if response.status_code == 401 and bearer_token and not refreshed_service_token:
                # If we used a cached service token and it expired, refresh once and retry.
                try:
                    body = (response.text or "")[:600].lower()
                except Exception:
                    body = ""
                token_expired = ("token expired" in body) or ("token_expired" in body)
                if token_expired and isinstance(cached_service_token, str) and cached_service_token.strip():
                    if bearer_token.strip() == cached_service_token.strip():
                        try:
                            cache.delete(self._service_token_cache_key())
                        except Exception:
                            pass
                        new_token = self._get_service_bearer_token()
                        if new_token and new_token.strip() and new_token.strip() != bearer_token.strip():
                            bearer_token = new_token.strip()
                            headers["Authorization"] = f"Bearer {bearer_token}"
                            refreshed_service_token = True
                            continue

            if response.status_code in (502, 503, 504):
                last_exception = UpstreamUnavailable(
                    f"Upstream unavailable with status {response.status_code}"
                )
                continue
            if response.status_code >= 400:
                raise ContractError(
                    f"Contract request failed ({response.status_code}): {response.text[:300]}"
                )
            try:
                return response.json()
            except ValueError as exc:
                raise ContractError("Contract response is not valid JSON.") from exc

        raise UpstreamUnavailable(
            f"Contract request failed after retries: {last_exception!s}"
        )
