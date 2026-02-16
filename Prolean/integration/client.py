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

    def _request(self, method: str, url: str, **kwargs: Any) -> Any:
        headers = kwargs.pop("headers", {})
        bearer_token = kwargs.pop("bearer_token", None)
        skip_auth = bool(kwargs.pop("skip_auth", False))
        if bearer_token:
            headers["Authorization"] = f"Bearer {bearer_token}"
        elif not skip_auth and self.config.api_token:
            headers["Authorization"] = f"Bearer {self.config.api_token}"
        headers["Accept"] = "application/json"

        last_exception: Exception | None = None
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
