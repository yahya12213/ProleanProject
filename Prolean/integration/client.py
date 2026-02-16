from __future__ import annotations

from typing import Any

import requests

from .exceptions import ContractError, UpstreamUnavailable
from .settings import get_contract_settings


class ManagementContractClient:
    """HTTP client for the external authority contract."""

    def __init__(self) -> None:
        self.config = get_contract_settings()

    def is_configured(self) -> bool:
        return bool(self.config.base_url)

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
        return self._request("POST", endpoint, json={"username": username, "password": password})

    def get_current_user(self, bearer_token: str) -> dict[str, Any]:
        if not self.is_configured():
            raise ContractError("Management contract URL is not configured.")
        endpoint = f"{self.config.base_url}/auth/me"
        return self._request("GET", endpoint, bearer_token=bearer_token)

    def list_formations(self, *, bearer_token: str | None = None) -> list[dict[str, Any]]:
        if not self.is_configured():
            raise ContractError("Management contract URL is not configured.")
        endpoint = f"{self.config.base_url}/cours/formations"
        data = self._request("GET", endpoint, bearer_token=bearer_token)
        # Barka returns a JSON array for this endpoint.
        if isinstance(data, list):
            return data
        raise ContractError("Unexpected formations payload (expected list).")

    def get_formation(self, formation_id: str, *, bearer_token: str | None = None) -> dict[str, Any]:
        if not self.is_configured():
            raise ContractError("Management contract URL is not configured.")
        endpoint = f"{self.config.base_url}/cours/formations/{formation_id}"
        return self._request("GET", endpoint, bearer_token=bearer_token)

    def _request(self, method: str, url: str, **kwargs: Any) -> dict[str, Any]:
        headers = kwargs.pop("headers", {})
        bearer_token = kwargs.pop("bearer_token", None)
        if bearer_token:
            headers["Authorization"] = f"Bearer {bearer_token}"
        elif self.config.api_token:
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
