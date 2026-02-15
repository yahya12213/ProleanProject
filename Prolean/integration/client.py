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

    def _request(self, method: str, url: str, **kwargs: Any) -> dict[str, Any]:
        headers = kwargs.pop("headers", {})
        if self.config.api_token:
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

