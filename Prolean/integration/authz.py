from __future__ import annotations

import logging
from dataclasses import asdict
from typing import Any

from django.core.cache import cache

from .adapter import to_access_snapshot, to_access_snapshot_from_barka_me
from .client import ManagementContractClient
from .contracts import AccessSnapshot, AuthorizationDecision
from .exceptions import ContractError, UpstreamUnavailable
from .settings import get_contract_settings

logger = logging.getLogger(__name__)


def _cache_key(subject_id: str) -> str:
    return f"integration:access:{subject_id}"


class ExternalAuthorizationService:
    """Centralized authorization facade aligned to external authority."""

    def __init__(self) -> None:
        self.config = get_contract_settings()
        self.client = ManagementContractClient()

    def evaluate(
        self,
        *,
        subject_id: str,
        required_roles: set[str] | None = None,
        required_permissions: set[str] | None = None,
        mutation: bool = False,
        allow_local_fallback: bool = True,
        bearer_token: str | None = None,
    ) -> AuthorizationDecision:
        required_roles = required_roles or set()
        required_permissions = required_permissions or set()

        snapshot = self._get_snapshot(subject_id, bearer_token=bearer_token)
        if snapshot is None:
            if self.config.strict_authority_mode and not allow_local_fallback:
                return AuthorizationDecision(
                    allowed=False,
                    is_read_only=True,
                    source="unavailable",
                    reason="External authority unavailable in strict mode.",
                )
            if mutation and self.config.read_only_on_outage:
                return AuthorizationDecision(
                    allowed=False,
                    is_read_only=True,
                    source="unavailable",
                    reason="Mutations are blocked while external authority is unavailable.",
                )
            return AuthorizationDecision(
                allowed=True,
                source="local_fallback",
                reason="External authority unavailable; local fallback active.",
            )

        if not snapshot.active:
            return AuthorizationDecision(
                allowed=False,
                source="external",
                reason="Access revoked by management authority.",
                snapshot=snapshot,
            )

        if required_roles and not (snapshot.roles & required_roles):
            return AuthorizationDecision(
                allowed=False,
                source="external",
                reason="Required role missing in external snapshot.",
                snapshot=snapshot,
            )
        if required_permissions and not required_permissions.issubset(snapshot.permissions):
            return AuthorizationDecision(
                allowed=False,
                source="external",
                reason="Required permission missing in external snapshot.",
                snapshot=snapshot,
            )
        return AuthorizationDecision(allowed=True, source="external", snapshot=snapshot)

    def _get_snapshot(self, subject_id: str, *, bearer_token: str | None = None) -> AccessSnapshot | None:
        if not subject_id:
            return None

        key = _cache_key(subject_id)
        cached = cache.get(key)
        if cached:
            return to_access_snapshot(subject_id, cached)

        try:
            if bearer_token:
                payload = self.client.get_current_user(bearer_token)
                snapshot = to_access_snapshot_from_barka_me(subject_id, payload)
                cache.set(key, snapshot.raw_payload, timeout=self.config.access_cache_ttl_seconds)
                return snapshot
            payload = self.client.get_access_snapshot(subject_id)
        except (UpstreamUnavailable, ContractError) as exc:
            logger.warning("External access snapshot unavailable for %s: %s", subject_id, exc)
            return None

        cache.set(key, payload, timeout=self.config.access_cache_ttl_seconds)
        return to_access_snapshot(subject_id, payload)

    def force_refresh(self, subject_id: str) -> AccessSnapshot | None:
        if not subject_id:
            return None
        try:
            payload = self.client.get_access_snapshot(subject_id)
        except (UpstreamUnavailable, ContractError) as exc:
            logger.warning("External snapshot refresh failed for %s: %s", subject_id, exc)
            return None
        cache.set(
            _cache_key(subject_id),
            payload,
            timeout=self.config.access_cache_ttl_seconds,
        )
        return to_access_snapshot(subject_id, payload)

    def export_cached_snapshot(self, subject_id: str) -> dict[str, Any] | None:
        snapshot = self._get_snapshot(subject_id)
        if snapshot is None:
            return None
        return asdict(snapshot)
