from __future__ import annotations

import logging
from typing import Any

from django.core.cache import cache

from .client import ManagementContractClient
from .exceptions import ContractError, UpstreamUnavailable

logger = logging.getLogger(__name__)

CURSOR_KEY = "integration:sync:cursor"
LAST_RESULT_KEY = "integration:sync:last_result"


class ContractSyncService:
    """Periodic synchronization service for non-critical domains."""

    def __init__(self) -> None:
        self.client = ManagementContractClient()

    def run(self) -> dict[str, Any]:
        cursor = cache.get(CURSOR_KEY, "")
        try:
            payload = self.client.sync_updates(cursor=cursor)
        except (UpstreamUnavailable, ContractError) as exc:
            result = {
                "ok": False,
                "cursor": cursor,
                "error": str(exc),
            }
            cache.set(LAST_RESULT_KEY, result, timeout=300)
            logger.warning("Integration sync failed: %s", exc)
            return result

        next_cursor = str(payload.get("next_cursor", cursor))
        updates = payload.get("updates", [])
        result = {
            "ok": True,
            "cursor": next_cursor,
            "updates_count": len(updates) if isinstance(updates, list) else 0,
        }
        cache.set(CURSOR_KEY, next_cursor, timeout=None)
        cache.set(LAST_RESULT_KEY, result, timeout=300)
        return result

