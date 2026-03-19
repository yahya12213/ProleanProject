from __future__ import annotations

from typing import Any

from django.core.cache import cache

from .client import ManagementContractClient
from .settings import get_contract_settings
from .sync import LAST_RESULT_KEY


def integration_health_snapshot() -> dict[str, Any]:
    config = get_contract_settings()
    client = ManagementContractClient()
    upstream = client.get_health()
    last_sync = cache.get(LAST_RESULT_KEY, {})

    healthy = upstream.get("status") not in {"down"}
    return {
        "configured": bool(config.base_url),
        "healthy": healthy,
        "upstream": upstream,
        "read_only_on_outage": config.read_only_on_outage,
        "strict_authority_mode": config.strict_authority_mode,
        "last_sync": last_sync,
    }

