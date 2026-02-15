from __future__ import annotations

from dataclasses import dataclass

from django.conf import settings


@dataclass(frozen=True, slots=True)
class ContractSettings:
    base_url: str
    api_token: str
    timeout_seconds: int
    max_retries: int
    access_cache_ttl_seconds: int
    health_cache_ttl_seconds: int
    strict_authority_mode: bool
    read_only_on_outage: bool


def get_contract_settings() -> ContractSettings:
    return ContractSettings(
        base_url=getattr(settings, "PROLEAN_MANAGEMENT_API_BASE_URL", "").rstrip("/"),
        api_token=getattr(settings, "PROLEAN_MANAGEMENT_API_TOKEN", ""),
        timeout_seconds=int(getattr(settings, "PROLEAN_MANAGEMENT_API_TIMEOUT_SECONDS", 8)),
        max_retries=int(getattr(settings, "PROLEAN_MANAGEMENT_API_MAX_RETRIES", 2)),
        access_cache_ttl_seconds=int(
            getattr(settings, "PROLEAN_EXTERNAL_ACCESS_CACHE_TTL_SECONDS", 60)
        ),
        health_cache_ttl_seconds=int(
            getattr(settings, "PROLEAN_EXTERNAL_HEALTH_CACHE_TTL_SECONDS", 30)
        ),
        strict_authority_mode=bool(getattr(settings, "PROLEAN_STRICT_AUTHORITY_MODE", False)),
        read_only_on_outage=bool(getattr(settings, "PROLEAN_READ_ONLY_ON_OUTAGE", True)),
    )

