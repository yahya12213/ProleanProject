from __future__ import annotations

from datetime import datetime
from typing import Any

from .contracts import AccessSnapshot


def _as_set(value: Any) -> set[str]:
    if not value:
        return set()
    if isinstance(value, (list, tuple, set)):
        return {str(item).strip() for item in value if str(item).strip()}
    return {str(value).strip()}


def _parse_emitted_at(value: Any) -> datetime | None:
    if not value:
        return None
    if isinstance(value, datetime):
        return value
    if isinstance(value, str):
        candidate = value.replace("Z", "+00:00")
        try:
            return datetime.fromisoformat(candidate)
        except ValueError:
            return None
    return None


def to_access_snapshot(subject_id: str, payload: dict[str, Any]) -> AccessSnapshot:
    return AccessSnapshot(
        subject_id=subject_id,
        active=bool(payload.get("active", False)),
        roles=_as_set(payload.get("roles")),
        permissions=_as_set(payload.get("permissions")),
        assignments=_as_set(payload.get("assignments")),
        version=str(payload.get("version", "")),
        emitted_at=_parse_emitted_at(payload.get("emitted_at")),
        raw_payload=payload,
    )


def to_access_snapshot_from_barka_me(subject_id: str, payload: dict[str, Any]) -> AccessSnapshot:
    """
    Adapter for Barka `/auth/me` payload:
    {
      "success": true,
      "user": {..., "role": "...", ...},
      "permissions": [...]
    }
    """
    user = payload.get("user") if isinstance(payload.get("user"), dict) else {}
    role = str(user.get("role", "")).strip()
    permissions = payload.get("permissions") if isinstance(payload.get("permissions"), list) else []

    # Treat presence of a user as "active". Fine-grained revocation comes from Barka.
    normalized = {
        "active": True,
        "roles": [role] if role else [],
        "permissions": permissions,
        # Keep useful identifiers for downstream debugging and optional policy checks.
        "assignments": [],
        "version": "",
        "emitted_at": None,
        "raw": payload,
    }
    return to_access_snapshot(subject_id, normalized)
