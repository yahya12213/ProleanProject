from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any

from django.conf import settings
from django.core.cache import cache
from django.utils import timezone


PRESENCE_TTL_SECONDS = int(getattr(settings, "PROLEAN_PRESENCE_TTL_SECONDS", 120))
PRESENCE_INDEX_KEY = "presence:students:index"
PRESENCE_INDEX_LIMIT = int(getattr(settings, "PROLEAN_PRESENCE_INDEX_LIMIT", 3000))


@dataclass
class PresenceEntry:
    user_id: int
    role: str
    name: str
    username: str
    last_seen_iso: str
    path: str
    session_id: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "user_id": self.user_id,
            "role": self.role,
            "name": self.name,
            "username": self.username,
            "last_seen": self.last_seen_iso,
            "path": self.path,
            "session_id": self.session_id,
        }


def _presence_key(user_id: int) -> str:
    return f"presence:user:{int(user_id)}"


def _normalize_role(user: Any) -> str:
    profile = getattr(user, "profile", None)
    return str(getattr(profile, "role", "") or "").upper()


def _update_student_index(user_id: int) -> None:
    idx = cache.get(PRESENCE_INDEX_KEY, [])
    if not isinstance(idx, list):
        idx = []
    uid = int(user_id)
    if uid in idx:
        return
    idx.append(uid)
    if len(idx) > PRESENCE_INDEX_LIMIT:
        idx = idx[-PRESENCE_INDEX_LIMIT:]
    cache.set(PRESENCE_INDEX_KEY, idx, timeout=PRESENCE_TTL_SECONDS * 4)


def touch_user_presence(user: Any, *, path: str = "", session_id: str = "") -> None:
    if not getattr(user, "is_authenticated", False):
        return
    now = timezone.now()
    role = _normalize_role(user)
    entry = PresenceEntry(
        user_id=int(user.id),
        role=role,
        name=str(getattr(getattr(user, "profile", None), "full_name", "") or user.get_full_name() or user.username),
        username=str(getattr(user, "username", "") or ""),
        last_seen_iso=now.isoformat(),
        path=str(path or "")[:255],
        session_id=str(session_id or "")[:64],
    )
    cache.set(_presence_key(user.id), entry.to_dict(), timeout=PRESENCE_TTL_SECONDS * 4)
    if role == "STUDENT":
        _update_student_index(int(user.id))


def get_online_students() -> dict[int, dict[str, Any]]:
    idx = cache.get(PRESENCE_INDEX_KEY, [])
    if not isinstance(idx, list):
        return {}
    online: dict[int, dict[str, Any]] = {}
    active_ids: list[int] = []
    now = timezone.now()
    for raw_id in idx:
        try:
            uid = int(raw_id)
        except (TypeError, ValueError):
            continue
        payload = cache.get(_presence_key(uid))
        if not isinstance(payload, dict):
            continue
        if str(payload.get("role", "")).upper() != "STUDENT":
            continue
        try:
            seen_at = datetime.fromisoformat(str(payload.get("last_seen")))
        except Exception:
            continue
        if timezone.is_naive(seen_at):
            seen_at = timezone.make_aware(seen_at, timezone.get_current_timezone())
        age = (now - seen_at).total_seconds()
        if age > PRESENCE_TTL_SECONDS:
            continue
        payload["age_seconds"] = int(max(0, age))
        online[uid] = payload
        active_ids.append(uid)
    cache.set(PRESENCE_INDEX_KEY, active_ids[-PRESENCE_INDEX_LIMIT:], timeout=PRESENCE_TTL_SECONDS * 4)
    return online
