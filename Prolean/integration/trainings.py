from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(slots=True)
class ExternalTraining:
    # Keep attribute names aligned with existing templates.
    slug: str
    title: str
    short_description: str
    price_mad: float
    duration_days: int
    thumbnail: str | None = None

    # Optional/template-driven fields (defaults avoid template errors).
    max_students: int = 20
    success_rate: int = 95
    badge: str = "none"
    is_featured: bool = False
    next_session: Any | None = None

    # Category flags used by templates (Barka does not currently provide these).
    category: str = "autre"
    category_caces: bool = False
    category_electricite: bool = False
    category_soudage: bool = False
    category_securite: bool = False
    category_management: bool = False
    category_autre: bool = True


def _as_float(value: Any, default: float = 0.0) -> float:
    try:
        if value is None:
            return default
        return float(value)
    except (TypeError, ValueError):
        return default


def _as_int(value: Any, default: int = 0) -> int:
    try:
        if value is None:
            return default
        return int(value)
    except (TypeError, ValueError):
        return default


def to_external_training(payload: dict[str, Any]) -> ExternalTraining:
    """
    Adapter: Barka formation payload -> Prolean template-friendly training object.

    Expected minimal keys (best-effort):
    - id
    - title
    - description
    - price
    - duration_hours
    - thumbnail_url
    """
    formation_id = str(payload.get("id", "")).strip()
    title = str(payload.get("title", "")).strip() or "Formation"
    description = str(payload.get("description", "")).strip()
    price = _as_float(payload.get("price"), 0.0)

    duration_hours = _as_int(payload.get("duration_hours"), 0)
    duration_days = max(1, (duration_hours + 7) // 8) if duration_hours else 0

    thumbnail = payload.get("thumbnail_url") or payload.get("thumbnail") or None
    thumbnail = str(thumbnail).strip() if thumbnail not in (None, "", "undefined") else None

    return ExternalTraining(
        slug=formation_id or title.lower().replace(" ", "-"),
        title=title,
        short_description=description,
        price_mad=price,
        duration_days=duration_days,
        thumbnail=thumbnail,
    )

