from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any


@dataclass(slots=True)
class AccessSnapshot:
    """Authoritative access snapshot received from the management system."""

    subject_id: str
    active: bool
    roles: set[str] = field(default_factory=set)
    permissions: set[str] = field(default_factory=set)
    assignments: set[str] = field(default_factory=set)
    version: str = ""
    emitted_at: datetime | None = None
    raw_payload: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class AuthorizationDecision:
    """Decision consumed by Prolean routes and business logic."""

    allowed: bool
    is_read_only: bool = False
    source: str = "local"
    reason: str = ""
    snapshot: AccessSnapshot | None = None

