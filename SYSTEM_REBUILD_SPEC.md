# Full system rebuild spec (Barka + Prolean)

This document describes the current intended end-state for rebuilding the full system from scratch:

- **Barka** = authority/source-of-truth (auth, RBAC, sessions, assignments, live lifecycle state).
- **Prolean** = consumer portal (Django) that logs in via Barka, stores Barka JWT in session, renders dashboards from Barka data, and hosts an **external live studio UI** using Agora RTC while still using Barka for authorization + live state.

## Folder layout (this workspace)
- Barka: `Barka Project/comptabilite_PL/`
- Prolean: `Prolean project/Project/`

## Barka (authority) required endpoints

### Auth
- `POST /api/auth/login` → `{ success, user, token, permissions, expiresIn }`
- `GET /api/auth/me` (auth) → `{ success, user, permissions }`

### Professor ownership sessions
- `GET /api/sessions-formation/my-sessions` (auth) → assigned sessions for professor (no RBAC dependency)
- `GET /api/sessions-formation/my-sessions/:id` (auth) → one assigned session detail + enrolled students

### Live lifecycle contract (authoritative)
Persist live state in DB tables (auto-created if missing):
- `session_lives` (latest per session)
- `session_live_participants` (join/leave tracking)

Endpoints (auth required):
- `GET  /api/sessions-formation/:id/live` → latest live row or null (allowed if assigned professor or enrolled student)
- `POST /api/sessions-formation/:id/live/start` → professor-only
- `POST /api/sessions-formation/:id/live/pause` → professor-only
- `POST /api/sessions-formation/:id/live/end` (+ optional `recording_url`) → professor-only
- `POST /api/sessions-formation/:id/live/join` → professor or enrolled student
- `POST /api/sessions-formation/:id/live/leave` → participant leave
- `POST /api/sessions-formation/:id/live/access` (auth) → check enrollment + live state for students (service token)

Config guard (start/join):
- Validate `LIVEKIT_URL`, `LIVEKIT_API_KEY`, `LIVEKIT_API_SECRET` (trim + quote stripping).
- Missing config must return **500** with explicit message (avoid 503 retry masking).
- Normalize `LIVEKIT_URL` returned (ensure websocket scheme).

## Prolean (consumer) required behavior

### External contract client
In `Prolean/integration/client.py` implement a resilient HTTP client that:
- Retries on 502/503/504 (bounded).
- Supports either API token or service login caching.
- Implements Barka-facing methods: login, me, my-sessions, session detail, live lifecycle calls.

### External auth enforcement
`Prolean/middleware.py`:
- `ExternalAuthorityGuardMiddleware` blocks authenticated mutations when authority denies/unavailable (with read-only outage policy).
- Skip safe endpoints like logout, presence heartbeat, language set, and leave-live.

### Prolean external login (projection)
`Prolean/views.py`:
- When Barka is configured, login calls Barka `/auth/login`, creates/updates a local Django user (unusable password), stores `barka_token` in session, and sets a local Profile projection role/status.

### Dashboards (external mode)
Student dashboard:
- Loads external formations/sessions and resolves live states per session.
- Shows “Join” CTAs linking to `/external/live/<session_id>/` when live is active.

Professor dashboard:
- Loads assigned sessions via `/sessions-formation/my-sessions`.
- Shows live status and provides Start/Pause/End controls (Prolean routes call Barka).
- Start should redirect directly into the external live room.

### External live room (Agora media + Barka authority)
Flow:
1) Prolean calls Barka `join_session_live` to authorize and obtain `live.room_name` + role.
2) Prolean uses `live.room_name` as the **Agora channel**.
3) Prolean generates Agora RTC tokens server-side using `AGORA_APP_ID` + `AGORA_APP_CERTIFICATE`.
4) Template `Prolean/templates/Prolean/live/external_live_room.html` joins Agora, enables mic/camera, supports professor screen-share, and implements presenter-style layout + presence board.

### i18n
- FR/EN/AR supported, with auto-detect when no preference exists.
- Header switcher posts to a Prolean endpoint for visible success feedback.

## Required env vars

### Barka
- `JWT_SECRET` (>= 32 chars)
- DB settings
- LiveKit: `LIVEKIT_URL`, `LIVEKIT_API_KEY`, `LIVEKIT_API_SECRET`

### Prolean
- DB settings (`DATABASE_URL` or `DATABASE_PUBLIC_URL`)
- Barka contract:
  - `PROLEAN_MANAGEMENT_API_BASE_URL` (should end with `/api`)
  - Optional: `PROLEAN_MANAGEMENT_API_TOKEN` OR service username/password
- Agora:
  - `AGORA_APP_ID`
  - `AGORA_APP_CERTIFICATE`

