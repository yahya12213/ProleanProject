# Content Protection & Anti-Recording System (WebRTC + DRM Fallback)

This document describes a practical, production-grade content protection strategy for the platform.

Important limitations (honest constraints):
- You **cannot fully prevent** OS-level screen recording or external cameras filming the screen.
- For **WebRTC live video**, browser DRM (EME/Widevine/FairPlay/PlayReady) is generally **not available** the same way it is for HLS/DASH players; DRM primarily applies to **HLS/DASH** streams.
- The best achievable outcome is: **raise the effort**, **deter redistribution**, **detect suspicious conditions**, and **respond** (blur/downscale/revoke), while keeping UX acceptable.

## 1) High-level security architecture

Core components:
- **Auth/Identity Authority (Barka)**: source-of-truth for users, roles, and authorization.
- **Portal (Prolean)**: UI + stream entrypoint; issues short-lived stream tokens; collects security telemetry; enforces headers (CSP / frame-ancestors).
- **Live Provider (WebRTC)**: LiveKit or Agora (production hosted).
- **Fallback Packager/CDN**: LL-HLS + CMAF-DASH origin (e.g., Wowza, AWS MediaLive + MediaPackage, Nimble, Unified Streaming).
- **DRM & License Service**: Multi-DRM (Widevine/PlayReady/FairPlay) using a vendor (e.g., Axinom, BuyDRM, EZDRM, castLabs) or an in-house license proxy if you already have keys and compliance.
- **Telemetry + Risk Engine**: event ingest + scoring (suspicious client reports, watermark tamper, devtools signals, iframe embedding attempts, unusual session patterns).
- **Revocation Service**: immediate token/session revocation + provider kick/disconnect.

## 2) Streaming architecture (diagram)

```mermaid
flowchart LR
  U[Browser Client] -->|Login| P[Prolean (Django)]
  P -->|Auth + roles| B[Barka API]

  U -->|Join Live (WebRTC)| P
  P -->|Issue short-lived stream token| U
  U -->|WebRTC connect| W[WebRTC Provider\n(LiveKit/Agora)]

  U -->|Security telemetry| P
  P -->|Risk score + revoke| R[Revocation Service]
  R -->|Kick/Disconnect| W

  W -->|Live ingest/record| O[Origin/Packager]
  O -->|CMAF| C[CDN]
  U -->|Fallback playback| C
  U -->|DRM license request| L[DRM License Service]
```

## 3) Backend endpoint design (no DB/table specifics)

All endpoints require TLS. All tokens are short-lived and audience-scoped.

### Stream access / token issuance
- `POST /api/stream/token`
  - Input: `{ session_id, mode: "webrtc"|"dash"|"hls", device_fingerprint? }`
  - Output: `{ token, expires_at, provider: {...}, constraints: {...} }`
  - Notes:
    - Token includes `sub`, `session_id`, `role`, `exp`, `aud`, `jti`, and a per-session key id.
    - Tokens are **one-time** or **bounded reuse** (server stores jti in cache to prevent sharing).

### Session validation / heartbeat
- `POST /api/stream/heartbeat`
  - Input: `{ session_id, token_jti, client_time, signals: {...} }`
  - Output: `{ ok, action: "none"|"blur"|"downscale"|"pause"|"revoke", reason? }`

### Revocation
- `POST /api/stream/revoke`
  - Input: `{ session_id, user_id, reason, token_jti? }`
  - Output: `{ ok }`
  - Called by admins/professors and automated risk engine.

### Telemetry / suspicious behavior reporting
- `POST /api/security/report`
  - Input: `{ session_id, type, severity, payload }`
  - Output: `{ ok }`
  - Examples of `type`: `watermark_tamper`, `devtools_open`, `iframe_embed_attempt`, `visibility_hidden`, `automation_detected`, `debugger_timing`, `integrity_failed`.

### DRM license delivery (fallback streams)
- `POST /api/drm/license`
  - Input: EME license challenge (Widevine/PlayReady/FairPlay)
  - Output: license bytes
  - Notes:
    - License requests are authenticated using the same short-lived stream token (`aud=drm`).
    - Enforce HDCP / output protections where applicable (platform-dependent).

### Secure playlist/manifest (HLS/DASH)
- `GET /stream/<session_id>/manifest.mpd` (DASH)
- `GET /stream/<session_id>/master.m3u8` (HLS)
  - Signed URLs or tokenized CDN with very short expiry and IP/UA binding (careful: IP binding can break mobile networks).

## 4) Client-side protection strategy (WebRTC + fallback)

### Baseline protections (cheap + high value)
- **Anti-embed**:
  - Server headers: `Content-Security-Policy: frame-ancestors 'none'` and `X-Frame-Options: DENY`.
- **Disable common in-page capture hooks**:
  - Guard `navigator.mediaDevices.getDisplayMedia` usage in the app (you can’t stop OS capture, but you can reduce in-app capture vectors).
- **Visibility / focus handling**:
  - On `visibilitychange` to hidden or repeated focus-loss: request server action and temporarily blur/downscale.
- **Automation signals**:
  - Detect `navigator.webdriver`, headless UA patterns, unrealistic deviceMemory/cores, etc.
- **DevTools tamper heuristics** (imperfect):
  - Outer/inner window deltas; `debugger` timing checks; repeated exception stack anomalies.
  - Response: raise watermark opacity + blur.

### Stronger (heavier) options
- **Insertable Streams E2EE (WebRTC)**:
  - Encrypt frames end-to-end with per-session keys (prevents provider-side access, but does not prevent client screen recording).
- **Risk-scored enforcement**:
  - Aggregate telemetry and require re-auth / re-token; revoke tokens on high risk.

## 5) DRM integration strategy (HLS/DASH fallback)

Recommended:
- Package live into **CMAF** and serve:
  - **DASH + Widevine/PlayReady** (Chrome/Edge/Android/Windows)
  - **HLS + FairPlay** (Safari/iOS/macOS)
- Use a multi-DRM vendor unless you already have operational maturity for key management, compliance, and device interoperability.

Player strategy:
- Use **Shaka Player** for DASH + Widevine/PlayReady.
- Use native Safari playback for FairPlay HLS (or a unified player that supports FairPlay on Apple devices).

## 6) Watermark rendering strategy (logo + real-time timestamp)

Rules:
- Only: **website logo** + **current date & time**.
- No user IDs/emails/IPs/PII.

Implementation (WebRTC and fallback):
- Render watermark into a **canvas overlay** (not simple HTML), updated in real time.
- Movement:
  - Slowly interpolate between randomized target positions.
  - Subtle opacity modulation.
- Tamper response:
  - Detect canvas removal/hidden styles and blur video while logging `watermark_tamper`.

Note:
- A determined user can still record the screen; the watermark’s purpose is deterrence and evidentiary context (time).

## 7) Threat model (summary) + mitigations

### Threat: Screen recording (OS-level, OBS, external device)
- Mitigation:
  - Canvas watermark + timestamp
  - Risk scoring + rapid revocation
  - DRM for fallback streams
  - Legal/UX deterrence (terms + warnings)

### Threat: Tab capture / browser APIs
- Mitigation:
  - Detect abnormal focus/visibility patterns
  - Detect in-app usage of capture APIs where possible
  - Respond with blur/downscale + logging

### Threat: DOM injection / overlay removal
- Mitigation:
  - Canvas watermark + integrity checks
  - CSP (no inline scripts unless hashed; lock down script-src)
  - Subresource integrity (SRI) for third-party scripts where used

### Threat: Token sharing / replay
- Mitigation:
  - Short-lived JWT + `jti`
  - Store active `jti` in server cache; revoke on anomaly
  - Device/session binding (soft binding: UA + coarse device hints)

### Threat: Embedding / clickjacking
- Mitigation:
  - `frame-ancestors 'none'`
  - `X-Frame-Options: DENY`

## 8) Step-by-step implementation plan

1) **Hard headers** in Prolean:
   - CSP, frame-ancestors, no-sniff, referrer-policy, permissions-policy.
2) **Stream token service**:
   - `POST /api/stream/token` with short-lived JWT (`aud=webrtc|drm`).
3) **Revocation + heartbeat**:
   - Heartbeat endpoint returns actions (`blur/downscale/revoke`).
4) **Client telemetry**:
   - Implement non-invasive detectors (no camera/mic usage).
   - Report to `/api/security/report`.
5) **Canvas watermark**:
   - Logo + timestamp; movement + opacity; integrity checks.
6) **DRM fallback**:
   - Add packaging + license integration; secure manifests.
7) **Risk engine**:
   - Start simple rules; evolve to scoring and correlation.
8) **Hardening + incident response**:
   - Alerting, dashboards, and automated revocation playbooks.

## 9) Production hardening checklist

- TLS everywhere; HSTS enabled.
- CSP locked down (`script-src` nonces/hashes; avoid broad `unsafe-inline`).
- `frame-ancestors 'none'` everywhere on player routes.
- Short-lived tokens (minutes), jti-based revocation.
- Rate-limit telemetry endpoints; validate payload sizes.
- Provider-side controls:
  - Kick/disconnect APIs
  - Room access control by token claims
- Audit logs: who muted/kicked/revoked and why.
- Fallback streams:
  - Signed manifests + DRM
  - Anti-hotlinking + origin shielding
- Security testing:
  - Attempt DOM removal of watermark, CSS overrides, script injection
  - Headless runs
  - OBS virtual cam / display mirroring validation (detection is limited, but record outcomes)

