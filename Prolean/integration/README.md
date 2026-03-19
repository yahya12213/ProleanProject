# Prolean External Contract Layer

This package isolates all authority-facing integration logic.

## Boundaries

- `client.py`: outbound management-system contract client
- `adapter.py`: payload-to-snapshot mapping
- `authz.py`: centralized authorization facade used by UI/API flows
- `sync.py`: periodic synchronization runner
- `health.py`: operational health snapshot
- `views.py`: admin-only integration health endpoint

## Runtime behavior

- External access snapshots are cached briefly to reduce latency.
- Mutations are blocked by middleware when authority check fails.
- When upstream is unavailable, read-only fallback behavior is controlled by settings.
- Strict mode can disable local fallback and force external authority checks.

