# Fixes Applied

Date: 2026-02-19

## 1) Import Errors (`No module named 'schema'` / `No module named 'model'`)

I replaced top-level imports with package-relative imports inside `src` package modules.

Updated files:
- `src/routes/oauth_routes.py`
- `src/services/oauth_service.py`
- `src/schema/auth_schema.py`

Examples:
- `from core.config import settings` -> `from ..core.config import settings`
- `from model.auth_model import User` -> `from ..model.auth_model import User`

## 2) Google Callback Route Issues

I fixed callback handling so it works with Google redirect flow and avoids Swagger/OpenAPI conflicts.

Updated file:
- `src/routes/oauth_routes.py`

Changes:
- Callback logic now awaits async service calls correctly.
- Split callback into two handlers:
  - `GET /api/v1/auth/google/callback` (for Google redirect)
  - `POST /api/v1/auth/google/callback` (for API/manual post)
- Added explicit operation ID for POST callback to avoid duplicate operation warnings.
- Hid redirect-only OAuth routes from Swagger:
  - `GET /google/authorize`
  - `GET /google/callback`
- Added `GET /google/authorize-url` for Swagger-safe/manual testing (returns JSON URL).

## 3) OAuth Service Async HTTP Fix

I changed token verification call to fully async (non-blocking).

Updated file:
- `src/services/oauth_service.py`

Change:
- `_verify_google_token` now uses `httpx.AsyncClient` with `await` instead of synchronous `httpx.get(...)`.

## 4) Schema Bug Fix

I fixed trailing-comma defaults that were creating tuple values.

Updated file:
- `src/schema/auth_schema.py`

Change:
- `CallbackParams` fields now have proper defaults:
  - `code: str | None = None`
  - `state: str | None = None`
  - `error: str | None = None`

## 5) Dev CORS Setup

I added CORS middleware so browser-based local frontend testing works.

Updated file:
- `src/main.py`

Change:
- Added `CORSMiddleware` with localhost/127.0.0.1 support (including ports via regex).

## 6) Why Swagger Showed `Failed to fetch`

This was caused by trying OAuth redirect endpoints via Swagger `fetch`/XHR flow.

Notes:
- OAuth redirect endpoints should be opened in browser navigation, not API fetch clients.
- For docs/testing, use `GET /api/v1/auth/google/authorize-url`, then open the returned URL manually.

