from fastapi import Body, HTTPException, Query, routing
from fastapi.responses import RedirectResponse
from urllib.parse import urlencode

from ..core.config import settings
from ..model.auth_model import User
from ..schema.auth_schema import (
    GoogleCallBackResponse,
    GoogleCallbackRequest,
    RefreshTokenRequest,
    RefreshTokenResponse,
    UpdateDomainRequest,
)
from ..services import oauth_service
from ..shared.dependencies import CurrentUser, SessionDep


route = routing.APIRouter(prefix=f"/api/v{settings.api_version}/auth", tags=["auth"])


def _build_google_auth_url() -> str:
    redirect_uri = f"{settings.OAUTH_REDIRECT}/auth/callback"
    params = {
        "client_id": settings.OAUTH_CLIENT_ID,
        "redirect_uri": redirect_uri,
        "response_type": "code",
        "scope": "openid email profile",
        "access_type": "online",
        "prompt": "select_account",
    }
    return f"https://accounts.google.com/o/oauth2/v2/auth?{urlencode(params)}"


async def _handle_google_callback(session: SessionDep, callback_code: str) -> GoogleCallBackResponse:
    service = oauth_service.OauthService(session=session)
    return await service.google_callback(callback_code)


def _refresh_google_tokens(session: SessionDep, refresh_token: str) -> RefreshTokenResponse:
    service = oauth_service.OauthService(session=session)
    return service.refresh_tokens(refresh_token)


def _google_auth_redirect() -> RedirectResponse:
    return RedirectResponse(_build_google_auth_url())



@route.get("/google/authorize", include_in_schema=False)
def google_authorize() -> RedirectResponse:
    return _google_auth_redirect()


@route.get("/google/authorize-url", operation_id="google_authorize_url")
def google_authorize_url() -> dict[str, str]:
    return {"authorization_url": _build_google_auth_url()}


@route.get("/google/callback", include_in_schema=False)
async def google_callback_get(
    session: SessionDep,
    code: str = Query(...),
) -> GoogleCallBackResponse:
    try:
        return await _handle_google_callback(session=session, callback_code=code)
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=500, detail=f"Error processing Google callback: {str(e)}"
        ) from e


@route.post("/google/callback", operation_id="google_callback_post")
async def google_callback_post(
    session: SessionDep,
    body: GoogleCallbackRequest = Body(...),
) -> GoogleCallBackResponse:
    try:
        return await _handle_google_callback(session=session, callback_code=body.code)
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=500, detail=f"Error processing Google callback: {str(e)}"
        ) from e


@route.post("/google/refresh", operation_id="google_refresh")
async def google_refresh_token(
    session: SessionDep,
    body: RefreshTokenRequest = Body(...),
) -> RefreshTokenResponse:
    try:
        return _refresh_google_tokens(session=session, refresh_token=body.refresh_token)
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=500, detail=f"Error refreshing token: {str(e)}"
        ) from e


@route.get("/me", operation_id="auth_me")
@route.get("/userinfo", include_in_schema=False)
def auth_me(current_user: CurrentUser) -> User:
    return current_user


@route.patch("/me/domain", operation_id="auth_update_domain")
def auth_update_domain(
    session: SessionDep,
    current_user: CurrentUser,
    body: UpdateDomainRequest = Body(...),
) -> User:
    service = oauth_service.OauthService(session=session)
    normalized_domain = body.domain.strip().lower()
    if not normalized_domain:
        raise HTTPException(status_code=422, detail="Domain must not be empty.")
    return service.update_user(current_user, domain=normalized_domain)
