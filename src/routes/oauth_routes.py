from fastapi import Body, HTTPException, Query, routing
from fastapi.responses import RedirectResponse
from urllib.parse import urlencode

from ..core.config import settings
from ..schema.auth_schema import GoogleCallBackResponse, GoogleCallbackRequest
from ..services import oauth_service
from ..shared.dependencies import SessionDep


route = routing.APIRouter(prefix=f"/api/v{settings.api_version}/auth", tags=["auth"])


def _build_google_auth_url() -> str:
    redirect_uri = f"{settings.OAUTH_REDIRECT}/api/v{settings.api_version}/auth/google/callback"
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


@route.get("/google/authorize", include_in_schema=False)
def google_authorize() -> RedirectResponse:
    return RedirectResponse(_build_google_auth_url())


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
