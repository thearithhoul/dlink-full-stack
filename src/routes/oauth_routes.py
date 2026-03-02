from fastapi import Body, HTTPException, Query, routing
from fastapi.responses import RedirectResponse
from urllib.parse import urlencode

from ..core.config import settings
from ..model.auth_model import User
from ..schema import ApiResponse
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


# def _google_auth_redirect() -> RedirectResponse:
#     return RedirectResponse(_build_google_auth_url())


# @route.get("/google/authorize", include_in_schema=False)
# def google_authorize() -> RedirectResponse:
#     return _google_auth_redirect()


@route.get(
    "/google/authorize-url",
    operation_id="google_authorize_url",
    response_model=ApiResponse[dict[str, str]],
)
def google_authorize_url() -> ApiResponse[dict[str, str]]:
    return ApiResponse(
        message="Google authorization URL generated successfully.",
        data={"authorization_url": _build_google_auth_url()},
    )


@route.get(
    "/google/callback",
    include_in_schema=False,
    response_model=ApiResponse[GoogleCallBackResponse],
)
async def google_callback_get(
    session: SessionDep,
    code: str = Query(...),
) -> ApiResponse[GoogleCallBackResponse]:
    try:
        callback_response = await _handle_google_callback(session=session, callback_code=code)
        return ApiResponse(
            message="Google callback processed successfully.",
            data=callback_response,
        )
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=500, detail=f"Error processing Google callback: {str(e)}"
        ) from e


@route.post(
    "/google/callback",
    operation_id="google_callback_post",
    response_model=ApiResponse[GoogleCallBackResponse],
)
async def google_callback_post(
    session: SessionDep,
    body: GoogleCallbackRequest = Body(...),
) -> ApiResponse[GoogleCallBackResponse]:
    try:
        callback_response = await _handle_google_callback(session=session, callback_code=body.code)
        return ApiResponse(
            message="Google callback processed successfully.",
            data=callback_response,
        )
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=500, detail=f"Error processing Google callback: {str(e)}"
        ) from e


@route.post(
    "/google/refresh",
    operation_id="google_refresh",
    response_model=ApiResponse[RefreshTokenResponse],
)
async def google_refresh_token(
    session: SessionDep,
    body: RefreshTokenRequest = Body(...),
) -> ApiResponse[RefreshTokenResponse]:
    try:
        refreshed_tokens = _refresh_google_tokens(session=session, refresh_token=body.refresh_token)
        return ApiResponse(
            message="Google token refreshed successfully.",
            data=refreshed_tokens,
        )
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=500, detail=f"Error refreshing token: {str(e)}"
        ) from e

@route.get("/me", operation_id="auth_me", response_model=ApiResponse[User])
@route.get("/userinfo", include_in_schema=False)
def auth_me(current_user: CurrentUser) -> ApiResponse[User]:
    return ApiResponse(message="User profile fetched successfully.", data=current_user)


@route.patch("/me/domain", operation_id="auth_update_domain", response_model=ApiResponse[User])
def auth_update_domain(
    session: SessionDep,
    current_user: CurrentUser,
    body: UpdateDomainRequest = Body(...),
) -> ApiResponse[User]:
    service = oauth_service.OauthService(session=session)
    updated_user = service.update_user_domain(current_user.id, body.domain)
    return ApiResponse(message="User domain updated successfully.", data=updated_user)
