
from fastapi import HTTPException
from datetime import datetime, timezone
import base64
import hashlib
import hmac
import json
from typing import Any

from sqlmodel import Session, select
from sqlalchemy.exc import IntegrityError
from ..core.config import settings

from ..schema.auth_schema import (
    GoogleCallBackResponse,
    GoogleTokenInfo,
    RefreshTokenResponse,
)

from ..model.auth_model import User
import httpx

class OauthService:
    def __init__(self , session:Session):
        self.session = session
        self.Jwt_secret = settings.JWT_SECRET
        self.access_token_expires_in = max(
            1, int(getattr(settings, "JWT_ACCESS_EXPIRE_SECONDS", 3600))
        )
        self.refresh_token_expires_in = max(
            1, int(getattr(settings, "JWT_REFRESH_EXPIRE_SECONDS", 60 * 60 * 24 * 30))
        )

    def get_user_by_id(self, user_id: str) -> User | None:
        return self.session.get(User, user_id)

    def get_user_by_email(self, email: str) -> User | None:
        statement = select(User).where(User.email == email)
        return self.session.exec(statement).first()

    def get_user_by_google_sub(self, google_sub: str) -> User | None:
        statement = select(User).where(User.google_sub == google_sub)
        return self.session.exec(statement).first()

    def list_users(self, limit: int = 100, offset: int = 0) -> list[User]:
        statement = select(User).offset(offset).limit(limit)
        return list(self.session.exec(statement).all())

    def create_user(
        self,
        *,
        email: str,
        google_sub: str | None = None,
        full_name: str | None = None,
        given_name: str | None = None,
        family_name: str | None = None,
        avatar_url: str | None = None,
        is_active: bool = True,
        is_email_verified: bool = False,
    ) -> User:
        user = User(
            email=email,
            google_sub=google_sub,
            full_name=full_name,
            given_name=given_name,
            family_name=family_name,
            avatar_url=avatar_url,
            is_active=is_active,
            is_email_verified=is_email_verified,
        )

        try:
            self.session.add(user)
            self.session.commit()
            self.session.refresh(user)
            return user
        except IntegrityError as exc:
            self.session.rollback()
            raise HTTPException(status_code=409, detail="User already exists") from exc

    def update_user(self, user: User, **changes: Any) -> User:
        allowed_fields = {
            "email",
            "google_sub",
            "full_name",
            "given_name",
            "family_name",
            "avatar_url",
            "domain",
            "is_active",
            "is_email_verified",
        }

        for key, value in changes.items():
            if key in allowed_fields:
                setattr(user, key, value)

        user.update_at = datetime.now(timezone.utc)

        try:
            self.session.add(user)
            self.session.commit()
            self.session.refresh(user)
            return user
        except IntegrityError as exc:
            self.session.rollback()
            raise HTTPException(status_code=409, detail="User update conflicts with existing data") from exc

    def delete_user(self, user_id: str) -> bool:
        user = self.get_user_by_id(user_id)
        if user is None:
            return False

        self.session.delete(user)
        self.session.commit()
        return True

    def upsert_google_user(self, token_info: GoogleTokenInfo) -> User:
        user = self.get_user_by_google_sub(token_info.sub)

        if user is None:
            user = self.get_user_by_email(token_info.email)

        user_payload = {
            "email": token_info.email,
            "google_sub": token_info.sub,
            "full_name": token_info.name,
            "given_name": token_info.given_name,
            "family_name": token_info.family_name,
            "avatar_url": token_info.picture,
            "is_email_verified": token_info.email_verified,
            "is_active": True,
        }

        if user is not None:
            return self.update_user(user, **user_payload)

        return self.create_user(**user_payload)

    def create_jwt_token(
        self,
        *,
        user_id: str,
        email: str,
        expires_in_seconds: int = 3600,
        token_type: str = "access",
        secret_key: str | None = None,
    ) -> str:
        key = secret_key or getattr(settings, "JWT_SECRET", None) or settings.OAUTH_SECRET
        if not key:
            raise HTTPException(status_code=500, detail="JWT secret is not configured")

        now = int(datetime.now(timezone.utc).timestamp())
        payload = {
            "sub": user_id,
            "email": email,
            "token_type": token_type,
            "iat": now,
            "exp": now + expires_in_seconds,
        }
        header = {"alg": "HS256", "typ": "JWT"}

        def _b64url(data: bytes) -> str:
            return base64.urlsafe_b64encode(data).rstrip(b"=").decode("utf-8")

        encoded_header = _b64url(json.dumps(header, separators=(",", ":")).encode("utf-8"))
        encoded_payload = _b64url(json.dumps(payload, separators=(",", ":")).encode("utf-8"))
        signing_input = f"{encoded_header}.{encoded_payload}".encode("utf-8")
        signature = hmac.new(key.encode("utf-8"), signing_input, hashlib.sha256).digest()
        encoded_signature = _b64url(signature)

        return f"{encoded_header}.{encoded_payload}.{encoded_signature}"

    @staticmethod
    def _b64url_decode(value: str) -> bytes:
        padding = "=" * (-len(value) % 4)
        return base64.urlsafe_b64decode(value + padding)

    def verify_local_jwt(
        self,
        token: str,
        *,
        secret_key: str | None = None,
    ) -> dict[str, Any]:
        key = secret_key or self.Jwt_secret
        if not key:
            raise HTTPException(status_code=500, detail="JWT secret is not configured")

        try:
            encoded_header, encoded_payload, encoded_signature = token.split(".")
        except ValueError as exc:
            raise HTTPException(status_code=401, detail="Invalid token format") from exc

        signing_input = f"{encoded_header}.{encoded_payload}".encode("utf-8")
        expected_sig = hmac.new(
            key.encode("utf-8"), signing_input, hashlib.sha256
        ).digest()

        try:
            provided_sig = self._b64url_decode(encoded_signature)
        except Exception as exc:
            raise HTTPException(status_code=401, detail="Invalid token signature") from exc

        if not hmac.compare_digest(expected_sig, provided_sig):
            raise HTTPException(status_code=401, detail="Invalid token signature")

        try:
            payload = json.loads(self._b64url_decode(encoded_payload))
        except Exception as exc:
            raise HTTPException(status_code=401, detail="Invalid token payload") from exc

        exp = payload.get("exp")
        now = int(datetime.now(timezone.utc).timestamp())
        if not isinstance(exp, int) or exp < now:
            raise HTTPException(status_code=401, detail="Token expired")

        return payload

    def refresh_tokens(self, refresh_token: str) -> RefreshTokenResponse:
        payload = self.verify_local_jwt(refresh_token, secret_key=self.Jwt_secret)

        if payload.get("token_type") != "refresh":
            raise HTTPException(status_code=401, detail="Invalid refresh token")

        user_id = payload.get("sub")
        email = payload.get("email")
        if not user_id or not email:
            raise HTTPException(status_code=401, detail="Invalid refresh token payload")

        user = self.get_user_by_id(user_id)
        if user is None:
            raise HTTPException(status_code=401, detail="User not found")
        if not user.is_active:
            raise HTTPException(status_code=403, detail="User is inactive")

        access_token = self.create_jwt_token(
            user_id=user.id,
            email=user.email,
            expires_in_seconds=self.access_token_expires_in,
            token_type="access",
            secret_key=self.Jwt_secret,
        )
        new_refresh_token = self.create_jwt_token(
            user_id=user.id,
            email=user.email,
            expires_in_seconds=self.refresh_token_expires_in,
            token_type="refresh",
            secret_key=self.Jwt_secret,
        )

        return RefreshTokenResponse(
            access_token=access_token,
            expires_in=self.access_token_expires_in,
            refresh_token=new_refresh_token,
            refresh_expires_in=self.refresh_token_expires_in,
        )
        
    async def google_callback(self, code: str) -> GoogleCallBackResponse:
        """Handle Google OAuth callback"""
        if not settings.OAUTH_CLIENT_ID or not settings.OAUTH_SECRET:
            raise HTTPException(status_code=400, detail="Google OAuth is not configured. Please set GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET in environment variables.")
        
        # Exchange Token
        token_payload = {
        "code": code,
        "client_id": settings.OAUTH_CLIENT_ID,
        "client_secret": settings.OAUTH_SECRET,
        "redirect_uri": f"{settings.OAUTH_REDIRECT}/auth/callback",
        "grant_type": "authorization_code",
        }
        
        async with httpx.AsyncClient(timeout=10) as client:
            token_resp = await client.post("https://oauth2.googleapis.com/token", data=token_payload)
        
        if token_resp.status_code != 200:
            raise HTTPException(status_code=401, detail="Failed to exchange code")
        
        tokens = token_resp.json()
        id_token = tokens.get("id_token")
        
        if not id_token:
            raise HTTPException(status_code=401, detail="Missing id_token")
        
        token_info = await self._verify_google_token(id_token)
        user = self.upsert_google_user(token_info)
        access_token = self.create_jwt_token(
            user_id=user.id,
            email=user.email,
            expires_in_seconds=self.access_token_expires_in,
            token_type="access",
            secret_key=self.Jwt_secret
        )
        refresh_token = self.create_jwt_token(
            user_id=user.id,
            email=user.email,
            expires_in_seconds=self.refresh_token_expires_in,
            token_type="refresh",
            secret_key=self.Jwt_secret,
        )
        
        return GoogleCallBackResponse(
            access_token=access_token,
            expires_in=self.access_token_expires_in,
            refresh_token=refresh_token,
            refresh_expires_in=self.refresh_token_expires_in,
            user=user,
        )
        
        
        
    async def _verify_google_token(self , id_token: str) -> GoogleTokenInfo:
        """Verify Google ID token and return token info."""
        async with httpx.AsyncClient(timeout=10) as client:
            response = await client.get(
                f"https://oauth2.googleapis.com/tokeninfo?id_token={id_token}"
            )
        if response.status_code != 200:
            raise HTTPException(status_code=400, detail="Invalid Google token")
        
        token_info = response.json()

        # Verify the audience
        if token_info.get("aud") != settings.OAUTH_CLIENT_ID:
            raise HTTPException(status_code=400, detail="Invalid token audience")

        # Verify the issuer
        if token_info.get("iss") not in [
            "https://accounts.google.com",
            "accounts.google.com",
        ]:
            raise HTTPException(status_code=400, detail="Invalid token issuer")

        email = token_info.get("email")
        google_id = token_info.get("sub")

        if not email or not google_id:
            raise HTTPException(
                status_code=400, detail="Invalid token: missing required fields"
            )

        return GoogleTokenInfo.model_validate(token_info)
        
        
  
    
