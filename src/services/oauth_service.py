
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

from ..schema.auth_schema import GoogleCallBackResponse, GoogleTokenInfo

from ..model.auth_model import User
import httpx

class OauthService:
    def __init__(self , session:Session):
        self.session = session
        self.Jwt_secret = settings.JWT_SECRET

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
        secret_key: str | None = None,
    ) -> str:
        key = secret_key or getattr(settings, "JWT_SECRET", None) or settings.OAUTH_SECRET
        if not key:
            raise HTTPException(status_code=500, detail="JWT secret is not configured")

        now = int(datetime.now(timezone.utc).timestamp())
        payload = {
            "sub": user_id,
            "email": email,
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
        
    async def google_callback(self, code: str) -> GoogleCallBackResponse:
        """Handle Google OAuth callback"""
        if not settings.OAUTH_CLIENT_ID or not settings.OAUTH_SECRET:
            raise HTTPException(status_code=400, detail="Google OAuth is not configured. Please set GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET in environment variables.")
        
        # Exchange Token
        token_payload = {
        "code": code,
        "client_id": settings.OAUTH_CLIENT_ID,
        "client_secret": settings.OAUTH_SECRET,
        "redirect_uri": f"{settings.OAUTH_REDIRECT}/api/v{settings.api_version}/auth/google/callback",
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
        user =  self.upsert_google_user(token_info)
        expires_in = 3600
        access_token = self.create_jwt_token(
            user_id=user.id,
            email=user.email,
            expires_in_seconds=expires_in,
            secret_key= self.Jwt_secret
        )
        
        return GoogleCallBackResponse(
            access_token=access_token,
            expires_in=expires_in,
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
        
        
  
    
