

from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional
from uuid import uuid4

from sqlmodel import Field, SQLModel


class User(SQLModel, table=True):
    __tablename__ = "users"
    id: str = Field(default_factory=lambda: str(uuid4()), primary_key=True, index=True)
    email: str = Field(index=True, unique=True)
    full_name: Optional[str] = None
    given_name: Optional[str] = None
    family_name: Optional[str] = None
    avatar_url: Optional[str] = None
    google_sub: Optional[str] = Field(default=None, index=True, unique=True)
    domain: Optional[str] = None
    is_active: bool = Field(default=True)
    is_email_verified: bool = Field(default=False)
    create_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    update_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
