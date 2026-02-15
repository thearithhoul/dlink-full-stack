from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional
from uuid import uuid4

from sqlmodel import Field, SQLModel


class Links(SQLModel, table=True):
    __tablename__ = "links"

    id: str = Field(default_factory=lambda: str(uuid4()), primary_key=True, index=True)
    code: str = Field(index=True, unique=True)
    web_url: str
    android_url: Optional[str] = None
    ios_url: Optional[str] = None
    android_store_url: Optional[str] = None
    ios_store_url: Optional[str] = None
    default_url: str
    is_active: bool = Field(default=True)
    expire_at: Optional[datetime] = None
    create_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


