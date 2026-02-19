from datetime import datetime
from pydantic import AnyUrl, BaseModel, ConfigDict, HttpUrl



class CreateLinks(BaseModel):
    default_url: HttpUrl
    android_store_url: HttpUrl | None = None
    ios_store_url: HttpUrl | None = None
    android_url: AnyUrl | None = None
    ios_url: AnyUrl | None = None
    expires_at: datetime | None = None


class LinksRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: str
    code: str
    web_url: HttpUrl
    android_url: AnyUrl | None = None
    ios_url: AnyUrl | None = None
    android_store_url: HttpUrl | None = None
    ios_store_url: HttpUrl | None = None
    default_url: HttpUrl
    is_active: bool
    expire_at: datetime | None = None
    create_at: datetime
