
from pydantic import BaseModel , ConfigDict



class create_links(BaseModel):
    default_url: str
    android_store_url: str 
    ios_store_url: str
    android_url: str
    ios_url: str
    default_url: str
    expires_at: str
    


class LinksRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)
