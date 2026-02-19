from pydantic import BaseModel, ConfigDict
from ..model.auth_model import User


class CallbackParams(BaseModel):
    code: str | None = None
    state: str | None = None
    error: str | None = None
    
    

    
class GoogleCallbackRequest(BaseModel):
    """Google login with ID token request."""
    code: str
    

class GoogleCallBackResponse(BaseModel):
    access_token: str
    token_type :str ="bearer"
    expires_in : int
    user: User
    

class GoogleTokenInfo(BaseModel):
    # tell Pydantic don't fail if input JSON has fields not defined in the model 
    # drop those extra fields instead of storing them
    model_config = ConfigDict(extra="ignore")

    iss: str
    sub: str
    aud: str
    iat: int
    exp: int
    email: str
    email_verified: bool
    name: str | None = None
    picture: str | None = None
    given_name: str | None = None
    family_name: str | None = None
