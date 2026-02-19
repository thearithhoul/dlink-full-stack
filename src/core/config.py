from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    database_url: str
    app_name: str = "Dynamic Link App"
    api_version: int = 1
    environment: str = "development"
    sentry_dsn: str | None = None
    sentry_traces_sample_rate: float = 0.0
    sentry_send_default_pii: bool = False
    OAUTH_CLIENT_ID :str
    OAUTH_SECRET :str
    OAUTH_REDIRECT : str
    JWT_SECRET : str
    
    model_config = SettingsConfigDict(
        env_file=".env",
        env_prefix="APP_",
        extra="ignore",
    )

        
settings = Settings()
