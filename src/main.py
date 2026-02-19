from datetime import datetime, timezone
import logging
from logging.config import dictConfig

import sentry_sdk
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import RedirectResponse
from sentry_sdk.integrations.fastapi import FastApiIntegration
from sentry_sdk.integrations.logging import LoggingIntegration
from sqlmodel import select

from .model.link_model import Links
from .routes.link_routes import route as link_route
from .routes.oauth_routes import route as oauth_route
from .shared.dependencies import SessionDep

from .core.config import settings

logger = logging.getLogger(__name__)

def setup_logging():
    dictConfig(LOGGING_CONFIG)


def setup_sentry():
    if not settings.sentry_dsn:
        logger.info("Sentry DSN is not configured. Sentry integration is disabled.")
        return

    sentry_logging = LoggingIntegration(
        level=logging.INFO,       # breadcrumbs
        event_level=logging.ERROR # send error logs as Sentry events
    )
    sentry_sdk.init(
        dsn=settings.sentry_dsn,
        environment=settings.environment,
        traces_sample_rate=settings.sentry_traces_sample_rate,
        send_default_pii=settings.sentry_send_default_pii,
        integrations=[FastApiIntegration(), sentry_logging],
    )

LOGGING_CONFIG= {
    "version": 1,
    "disable_existing_loggers":False,
    
    "formatters": {
        "json": {
            "format": '{"time":"%(asctime)s","level":"%(levelname)s","name":"%(name)s","message":"%(message)s"}'
        },
    },
    
    "handlers": {
        "console": {
            "class": "logging.StreamHandler",
            "formatter": "json",
            "level": "INFO",
        },
    },
    
    "root": {
        "handlers": ["console"],
        "level": "INFO",
    },
    
}

app = FastAPI(lifespan=None, title="Dynamic Link App", description="A FastAPI application for managing dynamic links.")

# Dev CORS: allow localhost/127.0.0.1 from any port (e.g. 3000/5173).
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost",
        "http://127.0.0.1",
    ],
    allow_origin_regex=r"^https?://(localhost|127\.0\.0\.1)(:\d+)?$",
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

setup_logging()
setup_sentry()

app.include_router(link_route)
app.include_router(oauth_route)


@app.get("/")
def redirectlink(code: str, session: SessionDep) -> RedirectResponse:
    if not code:
        logger.warning("Redirect failed: code is required")
        raise HTTPException(status_code=400, detail="code is required")
    
    link = session.exec(select(Links).where(Links.code == code, Links.is_active.is_(True))).first()
    
    if link is None:
        logger.warning("Redirect failed: link not found for code=%s", code)
        raise HTTPException(status_code=404, detail="Link not found.")
    
    if link.expire_at is not None:
        expires_at = link.expire_at
        if expires_at.tzinfo is None:
             expires_at = expires_at.replace(tzinfo=timezone.utc)
        if expires_at <= datetime.now(timezone.utc):
            logger.info("Redirect blocked: link expired for code=%s", code)
            raise HTTPException(status_code=410, detail="Link has Expired.")
    logger.info("Redirecting code=%s to destination", code)
    return RedirectResponse(url=link.default_url, status_code=307)
