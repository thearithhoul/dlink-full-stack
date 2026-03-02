from datetime import datetime, timezone
import logging
from logging.config import dictConfig
import re

import sentry_sdk
from fastapi import FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.responses import RedirectResponse
from sentry_sdk.integrations.fastapi import FastApiIntegration
from sentry_sdk.integrations.logging import LoggingIntegration
from sqlmodel import select

from src.model.auth_model import User

from .model.link_model import Links
from .routes.link_routes import route as link_route
from .routes.oauth_routes import route as oauth_route
from .schema import ApiResponse
from .shared.dependencies import  SessionDep

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

is_production = settings.environment.lower() == "production"

app = FastAPI(
    lifespan=None,
    title="Dynamic Link App",
    description="A FastAPI application for managing dynamic links.",
    docs_url=None if is_production else "/docs",
    redoc_url=None if is_production else "/redoc",
    openapi_url=None if is_production else "/openapi.json",
)

# Allow localhost plus configured base domain and all of its subdomains.
base_domain_pattern = re.escape(settings.base_domain.lower())
cors_origin_regex = rf"^https?://(([\w-]+\.)*localhost|127\.0\.0\.1|{base_domain_pattern}|([\w-]+\.)+{base_domain_pattern})(:\d+)?$"
app.add_middleware(
    CORSMiddleware,
    allow_origin_regex=cors_origin_regex,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

setup_logging()
setup_sentry()

app.include_router(link_route)
app.include_router(oauth_route)


@app.exception_handler(HTTPException)
async def http_exception_handler(_: Request, exc: HTTPException) -> JSONResponse:
    message = exc.detail if isinstance(exc.detail, str) else "Request failed."
    payload = ApiResponse[None](success=False, message=message, data=None).model_dump()
    return JSONResponse(status_code=exc.status_code, content=payload)


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(_: Request, __: RequestValidationError) -> JSONResponse:
    payload = ApiResponse[None](success=False, message="Validation failed.", data=None).model_dump()
    return JSONResponse(status_code=422, content=payload)


@app.exception_handler(Exception)
async def unhandled_exception_handler(_: Request, exc: Exception) -> JSONResponse:
    logger.exception("Unhandled server error", exc_info=exc)
    payload = ApiResponse[None](success=False, message="Internal server error.", data=None).model_dump()
    return JSONResponse(status_code=500, content=payload)


@app.get("/{code}", include_in_schema=False)
def redirectlink(code: str,
                session: SessionDep,
                request: Request,
                ) -> RedirectResponse:
    
    code = (code or "").strip()
    subdomain = get_subdomain(request=request)

    if not code:
        logger.warning("Redirect failed: code is required")
        raise HTTPException(status_code=400, detail="code is required")
    
    if subdomain:
        user =  session.exec(
            select(User).where(
                User.domain == subdomain,
            )
        ).first()
    
        if user is None:
            logger.warning("Redirect failed: unknown subdomain=%s", subdomain)
            raise HTTPException(status_code=404, detail="Link not found.")

        link = session.exec(
            select(Links).where(
                Links.code == code,
                Links.user_id == user.id,
                Links.is_active.is_(True),
            )
        ).first()
        
    
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


def get_subdomain(request: Request) -> str | None :
    host = (request.headers.get("host") or "").split(":")[0].lower()
    base_domain = settings.base_domain
    if host == base_domain:
        return None

    if host.endswith("."+base_domain):
        return host[:-(len(base_domain) + 1)]
    
    return None
