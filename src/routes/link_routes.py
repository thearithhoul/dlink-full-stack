from fastapi import HTTPException, Query, routing , Depends
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from sqlmodel import Session, select

from ..core.config import settings

from ..model.link_model import Links
from ..purefunction.short_link_generator import generate_7_digit_code
from ..schema import ApiResponse
from ..schema.link_schema import CreateLinks, LinksRead
from ..shared.dependencies import SessionDep , get_current_user

import logging
logger = logging.getLogger(__name__)

route = routing.APIRouter(prefix=f"/api/v{settings.api_version}/links", tags=["links"], dependencies=[Depends(get_current_user)])

def _generate_unique_code(session: Session, max_attempts: int = 10) -> str:
    for _ in range(max_attempts):
        code = generate_7_digit_code()
        code_exists = session.exec(select(Links.id).where(Links.code == code)).first()
        if code_exists is None:
            return code

    raise HTTPException(status_code=500, detail="Unable to generate a unique short code.")

@route.post("/add", response_model=ApiResponse[LinksRead])
def create_link(
    session: SessionDep,
    data: CreateLinks,
) -> ApiResponse[LinksRead]:
    try:
        logger.info("Create link requested")
        code = _generate_unique_code(session)

        new_link = Links(
            code=code,
            web_url=str(data.default_url),
            default_url=str(data.default_url),
            android_store_url=str(data.android_store_url) if data.android_store_url else None,
            ios_store_url=str(data.ios_store_url) if data.ios_store_url else None,
            android_url=str(data.android_url) if data.android_url else None,
            ios_url=str(data.ios_url) if data.ios_url else None,
            expire_at=data.expires_at,
        )

        session.add(new_link)
        session.commit()
        session.refresh(new_link)
        logger.info("Link created successfully with code=%s", new_link.code)

        return ApiResponse(message="Link created successfully.", data=LinksRead.model_validate(new_link))
    except IntegrityError as exc:
        session.rollback()
        logger.warning("Link code conflict detected during create")
        raise HTTPException(status_code=409, detail="Link code conflict, please retry.") from exc
    except SQLAlchemyError as exc:
        session.rollback()
        logger.exception("Database operation failed during create_link")
        raise HTTPException(status_code=500, detail="Database operation failed.") from exc

@route.get("/", response_model=ApiResponse[list[LinksRead]])
def list_links(
    session: SessionDep,
    limit: int = Query(default=20, ge=1, le=100),
    page: int = Query(default=1, ge=1),
) -> ApiResponse[list[LinksRead]]:
    try:
        logger.info("List links requested page=%s limit=%s", page, limit)
        offset = (page - 1) * limit
        links = session.exec(
            select(Links).order_by(Links.create_at.desc()).offset(offset).limit(limit)
        ).all()

        items = [LinksRead.model_validate(link) for link in links]
        return ApiResponse(message="Links fetched successfully.", data=items)
    except SQLAlchemyError as exc:
        logger.exception("Database operation failed during list_links")
        raise HTTPException(status_code=500, detail="Database operation failed.") from exc
