from contextlib import asynccontextmanager

from fastapi import FastAPI
from .routes.link_routes import route as link_route

app = FastAPI(lifespan=None, title="Dynamic Link App", description="A FastAPI application for managing dynamic links.")

@asynccontextmanager
async def lifespan(app: FastAPI):
    from .core.db.db import init_db
    init_db()
    yield
    
app.include_router(link_route)