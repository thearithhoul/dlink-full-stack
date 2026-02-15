from fastapi import Depends, routing


route = routing.APIRouter(prefix="/api/links", tags=["links"])



@route.post("/add")
def create_link():
    return

@route.get("/")
def list_links():
    return