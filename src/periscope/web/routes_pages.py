from fastapi import APIRouter
from fastapi.responses import RedirectResponse

router = APIRouter()


@router.get("/")
async def index():
    return RedirectResponse("/dashboard", 303)
