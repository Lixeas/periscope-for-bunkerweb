import asyncio
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import PlainTextResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles

from mc.config import get_settings
from mc.db import migrate
from mc.web.deps import Redirect

CSP = ("default-src 'self'; img-src 'self' data:; script-src 'self'; style-src 'self'; "
       "frame-ancestors 'none'; base-uri 'none'; form-action 'self'")


def create_app(run_migrations: bool = True) -> FastAPI:
    @asynccontextmanager
    async def lifespan(app: FastAPI):
        cfg = get_settings()
        if run_migrations:
            migrate()
        task = None
        if cfg.collector_enabled:
            from mc import collector

            task = asyncio.create_task(collector.run_forever())
        try:
            yield
        finally:
            if task:
                task.cancel()

    app = FastAPI(lifespan=lifespan, docs_url=None, redoc_url=None, openapi_url=None)
    app.mount("/static", StaticFiles(directory=str(Path(__file__).parent / "static")), name="static")

    @app.exception_handler(Redirect)
    async def _redirect(_: Request, exc: Redirect):
        return RedirectResponse(exc.url, 303)

    @app.middleware("http")
    async def guard(request: Request, call_next):
        cfg = get_settings()
        if request.method not in ("GET", "HEAD", "OPTIONS"):
            origin = request.headers.get("origin")
            if origin and origin not in cfg.origins:
                return PlainTextResponse("Origine refusée", status_code=403)
        resp = await call_next(request)
        resp.headers["Content-Security-Policy"] = CSP
        resp.headers["X-Frame-Options"] = "DENY"
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["Referrer-Policy"] = "same-origin"
        if cfg.cookie_secure:
            resp.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        if not request.url.path.startswith("/static/"):
            resp.headers["Cache-Control"] = "no-store"
        return resp

    from mc.web import routes_account, routes_admin, routes_auth, routes_pages, routes_views

    app.include_router(routes_auth.router)
    app.include_router(routes_account.router)
    app.include_router(routes_admin.router)
    app.include_router(routes_views.router)
    app.include_router(routes_pages.router)
    return app
