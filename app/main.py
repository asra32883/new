"""Application factory."""
from __future__ import annotations

import logging
import re
import secrets
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from sqlalchemy.orm import sessionmaker

from app.config import Settings, get_settings
from app.database import make_engine
from app.routes import account, auth, chats, health, keys, mailbox, pages
from app.security.headers import BodySizeLimitMiddleware, SecurityHeadersMiddleware, StaticOnlyGzip
from app.security.passwords import PasswordService

log = logging.getLogger("tormail")

BASE_DIR = Path(__file__).parent


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or get_settings()

    # No interactive docs or OpenAPI schema exposed in production.
    docs_enabled = settings.env != "production"
    app = FastAPI(
        title="Tor-Mail",
        docs_url="/docs" if docs_enabled else None,
        redoc_url=None,
        openapi_url="/openapi.json" if docs_enabled else None,
    )
    app.state.settings = settings
    app.state.engine = make_engine(settings.database_url)
    app.state.session_factory = sessionmaker(app.state.engine, expire_on_commit=False)
    # Outside production an unset key is replaced by a random per-process one (production refuses to start without it).
    app.state.secret = settings.secret_key.encode() if settings.secret_key else secrets.token_bytes(32)
    app.state.passwords = PasswordService(settings)
    app.state.chat_waiters = {}   # user id -> events of open long-poll requests (in-process wake-ups)

    if not settings.cookie_secure:
        log.warning("event=insecure_config detail=cookie_secure_disabled")

    @app.exception_handler(RequestValidationError)
    async def _validation_error(_: Request, exc: RequestValidationError) -> JSONResponse:
        # Never echo submitted values back: they can contain passwords.
        errors = [{"loc": [str(p) for p in e["loc"]], "msg": e["msg"]} for e in exc.errors()]
        return JSONResponse({"detail": errors}, status_code=422)

    app.add_middleware(StaticOnlyGzip)
    blob_path = re.compile(r"^/api/chats/[0-9a-fA-F-]{36}/blobs$")
    app.add_middleware(BodySizeLimitMiddleware, max_bytes=settings.max_request_bytes,
                       overrides=[(blob_path, settings.chat_max_blob_bytes + 1024)])
    app.add_middleware(SecurityHeadersMiddleware)

    app.include_router(health.router)
    app.include_router(auth.router)
    app.include_router(account.router)
    app.include_router(mailbox.router)
    app.include_router(keys.router)
    app.include_router(chats.router)
    app.include_router(pages.router)
    app.state.assets = pages.asset_manifest()   # static files are fixed for the life of the process
    app.mount("/static", StaticFiles(directory=BASE_DIR / "static"), name="static")
    return app


def factory() -> FastAPI:
    """Entry point for `uvicorn app.main:factory --factory`."""
    return create_app()
