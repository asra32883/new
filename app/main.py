"""Application factory."""
from __future__ import annotations

import logging
from pathlib import Path

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles

from app.config import Settings, get_settings
from app.routes import health
from app.security.headers import BodySizeLimitMiddleware, SecurityHeadersMiddleware

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

    if not settings.cookie_secure:
        log.warning("event=insecure_config detail=cookie_secure_disabled")

    app.add_middleware(BodySizeLimitMiddleware, max_bytes=settings.max_request_bytes)
    app.add_middleware(SecurityHeadersMiddleware)

    app.include_router(health.router)
    app.mount("/static", StaticFiles(directory=BASE_DIR / "static"), name="static")
    return app


def factory() -> FastAPI:
    """Entry point for `uvicorn app.main:factory --factory`."""
    return create_app()
