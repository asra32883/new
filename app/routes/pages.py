from __future__ import annotations

import hashlib
from pathlib import Path

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates

BASE = Path(__file__).resolve().parent.parent
templates = Jinja2Templates(directory=BASE / "templates")
router = APIRouter()


def asset_manifest() -> dict[str, str]:
    """SHA-256 of every static file, so auditors can compare what a server delivers with the published source."""
    static = BASE / "static"
    return {
        "/static/" + p.relative_to(static).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
        for p in sorted(static.rglob("*")) if p.is_file() and p.name != ".gitkeep"
    }


@router.get("/keys", response_class=HTMLResponse, include_in_schema=False)
def keys_page(request: Request):
    return templates.TemplateResponse(request, "keys.html")


@router.get("/.well-known/assets.json", include_in_schema=False)
def assets(request: Request):
    return JSONResponse({"algorithm": "sha256", "files": request.app.state.assets})
