from __future__ import annotations

import hashlib
import uuid
from pathlib import Path
from typing import Literal

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates

BASE = Path(__file__).resolve().parent.parent
templates = Jinja2Templates(directory=BASE / "templates")
router = APIRouter()

UI_ROUTES = ["/", "/register", "/login", "/inbox", "/sent", "/trash", "/compose", "/settings", "/keys", "/privacy", "/chats", "/chats/new"]


def asset_manifest() -> dict[str, str]:
    """SHA-256 of every static file, so auditors can compare what a server delivers with the published source."""
    static = BASE / "static"
    return {
        "/static/" + p.relative_to(static).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
        for p in sorted(static.rglob("*")) if p.is_file() and p.name != ".gitkeep"
    }


def _shell(request: Request) -> HTMLResponse:
    st = request.app.state
    s = st.settings
    assets: dict[str, str] = st.assets

    def asset(path: str) -> str:
        return f"{path}?v={assets[path][:16]}"       # content-hash URL: cacheable forever, never stale

    return templates.TemplateResponse(request, "app.html", {
        "asset": asset,
        "policy": {
            "contact": s.operator_contact.strip(), "trash_days": s.trash_purge_days,
            "idle_minutes": s.session_idle_minutes, "absolute_hours": s.session_absolute_hours,
            "max_kb": s.max_message_bytes // 1024,
        },
    })


for _path in UI_ROUTES:
    router.add_api_route(_path, _shell, methods=["GET"], response_class=HTMLResponse, include_in_schema=False)


@router.get("/message/{folder}/{message_id}", response_class=HTMLResponse, include_in_schema=False)
def message_page(request: Request, folder: Literal["inbox", "sent", "trash"], message_id: uuid.UUID):
    return _shell(request)


@router.get("/chats/{chat_id}", response_class=HTMLResponse, include_in_schema=False)
def chat_page(request: Request, chat_id: uuid.UUID):
    return _shell(request)


@router.get("/.well-known/assets.json", include_in_schema=False)
def assets(request: Request):
    return JSONResponse({"algorithm": "sha256", "files": request.app.state.assets})
