from __future__ import annotations

import hmac
from dataclasses import dataclass
from typing import Iterator

from fastapi import Depends, HTTPException, Request
from sqlalchemy.orm import Session

from app.config import Settings
from app.models import User, UserSession
from app.services import auth as auth_service


def get_settings_dep(request: Request) -> Settings:
    return request.app.state.settings


def cookie_name(settings: Settings) -> str:
    # The __Host- prefix is only valid on Secure cookies.
    return "__Host-tm_session" if settings.cookie_secure else "tm_session"


def get_db(request: Request) -> Iterator[Session]:
    db: Session = request.app.state.session_factory()
    try:
        yield db
    finally:
        db.close()


@dataclass
class AuthContext:
    user: User
    session: UserSession
    token: str
    csrf: str


def authenticate(request: Request, db: Session) -> AuthContext:
    settings: Settings = request.app.state.settings
    token = request.cookies.get(cookie_name(settings))
    if not token or len(token) > 128:
        raise HTTPException(status_code=401, detail="Not authenticated")
    session = auth_service.resolve_session(db, settings, token)
    user = db.get(User, session.user_id) if session else None
    if session is None or user is None:
        raise HTTPException(status_code=401, detail="Not authenticated")
    return AuthContext(user, session, token, auth_service.csrf_token(request.app.state.secret, session))


def current_auth(request: Request, db: Session = Depends(get_db)) -> AuthContext:
    return authenticate(request, db)


def require_csrf(request: Request, auth: AuthContext = Depends(current_auth)) -> AuthContext:
    sent = request.headers.get("x-csrf-token", "")
    if not hmac.compare_digest(sent.encode(), auth.csrf.encode()):
        raise HTTPException(status_code=403, detail="Invalid CSRF token")
    return auth
