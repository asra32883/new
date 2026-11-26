from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from pydantic import Field
from sqlalchemy.orm import Session

from app.deps import AuthContext, current_auth, get_db, require_csrf
from app.routes.auth import Strict
from app.services import keys as svc

router = APIRouter(prefix="/api", tags=["keys"])


class KeyIn(Strict):
    public_key: str = Field(max_length=80_000)
    fingerprint: str = Field(max_length=100)
    # Only for users who opt in to server-side backup. Must already be passphrase-encrypted by the browser.
    encrypted_private_key: str | None = Field(default=None, max_length=150_000)


def _view(key: svc.UserKey) -> dict:
    return {
        "public_key": key.public_key_armored, "fingerprint": key.fingerprint,
        "created_at": key.created_at.isoformat() + "Z", "has_server_backup": key.encrypted_private_key is not None,
    }


@router.get("/keys/me")
def my_key(auth: AuthContext = Depends(current_auth), db: Session = Depends(get_db)) -> dict:
    key = svc.active_key(db, auth.user.id)
    if key is None:
        raise HTTPException(404, "No encryption key set up")
    return _view(key)


@router.put("/keys/me")
def set_my_key(body: KeyIn, request: Request, auth: AuthContext = Depends(require_csrf),
               db: Session = Depends(get_db)) -> dict:
    try:
        key = svc.set_active_key(db, request.app.state.settings, auth.user, body.public_key, body.fingerprint,
                                 body.encrypted_private_key)
    except svc.InvalidKey as e:
        raise HTTPException(422, str(e)) from None
    except svc.KeyLimited:
        raise HTTPException(429, "Too many key changes today", headers={"Retry-After": "3600"}) from None
    return _view(key)


@router.get("/keys/me/backup")
def get_backup(auth: AuthContext = Depends(current_auth), db: Session = Depends(get_db)) -> dict:
    try:
        return {"encrypted_private_key": svc.get_backup(db, auth.user.id)}
    except svc.NoKey:
        raise HTTPException(404, "No server-side backup") from None


@router.delete("/keys/me/backup", status_code=204)
def delete_backup(auth: AuthContext = Depends(require_csrf), db: Session = Depends(get_db)) -> Response:
    try:
        svc.delete_backup(db, auth.user.id)
    except svc.NoKey:
        raise HTTPException(404, "No server-side backup") from None
    return Response(status_code=204)


@router.get("/users/{username}/key")
def user_key(username: str, auth: AuthContext = Depends(current_auth), db: Session = Depends(get_db)) -> dict:
    """Public key of another user. Authenticated only, so anonymous visitors cannot enumerate accounts."""
    if len(username) > 64:
        raise HTTPException(404, "No key for that user")
    try:
        name, key = svc.public_for_username(db, username)
    except svc.NoKey:
        raise HTTPException(404, "No key for that user") from None
    return {"username": name, "public_key": key.public_key_armored, "fingerprint": key.fingerprint}
