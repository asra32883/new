from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from pydantic import Field, model_validator
from sqlalchemy import delete
from sqlalchemy.orm import Session

from app.deps import AuthContext, get_db, require_csrf, current_auth
from app.models import UserSession
from app.routes.auth import Strict, clear_session_cookie, rate_limited
from app.security import policy
from app.services import auth as svc

router = APIRouter(prefix="/api/account", tags=["account"])


class PasswordChangeIn(Strict):
    current_password: str = Field(max_length=policy.MAX_PASSWORD)
    new_password: str = Field(max_length=policy.MAX_PASSWORD)

    @model_validator(mode="after")
    def _differs(self) -> "PasswordChangeIn":
        if self.current_password == self.new_password:
            raise ValueError("New password must differ from the current one")
        return self


class DeleteIn(Strict):
    password: str = Field(max_length=policy.MAX_PASSWORD)


@router.get("/sessions")
def list_sessions(auth: AuthContext = Depends(current_auth), db: Session = Depends(get_db)) -> list[dict]:
    rows = db.query(UserSession).filter(UserSession.user_id == auth.user.id).order_by(UserSession.created_at).all()
    return [
        {"id": str(s.id), "created_at": s.created_at.isoformat() + "Z",
         "last_seen_at": s.last_seen_at.isoformat() + "Z", "current": s.id == auth.session.id}
        for s in rows
    ]


@router.delete("/sessions/{session_id}", status_code=204)
def revoke_session(session_id: uuid.UUID, auth: AuthContext = Depends(require_csrf), db: Session = Depends(get_db)) -> Response:
    result = db.execute(delete(UserSession).where(UserSession.id == session_id, UserSession.user_id == auth.user.id))
    db.commit()
    if result.rowcount == 0:
        raise HTTPException(404, "Session not found")
    return Response(status_code=204)


@router.post("/password", status_code=204)
def change_password(body: PasswordChangeIn, request: Request, auth: AuthContext = Depends(require_csrf),
                    db: Session = Depends(get_db)) -> Response:
    st = request.app.state
    try:
        svc.change_password(db, st.settings, st.secret, st.passwords, auth.user, auth.session,
                            body.current_password, body.new_password)
    except svc.InvalidCredentials:
        raise HTTPException(401, "Current password is incorrect") from None
    except svc.RateLimited as e:
        raise rate_limited(e) from None
    except ValueError as e:
        raise HTTPException(422, str(e)) from None
    return Response(status_code=204)


@router.post("/delete", status_code=204)
def delete_account(body: DeleteIn, request: Request, auth: AuthContext = Depends(require_csrf),
                   db: Session = Depends(get_db)) -> Response:
    st = request.app.state
    try:
        svc.delete_account(db, st.settings, st.secret, st.passwords, auth.user, body.password)
    except svc.InvalidCredentials:
        raise HTTPException(401, "Password is incorrect") from None
    except svc.RateLimited as e:
        raise rate_limited(e) from None
    out = Response(status_code=204)
    clear_session_cookie(out, st.settings)
    return out
