from __future__ import annotations

import uuid
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response
from pydantic import Field
from sqlalchemy.orm import Session

from app.deps import AuthContext, current_auth, get_db, require_csrf
from app.routes.auth import Strict
from app.services import mailbox as svc

router = APIRouter(prefix="/api", tags=["mailbox"])
Folder = Literal["inbox", "sent", "trash"]


class SendIn(Strict):
    recipients: list[str] = Field(min_length=1, max_length=100)
    ciphertext: str = Field(max_length=700_000)


class ReadIn(Strict):
    is_read: bool


def _nf() -> HTTPException:
    return HTTPException(404, "Not found")


@router.post("/messages", status_code=201)
def send(body: SendIn, request: Request, auth: AuthContext = Depends(require_csrf),
         db: Session = Depends(get_db)) -> dict:
    st = request.app.state
    try:
        delivered = svc.send(db, st.settings, auth.user, body.recipients, body.ciphertext)
    except svc.InvalidMessage as e:
        raise HTTPException(422, str(e)) from None
    except svc.UnknownRecipients as e:
        raise HTTPException(404, f"Unknown recipient(s): {e}") from None
    except svc.SendLimited as e:
        raise HTTPException(429, "Sending limit reached. Try again later.",
                            headers={"Retry-After": str(e.retry_after)}) from None
    return {"status": "delivered", "delivered_to": delivered}


@router.get("/mailbox/{folder}")
def list_folder(folder: Folder, request: Request, cursor: str | None = Query(None, max_length=200),
                limit: int | None = Query(None, ge=1, le=200), auth: AuthContext = Depends(current_auth),
                db: Session = Depends(get_db)) -> dict:
    try:
        page = svc.list_folder(db, request.app.state.settings, auth.user, folder, cursor, limit)
    except svc.BadCursor:
        raise HTTPException(400, "Invalid cursor") from None
    out = {"items": page.items, "next_cursor": page.next_cursor}
    if page.unread is not None:
        out["unread"] = page.unread
    return out


@router.get("/mailbox/{folder}/{message_id}")
def get_message(folder: Folder, message_id: uuid.UUID, auth: AuthContext = Depends(current_auth),
                db: Session = Depends(get_db)) -> dict:
    try:
        return svc.get_message(db, auth.user, folder, message_id)
    except svc.NotFound:
        raise _nf() from None


@router.post("/mailbox/inbox/{message_id}/read", status_code=204)
def set_read(message_id: uuid.UUID, body: ReadIn, auth: AuthContext = Depends(require_csrf),
             db: Session = Depends(get_db)) -> Response:
    try:
        svc.set_read(db, auth.user, message_id, body.is_read)
    except svc.NotFound:
        raise _nf() from None
    return Response(status_code=204)


@router.post("/mailbox/trash/{message_id}/restore", status_code=204)
def restore(message_id: uuid.UUID, auth: AuthContext = Depends(require_csrf),
            db: Session = Depends(get_db)) -> Response:
    try:
        svc.restore(db, auth.user, message_id)
    except svc.NotFound:
        raise _nf() from None
    return Response(status_code=204)


@router.delete("/mailbox/{folder}/{message_id}")
def delete_message(folder: Folder, message_id: uuid.UUID, auth: AuthContext = Depends(require_csrf),
                   db: Session = Depends(get_db)) -> dict:
    try:
        return {"result": svc.delete_message(db, auth.user, folder, message_id)}
    except svc.NotFound:
        raise _nf() from None
