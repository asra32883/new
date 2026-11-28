"""Chat API. Opaque ciphertext in, opaque ciphertext out; membership and ownership are enforced in the service."""
from __future__ import annotations

import asyncio
import uuid
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response
from fastapi.concurrency import run_in_threadpool
from pydantic import Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.deps import AuthContext, authenticate, current_auth, get_db, require_csrf
from app.models import ChatMember, utcnow
from app.routes.auth import Strict
from app.services import chat as svc

router = APIRouter(prefix="/api/chats", tags=["chats"])
MAX_WAITERS_PER_USER = 4
POLL_RECHECK_SECONDS = 5      # also covers multi-process deployments, where in-process wake-ups do not cross workers


class NewChatIn(Strict):
    kind: str = Field(pattern="^(direct|group)$")
    username: str | None = Field(default=None, max_length=64)
    members: list[str] = Field(default_factory=list, max_length=100)
    meta_ciphertext: str | None = Field(default=None, max_length=100_000)


class SendIn(Strict):
    ciphertext: str = Field(max_length=200_000)
    members_version: int = Field(ge=0)
    blob_ids: list[uuid.UUID] = Field(default_factory=list, max_length=10)


class ReadIn(Strict):
    upto_seq: int = Field(ge=0)


class TtlIn(Strict):
    ttl_seconds: int | None = None


class AddMembersIn(Strict):
    usernames: list[str] = Field(min_length=1, max_length=100)
    members_version: int = Field(ge=0)
    meta_ciphertext: str = Field(max_length=100_000)


def _fail(e: Exception) -> HTTPException:
    if isinstance(e, svc.NotFound):
        return HTTPException(404, "Not found")
    if isinstance(e, svc.Forbidden):
        return HTTPException(403, str(e))
    if isinstance(e, svc.MembersChanged):
        return HTTPException(409, "members_changed")
    if isinstance(e, svc.MissingKey):
        return HTTPException(409, str(e))
    if isinstance(e, svc.UnknownUsers):
        return HTTPException(404, f"Unknown user(s): {e}")
    if isinstance(e, svc.Limited):
        return HTTPException(429, "Too many requests. Try again later.", headers={"Retry-After": str(e.retry_after)})
    return HTTPException(422, str(e))


def _member_ids(db: Session, chat_id: uuid.UUID) -> list[uuid.UUID]:
    return list(db.scalars(select(ChatMember.user_id).where(ChatMember.chat_id == chat_id)))


def _notify(request: Request, user_ids: list[uuid.UUID]) -> None:
    """Wakes long-polling clients in this process."""
    waiters = request.app.state.chat_waiters
    for uid in user_ids:
        for ev in list(waiters.get(uid, ())):
            ev.set()


def _after(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.removesuffix("Z")).replace(tzinfo=None)
    except ValueError:
        raise HTTPException(400, "Invalid cursor") from None


@router.post("", status_code=201)
def create(body: NewChatIn, request: Request, auth: AuthContext = Depends(require_csrf), db: Session = Depends(get_db)) -> dict:
    st = request.app.state
    try:
        if body.kind == "direct":
            if not body.username:
                raise HTTPException(422, "username required")
            chat = svc.create_direct(db, st.settings, auth.user, body.username)
        else:
            if not body.meta_ciphertext:
                raise HTTPException(422, "meta_ciphertext required for groups")
            chat = svc.create_group(db, st.settings, auth.user, body.members, body.meta_ciphertext)
    except svc.ChatError as e:
        raise _fail(e) from None
    _notify(request, _member_ids(db, chat.id))
    return svc.get_chat(db, auth.user, chat.id)


@router.get("")
async def updates(request: Request, after: str | None = Query(None, max_length=40), wait: int = Query(0, ge=0, le=25)) -> dict:
    """Chats changed since `after`. With `wait`, holds the request open (long poll) until something changes.
    No database session is held while waiting."""
    st = request.app.state
    after_dt = _after(after)
    started = utcnow()

    def query() -> tuple[uuid.UUID, list[dict]]:
        db = st.session_factory()
        try:
            auth = authenticate(request, db)
            return auth.user.id, svc.list_chats(db, auth.user, after_dt, overlap=(wait == 0))
        finally:
            db.close()

    uid, items = await run_in_threadpool(query)
    if items or wait == 0:
        return {"items": items, "cursor": svc._iso(started)}
    waiters: dict = st.chat_waiters
    mine = waiters.setdefault(uid, set())
    if len(mine) >= MAX_WAITERS_PER_USER:
        raise HTTPException(429, "Too many open connections", headers={"Retry-After": "5"})
    ev = asyncio.Event()
    mine.add(ev)
    loop = asyncio.get_running_loop()
    deadline = loop.time() + wait
    try:
        while loop.time() < deadline:
            try:
                await asyncio.wait_for(ev.wait(), min(POLL_RECHECK_SECONDS, max(0.1, deadline - loop.time())))
            except asyncio.TimeoutError:
                pass
            ev.clear()
            if await request.is_disconnected():
                break
            _, items = await run_in_threadpool(query)
            if items:
                break
    finally:
        mine.discard(ev)
        if not mine:
            waiters.pop(uid, None)
    return {"items": items, "cursor": svc._iso(started)}


@router.get("/{chat_id}")
def get_chat(chat_id: uuid.UUID, auth: AuthContext = Depends(current_auth), db: Session = Depends(get_db)) -> dict:
    try:
        return svc.get_chat(db, auth.user, chat_id)
    except svc.ChatError as e:
        raise _fail(e) from None


@router.get("/{chat_id}/messages")
def messages(chat_id: uuid.UUID, after_seq: int | None = Query(None, ge=0), before_seq: int | None = Query(None, ge=0),
             limit: int = Query(40, ge=1, le=100), auth: AuthContext = Depends(current_auth), db: Session = Depends(get_db)) -> dict:
    try:
        return svc.get_messages(db, auth.user, chat_id, after_seq, before_seq, limit)
    except svc.ChatError as e:
        raise _fail(e) from None


@router.post("/{chat_id}/messages", status_code=201)
def send(chat_id: uuid.UUID, body: SendIn, request: Request, auth: AuthContext = Depends(require_csrf), db: Session = Depends(get_db)) -> dict:
    try:
        item = svc.send_message(db, request.app.state.settings, auth.user, chat_id, body.ciphertext, body.members_version, body.blob_ids)
    except svc.ChatError as e:
        raise _fail(e) from None
    _notify(request, _member_ids(db, chat_id))
    return item


@router.delete("/{chat_id}/messages/{seq}", status_code=204)
def delete_message(chat_id: uuid.UUID, seq: int, request: Request, auth: AuthContext = Depends(require_csrf), db: Session = Depends(get_db)) -> Response:
    try:
        svc.delete_message(db, auth.user, chat_id, seq)
    except svc.ChatError as e:
        raise _fail(e) from None
    _notify(request, _member_ids(db, chat_id))
    return Response(status_code=204)


@router.post("/{chat_id}/read", status_code=204)
def read(chat_id: uuid.UUID, body: ReadIn, request: Request, auth: AuthContext = Depends(require_csrf), db: Session = Depends(get_db)) -> Response:
    try:
        svc.mark_read(db, auth.user, chat_id, body.upto_seq)
    except svc.ChatError as e:
        raise _fail(e) from None
    _notify(request, _member_ids(db, chat_id))
    return Response(status_code=204)


@router.put("/{chat_id}/ttl", status_code=204)
def ttl(chat_id: uuid.UUID, body: TtlIn, request: Request, auth: AuthContext = Depends(require_csrf), db: Session = Depends(get_db)) -> Response:
    try:
        svc.set_ttl(db, auth.user, chat_id, body.ttl_seconds)
    except svc.ChatError as e:
        raise _fail(e) from None
    _notify(request, _member_ids(db, chat_id))
    return Response(status_code=204)


@router.post("/{chat_id}/hide", status_code=204)
def hide(chat_id: uuid.UUID, auth: AuthContext = Depends(require_csrf), db: Session = Depends(get_db)) -> Response:
    try:
        svc.hide_chat(db, auth.user, chat_id)
    except svc.ChatError as e:
        raise _fail(e) from None
    return Response(status_code=204)


@router.post("/{chat_id}/members", status_code=204)
def add_members(chat_id: uuid.UUID, body: AddMembersIn, request: Request, auth: AuthContext = Depends(require_csrf),
                db: Session = Depends(get_db)) -> Response:
    try:
        svc.add_members(db, request.app.state.settings, auth.user, chat_id, body.usernames, body.members_version, body.meta_ciphertext)
    except svc.ChatError as e:
        raise _fail(e) from None
    _notify(request, _member_ids(db, chat_id))
    return Response(status_code=204)


@router.delete("/{chat_id}/members/{username}", status_code=204)
def remove_member(chat_id: uuid.UUID, username: str, request: Request, members_version: int | None = Query(None, ge=0),
                  auth: AuthContext = Depends(require_csrf), db: Session = Depends(get_db)) -> Response:
    before = _member_ids(db, chat_id)           # the removed person is told too
    try:
        svc.remove_member(db, auth.user, chat_id, username, members_version)
    except svc.ChatError as e:
        raise _fail(e) from None
    _notify(request, before)
    return Response(status_code=204)


@router.post("/{chat_id}/blobs", status_code=201)
async def upload_blob(chat_id: uuid.UUID, request: Request, auth: AuthContext = Depends(require_csrf), db: Session = Depends(get_db)) -> dict:
    data = await request.body()                 # size already capped by the body-size middleware for this path
    try:
        bid = await run_in_threadpool(svc.upload_blob, db, request.app.state.settings, auth.user, chat_id, data)
    except svc.ChatError as e:
        raise _fail(e) from None
    return {"id": str(bid)}


@router.get("/{chat_id}/blobs/{blob_id}")
def download_blob(chat_id: uuid.UUID, blob_id: uuid.UUID, auth: AuthContext = Depends(current_auth), db: Session = Depends(get_db)) -> Response:
    try:
        data = svc.get_blob(db, auth.user, chat_id, blob_id)
    except svc.ChatError as e:
        raise _fail(e) from None
    return Response(content=data, media_type="application/octet-stream")
